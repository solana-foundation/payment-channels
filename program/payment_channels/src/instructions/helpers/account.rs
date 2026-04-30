use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    PaymentChannelsError,
    helpers::token::{
        MintExtensionPolicy, TokenAccountExtensionPolicy, TokenProgramKind, base_layout,
        scan_tlv_extensions, tlv,
    },
};

/// Token-program validation entry points on [`AccountView`].
pub(crate) trait AccountValidator {
    /// Parses an SPL Token or Token-2022 mint. Token-2022 mints accept
    /// only transfer-amount-neutral extensions (metadata/group pointers
    /// and payloads); transfer fees, hooks, and confidential transfers
    /// are rejected.
    fn validate_as_mint<'a>(
        &'a self,
        program: TokenProgramKind,
    ) -> Result<ValidatedMint<'a>, PaymentChannelsError>;

    /// Parses an `Initialized` ATA for `(owner, mint.program, mint)`.
    /// Token-2022 accounts may carry only the `ImmutableOwner` extension.
    fn validate_as_token_account<'mint, 'a>(
        &'a self,
        owner: &Address,
        mint: &'mint ValidatedMint<'a>,
    ) -> Result<ValidatedTokenAccount<'mint, 'a>, PaymentChannelsError>;

    /// Asserts the address is the canonical ATA for `(owner, program, mint)`
    /// without reading account state. Used at `open` (account not yet
    /// allocated) and `top_up` (escrow address proof only).
    fn verify_ata_address(
        &self,
        owner: &Address,
        program: TokenProgramKind,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError>;
}

impl AccountValidator for AccountView {
    fn validate_as_mint<'a>(
        &'a self,
        program: TokenProgramKind,
    ) -> Result<ValidatedMint<'a>, PaymentChannelsError> {
        let decimals = match program {
            // pinocchio_token enforces owner == SPL Token + exact length.
            TokenProgramKind::SplToken => pinocchio_token::state::Mint::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals(),
            // pinocchio_token_2022 enforces owner == Token-2022 and (when
            // extensions are present) the AccountType discriminator byte.
            TokenProgramKind::Token2022 => {
                pinocchio_token_2022::state::Mint::from_account_view(self)
                    .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                    .decimals()
            }
        };

        if program.has_extensions() {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?;
            if data.len() >= tlv::START {
                // The gap between the mint base region and the AccountType
                // discriminator must be all zero so a Mint can never be
                // misread as an Account with extensions; upstream's
                // validate_account_type checks the discriminator byte itself
                // but not these padding bytes.
                //
                // SAFE: the `>= tlv::START` guard bounds both
                // `data[MINT_LEN..ACCOUNT_TYPE_OFFSET]` and the trailer
                // slice below; `MINT_LEN < TOKEN_ACCOUNT_LEN` is a
                // Token-2022 wire-format invariant.
                if data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]
                    .iter()
                    .any(|b| *b != 0)
                {
                    return Err(PaymentChannelsError::MalformedTokenAccountData);
                }
                scan_tlv_extensions(&data[tlv::START..], &MintExtensionPolicy)?;
            }
        }

        Ok(ValidatedMint {
            view: self,
            program,
            decimals,
        })
    }

    fn validate_as_token_account<'mint, 'a>(
        &'a self,
        owner: &Address,
        mint: &'mint ValidatedMint<'a>,
    ) -> Result<ValidatedTokenAccount<'mint, 'a>, PaymentChannelsError> {
        let mint_address = mint.view.address();

        let (expected_address, _) = Address::find_program_address(
            &[
                owner.as_ref(),
                mint.program.id().as_ref(),
                mint_address.as_ref(),
            ],
            &pinocchio_associated_token_account::ID,
        );
        if self.address() != &expected_address {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        let (acc_mint, acc_owner, initialized) = match mint.program {
            TokenProgramKind::SplToken => {
                let acc = pinocchio_token::state::Account::from_account_view(self)
                    .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
                let initialized = matches!(
                    acc.state(),
                    pinocchio_token::state::AccountState::Initialized
                );
                (*acc.mint(), *acc.owner(), initialized)
            }
            TokenProgramKind::Token2022 => {
                let acc = pinocchio_token_2022::state::Account::from_account_view(self)
                    .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
                let initialized = matches!(
                    acc.state(),
                    pinocchio_token_2022::state::AccountState::Initialized
                );
                (*acc.mint(), *acc.owner(), initialized)
            }
        };

        if &acc_mint != mint_address || &acc_owner != owner || !initialized {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        if mint.program.has_extensions() {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            if data.len() >= tlv::START {
                scan_tlv_extensions(&data[tlv::START..], &TokenAccountExtensionPolicy)?;
            }
        }

        Ok(ValidatedTokenAccount { view: self, mint })
    }

    fn verify_ata_address(
        &self,
        owner: &Address,
        program: TokenProgramKind,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError> {
        let (expected_address, _) = Address::find_program_address(
            &[owner.as_ref(), program.id().as_ref(), mint.as_ref()],
            &pinocchio_associated_token_account::ID,
        );
        if self.address() != &expected_address {
            return Err(PaymentChannelsError::AddressMismatch);
        }
        Ok(())
    }
}

/// Validated mint paired with its program kind and decimals.
pub(crate) struct ValidatedMint<'a> {
    view: &'a AccountView,
    program: TokenProgramKind,
    decimals: u8,
}

impl<'a> ValidatedMint<'a> {
    #[inline]
    pub(crate) fn view(&self) -> &'a AccountView {
        self.view
    }

    #[inline]
    pub(crate) fn decimals(&self) -> u8 {
        self.decimals
    }

    #[inline]
    pub(crate) fn program_id(&self) -> &'static Address {
        self.program.id()
    }

    /// `verify_ata_address` against this mint's program and address.
    #[inline]
    pub(crate) fn verify_ata_address(
        &self,
        ata: &AccountView,
        owner: &Address,
    ) -> Result<(), PaymentChannelsError> {
        ata.verify_ata_address(owner, self.program, self.view.address())
    }
}

/// Validated `Initialized` ATA bound to a [`ValidatedMint`].
pub(crate) struct ValidatedTokenAccount<'mint, 'a> {
    view: &'a AccountView,
    mint: &'mint ValidatedMint<'a>,
}

impl<'mint, 'a> ValidatedTokenAccount<'mint, 'a> {
    #[inline]
    pub(crate) fn view(&self) -> &'a AccountView {
        self.view
    }

    /// Raw token amount.
    pub(crate) fn amount(&self) -> Result<u64, PaymentChannelsError> {
        match self.mint.program {
            TokenProgramKind::SplToken => Ok(pinocchio_token::state::Account::from_account_view(
                self.view,
            )
            .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?
            .amount()),
            TokenProgramKind::Token2022 => Ok(
                pinocchio_token_2022::state::Account::from_account_view(self.view)
                    .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?
                    .amount(),
            ),
        }
    }

    /// Signed `TransferChecked` CPI to another account on the same mint.
    /// `amount == 0` short-circuits.
    pub(crate) fn transfer_signed_to(
        &self,
        to: &ValidatedTokenAccount<'mint, '_>,
        authority: &AccountView,
        amount: u64,
        signers: &[Signer<'_, '_>],
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }

        TransferChecked {
            from: self.view,
            mint: self.mint.view,
            to: to.view,
            authority,
            amount,
            decimals: self.mint.decimals,
            token_program: self.mint.program.id(),
        }
        .invoke_signed(signers)
    }
}
