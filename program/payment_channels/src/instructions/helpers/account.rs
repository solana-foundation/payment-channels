use pinocchio::{AccountView, Address};

use crate::{
    PaymentChannelsError,
    helpers::token::{
        MintExtensionPolicy, TokenAccountExtensionPolicy, base_layout, scan_tlv_extensions, tlv,
    },
};

/// Token-program validation entry points on [`AccountView`]. Returns
/// [`PaymentChannelsError`]; the consuming `process` function `?`-converts
/// to [`pinocchio::error::ProgramError`] at the instruction boundary.
pub trait AccountValidator {
    /// Validates that `self` is the canonical ATA for `(owner, token_program,
    /// mint)`. Does not parse account state or check `Initialized`; suitable
    /// for `open` where the account hasn't been allocated yet.
    fn validate_as_ata_unchecked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError>;

    /// Validates that `self` is the canonical ATA for `(owner, token_program,
    /// mint)`, parses it as `Initialized`, and (for Token-2022) walks the TLV
    /// trailer rejecting any extension other than `ImmutableOwner`.
    fn validate_as_ata_checked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError>;

    /// Validates `self` as a mint under `token_program` and returns its
    /// decimals. SPL classic mints must be exactly `MINT_LEN`. Token-2022
    /// mints accept only transfer-amount-neutral extensions (metadata/group
    /// pointers and payloads); transfer fees, hooks, and confidential
    /// transfers are rejected so amount accounting cannot diverge from the
    /// literal `amount`.
    fn validate_as_mint(&self, token_program: &Address) -> Result<u8, PaymentChannelsError>;
}

impl AccountValidator for AccountView {
    fn validate_as_ata_unchecked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError> {
        let (expected_address, _) = Address::find_program_address(
            &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
            &pinocchio_associated_token_account::ID,
        );
        if self.address() != &expected_address {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        Ok(())
    }

    fn validate_as_ata_checked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError> {
        self.validate_as_ata_unchecked(owner, token_program, mint)?;

        let (acc_mint, acc_owner, initialized) = if *token_program == pinocchio_token::ID {
            let acc = pinocchio_token::state::Account::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            let initialized = matches!(
                acc.state(),
                pinocchio_token::state::AccountState::Initialized
            );
            (*acc.mint(), *acc.owner(), initialized)
        } else if *token_program == pinocchio_token_2022::ID {
            let acc = pinocchio_token_2022::state::Account::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            let initialized = matches!(
                acc.state(),
                pinocchio_token_2022::state::AccountState::Initialized
            );
            (*acc.mint(), *acc.owner(), initialized)
        } else {
            return Err(PaymentChannelsError::InvalidTokenProgram);
        };

        if &acc_mint != mint || &acc_owner != owner || !initialized {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        if *token_program == pinocchio_token_2022::ID {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            if data.len() >= tlv::START {
                scan_tlv_extensions::<TokenAccountExtensionPolicy>(&data[tlv::START..])?;
            }
        }

        Ok(())
    }

    fn validate_as_mint(&self, token_program: &Address) -> Result<u8, PaymentChannelsError> {
        match *token_program {
            // pinocchio_token enforces owner == SPL classic + exact length.
            pinocchio_token::ID => Ok(pinocchio_token::state::Mint::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals()),
            pinocchio_token_2022::ID => {
                let decimals = pinocchio_token_2022::state::Mint::from_account_view(self)
                    .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                    .decimals();

                let data = self
                    .try_borrow()
                    .map_err(|_| PaymentChannelsError::MintAccountMismatch)?;
                if data.len() >= tlv::START {
                    // Upstream's `validate_account_type` checks the discriminator at
                    // `Account::BASE_LEN` but doesn't enforce that the gap between
                    // the mint base region and that offset is zero — guard against
                    // smuggled bytes here, then walk the whitelisted TLV trailer.
                    if data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]
                        .iter()
                        .any(|&b| b != 0)
                    {
                        return Err(PaymentChannelsError::MalformedTokenAccountData);
                    }
                    scan_tlv_extensions::<MintExtensionPolicy>(&data[tlv::START..])?;
                }

                Ok(decimals)
            }
            _ => Err(PaymentChannelsError::InvalidTokenProgram),
        }
    }
}
