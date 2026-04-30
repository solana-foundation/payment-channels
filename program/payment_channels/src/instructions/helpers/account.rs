use pinocchio::{AccountView, Address};

use crate::{
    PaymentChannelsError,
    helpers::token::{base_layout, scan_tlv_extensions, tlv},
};

pub trait AccountValidator {
    /// Validates that `self` is an associated token account created via seeds (`owner`, `token_program`, `mint`.
    /// Does not check any safety pre-conditions, or if the account is `Initialized`.
    fn validate_as_ata_unchecked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError>;

    /// Validates that `self` is an associated token account owned by `token_program`, holds
    /// `expected_mint`, is owned by `expected_owner`, and is in the `Initialized`
    /// state. Token-2022 accounts may carry only the `ImmutableOwner` extension.
    fn validate_as_ata_checked(
        &self,
        owner: &Address,
        token_program: &Address,
        mint: &Address,
    ) -> Result<(), PaymentChannelsError>;

    /// Validates the `self` mint account against `token_program` and returns its decimals.
    ///
    /// SPL classic mints must be exactly `MINT_LEN`. Token-2022 mints are accepted
    /// only when their TLV trailer carries extensions whitelisted as
    /// transfer-amount-neutral (metadata/group pointers and payloads); anything
    /// else — most importantly transfer fees, hooks, or confidential transfers —
    /// is rejected so amount accounting cannot diverge from the literal `amount`.
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
        let (expected_address, _) = Address::find_program_address(
            &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
            &pinocchio_associated_token_account::ID,
        );
        if self.address() != &expected_address {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        let (mint_addr, owner_addr, initialized) = if *token_program == pinocchio_token::ID {
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

        if &mint_addr != mint || &owner_addr != owner || !initialized {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        if *token_program == pinocchio_token_2022::ID {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            if data.len() > base_layout::TOKEN_ACCOUNT_LEN {
                // Token-account base layout already aligns with the AccountType
                // discriminator offset, so there's no padding to police — go
                // straight to the whitelisted TLV walk.
                scan_tlv_extensions(&data[tlv::START..], false)?;
            }
        }

        Ok(())
    }

    fn validate_as_mint(&self, token_program: &Address) -> Result<u8, PaymentChannelsError> {
        let decimals = if *token_program == pinocchio_token::ID {
            // pinocchio_token enforces owner == SPL classic + exact length.
            pinocchio_token::state::Mint::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals()
        } else if *token_program == pinocchio_token_2022::ID {
            // pinocchio_token_2022 enforces owner == Token-2022 and (when
            // extensions are present) the AccountType discriminator byte.
            pinocchio_token_2022::state::Mint::from_account_view(self)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals()
        } else {
            return Err(PaymentChannelsError::InvalidTokenProgram);
        };

        if *token_program == pinocchio_token_2022::ID {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?;
            if data.len() > base_layout::MINT_LEN {
                // Upstream's `validate_account_type` checks the discriminator at
                // `Account::BASE_LEN` but doesn't enforce that the gap between the
                // mint base region and that offset is zero — guard against
                // smuggled bytes here, then walk the whitelisted TLV trailer.
                let all_zero = data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]
                    .iter()
                    .all(|b| *b == 0);
                if !all_zero {
                    return Err(PaymentChannelsError::MalformedTokenAccountData);
                }
                scan_tlv_extensions(&data[tlv::START..], true)?;
            }
        }

        Ok(decimals)
    }
}
