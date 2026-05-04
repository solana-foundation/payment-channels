use pinocchio::{AccountView, Address};

use crate::{
    PaymentChannelsError,
    helpers::{
        accounts::view::TokenContext,
        token::{TokenAccountExtensionPolicy, base_layout, scan_tlv_extensions, tlv},
    },
};

pub trait AccountValidator {
    /// Validates that `self` is an associated token account created via seeds (`owner`, `token_program`, `mint`).
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
        token_ctx: &TokenContext,
    ) -> Result<(), PaymentChannelsError>;
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
        token_ctx: &TokenContext,
    ) -> Result<(), PaymentChannelsError> {
        let (expected_address, _) = Address::find_program_address(
            &[
                owner.as_ref(),
                token_ctx.token_program.address().as_ref(),
                token_ctx.mint.address().as_ref(),
            ],
            &pinocchio_associated_token_account::ID,
        );
        if self.address() != &expected_address {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        let (mint_addr, owner_addr, initialized) =
            if token_ctx.token_program.address() == &pinocchio_token::ID {
                let acc = pinocchio_token::state::Account::from_account_view(self)
                    .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
                let initialized = matches!(
                    acc.state(),
                    pinocchio_token::state::AccountState::Initialized
                );
                (*acc.mint(), *acc.owner(), initialized)
            } else if token_ctx.token_program.address() == &pinocchio_token_2022::ID {
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

        if &mint_addr != token_ctx.mint.address() || &owner_addr != owner || !initialized {
            return Err(PaymentChannelsError::AddressMismatch);
        }

        if token_ctx.token_program.address() == &pinocchio_token_2022::ID {
            let data = self
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MalformedTokenAccountData)?;
            if data.len() > base_layout::TOKEN_ACCOUNT_LEN {
                // Token-account base layout already aligns with the AccountType
                // discriminator offset, so there's no padding to police — go
                // straight to the whitelisted TLV walk.
                scan_tlv_extensions::<TokenAccountExtensionPolicy>(&data[tlv::START..])?;
            }
        }

        Ok(())
    }
}
