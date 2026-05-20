use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer};

use crate::{
    PaymentChannelsError, TREASURY_OWNER,
    helpers::{
        DistributionEntry,
        accounts::validation::{AccountValidationError, AccountValidator},
        token::{MintExtensionPolicy, TokenExtensionError, base_layout, scan_tlv_extensions, tlv},
    },
};

pub struct Unchecked;
pub struct Checked;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Unchecked {}
    impl Sealed for super::Checked {}
}

pub trait State: private::Sealed {}
impl State for Unchecked {}
impl State for Checked {}

pub struct AnyTokenAccountView<'a, S: State = Unchecked> {
    inner: &'a AccountView,
    _s: PhantomData<S>,
}

impl<'a, S> Deref for AnyTokenAccountView<'a, S>
where
    S: State,
{
    type Target = AccountView;
    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

macro_rules! decl_account_view {
    ($($T:ident),+ $(,)?) => {$(
        pub struct $T<'a, S: State = Unchecked> {
            inner: &'a mut AccountView,
            _s: PhantomData<S>,
        }

        impl<'a> $T<'a, Checked> {
            pub fn as_any(&self) -> AnyTokenAccountView<'_, Checked> {
                AnyTokenAccountView { inner: self.inner, _s: PhantomData }
            }
        }

        impl<'a> From<&'a mut AccountView> for $T<'a, Unchecked> {
            fn from(value: &'a mut AccountView) -> Self {
                Self {
                    inner: value,
                    _s: Default::default(),
                }
            }
        }

        impl<'a, S> Deref for $T<'a, S> where S: State {
            type Target = AccountView;
            fn deref(&self) -> &Self::Target { self.inner }
        }

        impl<'a, S> DerefMut for $T<'a, S> where S: State {
            fn deref_mut(&mut self) -> &mut Self::Target { self.inner }
        }

    )*};
}

// General account view definitions

decl_account_view!(
    ChannelAccountView,
    ChannelTokenAccountView,
    PayerAccountView,
    PayerTokenAccountView,
    PayeeAccountView,
    PayeeTokenAccountView,
    TokenProgramAccountView,
    MintAccountView,
    TreasuryTokenAccountView,
);

impl<'a> TokenProgramAccountView<'a, Checked> {
    pub fn amount(
        &self,
        account: &AnyTokenAccountView<'_, Checked>,
    ) -> Result<u64, PaymentChannelsError> {
        match TokenProgramKind::from_address(self.address())? {
            TokenProgramKind::Spl => {
                Ok(pinocchio_token::state::Account::from_account_view(account)
                    .map_err(|_| PaymentChannelsError::MalformedMintTokenAccountData)?
                    .amount())
            }
            TokenProgramKind::Token2022 => Ok(
                pinocchio_token_2022::state::Account::from_account_view(account)
                    .map_err(|_| PaymentChannelsError::MalformedMintTokenAccountData)?
                    .amount(),
            ),
        }
    }
}

impl<'a> TreasuryTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        token_ctx: &TokenContext<'a>,
    ) -> Result<TreasuryTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner
            .validate_as_ata_checked(&TREASURY_OWNER, token_ctx)
            .map_err(|err| match err {
                AccountValidationError::AddressMismatch => {
                    PaymentChannelsError::TreasuryAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidTreasuryTokenAccount
                }
                AccountValidationError::TokenExtensionError => {
                    PaymentChannelsError::InvalidTreasuryTokenExtensions
                }
            })?;

        Ok(TreasuryTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayeeTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        payee: &Address,
        token_ctx: &TokenContext<'a>,
    ) -> Result<PayeeTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner
            .validate_as_ata_checked(payee, token_ctx)
            .map_err(|err| match err {
                AccountValidationError::AddressMismatch => {
                    PaymentChannelsError::PayeeAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidPayeeTokenAccount
                }
                AccountValidationError::TokenExtensionError => {
                    PaymentChannelsError::InvalidPayeeTokenExtensions
                }
            })?;

        Ok(PayeeTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

// Edge case-specific manual implementations

pub struct RecipientTokenAccountsView<'a, S: State = Unchecked> {
    inner: &'a mut [AccountView],
    _s: PhantomData<S>,
}

impl<'a> RecipientTokenAccountsView<'a, Unchecked> {
    pub fn check(
        self,
        entries: &[DistributionEntry],
        token_ctx: &TokenContext<'a>,
    ) -> Result<RecipientTokenAccountsView<'a, Checked>, PaymentChannelsError> {
        for (entry, account) in entries.iter().zip(self.inner.iter()) {
            account
                .validate_as_ata_checked(&entry.recipient, token_ctx)
                .map_err(|err| match err {
                    AccountValidationError::AddressMismatch => {
                        PaymentChannelsError::RecipientAccountMismatch
                    }
                    AccountValidationError::MalformedTokenAccountData => {
                        PaymentChannelsError::InvalidRecipientTokenAccount
                    }
                    AccountValidationError::TokenExtensionError => {
                        PaymentChannelsError::InvalidRecipientTokenExtensions
                    }
                })?;
        }

        Ok(RecipientTokenAccountsView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> RecipientTokenAccountsView<'a, Checked> {
    pub fn iter_as_any(&self) -> impl Iterator<Item = AnyTokenAccountView<'_, Checked>> {
        self.iter().map(|acc| AnyTokenAccountView::<Checked> {
            inner: acc,
            _s: Default::default(),
        })
    }
}

impl<'a> From<&'a mut [AccountView]> for RecipientTokenAccountsView<'a, Unchecked> {
    fn from(value: &'a mut [AccountView]) -> Self {
        Self {
            inner: value,
            _s: Default::default(),
        }
    }
}

impl<'a, S> Deref for RecipientTokenAccountsView<'a, S>
where
    S: State,
{
    type Target = [AccountView];
    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

/// Which SPL token program backs this channel's mint and ATAs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TokenProgramKind {
    /// Classic SPL Token (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
    Spl,
    /// Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
    Token2022,
}

impl TokenProgramKind {
    pub fn from_address(address: &Address) -> Result<Self, PaymentChannelsError> {
        if address == &pinocchio_token::ID {
            Ok(Self::Spl)
        } else if address == &pinocchio_token_2022::ID {
            Ok(Self::Token2022)
        } else {
            Err(PaymentChannelsError::InvalidMintTokenProgram)
        }
    }

    /// Whether [`Transfer::flush`](crate::instructions::helpers::Transfer::flush)
    /// should emit SPL `Batch` CPIs for `pending_len` queued payouts.
    pub const fn spl_batch_flush_eligible(self, pending_len: usize) -> bool {
        matches!(self, Self::Spl) && pending_len >= 2
    }
}

pub struct TokenContext<'a> {
    pub mint: MintAccountView<'a, Checked>,
    pub token_program: TokenProgramAccountView<'a, Checked>,
    pub decimals: u8,
    pub kind: TokenProgramKind,
}

impl<'a> TokenContext<'a> {
    pub fn new(
        mint: MintAccountView<'a, Unchecked>,
        token_program: TokenProgramAccountView<'a, Unchecked>,
    ) -> Result<Self, PaymentChannelsError> {
        let kind = TokenProgramKind::from_address(token_program.address())?;

        let decimals = match kind {
            TokenProgramKind::Spl => {
                // pinocchio_token enforces owner == SPL classic + exact length.
                pinocchio_token::state::Mint::from_account_view(&mint)
                    .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                    .decimals()
            }
            TokenProgramKind::Token2022 => {
                // pinocchio_token_2022 enforces owner == Token-2022 and (when
                // extensions are present) the AccountType discriminator byte.
                pinocchio_token_2022::state::Mint::from_account_view(&mint)
                    .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                    .decimals()
            }
        };

        if kind == TokenProgramKind::Token2022 {
            let data = mint
                .try_borrow()
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?;
            if data.len() > base_layout::MINT_LEN {
                // Require zero padding between mint base and AccountType offset,
                // then walk the whitelisted TLV trailer.
                let all_zero = data[base_layout::MINT_LEN..tlv::ACCOUNT_TYPE_OFFSET]
                    .iter()
                    .all(|b| *b == 0);
                if !all_zero {
                    return Err(PaymentChannelsError::MalformedMintTokenAccountData);
                }
                scan_tlv_extensions::<MintExtensionPolicy>(&data[tlv::START..]).map_err(|err| {
                    match err {
                        TokenExtensionError::MalformedTokenAccountData
                        | TokenExtensionError::UnsupportedTokenExtension => {
                            PaymentChannelsError::MalformedMintTokenExtensions
                        }
                    }
                })?;
            }
        }

        Ok(Self {
            token_program: TokenProgramAccountView {
                inner: token_program.inner,
                _s: Default::default(),
            },
            mint: MintAccountView {
                inner: mint.inner,
                _s: Default::default(),
            },
            decimals,
            kind,
        })
    }
}

pub struct ChannelContext<'a> {
    pub channel: ChannelAccountView<'a, Unchecked>,
    pub channel_token_account: ChannelTokenAccountView<'a, Checked>,
    pub token_ctx: TokenContext<'a>,
}

impl<'a> ChannelContext<'a> {
    pub fn new(
        channel: ChannelAccountView<'a, Unchecked>,
        channel_token_account: ChannelTokenAccountView<'a, Unchecked>,
        token_ctx: TokenContext<'a>,
    ) -> Result<Self, PaymentChannelsError> {
        channel_token_account
            .validate_as_ata_checked(channel.address(), &token_ctx)
            .map_err(|err| match err {
                AccountValidationError::AddressMismatch => {
                    PaymentChannelsError::ChannelAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidChannelTokenAccount
                }
                AccountValidationError::TokenExtensionError => {
                    PaymentChannelsError::InvalidChannelTokenExtensions
                }
            })?;

        Ok(Self {
            channel,
            channel_token_account: ChannelTokenAccountView {
                inner: channel_token_account.inner,
                _s: Default::default(),
            },
            token_ctx,
        })
    }

    /// For use in `open` where the escrow ATA has not been created yet —
    /// validates the derived address only, skipping token account data parsing.
    pub fn new_uninit(
        channel: ChannelAccountView<'a, Unchecked>,
        channel_token_account: ChannelTokenAccountView<'a, Unchecked>,
        token_ctx: TokenContext<'a>,
    ) -> Result<Self, PaymentChannelsError> {
        channel_token_account
            .validate_as_ata_unchecked(
                channel.address(),
                token_ctx.token_program.address(),
                token_ctx.mint.address(),
            )
            .map_err(|_| PaymentChannelsError::ChannelAccountMismatch)?;

        Ok(Self {
            channel,
            channel_token_account: ChannelTokenAccountView {
                inner: channel_token_account.inner,
                _s: Default::default(),
            },
            token_ctx,
        })
    }

    /// Invokes a signed `TransferChecked` CPI from a channel-owned token account.
    pub fn transfer_checked_signed(
        &self,
        to: &AnyTokenAccountView<'_, Checked>,
        amount: u64,
        signers: &[Signer<'_, '_>],
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }

        pinocchio_token_2022::instructions::TransferChecked {
            from: &self.channel_token_account,
            mint: &self.token_ctx.mint,
            to,
            authority: &self.channel,
            amount,
            decimals: self.token_ctx.decimals,
            token_program: self.token_ctx.token_program.address(),
        }
        .invoke_signed(signers)
    }
}

pub struct PayerContext<'a> {
    pub payer: PayerAccountView<'a, Checked>,
    pub payer_token_account: PayerTokenAccountView<'a, Checked>,
}

impl<'a> PayerContext<'a> {
    pub fn new(
        payer: PayerAccountView<'a, Unchecked>,
        payer_token_account: PayerTokenAccountView<'a, Unchecked>,
        token_ctx: &TokenContext<'a>,
    ) -> Result<Self, PaymentChannelsError> {
        payer_token_account
            .validate_as_ata_checked(payer.address(), token_ctx)
            .map_err(|err| match err {
                AccountValidationError::AddressMismatch => {
                    PaymentChannelsError::PayerAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidPayerTokenAccount
                }
                AccountValidationError::TokenExtensionError => {
                    PaymentChannelsError::InvalidPayerTokenExtensions
                }
            })?;

        Ok(Self {
            payer: PayerAccountView {
                inner: payer.inner,
                _s: Default::default(),
            },
            payer_token_account: PayerTokenAccountView {
                inner: payer_token_account.inner,
                _s: Default::default(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TokenProgramKind;

    #[test]
    fn spl_batch_flush_eligible_spl_needs_two_or_more() {
        assert!(!TokenProgramKind::Spl.spl_batch_flush_eligible(0));
        assert!(!TokenProgramKind::Spl.spl_batch_flush_eligible(1));
        assert!(TokenProgramKind::Spl.spl_batch_flush_eligible(2));
    }

    #[test]
    fn spl_batch_flush_eligible_token2022_never_batches() {
        assert!(!TokenProgramKind::Token2022.spl_batch_flush_eligible(0));
        assert!(!TokenProgramKind::Token2022.spl_batch_flush_eligible(1));
        assert!(!TokenProgramKind::Token2022.spl_batch_flush_eligible(35));
    }
}
