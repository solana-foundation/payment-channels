use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer};

use crate::{
    PaymentChannelsError, TREASURY_OWNER,
    helpers::{
        DistributionEntry,
        accounts::validation::AccountValidator,
        token::{base_layout, scan_tlv_extensions, tlv},
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
        #[allow(dead_code)]
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

// General account view checks

impl<'a> ChannelAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<ChannelAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(ChannelAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayeeAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<PayeeAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(PayeeAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> TokenProgramAccountView<'a, Checked> {
    pub fn amount(
        &self,
        account: &AnyTokenAccountView<'_, Checked>,
    ) -> Result<u64, PaymentChannelsError> {
        if self.address() == &pinocchio_token::ID {
            Ok(pinocchio_token::state::Account::from_account_view(account)
                .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?
                .amount())
        } else if self.address() == &pinocchio_token_2022::ID {
            Ok(
                pinocchio_token_2022::state::Account::from_account_view(account)
                    .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?
                    .amount(),
            )
        } else {
            Err(PaymentChannelsError::InvalidTokenProgram)
        }
    }
}

impl<'a> TreasuryTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        token_ctx: &TokenContext<'a>,
    ) -> Result<TreasuryTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner
            .validate_as_ata_checked(&TREASURY_OWNER, &token_ctx)?;

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
        self.inner.validate_as_ata_checked(payee, &token_ctx)?;

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
                .map_err(|e| match e {
                    PaymentChannelsError::AddressMismatch => {
                        PaymentChannelsError::InvalidRecipientAccount
                    }
                    other => other,
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

pub struct TokenContext<'a> {
    pub mint: MintAccountView<'a, Checked>,
    pub token_program: TokenProgramAccountView<'a, Checked>,
    pub decimals: u8,
}

impl<'a> TokenContext<'a> {
    pub fn new(
        mint: MintAccountView<'a, Unchecked>,
        token_program: TokenProgramAccountView<'a, Unchecked>,
    ) -> Result<Self, PaymentChannelsError> {
        let decimals = if token_program.address() == &pinocchio_token::ID {
            // pinocchio_token enforces owner == SPL classic + exact length.
            pinocchio_token::state::Mint::from_account_view(&mint)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals()
        } else if token_program.address() == &pinocchio_token_2022::ID {
            // pinocchio_token_2022 enforces owner == Token-2022 and (when
            // extensions are present) the AccountType discriminator byte.
            pinocchio_token_2022::state::Mint::from_account_view(&mint)
                .map_err(|_| PaymentChannelsError::MintAccountMismatch)?
                .decimals()
        } else {
            return Err(PaymentChannelsError::InvalidTokenProgram);
        };

        if token_program.address() == &pinocchio_token_2022::ID {
            let data = mint
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
        })
    }
}

pub struct ChannelContext<'a> {
    pub channel: ChannelAccountView<'a, Checked>,
    pub channel_token_account: ChannelTokenAccountView<'a, Checked>,
    pub token_ctx: TokenContext<'a>,
}

impl<'a> ChannelContext<'a> {
    pub fn new(
        channel: ChannelAccountView<'a, Checked>,
        channel_token_account: ChannelTokenAccountView<'a, Unchecked>,
        token_ctx: TokenContext<'a>,
    ) -> Result<Self, PaymentChannelsError> {
        channel_token_account.validate_as_ata_checked(channel.address(), &token_ctx)?;

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
        payer_token_account.validate_as_ata_checked(payer.address(), &token_ctx)?;

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
