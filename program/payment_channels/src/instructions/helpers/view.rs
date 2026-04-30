use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use pinocchio::{AccountView, Address};

use crate::{
    PaymentChannelsError, TREASURY_OWNER,
    helpers::{AccountValidator, DistributionEntry},
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

pub struct AnyTokenAccountsView<'a, S: State = Unchecked> {
    inner: &'a AccountView,
    _s: PhantomData<S>,
}

#[allow(dead_code)]
impl<'a, S: State> AnyTokenAccountsView<'a, S> {
    pub fn new(inner: &'a AccountView) -> Self {
        Self {
            inner,
            _s: Default::default(),
        }
    }
}

impl<'a> From<&'a AccountView> for AnyTokenAccountsView<'a, Unchecked> {
    fn from(value: &'a AccountView) -> Self {
        Self {
            inner: value,
            _s: Default::default(),
        }
    }
}

impl<'a> From<&'a AccountView> for AnyTokenAccountsView<'a, Checked> {
    fn from(value: &'a AccountView) -> Self {
        Self {
            inner: value,
            _s: Default::default(),
        }
    }
}

macro_rules! decl_account_view {
    ($($T:ident),+ $(,)?) => {$(
        #[allow(dead_code)]
        pub struct $T<'a, S: State = Unchecked> {
            inner: &'a mut AccountView,
            _s: PhantomData<S>,
        }

        #[allow(dead_code)]
        impl<'a> $T<'a, Unchecked> {
            pub fn new_unchecked(inner: &'a mut AccountView) -> Self {
                Self {
                    inner,
                    _s: Default::default(),
                }
            }
        }

        impl<'a, S: State> $T<'a, S> {
            pub fn as_any(&self) -> AnyTokenAccountsView<'_, S> {
                AnyTokenAccountsView { inner: self.inner, _s: PhantomData }
            }
        }

        #[allow(dead_code)]
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

// checks

impl<'a> ChannelAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<ChannelAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(ChannelAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayerAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<PayerAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(PayerAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayeeAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<ChannelAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(ChannelAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> ChannelTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        channel_address: &Address,
        token_program: &TokenProgramAccountView<'a, Checked>,
        mint: &MintAccountView<'a, Checked>,
    ) -> Result<ChannelTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner.validate_as_ata_checked(
            &channel_address,
            token_program.address(),
            mint.address(),
        )?;

        Ok(ChannelTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> TokenProgramAccountView<'a, Unchecked> {
    pub fn check(self) -> Result<TokenProgramAccountView<'a, Checked>, PaymentChannelsError> {
        Ok(TokenProgramAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> TokenProgramAccountView<'a, Checked> {
    pub fn amount(
        &self,
        account: &AnyTokenAccountsView<'_, Checked>,
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

impl<'a> MintAccountView<'a, Unchecked> {
    pub fn check(
        self,
        token_program: &TokenProgramAccountView<'a, Checked>,
    ) -> Result<MintAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner.validate_as_mint(token_program.address())?;

        Ok(MintAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> TreasuryTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        token_program: &TokenProgramAccountView<'a, Checked>,
        mint: &MintAccountView<'a, Checked>,
    ) -> Result<TreasuryTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner.validate_as_ata_checked(
            &TREASURY_OWNER,
            token_program.address(),
            mint.address(),
        )?;

        Ok(TreasuryTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayerTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        payer: &Address,
        token_program: &TokenProgramAccountView<'a, Checked>,
        mint: &MintAccountView<'a, Checked>,
    ) -> Result<PayerTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner
            .validate_as_ata_checked(payer, token_program.address(), mint.address())?;

        Ok(PayerTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

impl<'a> PayeeTokenAccountView<'a, Unchecked> {
    pub fn check(
        self,
        payee: &Address,
        token_program: &TokenProgramAccountView<'a, Checked>,
        mint: &MintAccountView<'a, Checked>,
    ) -> Result<PayeeTokenAccountView<'a, Checked>, PaymentChannelsError> {
        self.inner
            .validate_as_ata_checked(payee, token_program.address(), mint.address())?;

        Ok(PayeeTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}
// Manual case-specific implementations

impl<'a, S> Deref for AnyTokenAccountsView<'a, S>
where
    S: State,
{
    type Target = AccountView;
    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

pub struct RecipientTokenAccountsView<'a, S: State = Unchecked> {
    inner: &'a mut [AccountView],
    _s: PhantomData<S>,
}

#[allow(dead_code)]
impl<'a> RecipientTokenAccountsView<'a, Unchecked> {
    pub fn new_unchecked(inner: &'a mut [AccountView]) -> Self {
        Self {
            inner,
            _s: Default::default(),
        }
    }
}

impl<'a> RecipientTokenAccountsView<'a, Unchecked> {
    pub fn check(
        self,
        entries: &[DistributionEntry],
        token_program: &TokenProgramAccountView<'a, Checked>,
        mint: &MintAccountView<'a, Checked>,
    ) -> Result<RecipientTokenAccountsView<'a, Checked>, PaymentChannelsError> {
        for (entry, account) in entries.iter().zip(self.inner.iter()) {
            account
                .validate_as_ata_checked(&entry.recipient, token_program.address(), mint.address())
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

#[allow(dead_code)]
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
