use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer};

use crate::{
    PaymentChannelsError, TREASURY_OWNER,
    helpers::{
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

impl<'a, S> Copy for AnyTokenAccountView<'a, S> where S: State {}

impl<'a, S> Clone for AnyTokenAccountView<'a, S>
where
    S: State,
{
    fn clone(&self) -> Self {
        *self
    }
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

impl<'a, S> AsRef<AccountView> for AnyTokenAccountView<'a, S>
where
    S: State,
{
    fn as_ref(&self) -> &AccountView {
        self.inner
    }
}

macro_rules! decl_account_views {
    (
        token { $($Token:ident),+ $(,)? }
        account { $($Account:ident),+ $(,)? }
    ) => {
        $(
            decl_account_views!(@base $Token);
            decl_account_views!(@token $Token);
        )+
        $(
            decl_account_views!(@base $Account);
        )+
    };

    (@base $T:ident) => {
        pub struct $T<'a, S: State = Unchecked> {
            inner: &'a mut AccountView,
            _s: PhantomData<S>,
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
    };

    (@token $T:ident) => {
        impl<'a> $T<'a, Checked> {
            pub fn as_any(&self) -> AnyTokenAccountView<'_, Checked> {
                AnyTokenAccountView { inner: self.inner, _s: PhantomData }
            }
        }
    };
}

// General account view definitions
decl_account_views! {
    token {
        ChannelTokenAccountView,
        PayerTokenAccountView,
        PayeeTokenAccountView,
        TreasuryTokenAccountView,
    }
    account {
        ChannelAccountView,
        PayerAccountView,
        PayeeAccountView,
        TokenProgramAccountView,
        MintAccountView,
    }
}

fn channel_token_error_for_account_validation(err: AccountValidationError) -> PaymentChannelsError {
    match err {
        AccountValidationError::AddressMismatch => PaymentChannelsError::ChannelAccountMismatch,
        AccountValidationError::MalformedTokenAccountData
        | AccountValidationError::InvalidTokenProgram => {
            PaymentChannelsError::InvalidChannelTokenAccount
        }
        AccountValidationError::TokenExtensionError(_) => {
            PaymentChannelsError::InvalidChannelTokenExtensions
        }
    }
}

fn payer_token_error_for_account_validation(err: AccountValidationError) -> PaymentChannelsError {
    match err {
        AccountValidationError::AddressMismatch => PaymentChannelsError::PayerAccountMismatch,
        AccountValidationError::MalformedTokenAccountData
        | AccountValidationError::InvalidTokenProgram => {
            PaymentChannelsError::InvalidPayerTokenAccount
        }
        AccountValidationError::TokenExtensionError(_) => {
            PaymentChannelsError::InvalidPayerTokenExtensions
        }
    }
}

fn payee_token_error_for_account_validation(err: AccountValidationError) -> PaymentChannelsError {
    match err {
        AccountValidationError::AddressMismatch => PaymentChannelsError::PayeeAccountMismatch,
        AccountValidationError::MalformedTokenAccountData
        | AccountValidationError::InvalidTokenProgram => {
            PaymentChannelsError::InvalidPayeeTokenAccount
        }
        AccountValidationError::TokenExtensionError(_) => {
            PaymentChannelsError::InvalidPayeeTokenExtensions
        }
    }
}

fn treasury_token_error_for_account_validation(
    err: AccountValidationError,
) -> PaymentChannelsError {
    match err {
        AccountValidationError::AddressMismatch => PaymentChannelsError::TreasuryAccountMismatch,
        AccountValidationError::MalformedTokenAccountData
        | AccountValidationError::InvalidTokenProgram => {
            PaymentChannelsError::InvalidTreasuryTokenAccount
        }
        AccountValidationError::TokenExtensionError(_) => {
            PaymentChannelsError::InvalidTreasuryTokenExtensions
        }
    }
}

fn recipient_token_error_for_account_validation(
    err: AccountValidationError,
) -> PaymentChannelsError {
    match err {
        AccountValidationError::AddressMismatch => PaymentChannelsError::RecipientAccountMismatch,
        AccountValidationError::MalformedTokenAccountData
        | AccountValidationError::InvalidTokenProgram => {
            PaymentChannelsError::InvalidRecipientTokenAccount
        }
        AccountValidationError::TokenExtensionError(_) => {
            PaymentChannelsError::InvalidRecipientTokenExtensions
        }
    }
}

impl<'a> TokenProgramAccountView<'a, Checked> {
    pub fn amount(
        &self,
        account: &AnyTokenAccountView<'_, Checked>,
    ) -> Result<u64, PaymentChannelsError> {
        if self.address() == &pinocchio_token::ID {
            Ok(pinocchio_token::state::Account::from_account_view(account)
                .map_err(|_| PaymentChannelsError::MalformedMintTokenAccountData)?
                .amount())
        } else if self.address() == &pinocchio_token_2022::ID {
            Ok(
                pinocchio_token_2022::state::Account::from_account_view(account)
                    .map_err(|_| PaymentChannelsError::MalformedMintTokenAccountData)?
                    .amount(),
            )
        } else {
            Err(PaymentChannelsError::InvalidMintTokenProgram)
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
            .map_err(treasury_token_error_for_account_validation)?;

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
            .map_err(payee_token_error_for_account_validation)?;

        Ok(PayeeTokenAccountView {
            inner: self.inner,
            _s: Default::default(),
        })
    }
}

// Edge case-specific manual implementations

pub struct RecipientTokenAccountsView<'a> {
    inner: &'a mut [AccountView],
}

impl<'a> From<&'a mut [AccountView]> for RecipientTokenAccountsView<'a> {
    fn from(value: &'a mut [AccountView]) -> Self {
        Self { inner: value }
    }
}

impl<'a> Deref for RecipientTokenAccountsView<'a> {
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

/// Reason a beneficiary ATA was considered redirectable instead of fatal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectReason {
    /// Beneficiary ATA is canonical but carries unsupported Token-2022 account extensions.
    UnsupportedTokenAccountExtension,
}

/// Result of validating a beneficiary ATA for a payout.
#[derive(Clone, Copy)]
pub enum RedirectableAta<'a> {
    /// Canonical ATA passed full validation and can receive the transfer.
    Valid(
        /// Checked token account view for the beneficiary destination.
        AnyTokenAccountView<'a, Checked>,
    ),
    /// Canonical ATA failed only by a redirectable condition.
    RedirectToTreasury {
        /// Reason the beneficiary payout should be sent to treasury.
        reason: RedirectReason,
    },
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
            return Err(PaymentChannelsError::InvalidMintTokenProgram);
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
        })
    }

    /// Validates only that `account` is the canonical ATA for `owner`.
    pub(crate) fn validate_ata_address(
        &self,
        account: &AccountView,
        owner: &Address,
    ) -> Result<(), AccountValidationError> {
        account.validate_as_ata_unchecked(owner, self.token_program.address(), self.mint.address())
    }

    /// Validates the canonical ATA address, base token account data, and allowed extensions.
    pub(crate) fn validate_ata_checked<'b>(
        &self,
        account: &'b AccountView,
        owner: &Address,
    ) -> Result<AnyTokenAccountView<'b, Checked>, AccountValidationError> {
        account.validate_as_ata_checked(owner, self)?;
        Ok(AnyTokenAccountView {
            inner: account,
            _s: PhantomData,
        })
    }

    /// Validates a beneficiary ATA, converting unsupported account extensions into a redirect.
    pub(crate) fn validate_redirectable_ata<'b>(
        &self,
        account: &'b AccountView,
        owner: &Address,
    ) -> Result<RedirectableAta<'b>, AccountValidationError> {
        match self.validate_ata_checked(account, owner) {
            Ok(checked) => Ok(RedirectableAta::Valid(checked)),
            Err(AccountValidationError::TokenExtensionError(
                TokenExtensionError::UnsupportedTokenExtension,
            )) => Ok(RedirectableAta::RedirectToTreasury {
                reason: RedirectReason::UnsupportedTokenAccountExtension,
            }),
            Err(err) => Err(err),
        }
    }

    /// Maps payer ATA validation failures onto payer-specific public errors.
    pub(crate) fn map_payer_account_error(err: AccountValidationError) -> PaymentChannelsError {
        payer_token_error_for_account_validation(err)
    }

    /// Maps payee ATA validation failures onto payee-specific public errors.
    pub(crate) fn map_payee_account_error(err: AccountValidationError) -> PaymentChannelsError {
        payee_token_error_for_account_validation(err)
    }

    /// Maps recipient ATA validation failures onto recipient-specific public errors.
    pub(crate) fn map_recipient_account_error(err: AccountValidationError) -> PaymentChannelsError {
        recipient_token_error_for_account_validation(err)
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
            .map_err(channel_token_error_for_account_validation)?;

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

/// Marker trait for the payer validation mode carried by [`PayerContext`].
pub trait PayerContextMode {}

/// Payer context mode that validates only the payer wallet identity.
pub struct WalletOnly;

/// Payer context mode that also holds a checked payer token account.
pub struct WithTokenAccount<'a> {
    /// Checked canonical payer ATA used for direct payer refunds.
    pub payer_token_account: PayerTokenAccountView<'a, Checked>,
}

impl PayerContextMode for WalletOnly {}
impl<'a> PayerContextMode for WithTokenAccount<'a> {}

pub struct PayerContext<'a, M: PayerContextMode = WithTokenAccount<'a>> {
    pub payer: PayerAccountView<'a, Checked>,
    pub mode: M,
}

impl<'a> PayerContext<'a, WalletOnly> {
    /// Builds a payer context when only the payer wallet identity is needed.
    pub fn new_wallet(
        payer: PayerAccountView<'a, Unchecked>,
        expected_payer: &Address,
    ) -> Result<Self, PaymentChannelsError> {
        if payer.address() != expected_payer {
            return Err(PaymentChannelsError::InvalidChannelPayer);
        }

        Ok(Self {
            payer: PayerAccountView {
                inner: payer.inner,
                _s: Default::default(),
            },
            mode: WalletOnly,
        })
    }
}

impl<'a> PayerContext<'a, WithTokenAccount<'a>> {
    /// Builds a payer context with a checked payer ATA for direct refunds.
    pub fn new_with_token(
        payer: PayerAccountView<'a, Unchecked>,
        payer_token_account: PayerTokenAccountView<'a, Unchecked>,
        token_ctx: &TokenContext<'a>,
    ) -> Result<Self, PaymentChannelsError> {
        payer_token_account
            .validate_as_ata_checked(payer.address(), token_ctx)
            .map_err(payer_token_error_for_account_validation)?;

        Ok(Self {
            payer: PayerAccountView {
                inner: payer.inner,
                _s: Default::default(),
            },
            mode: WithTokenAccount {
                payer_token_account: PayerTokenAccountView {
                    inner: payer_token_account.inner,
                    _s: Default::default(),
                },
            },
        })
    }

    /// Returns the checked payer ATA carried by this context.
    pub fn payer_token_account(&self) -> &PayerTokenAccountView<'a, Checked> {
        &self.mode.payer_token_account
    }
}
