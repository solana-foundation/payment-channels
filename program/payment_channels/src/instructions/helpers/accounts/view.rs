use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use borsh::BorshSerialize;
#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};

use crate::{
    PaymentChannelsError, TREASURY_OWNER,
    event_engine::{EventSerialize, emit_event},
    events::PayoutRedirected,
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
                AccountValidationError::AddressMismatch
                | AccountValidationError::OwnerMismatch
                | AccountValidationError::AccountNotInitialized => {
                    PaymentChannelsError::TreasuryAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidTreasuryTokenAccount
                }
                AccountValidationError::TokenExtensionError(_) => {
                    PaymentChannelsError::InvalidTreasuryTokenExtensions
                }
            })?;

        Ok(TreasuryTokenAccountView {
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

/// Which token program backs this channel's mint and ATAs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TokenProgramKind {
    /// SPL Token program.
    Spl,
    /// Token-2022 program.
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

    /// Whether this token program exposes a `Batch` CPI for folding multiple
    /// sub-instructions into a single invocation. SPL Token does; Token-2022
    /// does not.
    pub const fn supports_transfer_batching(self) -> bool {
        matches!(self, Self::Spl)
    }
}

pub struct TokenContext<'a> {
    pub mint: MintAccountView<'a, Checked>,
    pub token_program: TokenProgramAccountView<'a, Checked>,
    pub decimals: u8,
    pub kind: TokenProgramKind,
}

/// Which payout role a [`crate::events::PayoutRedirected`] concerns. Borsh
/// serializes the variant index (0 recipient, 1 payee, 2 payer) as one byte, so
/// declaration order is part of the event wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
#[repr(u8)]
pub enum PayoutBeneficiary {
    Recipient,
    Payee,
    Payer,
}

/// Why a nonzero payout was forfeited to the treasury. Borsh serializes the
/// variant index (0/1/2/3) as one byte — declaration order is part of the
/// [`crate::events::PayoutRedirected`] wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
#[repr(u8)]
pub enum RedirectReason {
    /// Well-formed Token-2022 account carrying an unsupported extension.
    UnsupportedExtension,
    /// Canonical ATA could not be read as a token account (closed/malformed).
    ClosedOrMalformed,
    /// Canonical ATA is not in the `Initialized` state (frozen/uninitialized).
    NotInitialized,
    /// Canonical ATA's `owner`/`mint` field no longer matches the beneficiary
    /// (e.g. a `SetAuthority(AccountOwner)` reassignment).
    ReassignedAuthority,
}

impl PayoutBeneficiary {
    /// Total map from a validation failure to the beneficiary-specific error
    /// surfaced to the cranker. `payout_destination` redirects the forfeitable
    /// failures (closed/frozen/uninitialized ATA, unsupported extension,
    /// reassigned owner) to treasury before they would reach here, so on the
    /// payout path only `AddressMismatch` and a malformed TLV extension trailer
    /// are fatal; the mapping stays total so every variant has a defined error
    /// regardless.
    fn map_account_error(self, err: AccountValidationError) -> PaymentChannelsError {
        match (self, err) {
            (
                Self::Recipient,
                AccountValidationError::AddressMismatch | AccountValidationError::OwnerMismatch,
            ) => PaymentChannelsError::RecipientAccountMismatch,
            (
                Self::Recipient,
                AccountValidationError::MalformedTokenAccountData
                | AccountValidationError::AccountNotInitialized,
            ) => PaymentChannelsError::InvalidRecipientTokenAccount,
            (Self::Recipient, AccountValidationError::TokenExtensionError(_)) => {
                PaymentChannelsError::InvalidRecipientTokenExtensions
            }
            (
                Self::Payee,
                AccountValidationError::AddressMismatch | AccountValidationError::OwnerMismatch,
            ) => PaymentChannelsError::PayeeAccountMismatch,
            (
                Self::Payee,
                AccountValidationError::MalformedTokenAccountData
                | AccountValidationError::AccountNotInitialized,
            ) => PaymentChannelsError::InvalidPayeeTokenAccount,
            (Self::Payee, AccountValidationError::TokenExtensionError(_)) => {
                PaymentChannelsError::InvalidPayeeTokenExtensions
            }
            (
                Self::Payer,
                AccountValidationError::AddressMismatch | AccountValidationError::OwnerMismatch,
            ) => PaymentChannelsError::PayerAccountMismatch,
            (
                Self::Payer,
                AccountValidationError::MalformedTokenAccountData
                | AccountValidationError::AccountNotInitialized,
            ) => PaymentChannelsError::InvalidPayerTokenAccount,
            (Self::Payer, AccountValidationError::TokenExtensionError(_)) => {
                PaymentChannelsError::InvalidPayerTokenExtensions
            }
        }
    }
}

impl<'a> TokenContext<'a> {
    pub fn new(
        mint: MintAccountView<'a, Unchecked>,
        token_program: TokenProgramAccountView<'a, Unchecked>,
    ) -> Result<Self, PaymentChannelsError> {
        let kind = TokenProgramKind::from_address(token_program.address())?;

        let decimals = match kind {
            TokenProgramKind::Spl => {
                // pinocchio_token enforces owner == SPL Token + exact length.
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

    /// Validates only that `account` is the canonical ATA for `owner`.
    pub(crate) fn validate_ata_address(
        &self,
        account: &AccountView,
        owner: &Address,
    ) -> Result<(), AccountValidationError> {
        account.validate_as_ata_unchecked(owner, self.token_program.address(), self.mint.address())
    }

    /// Resolves where `beneficiary`'s share should land. A poisoned-but-self-
    /// inflicted destination forfeits the nonzero share to `treasury` instead of
    /// bricking the crank — an unsupported extension, a closed/unreadable
    /// canonical ATA, a frozen/uninitialized ATA, or a reassigned `owner`/`mint`
    /// field (`SetAuthority(AccountOwner)`) — and emits a [`PayoutRedirected`]
    /// self-CPI so the diversion is observable off-chain.
    ///
    /// The canonical ATA address is verified inside `validate_as_ata_checked`
    /// before these states are reached, so they cannot mask a wrong account
    /// passed by the cranker; a genuine address mismatch and a malformed TLV
    /// extension trailer stay fatal.
    ///
    /// WARNING: the redirect is invisible to the channel FSM. In `OPEN`,
    /// `payout_watermark` advances to `settled` (via `mark_as_settled`) after
    /// `Transfer::flush`, so a share forfeited here is permanently lost to the
    /// beneficiary — repairing the ATA on a later run does not reclaim it, since
    /// future cumulative deltas only cover newly settled amounts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn payout_destination<'b>(
        &self,
        beneficiary: PayoutBeneficiary,
        account: &'b AccountView,
        owner: &Address,
        amount: u64,
        treasury: &'b TreasuryTokenAccountView<'_, Checked>,
        program_id: &Address,
        event_authority: &AccountView,
        self_program: &AccountView,
        channel: &Address,
    ) -> Result<&'b AccountView, ProgramError> {
        // Zero-share payouts no-op in `Transfer`; only the canonical ATA
        // address is checked so a poisoned zero-share beneficiary cannot veto
        // the crank.
        if amount == 0 {
            return self
                .validate_ata_address(account, owner)
                .map(|()| account)
                .map_err(|err| beneficiary.map_account_error(err).into());
        }

        let reason = match account.validate_as_ata_checked(owner, self) {
            Ok(()) => return Ok(account),
            Err(AccountValidationError::TokenExtensionError(
                TokenExtensionError::UnsupportedTokenExtension,
            )) => RedirectReason::UnsupportedExtension,
            Err(AccountValidationError::MalformedTokenAccountData) => {
                RedirectReason::ClosedOrMalformed
            }
            Err(AccountValidationError::AccountNotInitialized) => RedirectReason::NotInitialized,
            Err(AccountValidationError::OwnerMismatch) => RedirectReason::ReassignedAuthority,
            Err(err) => return Err(beneficiary.map_account_error(err).into()),
        };

        let event = PayoutRedirected {
            channel: *channel,
            owner: *owner,
            amount,
            beneficiary,
            reason,
        };
        let bytes = event.to_bytes_fixed::<{ PayoutRedirected::WIRE_LEN }>();
        emit_event(program_id, event_authority, self_program, bytes.as_slice())?;
        Ok(&**treasury)
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
                AccountValidationError::AddressMismatch
                | AccountValidationError::OwnerMismatch
                | AccountValidationError::AccountNotInitialized => {
                    PaymentChannelsError::ChannelAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidChannelTokenAccount
                }
                AccountValidationError::TokenExtensionError(_) => {
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
                AccountValidationError::AddressMismatch
                | AccountValidationError::OwnerMismatch
                | AccountValidationError::AccountNotInitialized => {
                    PaymentChannelsError::PayerAccountMismatch
                }
                AccountValidationError::MalformedTokenAccountData => {
                    PaymentChannelsError::InvalidPayerTokenAccount
                }
                AccountValidationError::TokenExtensionError(_) => {
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
