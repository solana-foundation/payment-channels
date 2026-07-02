#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::errors::PaymentChannelsError;
use crate::helpers::accounts::view::{
    ChannelAccountView, ChannelContext, ChannelTokenAccountView, MintAccountView, PayerAccountView,
    PayerContext, PayerTokenAccountView, TokenContext, TokenProgramAccountView,
};
use crate::state::channel::ChannelStatus;
use crate::state::{Channel, Transmutable, load};

/// Instruction discriminator byte for `topUp`.
pub const DISCRIMINATOR: u8 = 3;

/// Extends an `OPEN` channel's escrow. The full amount is transferred from
/// [`TopUpAccounts::payer_token_account`] to
/// [`TopUpAccounts::channel_token_account`] and added to
/// [`Channel::deposit`](crate::Channel::deposit), raising the ceiling on
/// future [`settled`](crate::Channel::settled) growth.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct TopUpArgs {
    /// Base-unit amount to pull from the payer's token account into escrow.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    pub amount: [u8; 8],
    /// Must equal [`Channel::open_slot`](crate::Channel::open_slot). Scopes
    /// this top-up to the intended channel incarnation.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    pub expected_open_slot: [u8; 8],
}

impl TopUpArgs {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn amount(&self) -> u64 {
        u64::from_le_bytes(self.amount)
    }

    #[inline(always)]
    pub fn expected_open_slot(&self) -> u64 {
        u64::from_le_bytes(self.expected_open_slot)
    }

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for TopUpArgs {
    const LEN: usize = size_of::<Self>();
}

pub struct TopUpAccounts<'a> {
    /// Must equal [`Channel::payer`](crate::Channel::payer) and be a signer.
    pub payer: PayerAccountView<'a>,
    /// [`deposit`](crate::Channel::deposit) grows by [`TopUpArgs::amount`].
    pub channel: ChannelAccountView<'a>,
    pub payer_token_account: PayerTokenAccountView<'a>,
    /// Escrow ATA owned by the channel PDA.
    pub channel_token_account: ChannelTokenAccountView<'a>,
    pub mint: MintAccountView<'a>,
    pub token_program: TokenProgramAccountView<'a>,
}

impl<'a> TryFrom<&'a mut [AccountView]> for TopUpAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            channel,
            payer_token_account,
            channel_token_account,
            mint,
            token_program,
        ] = accounts
        else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self {
            payer: payer.into(),
            channel: channel.into(),
            payer_token_account: payer_token_account.into(),
            channel_token_account: channel_token_account.into(),
            mint: mint.into(),
            token_program: token_program.into(),
        })
    }
}

/// Payer-signed; extends
/// [`Channel::deposit`](crate::Channel::deposit) by [`TopUpArgs::amount`].
/// `OPEN` only — only the original payer may call this.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &TopUpArgs,
) -> ProgramResult {
    let accs = TopUpAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    let amount = args.amount();
    if amount == 0 {
        return Err(PaymentChannelsError::DepositMustBeNonZero.into());
    }

    {
        let ch = Channel::from_account(&accs.channel)?;
        if ch.status != ChannelStatus::Open as u8 {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }
        if accs.payer.address() != &ch.payer {
            return Err(PaymentChannelsError::InvalidChannelPayer.into());
        }
        if accs.mint.address() != &ch.mint {
            return Err(PaymentChannelsError::InvalidChannelMint.into());
        }
        if args.expected_open_slot() != ch.open_slot() {
            return Err(PaymentChannelsError::ChannelSlotMismatch.into());
        }
    }

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx = ChannelContext::new(accs.channel, accs.channel_token_account, token_ctx)?;
    let payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    {
        let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;
        let new_deposit = ch
            .deposit()
            .checked_add(amount)
            .ok_or(PaymentChannelsError::TopUpDepositOverflow)?;
        ch.set_deposit(new_deposit);
    }

    TransferChecked {
        from: &payer_ctx.payer_token_account,
        mint: &channel_ctx.token_ctx.mint,
        to: &channel_ctx.channel_token_account,
        authority: &payer_ctx.payer,
        amount,
        decimals: channel_ctx.token_ctx.decimals,
        token_program: channel_ctx.token_ctx.token_program.address(),
    }
    .invoke()?;

    Ok(())
}
