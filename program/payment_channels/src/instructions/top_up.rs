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
}

impl TopUpArgs {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn amount(&self) -> u64 {
        u64::from_le_bytes(self.amount)
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
            return Err(ProgramError::NotEnoughAccountKeys);
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
        return Err(ProgramError::MissingRequiredSignature);
    }

    let amount = args.amount();
    if amount == 0 {
        return Err(PaymentChannelsError::DepositMustBeNonZero.into());
    }

    let channel = accs.channel.check()?;
    let token_ctx = TokenContext::new(accs.mint, accs.token_program)
        .map_err(|_| PaymentChannelsError::EscrowAddressMismatch)?;
    let mut channel_ctx = ChannelContext::new(channel, accs.channel_token_account, token_ctx)
        .map_err(|_| PaymentChannelsError::InvalidChannelTokenAccount)?;
    let payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    {
        let mut ch = Channel::from_account_mut(&mut channel_ctx.channel)?;

        if ch.status != ChannelStatus::Open as u8 {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }

        if payer_ctx.payer.address() != &ch.payer {
            return Err(PaymentChannelsError::UnauthorizedPayer.into());
        }

        if channel_ctx.token_ctx.mint.address() != &ch.mint {
            return Err(PaymentChannelsError::MintAccountMismatch.into());
        }

        let new_deposit = ch
            .deposit()
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        ch.set_deposit(new_deposit);
    };

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
