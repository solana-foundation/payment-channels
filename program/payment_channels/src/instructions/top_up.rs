#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};
use pinocchio_token::instructions::Transfer as TransferTokens;

use crate::errors::PaymentChannelsError;
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
    amount: [u8; 8],
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
    pub payer: &'a AccountView,
    /// [`deposit`](crate::Channel::deposit) grows by [`TopUpArgs::amount`].
    pub channel: &'a mut AccountView,
    pub payer_token_account: &'a mut AccountView,
    /// Escrow ATA owned by the channel PDA.
    pub channel_token_account: &'a mut AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
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
            payer,
            channel,
            payer_token_account,
            channel_token_account,
            mint,
            token_program,
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

    // Capture before the mutable borrow of channel below.
    let channel_address = *accs.channel.address();

    {
        let mut ch = Channel::from_account_mut(accs.channel)?;

        if ch.status != ChannelStatus::Open as u8 {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }

        if accs.payer.address() != &ch.payer {
            return Err(PaymentChannelsError::UnauthorizedPayer.into());
        }

        if accs.mint.address() != &ch.mint {
            return Err(PaymentChannelsError::MintAddressMismatch.into());
        }

        // Re-derive the canonical escrow ATA using the mint recorded at open.
        // Without this a caller could pass any token account, increment
        // ch.deposit, and leave the actual escrow underfunded.
        let channel_mint = ch.mint;
        let (expected_ata, _) = Address::find_program_address(
            &[
                channel_address.as_ref(),
                accs.token_program.address().as_ref(),
                channel_mint.as_ref(),
            ],
            &pinocchio_associated_token_account::ID,
        );
        if accs.channel_token_account.address() != &expected_ata {
            return Err(PaymentChannelsError::EscrowAddressMismatch.into());
        }

        let new_deposit = ch
            .deposit()
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        ch.set_deposit(new_deposit);
    }

    TransferTokens::new(
        accs.payer_token_account,
        accs.channel_token_account,
        accs.payer,
        amount,
    )
    .invoke()?;

    Ok(())
}
