#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;

/// Instruction discriminator byte for `open`.
pub const DISCRIMINATOR: u8 = 0;

/// Init payload. Fields land in the [`Channel`](crate::Channel) PDA either
/// directly ([`Self::deposit`], [`Self::grace_period`],
/// [`Self::distribution_hash`]) or through seeds ([`Self::salt`]).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct OpenArgs {
    /// PDA disambiguator; seed-only, not stored. Enables concurrent
    /// channels for the same `(payer, payee, mint, authorized_signer)`
    /// tuple.
    pub salt: u64,
    /// Initial escrow; the immutable ceiling on
    /// [`Channel::settled`](crate::Channel::settled) (raised later only by
    /// `topUp`).
    pub deposit: u64,
    /// Grace duration (seconds). Governs the `CLOSING → FINALIZED`
    /// unlock for `finalize` and the `withdraw_payee` timer.
    pub grace_period: u32,
    /// Blake3 commitment to the `distribute` splits preimage.
    pub distribution_hash: [u8; 32],
}

impl OpenArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

/// [`Self::payer`], [`Self::payee`], [`Self::mint`],
/// [`Self::authorized_signer`] are PDA seed inputs.
pub struct OpenAccounts<'a> {
    /// Funds the deposit and the PDA rent.
    pub payer: &'a AccountView,
    /// Bound into [`Channel::payee`](crate::Channel::payee).
    pub payee: &'a AccountView,
    /// Token mint for the channel's escrow.
    pub mint: &'a AccountView,
    /// Bound as
    /// [`Channel::authorized_signer`](crate::Channel::authorized_signer)
    /// (voucher author).
    pub authorized_signer: &'a AccountView,
    /// Uninitialized; the ix allocates the [`Channel`](crate::Channel) PDA here.
    pub channel: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    /// Escrow ATA owned by the channel PDA.
    pub channel_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
    pub system_program: &'a AccountView,
    pub rent: &'a AccountView,
    /// Signer PDA for the self-CPI that emits [`crate::events::Opened`].
    pub event_authority: &'a AccountView,
    /// This program's ID; CPI target for the event emission.
    pub self_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for OpenAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            payer_token_account,
            channel_token_account,
            token_program,
            system_program,
            rent,
            event_authority,
            self_program,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            payer_token_account,
            channel_token_account,
            token_program,
            system_program,
            rent,
            event_authority,
            self_program,
        })
    }
}

/// Payer-signed; creates the [`Channel`](crate::Channel) PDA, locks the
/// deposit, and commits the distribution hash.
pub fn process(program_id: &Address, accounts: &[AccountView], _args: &OpenArgs) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    let event = Opened {
        channel: *accs.channel.address(),
    };
    let bytes = event.to_bytes_fixed::<{ Opened::WIRE_LEN }>();
    emit_event(
        program_id,
        accs.event_authority,
        accs.self_program,
        bytes.as_slice(),
    )?;

    Ok(())
}
