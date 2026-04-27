#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `open`.
pub const DISCRIMINATOR: u8 = 1;

/// Ceiling on recipients committed at `open` / paid at `distribute`. Sized to
/// fit a legacy single-tx envelope end-to-end (see repo plan — scaling past
/// this requires client-side ALTs or an alternative commitment scheme).
pub const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;

/// One entry in the distribution plan committed at `open`. `recipient` owns
/// the ATA that receives the bps share at `distribute` time.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionEntry {
    /// Token-account owner; the ATA is re-derived on-chain as
    /// `ATA(recipient, mint, token_program)`.
    pub recipient: Address,
    /// Basis points of the distribute-time pool paid to this recipient.
    /// `Σbps < 10_000` so the payer always retains an implicit share.
    #[cfg_attr(feature = "idl", codama(type = number(u16)))]
    pub bps: [u8; 2],
}

impl DistributionEntry {
    #[inline(always)]
    pub fn bps(&self) -> u16 {
        u16::from_le_bytes(self.bps)
    }
}

unsafe impl Transmutable for DistributionEntry {
    const LEN: usize = size_of::<Self>();
}

const _: () = assert!(size_of::<DistributionEntry>() == 34);

/// Init payload. `deposit`, `grace_period`, and `distribution_hash` are
/// stored on the [`Channel`](crate::Channel) PDA; `salt` is a seed input
/// (address-only, not persisted).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct OpenArgs {
    /// PDA disambiguator; seed-only, not stored. Enables concurrent
    /// channels for the same `(payer, payee, mint, authorized_signer)`
    /// tuple.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    salt: [u8; 8],
    /// Initial escrow; the immutable ceiling on
    /// [`Channel::settled`](crate::Channel::settled) (raised later only by
    /// `topUp`).
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    deposit: [u8; 8],
    /// Grace duration (seconds). Governs the `CLOSING → FINALIZED`
    /// unlock for permissionless `finalize`.
    #[cfg_attr(feature = "idl", codama(type = number(u32)))]
    grace_period: [u8; 4],
    /// Blake3 commitment to the `distribute` splits preimage.
    pub distribution_hash: [u8; 32],
}

impl OpenArgs {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn salt(&self) -> u64 {
        u64::from_le_bytes(self.salt)
    }
    #[inline(always)]
    pub fn deposit(&self) -> u64 {
        u64::from_le_bytes(self.deposit)
    }
    #[inline(always)]
    pub fn grace_period(&self) -> u32 {
        u32::from_le_bytes(self.grace_period)
    }

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for OpenArgs {
    const LEN: usize = size_of::<Self>();
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
