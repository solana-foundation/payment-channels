#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_associated_token_account::instructions::Create as CreateAta;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token::instructions::Transfer as TransferTokens;

use crate::state::Channel;

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;
use crate::instructions::helpers::channel_signer_seeds;

/// Instruction discriminator byte for `open`.
pub const DISCRIMINATOR: u8 = 1;

/// Maximum number of distribution recipients per channel.
pub const MAX_DISTRIBUTION_RECIPIENTS: usize = 30;

/// One entry in the distribution plan committed at `open`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionEntry {
    /// Token destination for this split.
    pub recipient: Address,
    /// Token amount for this recipient.
    pub amount: u64,
}

/// Init payload. The distribution plan is hashed on-chain with `blake3` and
/// the digest stored in
/// [`Channel::distribution_hash`](crate::Channel::distribution_hash).
/// [`distribute`](crate::instructions::distribute) later verifies a matching
/// preimage before paying out splits.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct OpenArgs {
    /// PDA disambiguator; stored in [`Channel::salt`](crate::Channel::salt).
    /// Enables concurrent channels for the same
    /// `(payer, payee, mint, authorized_signer)` tuple.
    pub salt: u64,
    /// Initial escrow; the immutable ceiling on
    /// [`Channel::settled`](crate::Channel::settled) (raised later only by
    /// `topUp`).
    pub deposit: u64,
    /// Grace duration (seconds). Governs the `CLOSING → FINALIZED`
    /// unlock for permissionless `finalize`.
    pub grace_period: u32,
    /// Number of valid entries in [`Self::recipients`] (1–30).
    pub num_recipients: u8,
    /// Packed distribution plan. Only the first `num_recipients` entries are
    /// used; trailing entries must be zeroed.  `open` computes
    /// `blake3(num_recipients_byte || active_entries_bytes)` and stores the
    /// digest as [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    #[cfg_attr(
        feature = "idl",
        codama(type = fixed_count(array, MAX_DISTRIBUTION_RECIPIENTS))
    )]
    pub recipients: [DistributionEntry; MAX_DISTRIBUTION_RECIPIENTS],
}

impl OpenArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        // SAFETY: length == Self::LEN verified above; `OpenArgs` is `repr(C, packed)`
        // so its alignment requirement is 1 — valid at any byte boundary.  The
        // returned reference borrows `data` for its full lifetime.
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Read `salt` from the packed struct without creating an unaligned reference.
    #[inline(always)]
    pub fn salt(&self) -> u64 {
        // SAFETY: `addr_of!` produces a raw pointer without materialising a
        // reference to the field; `read_unaligned` copies the bytes without
        // requiring pointer alignment.
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.salt)) }
    }

    /// Read `deposit` from the packed struct without creating an unaligned reference.
    #[inline(always)]
    pub fn deposit(&self) -> u64 {
        // SAFETY: same as `salt`.
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.deposit)) }
    }

    /// Read `grace_period` from the packed struct without creating an unaligned reference.
    #[inline(always)]
    pub fn grace_period(&self) -> u32 {
        // SAFETY: same as `salt`.
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.grace_period)) }
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
    /// Channel PDA. Must equal `Channel::find_pda(payer, payee, mint,
    /// authorized_signer, salt)` — derive client-side and pass as writable.
    /// Verified on-chain against the derived address before allocation.
    pub channel: &'a mut AccountView,
    pub payer_token_account: &'a mut AccountView,
    /// Escrow ATA owned by the channel PDA. Must equal the associated token
    /// address for `(channel, token_program, mint)` — derive client-side
    /// and pass as writable. Verified on-chain before the ATA is created.
    pub channel_token_account: &'a mut AccountView,
    pub token_program: &'a AccountView,
    pub system_program: &'a AccountView,
    pub rent: &'a AccountView,
    /// Associated Token Account program; required by the runtime for the
    /// `CreateAta` CPI.
    pub associated_token_program: &'a AccountView,
    /// Signer PDA for the self-CPI that emits [`crate::events::Opened`].
    pub event_authority: &'a AccountView,
    /// This program's ID; CPI target for the event emission.
    pub self_program: &'a AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for OpenAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
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
            associated_token_program,
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
            associated_token_program,
            event_authority,
            self_program,
        })
    }
}

/// Compute `blake3(num_recipients_byte || active_entry_bytes)`.
///
/// Reads directly from the packed struct's memory so no field references
/// through unaligned pointers are created.
///
/// # Layout (repr C, packed)
/// ```text
/// offset  0: salt          (8 bytes)
/// offset  8: deposit       (8 bytes)
/// offset 16: grace_period  (4 bytes)
/// offset 20: num_recipients(1 byte)
/// offset 21: recipients    (30 × 40 bytes)
/// ```
/// `n` must be in `1..=MAX_DISTRIBUTION_RECIPIENTS`; callers are responsible
/// for validating before calling.
fn distribution_hash(args: &OpenArgs, n: usize) -> [u8; 32] {
    let base = args as *const OpenArgs as *const u8;
    // SAFETY: `args` is a valid `&OpenArgs`; `base.add(20)` is the address of
    // `num_recipients` (offset = salt(8)+deposit(8)+grace_period(4) = 20).
    // The slice covers `num_recipients(1) + n×40` bytes.  Because the caller
    // guarantees `n ≤ MAX_DISTRIBUTION_RECIPIENTS` (30), the maximum length is
    // 1+30×40 = 1201, which fits entirely within the 1221-byte struct body
    // starting at offset 20.  `OpenArgs` is `repr(C, packed)` so all bytes are
    // initialised and the pointer arithmetic stays within the allocation.
    let input = unsafe { core::slice::from_raw_parts(base.add(20), 1 + n * 40) };
    blake3(input)
}

/// BPF target: delegate to the `sol_blake3` syscall.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn blake3(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let slices: &[&[u8]] = &[input];
    // SAFETY: sol_blake3 fills exactly 32 bytes; each &[u8] is a fat pointer
    // (ptr, len) matching the SolBytes C layout on 64-bit BPF.
    unsafe {
        pinocchio::syscalls::sol_blake3(slices.as_ptr() as *const u8, 1, hash.as_mut_ptr());
    }
    hash
}

/// Non-BPF (host) stub — the syscall is unavailable off-chain.
/// Never executed at runtime; present only so `cargo check --tests` succeeds.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn blake3(_input: &[u8]) -> [u8; 32] {
    [0u8; 32]
}

/// Payer-signed; creates the [`Channel`](crate::Channel) PDA, locks the
/// deposit, and commits the distribution hash.
pub fn process(program_id: &Address, accounts: &mut [AccountView], args: &OpenArgs) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let n = args.num_recipients as usize;
    if n == 0 || n > MAX_DISTRIBUTION_RECIPIENTS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let deposit = args.deposit();
    if deposit == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let distribution_hash = distribution_hash(args, n);

    let (channel_address, bump) = Channel::find_pda(
        accs.payer.address(),
        accs.payee.address(),
        accs.mint.address(),
        accs.authorized_signer.address(),
        args.salt(),
    );

    // Client-side derives these addresses; validate explicitly as defense in
    // depth before any mutation (CPI enforcement provides a second layer).
    if accs.channel.address() != &channel_address {
        return Err(ProgramError::InvalidAccountData);
    }
    let (expected_ata, _) = Address::find_program_address(
        &[
            channel_address.as_ref(),
            accs.token_program.address().as_ref(),
            accs.mint.address().as_ref(),
        ],
        &pinocchio_associated_token_account::ID,
    );
    if accs.channel_token_account.address() != &expected_ata {
        return Err(ProgramError::InvalidAccountData);
    }

    // Allocate the channel PDA. The runtime verifies the seeds match
    // accs.channel.address(); mismatched account → CPI failure.
    let salt_bytes = args.salt().to_le_bytes();
    let bump_byte = [bump];
    let seeds = channel_signer_seeds(
        accs.payer.address().as_ref(),
        accs.payee.address().as_ref(),
        accs.mint.address().as_ref(),
        accs.authorized_signer.address().as_ref(),
        &salt_bytes,
        &bump_byte,
    );
    let channel_signer = Signer::from(&seeds);

    CreateAccount::with_minimum_balance(
        accs.payer,
        accs.channel,
        Channel::LEN as u64,
        &crate::ID,
        Some(accs.rent),
    )?
    .invoke_signed(&[channel_signer])?;

    // Create the escrow ATA owned by the channel PDA.
    CreateAta {
        funding_account: accs.payer,
        account: accs.channel_token_account,
        wallet: accs.channel,
        mint: accs.mint,
        system_program: accs.system_program,
        token_program: accs.token_program,
    }
    .invoke()?;

    // Transfer the deposit from payer to escrow.
    TransferTokens::new(accs.payer_token_account, accs.channel_token_account, accs.payer, deposit)
        .invoke()?;

    Channel::init_at(
        &mut accs.channel.try_borrow_mut()?,
        bump,
        args.salt(),
        deposit,
        args.grace_period(),
        distribution_hash,
        *accs.payer.address(),
        *accs.payee.address(),
        *accs.authorized_signer.address(),
        *accs.mint.address(),
    )?;

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
