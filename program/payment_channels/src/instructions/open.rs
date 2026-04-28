#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_associated_token_account::instructions::Create as CreateAta;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token_2022::instructions::TransferChecked;

use crate::errors::PaymentChannelsError;
use crate::state::Channel;

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;
pub use crate::instructions::helpers::MAX_DISTRIBUTION_RECIPIENTS;
use crate::instructions::helpers::{
    DistributionRecipients, channel_signer_seeds, derive_ata, validate_ata_token_account,
    validate_mint,
};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `open`.
pub const DISCRIMINATOR: u8 = 1;

/// Init payload. The distribution plan is hashed on-chain with `blake3` and
/// the digest stored in
/// [`Channel::distribution_hash`](crate::Channel::distribution_hash).
/// [`distribute`](crate::instructions::distribute) later verifies a matching
/// preimage before paying out splits.
///
/// Wire layout: `salt(8) | deposit(8) | grace_period(4) | count(1) | entries(32×34)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct OpenArgs {
    /// PDA disambiguator; stored in [`Channel::salt`](crate::Channel::salt).
    /// Enables concurrent channels for the same
    /// `(payer, payee, mint, authorized_signer)` tuple.
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
    pub recipients: DistributionRecipients,
}

impl OpenArgs {
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

/// Payer-signed; creates the [`Channel`](crate::Channel) PDA, locks the
/// deposit, and commits the distribution hash.
pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &OpenArgs,
) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if accs.payer.address() == accs.payee.address() {
        return Err(PaymentChannelsError::PayerPayeeMustDiffer.into());
    }

    let validated = args.recipients.validate_view()?;
    assert_unique_recipients(&args.recipients)?;

    let deposit = args.deposit();
    if deposit == 0 {
        return Err(PaymentChannelsError::DepositMustBeNonZero.into());
    }

    let (channel_address, bump) = Channel::find_pda(
        accs.payer.address(),
        accs.payee.address(),
        accs.mint.address(),
        accs.authorized_signer.address(),
        args.salt(),
    );

    if validated
        .entries
        .iter()
        .any(|entry| entry.recipient == channel_address)
    {
        return Err(PaymentChannelsError::InvalidSplitConfig.into());
    }

    let distribution_hash = args.recipients.preimage_hash();

    // Client-side derives these addresses; validate explicitly as defense in
    // depth before any mutation (CPI enforcement provides a second layer).
    if accs.channel.address() != &channel_address {
        return Err(PaymentChannelsError::ChannelAddressMismatch.into());
    }
    let token_program = accs.token_program.address();
    let expected_ata = derive_ata(&channel_address, accs.mint.address(), token_program);
    if accs.channel_token_account.address() != &expected_ata {
        return Err(PaymentChannelsError::EscrowAddressMismatch.into());
    }
    let decimals = validate_mint(accs.mint, token_program)?;
    validate_ata_token_account(
        accs.payer_token_account,
        accs.payer.address(),
        accs.mint.address(),
        token_program,
        PaymentChannelsError::InvalidPayerTokenAccount,
    )?;

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
    TransferChecked {
        from: accs.payer_token_account,
        mint: accs.mint,
        to: accs.channel_token_account,
        authority: accs.payer,
        amount: deposit,
        decimals,
        token_program,
    }
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

/// O(n²) duplicate-recipient scan over the active entries. Lives here
/// because `distribute` re-establishes the same plan via the blake3
/// preimage check, so the dedup invariant only needs to be enforced once
/// — at `open`. Floored per-entry shares are biased against aggregated
/// splits, which is why duplicates are rejected outright instead of
/// summed downstream.
fn assert_unique_recipients(recipients: &DistributionRecipients) -> Result<(), ProgramError> {
    let n = recipients.count as usize;
    let entries = &recipients.entries[..n];
    for (i, a) in entries.iter().enumerate() {
        for b in &entries[i + 1..] {
            if a.recipient == b.recipient {
                return Err(PaymentChannelsError::DuplicateRecipient.into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instructions::helpers::DistributionEntry;

    fn recipients_from(active: &[Address]) -> DistributionRecipients {
        let placeholder = DistributionEntry::new(Address::default(), 100);
        let mut entries = [placeholder; MAX_DISTRIBUTION_RECIPIENTS];
        for (i, addr) in active.iter().enumerate() {
            entries[i] = DistributionEntry::new(*addr, 100);
        }
        DistributionRecipients {
            count: active.len() as u8,
            entries,
        }
    }

    #[test]
    fn assert_unique_recipients_accepts_distinct() {
        let r = recipients_from(&[
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            Address::new_from_array([3u8; 32]),
        ]);
        assert_eq!(assert_unique_recipients(&r), Ok(()));
    }

    #[test]
    fn assert_unique_recipients_rejects_duplicate() {
        let r = recipients_from(&[
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            Address::new_from_array([1u8; 32]),
        ]);
        assert_eq!(
            assert_unique_recipients(&r),
            Err(ProgramError::from(PaymentChannelsError::DuplicateRecipient)),
        );
    }

    #[test]
    fn assert_unique_recipients_ignores_inactive_tail() {
        // Entries past `count` repeat a placeholder address; that must not
        // count as a duplicate because the scan slices on `count`.
        let r = recipients_from(&[
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
        ]);
        assert_eq!(assert_unique_recipients(&r), Ok(()));
    }

    #[test]
    fn assert_unique_recipients_accepts_zero_count() {
        let r = recipients_from(&[]);
        assert_eq!(assert_unique_recipients(&r), Ok(()));
    }
}
