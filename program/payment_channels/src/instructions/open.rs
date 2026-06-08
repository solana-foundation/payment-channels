#[cfg(feature = "idl")]
use alloc::vec::Vec;
#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError, sysvars::rent::Rent,
};
use pinocchio_associated_token_account::instructions::CreateIdempotent;
use pinocchio_system::instructions::{Allocate, Assign, Transfer as SystemTransfer};
use pinocchio_token_2022::instructions::TransferChecked;

use crate::errors::PaymentChannelsError;
use crate::helpers::accounts::view::ChannelAccountView;
use crate::helpers::accounts::view::ChannelContext;
use crate::helpers::accounts::view::ChannelTokenAccountView;
use crate::helpers::accounts::view::MintAccountView;
use crate::helpers::accounts::view::PayeeAccountView;
use crate::helpers::accounts::view::PayerAccountView;
use crate::helpers::accounts::view::PayerContext;
use crate::helpers::accounts::view::PayerTokenAccountView;
use crate::helpers::accounts::view::TokenContext;
use crate::helpers::accounts::view::TokenProgramAccountView;
use crate::state::{Channel, Transmutable, load};

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;
#[cfg(feature = "idl")]
use crate::instructions::helpers::DistributionEntry;
pub use crate::instructions::helpers::MAX_DISTRIBUTION_RECIPIENTS;
use crate::instructions::helpers::{DistributionPreimage, channel_signer_seeds};

/// Instruction discriminator byte for `open`.
pub const DISCRIMINATOR: u8 = 1;

/// Init payload. The distribution plan is hashed on-chain with `blake3` and
/// the digest stored in
/// [`Channel::distribution_hash`](crate::Channel::distribution_hash).
/// [`distribute`](crate::instructions::distribute) later verifies a matching
/// preimage before paying out splits.
///
/// Wire layout: `salt(8) | deposit(8) | grace_period(4) | count(u32 LE) |
/// entries(count × 34)`.
#[derive(Debug, Clone, Copy)]
pub struct OpenArgs<'a> {
    header: &'a OpenArgsHeader,
    pub recipients: DistributionPreimage<'a>,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct LeU64([u8; size_of::<u64>()]);

impl LeU64 {
    #[inline(always)]
    fn get(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct LeU32([u8; size_of::<u32>()]);

impl LeU32 {
    #[inline(always)]
    fn get(&self) -> u32 {
        u32::from_le_bytes(self.0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OpenArgsHeader {
    /// PDA disambiguator stored in [`Channel::salt`](crate::Channel::salt).
    salt: LeU64,
    /// Initial escrow amount and ceiling for [`Channel::settled`](crate::Channel::settled).
    deposit: LeU64,
    /// Grace duration, in seconds.
    grace_period: LeU32,
}

unsafe impl Transmutable for OpenArgsHeader {
    const LEN: usize = size_of::<Self>();
}

const _: () = assert!(size_of::<LeU64>() == size_of::<u64>());
const _: () = assert!(core::mem::align_of::<LeU64>() == 1);
const _: () = assert!(size_of::<LeU32>() == size_of::<u32>());
const _: () = assert!(core::mem::align_of::<LeU32>() == 1);
const _: () =
    assert!(size_of::<OpenArgsHeader>() == size_of::<u64>() + size_of::<u64>() + size_of::<u32>());
const _: () = assert!(core::mem::align_of::<OpenArgsHeader>() == 1);

#[cfg(feature = "idl")]
#[allow(dead_code)]
#[derive(CodamaType)]
#[codama(name = "open_args")]
pub struct OpenArgsWire {
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<DistributionEntry>,
}

impl<'a> OpenArgs<'a> {
    #[inline(always)]
    pub fn salt(&self) -> u64 {
        self.header.salt.get()
    }

    #[inline(always)]
    pub fn deposit(&self) -> u64 {
        self.header.deposit.get()
    }

    #[inline(always)]
    pub fn grace_period(&self) -> u32 {
        self.header.grace_period.get()
    }

    pub fn load(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < OpenArgsHeader::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (header_bytes, recipients_bytes) = data.split_at(OpenArgsHeader::LEN);
        let header = unsafe { load::<OpenArgsHeader>(header_bytes) }
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let recipients = DistributionPreimage::load(recipients_bytes)?;
        Ok(Self { header, recipients })
    }
}

/// [`Self::payer`], [`Self::payee`], [`Self::mint`],
/// [`Self::authorized_signer`] are PDA seed inputs.
pub struct OpenAccounts<'a> {
    /// Funds the deposit and the PDA rent.
    pub payer: PayerAccountView<'a>,
    /// Bound into [`Channel::payee`](crate::Channel::payee).
    pub payee: PayeeAccountView<'a>,
    /// Token mint for the channel's escrow.
    pub mint: MintAccountView<'a>,
    /// Bound as
    /// [`Channel::authorized_signer`](crate::Channel::authorized_signer)
    /// (voucher author).
    pub authorized_signer: &'a AccountView,
    /// Channel PDA. Must equal `Channel::find_pda(payer, payee, mint,
    /// authorized_signer, salt)` — derive client-side and pass as writable.
    /// Verified on-chain against the derived address before allocation.
    pub channel: ChannelAccountView<'a>,
    pub payer_token_account: PayerTokenAccountView<'a>,
    /// Escrow ATA owned by the channel PDA. Must equal the associated token
    /// address for `(channel, token_program, mint)` — derive client-side
    /// and pass as writable. Verified on-chain before the ATA is created.
    pub channel_token_account: ChannelTokenAccountView<'a>,
    pub token_program: TokenProgramAccountView<'a>,
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
            payer: payer.into(),
            payee: payee.into(),
            mint: mint.into(),
            authorized_signer,
            channel: channel.into(),
            payer_token_account: payer_token_account.into(),
            channel_token_account: channel_token_account.into(),
            token_program: token_program.into(),
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
    args: &OpenArgs<'_>,
) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    if accs.payer.address() == accs.payee.address() {
        return Err(PaymentChannelsError::PayerPayeeMustDiffer.into());
    }

    let deposit = args.deposit();
    if deposit == 0 {
        return Err(PaymentChannelsError::DepositMustBeNonZero.into());
    }
    if args.grace_period() < 1 {
        return Err(PaymentChannelsError::GracePeriodMustBeNonZero.into());
    }

    if !accs.authorized_signer.address().is_on_curve() {
        return Err(PaymentChannelsError::InvalidAuthorizedSigner.into());
    }

    let (channel_address, bump) = Channel::find_pda(
        accs.payer.address(),
        accs.payee.address(),
        accs.mint.address(),
        accs.authorized_signer.address(),
        args.salt(),
    );

    if args
        .recipients
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

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx =
        ChannelContext::new_uninit(accs.channel, accs.channel_token_account, token_ctx)?;
    let payer_ctx =
        PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)?;

    let salt_bytes = args.salt().to_le_bytes();
    let bump_byte = [bump];
    let seeds = channel_signer_seeds(
        payer_ctx.payer.address().as_ref(),
        accs.payee.address().as_ref(),
        channel_ctx.token_ctx.mint.address().as_ref(),
        accs.authorized_signer.address().as_ref(),
        &salt_bytes,
        &bump_byte,
    );
    let signers = [Signer::from(&seeds)];

    // Prefund-tolerant PDA creation: top up the rent shortfall, then signed
    // Allocate + Assign. Surplus lamports refund to payer at tombstone.
    let min_rent = Rent::from_account_view(accs.rent)?.try_minimum_balance(Channel::LEN)?;
    let shortfall = min_rent.saturating_sub(channel_ctx.channel.lamports());
    if shortfall > 0 {
        SystemTransfer {
            from: &payer_ctx.payer,
            to: &channel_ctx.channel,
            lamports: shortfall,
        }
        .invoke()?;
    }
    Allocate {
        account: &channel_ctx.channel,
        space: Channel::LEN as u64,
    }
    .invoke_signed(&signers)?;
    Assign {
        account: &channel_ctx.channel,
        owner: &crate::ID,
    }
    .invoke_signed(&signers)?;

    // Create the escrow ATA owned by the channel PDA. Idempotent: tolerates
    // a pre-existing canonical ATA so a griefer cannot block open by
    // front-running ATA creation (audit 3.2.2).
    CreateIdempotent {
        funding_account: &payer_ctx.payer,
        account: &channel_ctx.channel_token_account,
        wallet: &channel_ctx.channel,
        mint: &channel_ctx.token_ctx.mint,
        system_program: accs.system_program,
        token_program: &channel_ctx.token_ctx.token_program,
    }
    .invoke()?;

    // Transfer the deposit from payer to escrow.
    TransferChecked {
        from: &payer_ctx.payer_token_account,
        mint: &channel_ctx.token_ctx.mint,
        to: &channel_ctx.channel_token_account,
        authority: &payer_ctx.payer,
        amount: deposit,
        decimals: channel_ctx.token_ctx.decimals,
        token_program: channel_ctx.token_ctx.token_program.address(),
    }
    .invoke()?;

    Channel::init_at(
        &mut channel_ctx.channel.try_borrow_mut()?,
        bump,
        args.salt(),
        deposit,
        args.grace_period(),
        distribution_hash,
        *payer_ctx.payer.address(),
        *accs.payee.address(),
        *accs.authorized_signer.address(),
        *channel_ctx.token_ctx.mint.address(),
    )?;

    let event = Opened {
        channel: *channel_ctx.channel.address(),
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
