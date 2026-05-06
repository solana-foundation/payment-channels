#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, cpi::Signer, error::ProgramError};
use pinocchio_associated_token_account::instructions::Create as CreateAta;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token_2022::instructions::TransferChecked;

use crate::{
    errors::PaymentChannelsError,
    event_engine::{EventSerialize, emit_event},
    events::Opened,
    helpers::accounts::{
        validation::AccountValidator,
        view::{
            ChannelAccountView, ChannelContext, ChannelTokenAccountView, MintAccountView,
            PayeeAccountView, PayerAccountView, PayerContext, PayerTokenAccountView, TokenContext,
            TokenProgramAccountView,
        },
    },
    instructions::helpers::{DistributionRecipients, channel_signer_seeds},
    state::{Channel, Transmutable, load},
};

pub use crate::instructions::helpers::MAX_DISTRIBUTION_RECIPIENTS;

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
    args: &OpenArgs,
) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if accs.payer.address() == accs.payee.address() {
        return Err(PaymentChannelsError::PayerPayeeMustDiffer.into());
    }

    let validated = args.recipients.validate()?;

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

    accs.channel_token_account
        .validate_as_ata_unchecked(
            &channel_address,
            accs.token_program.address(),
            accs.mint.address(),
        )
        .map_err(|_| PaymentChannelsError::EscrowAddressMismatch)?;

    let token_ctx = TokenContext::new(accs.mint, accs.token_program)?;
    let mut channel_ctx =
        ChannelContext::new_uninit(accs.channel, accs.channel_token_account, token_ctx)
            .map_err(|_| PaymentChannelsError::EscrowAddressMismatch)?;
    let payer_ctx = PayerContext::new(accs.payer, accs.payer_token_account, &channel_ctx.token_ctx)
        .map_err(|e| match e {
            PaymentChannelsError::AddressMismatch => PaymentChannelsError::InvalidPayerTokenAccount,
            other => other,
        })?;

    // Allocate the channel PDA. The runtime verifies the seeds match
    // accs.channel.address(); mismatched account → CPI failure.
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
    let channel_signer = Signer::from(&seeds);

    CreateAccount::with_minimum_balance(
        &payer_ctx.payer,
        &channel_ctx.channel,
        Channel::LEN as u64,
        &crate::ID,
        Some(accs.rent),
    )?
    .invoke_signed(&[channel_signer])?;

    // Create the escrow ATA owned by the channel PDA.
    CreateAta {
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
