use borsh::to_vec;
use payment_channels::{PaymentChannelsError, instructions};
use payment_channels_client::{
    instructions::{DistributeInstructionArgs, OpenInstructionArgs},
    types::{
        DistributeArgs as ClientDistributeArgs, DistributionEntry as ClientDistributionEntry,
        DistributionRecipients as ClientDistributionRecipients, OpenArgs as ClientOpenArgs,
    },
};
use pinocchio::error::ProgramError;
use solana_address::Address;

fn entry(byte: u8, bps: u16) -> ClientDistributionEntry {
    ClientDistributionEntry {
        recipient: Address::from([byte; 32]),
        bps,
    }
}

fn recipients(entries: Vec<ClientDistributionEntry>) -> ClientDistributionRecipients {
    ClientDistributionRecipients::from(entries)
}

fn serialize_open_args(open_args: ClientOpenArgs) -> Vec<u8> {
    to_vec(&OpenInstructionArgs { open_args }).expect("serialize open args")
}

fn serialize_distribute_args(distribute_args: ClientDistributeArgs) -> Vec<u8> {
    to_vec(&DistributeInstructionArgs { distribute_args }).expect("serialize distribute args")
}

#[test]
fn generated_open_args_parse_with_on_chain_loader() {
    let salt = 42u64;
    let deposit = 1_000_000u64;
    let grace_period = 900u32;
    let open_args = ClientOpenArgs {
        salt,
        deposit,
        grace_period,
        recipients: recipients(vec![entry(1, 2_500), entry(2, 3_000)]),
    };

    let payload = serialize_open_args(open_args);
    let parsed = instructions::open::OpenArgs::load(&payload).expect("on-chain open parse");

    assert_eq!(parsed.salt(), salt);
    assert_eq!(parsed.deposit(), deposit);
    assert_eq!(parsed.grace_period(), grace_period);
    assert_eq!(parsed.recipients.entries.len(), 2);
    assert_eq!(parsed.recipients.entries[0].recipient.as_ref(), &[1u8; 32]);
    assert_eq!(parsed.recipients.entries[0].bps(), 2_500);
    assert_eq!(parsed.recipients.entries[1].recipient.as_ref(), &[2u8; 32]);
    assert_eq!(parsed.recipients.entries[1].bps(), 3_000);
    assert_eq!(parsed.recipients.payee_bps(), 4_500);

    let recipients_preimage = &payload[20..];
    assert_eq!(parsed.recipients.preimage(), recipients_preimage);
    assert_eq!(&recipients_preimage[..4], &2u32.to_le_bytes());
    assert_eq!(recipients_preimage.len(), 4 + 2 * 34);
    assert_ne!(
        blake3::hash(recipients_preimage),
        blake3::hash(&payload),
        "distribution hash preimage must exclude the open fixed header",
    );
}

#[test]
fn generated_distribute_zero_recipients_parse_with_on_chain_loader() {
    let payload = serialize_distribute_args(ClientDistributeArgs {
        recipients: recipients(Vec::new()),
    });

    let parsed = instructions::distribute::DistributeArgs::load(&payload)
        .expect("on-chain distribute parse");

    assert_eq!(payload.as_slice(), &0u32.to_le_bytes());
    assert!(parsed.recipients.entries.is_empty());
    assert_eq!(parsed.recipients.preimage(), &0u32.to_le_bytes());
    assert_eq!(parsed.recipients.payee_bps(), 10_000);
}

#[test]
fn generated_distribute_multi_recipient_parse_with_on_chain_loader() {
    let payload = serialize_distribute_args(ClientDistributeArgs {
        recipients: recipients(vec![entry(3, 1_250), entry(4, 8_750)]),
    });

    let parsed = instructions::distribute::DistributeArgs::load(&payload)
        .expect("on-chain distribute parse");

    assert_eq!(&payload[..4], &2u32.to_le_bytes());
    assert_eq!(parsed.recipients.entries.len(), 2);
    assert_eq!(parsed.recipients.entries[0].recipient.as_ref(), &[3u8; 32]);
    assert_eq!(parsed.recipients.entries[0].bps(), 1_250);
    assert_eq!(parsed.recipients.entries[1].recipient.as_ref(), &[4u8; 32]);
    assert_eq!(parsed.recipients.entries[1].bps(), 8_750);
    assert_eq!(parsed.recipients.payee_bps(), 0);
    assert_eq!(parsed.recipients.preimage(), payload.as_slice());
}

#[test]
fn generated_u32_count_above_program_max_is_rejected_by_on_chain_loader() {
    let too_many = instructions::helpers::MAX_DISTRIBUTION_RECIPIENTS + 1;
    let entries = (0..too_many)
        .map(|i| entry(i as u8 + 1, 1))
        .collect::<Vec<_>>();
    let payload = serialize_distribute_args(ClientDistributeArgs {
        recipients: recipients(entries),
    });

    assert_eq!(&payload[..4], &(too_many as u32).to_le_bytes());
    let err = instructions::distribute::DistributeArgs::load(&payload).unwrap_err();
    assert_eq!(
        err,
        ProgramError::from(PaymentChannelsError::InvalidRecipientCount),
    );
}
