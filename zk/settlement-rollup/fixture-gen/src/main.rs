use borsh::to_vec;
use payment_channels::{VOUCHER_MAGIC, VOUCHER_PAYLOAD_SIZE};
use payment_channels_client::types::VoucherArgs;
use serde::Serialize;
use solana_address::Address;
use solana_keypair::keypair_from_seed;
use solana_signature::Signature;
use solana_signer::Signer;
use std::{fs, path::PathBuf};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V1Fixture {
    fixture_version: u8,
    magic_hex: String,
    channel_id_hex: String,
    cumulative_amount: String,
    expires_at: String,
    payload_hex: String,
    authorized_signer_base58: String,
    authorized_signer_hex: String,
    signature_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Public deterministic test-vector seed.
    // NEVER use this seed for real funds or production keys.
    let seed = [1u8; 32];

    let signer = keypair_from_seed(&seed)?;
    let authorized_signer = signer.pubkey();

    let channel_id = Address::new_from_array([7u8; 32]);

    let cumulative_amount = 500_000u64;
    let expires_at = 0i64;

    let voucher = VoucherArgs {
        magic: VOUCHER_MAGIC,
        channel_id,
        cumulative_amount,
        expires_at,
    };

    let payload = to_vec(&voucher)?;

    assert_eq!(payload.len(), VOUCHER_PAYLOAD_SIZE);
    assert_eq!(VOUCHER_PAYLOAD_SIZE, 50);

    assert_eq!(&payload[0..2], &VOUCHER_MAGIC);
    assert_eq!(&payload[2..34], channel_id.as_array());
    assert_eq!(&payload[34..42], &cumulative_amount.to_le_bytes());
    assert_eq!(&payload[42..50], &expires_at.to_le_bytes());

    let signature = signer.sign_message(&payload);

    assert!(
        signature.verify(authorized_signer.as_array(), &payload),
        "valid V1 voucher signature must verify"
    );
    let mut tampered_payload = payload.clone();
    tampered_payload[34] ^= 0x01;

    assert!(
        !signature.verify(authorized_signer.as_array(), &tampered_payload),
        "signature must fail if the signed voucher bytes change"
    );

    println!("authorized signer: {authorized_signer}");
    println!("voucher payload length: {}", payload.len());
    println!("payload hex: {}", hex::encode(&payload));
    println!("signature hex: {}", hex::encode(signature.as_array()));
    println!("valid signature: true");
    println!("tampered payload rejected: true");

    let mut bad_magic = payload.clone();
    bad_magic[0] ^= 0x01;

    assert!(
        !signature.verify(authorized_signer.as_array(), &bad_magic),
        "signature must fail if voucher magic changes"
    );

    let mut bad_channel = payload.clone();
    bad_channel[2] ^= 0x01;

    assert!(
        !signature.verify(authorized_signer.as_array(), &bad_channel),
        "signature must fail if channel_id changes"
    );

    let mut bad_expiry = payload.clone();
    bad_expiry[42] ^= 0x01;

    assert!(
        !signature.verify(authorized_signer.as_array(), &bad_expiry),
        "signature must fail if expires_at changes"
    );

    let impostor = keypair_from_seed(&[2u8; 32])?;

    assert!(
        !signature.verify(impostor.pubkey().as_array(), &payload),
        "signature must fail under a different authorized signer"
    );

    let mut bad_signature_bytes = *signature.as_array();
    bad_signature_bytes[0] ^= 0x01;

    let bad_signature = Signature::from(bad_signature_bytes);

    assert!(
        !bad_signature.verify(authorized_signer.as_array(), &payload),
        "mutated signature must fail"
    );

    println!("magic mutation rejected: true");
    println!("channel mutation rejected: true");
    println!("amount mutation rejected: true");
    println!("expiry mutation rejected: true");
    println!("signer substitution rejected: true");
    println!("signature mutation rejected: true");

    let fixture = V1Fixture {
        fixture_version: 1,
        magic_hex: hex::encode(VOUCHER_MAGIC),
        channel_id_hex: hex::encode(channel_id.as_array()),
        cumulative_amount: cumulative_amount.to_string(),
        expires_at: expires_at.to_string(),
        payload_hex: hex::encode(&payload),
        authorized_signer_base58: authorized_signer.to_string(),
        authorized_signer_hex: hex::encode(authorized_signer.as_array()),
        signature_hex: hex::encode(signature.as_array()),
    };

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/v1-valid.json");

    if let Some(parent) = fixture_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(
        &fixture_path,
        format!("{}\n", serde_json::to_string_pretty(&fixture)?),
    )?;

    println!("fixture written: {}", fixture_path.display());

    Ok(())
}
