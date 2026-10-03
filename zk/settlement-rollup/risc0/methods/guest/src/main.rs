#![no_main]

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};
use risc0_zkvm::guest::env;

use zkchannel_zk_shared::{
    V1VoucherInput,
    V1VoucherJournal,
    V1_MAGIC,
    V1_PAYLOAD_LEN,
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input =
        V1VoucherInput::deserialize_reader(&mut env::stdin())
            .expect("invalid V1 voucher input encoding");

    // ------------------------------------------------------------
    // 1. Enforce the exact existing V1 payload shape.
    // ------------------------------------------------------------

    assert_eq!(
        input.payload.len(),
        V1_PAYLOAD_LEN,
        "V1 voucher payload must be exactly 50 bytes"
    );

    assert_eq!(
        &input.payload[0..2],
        &V1_MAGIC,
        "invalid V1 voucher magic"
    );

    // ------------------------------------------------------------
    // 2. Verify the Ed25519 authorization.
    //
    // The signature must verify over the exact canonical 50-byte
    // V1 payload under the supplied authorized signer.
    // ------------------------------------------------------------

    let verifying_key =
        VerifyingKey::from_bytes(&input.authorized_signer)
            .expect("invalid Ed25519 authorized signer");

    let signature =
        Signature::from_bytes(&input.signature);

    verifying_key
        .verify_strict(&input.payload, &signature)
        .expect("invalid V1 voucher Ed25519 signature");

    // ------------------------------------------------------------
    // 3. Parse the already-authenticated V1 payload.
    // ------------------------------------------------------------

    let mut channel_id = [0u8; 32];
    channel_id.copy_from_slice(&input.payload[2..34]);

    let cumulative_amount = u64::from_le_bytes(
        input.payload[34..42]
            .try_into()
            .expect("invalid cumulative amount slice"),
    );

    let expires_at = i64::from_le_bytes(
        input.payload[42..50]
            .try_into()
            .expect("invalid expiry slice"),
    );

    // ------------------------------------------------------------
    // 4. Commit only the public result.
    // ------------------------------------------------------------

    let journal = V1VoucherJournal {
        channel_id,
        cumulative_amount,
        expires_at,
    };

    journal
        .serialize(&mut env::journal())
        .expect("failed to serialize V1 voucher journal");
}
