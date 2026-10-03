use std::{fs, path::PathBuf};

use borsh::{to_vec, BorshDeserialize};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::Deserialize;

use zkchannel_zk_methods::{ZKCHANNEL_VOUCHER_GUEST_ELF, ZKCHANNEL_VOUCHER_GUEST_ID};
use zkchannel_zk_shared::{V1VoucherInput, V1VoucherJournal, V1_PAYLOAD_LEN};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    payload_hex: String,
    authorized_signer_hex: String,
    signature_hex: String,
    channel_id_hex: String,
    cumulative_amount: String,
    expires_at: String,
}

fn load_fixture() -> Fixture {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v1-valid.json");

    let fixture_json =
        fs::read_to_string(fixture_path).expect("failed to read canonical V1 fixture");

    serde_json::from_str(&fixture_json).expect("failed to parse canonical V1 fixture")
}

fn fixture_input(fixture: &Fixture) -> V1VoucherInput {
    let payload = hex::decode(&fixture.payload_hex).expect("invalid payload hex");

    assert_eq!(
        payload.len(),
        V1_PAYLOAD_LEN,
        "fixture payload must be exactly 50 bytes"
    );

    let authorized_signer: [u8; 32] = hex::decode(&fixture.authorized_signer_hex)
        .expect("invalid authorized signer hex")
        .try_into()
        .expect("authorized signer must be 32 bytes");

    let signature: [u8; 64] = hex::decode(&fixture.signature_hex)
        .expect("invalid signature hex")
        .try_into()
        .expect("signature must be 64 bytes");

    V1VoucherInput {
        payload,
        authorized_signer,
        signature,
    }
}

fn expected_journal(fixture: &Fixture) -> V1VoucherJournal {
    let channel_id: [u8; 32] = hex::decode(&fixture.channel_id_hex)
        .expect("invalid channel ID hex")
        .try_into()
        .expect("channel ID must be 32 bytes");

    let cumulative_amount = fixture
        .cumulative_amount
        .parse()
        .expect("invalid cumulative amount");

    let expires_at = fixture.expires_at.parse().expect("invalid expiry");

    V1VoucherJournal {
        channel_id,
        cumulative_amount,
        expires_at,
    }
}

fn prove_and_decode(input: &V1VoucherInput) -> Option<V1VoucherJournal> {
    let encoded_input = to_vec(input).ok()?;

    let env = ExecutorEnv::builder()
        .write_slice(&encoded_input)
        .build()
        .ok()?;

    let prove_info = default_prover()
        .prove(env, ZKCHANNEL_VOUCHER_GUEST_ELF)
        .ok()?;

    let receipt = prove_info.receipt;

    receipt.verify(ZKCHANNEL_VOUCHER_GUEST_ID).ok()?;

    V1VoucherJournal::try_from_slice(&receipt.journal.bytes).ok()
}

fn main() {
    let fixture = load_fixture();
    let input = fixture_input(&fixture);

    println!("Proving ZKChannel V1 voucher authorization...");

    let journal = prove_and_decode(&input).expect("canonical V1 voucher was rejected");

    let expected = expected_journal(&fixture);

    assert_eq!(journal, expected);

    println!("Receipt verified against ZKChannel guest image ID.");

    println!("V1 voucher journal verified:");
    println!("  channel_id        = {}", hex::encode(journal.channel_id));
    println!("  cumulative_amount = {}", journal.cumulative_amount);
    println!("  expires_at        = {}", journal.expires_at);

    println!("ZKChannel V1 authorization succeeded.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_v1_voucher() {
        let fixture = load_fixture();
        let input = fixture_input(&fixture);

        let journal = prove_and_decode(&input).expect("canonical V1 voucher was rejected");

        assert_eq!(journal, expected_journal(&fixture));
    }

    #[test]
    fn rejects_mutated_signature() {
        let fixture = load_fixture();
        let mut input = fixture_input(&fixture);

        input.signature[0] ^= 0x01;

        assert!(
            prove_and_decode(&input).is_none(),
            "mutated signature was accepted"
        );
    }

    #[test]
    fn rejects_wrong_authorized_signer() {
        let fixture = load_fixture();
        let mut input = fixture_input(&fixture);

        input.authorized_signer =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("invalid wrong-signer test key")
                .try_into()
                .expect("wrong signer must be 32 bytes");

        assert!(
            prove_and_decode(&input).is_none(),
            "wrong authorized signer was accepted"
        );
    }

    #[test]
    fn rejects_mutated_signed_payload() {
        let fixture = load_fixture();
        let mut input = fixture_input(&fixture);

        // Byte 34 is the first byte of cumulative_amount.
        // Mutating it changes signed protocol data while keeping
        // the original Ed25519 signature.
        input.payload[34] ^= 0x01;

        assert!(
            prove_and_decode(&input).is_none(),
            "mutated signed payload was accepted"
        );
    }
}
