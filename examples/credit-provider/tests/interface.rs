#![cfg(feature = "client")]

use borsh::{BorshDeserialize, BorshSerialize};
use credit_provider::{
    Authorization, CALLBACK_ENTRYPOINT, Ledger, client, decode_callback, hook_state,
};
use payment_channels::hooks::HookContext;
use pinocchio::Address;

#[test]
fn fixed_ledger_layout_and_authorization_round_trip() {
    let mut bytes = Vec::new();
    Ledger::default().serialize(&mut bytes).unwrap();
    assert_eq!(bytes.len(), Ledger::LEN);
    Ledger::try_from_slice(&bytes).unwrap();
    let authorization = Authorization {
        payee: [2; 32],
        authorized_signer: [3; 32],
        distribution_hash: [4; 32],
        salt: 5,
        open_slot: 6,
        cap: 7,
        nonce: 8,
        expires_at_slot: 9,
    };
    let ix = client::authorize(
        &Address::new_from_array([10; 32]),
        &Address::new_from_array([11; 32]),
        &Address::new_from_array([12; 32]),
        &Address::new_from_array([13; 32]),
        authorization,
    );
    assert_eq!(Authorization::try_from_slice(&ix.data[1..]).unwrap().cap, 7);
    assert!(ix.accounts[0].is_signer && ix.accounts[1].is_signer);
}

#[test]
fn decoder_round_trips_the_actual_core_abi_and_rejects_unknown_encodings() {
    // Every field of the core ABI is an integer or fixed byte array.
    let mut context: HookContext = unsafe { core::mem::zeroed() };
    context.abi_version = 1;
    context.phase = 3;
    context.sequence = 42;
    context.refund_transferred_to_payer = 91;
    context.refund_destination = [7; 32];
    let mut bytes = CALLBACK_ENTRYPOINT.to_vec();
    context.serialize(&mut bytes).unwrap();
    bytes.push(0);
    let decoded = decode_callback(&bytes).unwrap();
    assert_eq!(decoded.sequence, 42);
    assert_eq!(decoded.refund_transferred_to_payer, 91);
    assert_eq!(decoded.refund_destination, [7; 32]);
    for end in 0..bytes.len() {
        assert!(decode_callback(&bytes[..end]).is_err());
    }
    for (offset, value) in [(8, 0), (8, 2), (9, 1), (9, 2), (9, 4)] {
        let mut invalid = bytes.clone();
        invalid[offset] = value;
        assert!(decode_callback(&invalid).is_err());
    }
    bytes.push(0);
    assert!(decode_callback(&bytes).is_err());
}

#[test]
fn configuration_matches_core_memory_commitment_and_four_extra_limit() {
    let program = Address::new_from_array([10; 32]);
    let owner = Address::new_from_array([11; 32]);
    let mint = Address::new_from_array([12; 32]);
    let state = hook_state(&program, &owner, &mint);
    // Core asserts repr(C), alignment one and no padding for these types.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            state.descriptors.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&state.descriptors),
        )
    };
    assert_eq!(
        state.commitment,
        const_crypto::sha2::Sha256::new().update(bytes).finalize()
    );
    assert_eq!(client::hook_config(&program, &owner, &mint).len(), 352);
    assert_eq!(
        state.descriptors[0].account_count as usize,
        payment_channels::hooks::MAX_HOOK_ACCOUNTS
    );
    assert!(!state.descriptors[1].enabled() && !state.descriptors[2].enabled());
    for phase in [0, 3] {
        let tail = client::hook_tail(
            &program,
            &owner,
            &mint,
            &Address::new_from_array([13; 32]),
            phase,
        );
        assert_eq!(tail.len(), 6);
        assert!(tail.iter().all(|m| !m.is_signer));
        assert!(tail[2..5].iter().all(|m| m.is_writable));
        assert!(!tail[5].is_writable);
    }
}
