use borsh::{BorshDeserialize, to_vec};
use payment_channels_client::{accounts::ChannelWithHooks, types::*};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/lifecycle-v2.json")).unwrap()
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn compact_configs_match_typescript_and_the_actual_program_layout() {
    assert_eq!(
        std::mem::size_of::<payment_channels::hooks::HookState>(),
        865
    );
    assert_eq!(
        std::mem::align_of::<payment_channels::hooks::HookState>(),
        1
    );
    for (count, value) in fixture()["compact"].as_array().unwrap().iter().enumerate() {
        let bytes = unhex(value.as_str().unwrap());
        let config = HookConfig::try_from_slice(&bytes).unwrap();
        assert_eq!(to_vec(&config).unwrap(), bytes);
        // Parser execution is covered by program SBF tests: hashing invokes an
        // SBF-only syscall when the program is used as a dependency.
        let mut state = payment_channels::hooks::HookState::EMPTY;
        let descriptor = &mut state.descriptors[1];
        descriptor.program = config[1].as_ref().unwrap().program;
        descriptor.entrypoint = [1, 2, 3, 4, 5, 6, 7, 8];
        descriptor.account_count = count as u8;
        descriptor.static_len = 3;
        descriptor.static_context[..3].copy_from_slice(&[9, 10, 11]);
        for (i, meta) in descriptor.accounts[..count].iter_mut().enumerate() {
            meta.address = solana_address::Address::new_from_array([i as u8 + 1; 32]);
            meta.writable = (i % 2) as u8;
        }
        // SAFETY: the program's byte-aligned HookState has no padding.
        let state_bytes = unsafe {
            std::slice::from_raw_parts(
                (&state as *const payment_channels::hooks::HookState).cast::<u8>(),
                865,
            )
        };
        let generated = HookState::try_from_slice(state_bytes).unwrap();
        assert_eq!(generated.descriptors[1].account_count as usize, count);
        assert_eq!(&generated.descriptors[1].static_context[..3], &[9, 10, 11]);
        assert_eq!(to_vec(&generated).unwrap(), state_bytes);
    }
}

#[test]
fn unhooked_open_and_fixed_layouts_match() {
    let bytes = unhex(fixture()["unhookedOpen"].as_str().unwrap());
    assert_eq!(bytes[0], 10);
    let args = OpenWithHooksArgs::try_from_slice(&bytes[1..]).unwrap();
    assert_eq!(to_vec(&args).unwrap(), bytes[1..]);
    assert_eq!(args.hook_config, [None, None, None, None]);
    assert_eq!(args.salt, 1);
    assert_eq!(args.deposit, 2);
    assert_eq!(args.grace_period, 3);
    assert_eq!(args.open_slot, 4);
    assert_eq!(
        to_vec(&ChannelWithHooks::try_from_slice(&[0; 1121]).unwrap())
            .unwrap()
            .len(),
        1121
    );
    assert_eq!(
        to_vec(&HookDescriptor::try_from_slice(&[0; 206]).unwrap())
            .unwrap()
            .len(),
        206
    );
    assert_eq!(
        to_vec(&HookContext::try_from_slice(&[0; 428]).unwrap())
            .unwrap()
            .len(),
        428
    );
    assert_eq!(
        payment_channels_client::programs::PAYMENT_CHANNELS_ID,
        payment_channels::ID
    );
}

#[test]
fn callback_context_uses_the_programs_borsh_order() {
    // All fields are integers or byte arrays: zero is a valid representation.
    let mut actual: payment_channels::hooks::HookContext = unsafe { std::mem::zeroed() };
    actual.abi_version = 1;
    actual.phase = 3;
    actual.operation = 7;
    actual.executed = 1;
    actual.sequence = 0x0807060504030201;
    actual.withdrawn_before = -42;
    actual.refund_transferred_to_payer = 123;
    actual.refund_destination = [9; 32];
    let bytes = to_vec(&actual).unwrap();
    assert_eq!(bytes.len(), 428);
    assert_eq!(bytes, unhex(fixture()["callbackContext"].as_str().unwrap()));
    let generated = HookContext::try_from_slice(&bytes).unwrap();
    assert_eq!(generated.sequence, actual.sequence);
    assert_eq!(generated.withdrawn_before, -42);
    assert_eq!(generated.refund_transferred_to_payer, 123);
    assert_eq!(generated.refund_destination, [9; 32]);
    assert_eq!(to_vec(&generated).unwrap(), bytes);
}
