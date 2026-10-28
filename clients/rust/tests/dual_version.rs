use borsh::to_vec;
use payment_channels_client::{
    accounts::{Channel, ChannelWithHooks},
    instructions::{TopUp, TopUpInstructionArgs, TopUpWithHooks, TopUpWithHooksInstructionArgs},
    types::TopUpArgs,
};

#[test]
fn explicit_account_decoders_validate_size_and_version_without_downgrade() {
    let mut legacy = [0u8; 256];
    legacy[..2].copy_from_slice(&[1, 1]);
    assert_eq!(
        to_vec(&Channel::from_bytes(&legacy).unwrap()).unwrap(),
        legacy
    );
    let mut hooked = [0u8; 1121];
    hooked[..2].copy_from_slice(&[1, 2]);
    let decoded = ChannelWithHooks::from_bytes(&hooked).unwrap();
    assert_eq!(decoded.channel.version, 2);
    assert_eq!(to_vec(&decoded).unwrap(), hooked);
    assert!(Channel::from_bytes(&hooked).is_err());
    assert!(ChannelWithHooks::from_bytes(&legacy).is_err());
    for version in [0, 2, 3, 255] {
        legacy[1] = version;
        assert!(Channel::from_bytes(&legacy).is_err());
    }
    for version in [0, 1, 3, 255] {
        hooked[1] = version;
        assert!(ChannelWithHooks::from_bytes(&hooked).is_err());
    }
    legacy[1] = 1;
    hooked[1] = 2;
    assert!(Channel::from_bytes(&legacy[..255]).is_err());
    assert!(ChannelWithHooks::from_bytes(&hooked[..1120]).is_err());
    assert!(Channel::from_bytes(&[legacy.as_slice(), &[0]].concat()).is_err());
    assert!(ChannelWithHooks::from_bytes(&[hooked.as_slice(), &[0]].concat()).is_err());
}

#[test]
fn old_and_hooked_builders_use_distinct_tags_on_the_same_address() {
    let address = solana_address::Address::new_from_array([1; 32]);
    let old = TopUp {
        payer: address,
        channel: address,
        payer_token_account: address,
        channel_token_account: address,
        mint: address,
        token_program: address,
    }
    .instruction(TopUpInstructionArgs {
        top_up_args: TopUpArgs { amount: 42 },
    });
    let new = TopUpWithHooks {
        payer: address,
        channel: address,
        payer_token_account: address,
        channel_token_account: address,
        mint: address,
        token_program: address,
    }
    .instruction(TopUpWithHooksInstructionArgs {
        top_up_args: TopUpArgs { amount: 42 },
    });
    assert_eq!(
        old.program_id,
        payment_channels_client::generated::programs::PAYMENT_CHANNELS_ID
    );
    assert_eq!(new.program_id, old.program_id);
    assert_eq!(new.accounts, old.accounts);
    assert_eq!(old.data, [3, 42, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(new.data, [11, 42, 0, 0, 0, 0, 0, 0, 0]);
}
