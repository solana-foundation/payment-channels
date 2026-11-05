use borsh::{BorshDeserialize, BorshSerialize};
use payment_channel_interface::{
    HookContext, HookDescriptor, HookMeta, HookState, ID,
    channel::{CHANNEL_V1_LEN, CHANNEL_V2_LEN, ChannelAccountView, ChannelView, channel_address},
    hooks::{HOOK_CONTEXT_LEN, Operation, Phase, descriptor_commitment, hook_authority},
    validation::{CallbackExpectations, ValidatedCallback, validate_callback},
};
use pinocchio::{AccountView, Address, account::RuntimeAccount, error::ProgramError};

fn address(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

#[test]
fn golden_context_serialization_covers_every_field_in_frozen_order() {
    let context = HookContext {
        abi_version: 1,
        phase: 2,
        operation: 3,
        executed: 4,
        channel: [5; 32],
        sequence: 6,
        open_slot: 7,
        payer: [8; 32],
        payee: [9; 32],
        mint: [10; 32],
        token_program: [11; 32],
        configuration: [12; 32],
        authorized_signer: [13; 32],
        distribution_hash: [14; 32],
        deposit_before: 15,
        settled_before: 16,
        payout_before: 17,
        withdrawn_before: -18,
        funding_requested: 19,
        merchant_due: 20,
        refund_due: 21,
        funding_transferred: 22,
        merchant_transferred: 23,
        refund_transferred_to_payer: 24,
        redirected_principal: 25,
        treasury_surplus: 26,
        deposit_after: 27,
        payout_after: 28,
        withdrawn_after: -29,
        refund_destination: [30; 32],
    };
    // Independent frozen wire vector, not a second ABI type or serialized struct.
    let mut golden = vec![1, 2, 3, 4];
    golden.extend([5; 32]);
    golden.extend(6u64.to_le_bytes());
    golden.extend(7u64.to_le_bytes());
    for byte in 8..=14 {
        golden.extend([byte; 32]);
    }
    for value in [
        15i64, 16, 17, -18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, -29,
    ] {
        golden.extend(value.to_le_bytes());
    }
    golden.extend([30; 32]);
    assert_eq!(golden.len(), HOOK_CONTEXT_LEN);
    let mut encoded = [0; HOOK_CONTEXT_LEN];
    context.serialize(&mut &mut encoded[..]).unwrap();
    assert_eq!(encoded.as_slice(), golden);
    assert_eq!(HookContext::try_from_slice(&golden).unwrap(), context);
}

#[test]
fn golden_sparse_config_commits_the_original_fixed_slots() {
    let mut sparse = vec![1];
    sparse.extend([8; 32]);
    sparse.extend(*b"prefund!");
    sparse.extend([1, 2, 4, 5]);
    sparse.extend([9; 32]);
    sparse.extend([1, 0, 0, 0]);
    let state = HookState::parse(&sparse).unwrap();
    let mut fixed = [0; 824];
    fixed[..32].fill(8);
    fixed[32..40].copy_from_slice(b"prefund!");
    fixed[40..44].copy_from_slice(&[1, 2, 4, 5]);
    fixed[74..106].fill(9);
    fixed[106] = 1;
    assert_eq!(state.commitment, payment_channel_interface::sha256(&fixed));
    for end in 0..sparse.len() {
        assert!(HookState::parse(&sparse[..end]).is_err());
    }
    for (offset, value) in [(0, 2), (41, 5), (42, 33), (77, 2)] {
        let mut invalid = sparse.clone();
        invalid[offset] = value;
        assert!(HookState::parse(&invalid).is_err());
    }
    assert!(HookState::parse_for_program(&sparse, &address(8)).is_err());
}

#[test]
fn version_readers_reject_every_short_layout_and_cross_version_cast() {
    let mut v1 = [0; CHANNEL_V1_LEN];
    v1[0..2].copy_from_slice(&[1, 1]);
    let mut v2 = [0; CHANNEL_V2_LEN];
    v2[0..2].copy_from_slice(&[1, 2]);
    assert!(ChannelView::v1(&v1).unwrap().hooks().is_err());
    assert!(ChannelView::v2(&v2).unwrap().hooks().is_ok());
    assert!(ChannelView::v1(&v2).is_err());
    assert!(ChannelView::v2(&v1).is_err());
    for len in 0..CHANNEL_V2_LEN {
        assert!(ChannelView::v2(&v2[..len]).is_err());
    }
    for len in 0..CHANNEL_V1_LEN {
        assert!(ChannelView::v1(&v1[..len]).is_err());
    }
    for version in [0, 1, 3, 255] {
        v2[1] = version;
        assert!(ChannelView::v2(&v2).is_err());
    }
    v2[1] = 2;
    v2[0] = 0;
    assert!(ChannelView::v2(&v2).is_err());
}

#[repr(C)]
struct TestAccount {
    raw: RuntimeAccount,
    data: [u8; CHANNEL_V2_LEN + 1],
}

impl TestAccount {
    fn new(
        address: Address,
        owner: Address,
        signer: bool,
        writable: bool,
        data: &[u8],
    ) -> Box<Self> {
        let mut account = Box::new(Self {
            raw: RuntimeAccount {
                borrow_state: u8::MAX,
                address,
                owner,
                is_signer: u8::from(signer),
                is_writable: u8::from(writable),
                data_len: data.len() as u64,
                ..RuntimeAccount::default()
            },
            data: [0; CHANNEL_V2_LEN + 1],
        });
        account.data[..data.len()].copy_from_slice(data);
        account
    }

    fn view(&mut self) -> AccountView {
        // SAFETY: repr(C) puts the data immediately after RuntimeAccount;
        // tests keep the Box alive and never resize it while views exist.
        unsafe { AccountView::new_unchecked(&mut self.raw) }
    }
}

#[test]
fn account_facade_checks_owner_layout_and_exact_version() {
    for version in [1, 2] {
        let len = if version == 1 {
            CHANNEL_V1_LEN
        } else {
            CHANNEL_V2_LEN
        };
        let mut data = vec![0; len];
        data[..2].copy_from_slice(&[1, version]);
        let mut account = TestAccount::new(address(8), ID, false, true, &data);
        let view = account.view();
        let mut alias = account.view();
        let facade = ChannelAccountView::new(&view, &ID).unwrap();
        assert_eq!(facade.with_v1(|_| Ok(())).is_ok(), version == 1);
        assert_eq!(facade.with_v2(|_| Ok(())).is_ok(), version == 2);
        assert!(matches!(
            ChannelAccountView::new(&view, &address(9)),
            Err(ProgramError::InvalidAccountOwner)
        ));
        for (offset, value) in [(0, 0), (1, 0), (1, 3), (1, 255), (3, 4), (3, 255)] {
            alias.try_borrow_mut().unwrap()[offset] = value;
            assert!(matches!(
                ChannelAccountView::new(&view, &ID),
                Err(ProgramError::InvalidAccountData)
            ));
            assert_eq!(
                facade.with_v1(|_| Ok(())),
                Err(ProgramError::InvalidAccountData)
            );
            assert_eq!(
                facade.with_v2(|_| Ok(())),
                Err(ProgramError::InvalidAccountData)
            );
            alias.try_borrow_mut().unwrap()[offset] = data[offset];
        }
    }
    // Includes zero, truncated headers, every short layout and mismatched sizes.
    for len in 0..=CHANNEL_V2_LEN + 1 {
        for version in [1, 2] {
            let mut data = vec![0; len];
            if len > 0 {
                data[0] = 1;
            }
            if len > 1 {
                data[1] = version;
            }
            let mut account = TestAccount::new(address(8), ID, false, true, &data);
            let view = account.view();
            let valid =
                (version == 1 && len == CHANNEL_V1_LEN) || (version == 2 && len == CHANNEL_V2_LEN);
            assert_eq!(ChannelAccountView::new(&view, &ID).is_ok(), valid);
        }
    }
}

#[test]
fn account_facade_releases_borrows_and_observes_changes() {
    let mut data = [0; CHANNEL_V2_LEN];
    data[..2].copy_from_slice(&[1, 2]);
    let mut account = TestAccount::new(address(8), ID, false, true, &data);
    let view = account.view();
    let mut alias = account.view();
    let facade = ChannelAccountView::new(&view, &ID).unwrap();
    {
        let _borrow = alias.try_borrow_mut().unwrap();
        assert!(matches!(
            ChannelAccountView::new(&view, &ID),
            Err(ProgramError::AccountBorrowFailed)
        ));
        assert_eq!(
            facade.with_v2(|_| Ok(())),
            Err(ProgramError::AccountBorrowFailed)
        );
    }
    assert_eq!(
        facade.with_v2(|ch| {
            assert!(alias.try_borrow_mut().is_err());
            Ok(ch.deposit())
        }),
        Ok(0)
    );
    alias.try_borrow_mut().unwrap()[12..20].copy_from_slice(&42u64.to_le_bytes());
    assert_eq!(facade.with_v2(|ch| Ok(ch.deposit())), Ok(42));
    assert_eq!(
        facade.with_v2::<()>(|_| Err(ProgramError::InvalidArgument)),
        Err(ProgramError::InvalidArgument)
    );
    assert!(alias.try_borrow_mut().is_ok());
    assert_eq!(
        facade.with_v1(|_| Ok(())),
        Err(ProgramError::InvalidAccountData)
    );
    assert!(alias.try_borrow_mut().is_ok());
    // SAFETY: no references to the owner are retained; simulates a CPI owner change.
    unsafe {
        alias.assign(&address(9));
    }
    assert_eq!(
        facade.with_v2(|_| Ok(())),
        Err(ProgramError::InvalidAccountOwner)
    );
    // SAFETY: same as above.
    unsafe {
        alias.assign(&ID);
    }
    assert_eq!(facade.with_v2(|ch| Ok(ch.deposit())), Ok(42));
}

struct Fixture {
    accounts: [Box<TestAccount>; 3],
    context: HookContext,
    descriptors: [HookDescriptor; 4],
    channel: Address,
    program: Address,
    token: Address,
}

impl Fixture {
    fn new(phase: Phase, operation: Operation) -> Self {
        let program = address(50);
        let token = address(51);
        let (channel, bump) = channel_address(
            &ID,
            &address(1),
            &address(2),
            &address(3),
            &address(4),
            5,
            6,
        );
        let mut descriptors = [HookDescriptor::EMPTY; 4];
        descriptors[phase as usize] = HookDescriptor {
            program,
            entrypoint: *b"callback",
            account_count: 1,
            static_len: 2,
            static_context: [7; 32],
            accounts: [
                HookMeta {
                    address: address(52),
                    writable: 1,
                },
                HookDescriptor::EMPTY.accounts[0],
                HookDescriptor::EMPTY.accounts[0],
                HookDescriptor::EMPTY.accounts[0],
            ],
        };
        let commitment = descriptor_commitment(&descriptors);
        let authority = hook_authority(&ID, &channel, &commitment, phase, &program).0;
        let mut bytes = [0; CHANNEL_V2_LEN];
        bytes[..4].copy_from_slice(&[1, 2, bump, 0]);
        bytes[4..12].copy_from_slice(&5u64.to_le_bytes());
        bytes[12..20].copy_from_slice(&100u64.to_le_bytes());
        bytes[56..88].fill(9);
        bytes[88..120].fill(1);
        bytes[120..152].fill(2);
        bytes[152..184].fill(4);
        bytes[184..216].fill(3);
        bytes[248..256].copy_from_slice(&6u64.to_le_bytes());
        bytes[256] = 1;
        bytes[257..265].copy_from_slice(&1u64.to_le_bytes());
        bytes[265..297].copy_from_slice(&commitment);
        // SAFETY: fixed descriptors are padding-free alignment-one byte fields.
        bytes[297..].copy_from_slice(unsafe {
            core::slice::from_raw_parts(descriptors.as_ptr().cast(), 824)
        });
        let mut context = HookContext::try_from_slice(&[0; HOOK_CONTEXT_LEN]).unwrap();
        context.abi_version = 1;
        context.phase = phase as u8;
        context.operation = operation as u8;
        context.executed = u8::from(matches!(phase, Phase::PostFund | Phase::PostDistribute));
        context.channel = *channel.as_array();
        context.sequence = 1;
        context.open_slot = 6;
        context.payer = [1; 32];
        context.payee = [2; 32];
        context.mint = [3; 32];
        context.authorized_signer = [4; 32];
        context.distribution_hash = [9; 32];
        context.configuration = commitment;
        context.token_program = *token.as_array();
        context.deposit_before = 100;
        context.deposit_after = 100;
        Self {
            accounts: [
                TestAccount::new(authority, address(0), true, false, &[]),
                TestAccount::new(channel, ID, false, false, &bytes),
                TestAccount::new(address(52), program, false, true, &[]),
            ],
            context,
            descriptors,
            channel,
            program,
            token,
        }
    }

    fn data(&self) -> Vec<u8> {
        let mut bytes = b"callback".to_vec();
        self.context.serialize(&mut bytes).unwrap();
        bytes.extend([2, 7, 7]);
        bytes
    }

    fn validate_data(
        &mut self,
        data: &[u8],
        program: Address,
    ) -> Result<ValidatedCallback, ProgramError> {
        let mut accounts = self.accounts.each_mut().map(|a| a.view());
        let result = validate_callback(
            &accounts,
            data,
            &CallbackExpectations {
                channel_program: &program,
                callback_program: &self.program,
                channel: &self.channel,
                token_program: &self.token,
                descriptors: &self.descriptors,
            },
        );
        // Success and every rejection path must release the callback data borrow.
        assert!(accounts[1].try_borrow_mut().is_ok());
        result
    }

    fn validate(&mut self) -> Result<ValidatedCallback, ProgramError> {
        self.validate_data(&self.data(), ID)
    }
}

#[test]
fn all_economic_phase_operation_pairs_accept_the_frozen_tags() {
    for (phases, operations) in [
        (
            [Phase::PreFund, Phase::PostFund],
            [Operation::Open, Operation::TopUp],
        ),
        (
            [Phase::PreDistribute, Phase::PostDistribute],
            [Operation::Distribute, Operation::WithdrawPayer],
        ),
    ] {
        for phase in phases {
            for operation in operations {
                let mut fixture = Fixture::new(phase, operation);
                assert_eq!(fixture.validate().unwrap().context, fixture.context);
            }
        }
    }
}

#[test]
fn rejects_untrusted_program_configuration_channel_and_scoped_authority() {
    let mut f = Fixture::new(Phase::PreFund, Operation::Open);
    assert!(f.validate().is_ok());
    let data = f.data();
    assert!(f.validate_data(&data, address(99)).is_err());
    f.accounts[1].raw.owner = address(99);
    assert!(f.validate().is_err());
    f.accounts[1].raw.owner = ID;
    f.accounts[0].raw.address = hook_authority(
        &ID,
        &f.channel,
        &f.context.configuration,
        Phase::PostFund,
        &f.program,
    )
    .0;
    assert!(f.validate().is_err());
    f.accounts[0].raw.address = hook_authority(
        &ID,
        &f.channel,
        &f.context.configuration,
        Phase::PreFund,
        &f.program,
    )
    .0;
    f.descriptors[0].entrypoint[0] ^= 1;
    assert!(f.validate().is_err());
    f.descriptors[0].entrypoint[0] ^= 1;
    f.channel = address(99);
    assert!(f.validate().is_err());
}

#[test]
fn rejects_invalid_callback_envelopes_tags_and_bindings() {
    let mut f = Fixture::new(Phase::PreFund, Operation::Open);
    let data = f.data();
    for len in 0..data.len() {
        assert!(f.validate_data(&data[..len], ID).is_err());
    }
    for (offset, value) in [
        (0, 0),
        (8, 0),
        (8, 2),
        (9, 4),
        (10, 10),
        (10, 11),
        (10, 12),
        (10, 13),
        (10, 7),
        (11, 1),
        (11, 2),
        (8 + HOOK_CONTEXT_LEN, 1),
        (9 + HOOK_CONTEXT_LEN, 8),
    ] {
        let mut invalid = data.clone();
        invalid[offset] = value;
        assert!(
            f.validate_data(&invalid, ID).is_err(),
            "offset {offset}, value {value}"
        );
    }
    // channel, sequence, open-slot, payer/payee/mint/token/config/signer/distribution.
    for offset in [4, 36, 44, 52, 84, 116, 148, 180, 212, 244] {
        let mut invalid = data.clone();
        invalid[8 + offset] ^= 1;
        assert!(
            f.validate_data(&invalid, ID).is_err(),
            "context offset {offset}"
        );
    }
    let mut trailing = data;
    trailing.push(0);
    assert!(f.validate_data(&trailing, ID).is_err());
}

#[test]
fn rejects_guard_sequence_layout_pda_and_descriptor_tampering() {
    for offset in [
        0, 1, 2, 4, 88, 120, 152, 184, 248, 256, 257, 265, 297, 337, 338, 371,
    ] {
        let mut f = Fixture::new(Phase::PreFund, Operation::Open);
        f.accounts[1].data[offset] ^= 1;
        assert!(f.validate().is_err(), "channel offset {offset}");
    }
    for len in [0, 1, 255, 256, 1120] {
        let mut f = Fixture::new(Phase::PreFund, Operation::Open);
        f.accounts[1].raw.data_len = len;
        assert!(f.validate().is_err());
    }
}

#[test]
fn rejects_account_contract_and_privilege_changes() {
    for index in 0..3 {
        let mut f = Fixture::new(Phase::PreFund, Operation::Open);
        f.accounts[index].raw.is_signer ^= 1;
        assert!(f.validate().is_err());
        f.accounts[index].raw.is_signer ^= 1;
        f.accounts[index].raw.is_writable ^= 1;
        assert!(f.validate().is_err());
        f.accounts[index].raw.is_writable ^= 1;
        f.accounts[index].raw.address = address(99);
        assert!(f.validate().is_err());
    }
    let mut f = Fixture::new(Phase::PreFund, Operation::Open);
    let data = f.data();
    let views = f.accounts.each_mut().map(|a| a.view());
    let expected = CallbackExpectations {
        channel_program: &ID,
        callback_program: &f.program,
        channel: &f.channel,
        token_program: &f.token,
        descriptors: &f.descriptors,
    };
    assert!(validate_callback(&views[..2], &data, &expected).is_err());
    let mut extra = views.to_vec();
    // Workspace feature unification may enable pinocchio's optional Copy impl.
    #[allow(clippy::clone_on_copy)]
    extra.push(views[2].clone());
    assert!(validate_callback(&extra, &data, &expected).is_err());
}
