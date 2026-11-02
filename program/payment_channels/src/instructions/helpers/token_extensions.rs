//! Token-2022 extension allow-list and state gates (ADR-007).

use super::token::TokenExtensionError;

/// `TransferFeeConfig` payload (type 1): `authority(32) | withdraw_authority(32) |
/// withheld(u64) | older_fee | newer_fee`, each fee `epoch(u64) | maximum_fee(u64) | bps(u16)`.
/// Offsets are pinned against `spl_token_2022_interface` in tests.
pub(crate) mod transfer_fee_config {
    use super::TokenExtensionError;

    const AUTHORITY_LEN: usize = 32;
    const WITHHELD_AMOUNT_LEN: usize = 8;
    const FEE_EPOCH_LEN: usize = 8;
    const FEE_MAXIMUM_LEN: usize = 8;
    const FEE_BPS_LEN: usize = 2;

    pub(super) const FEE_LEN: usize = FEE_EPOCH_LEN + FEE_MAXIMUM_LEN + FEE_BPS_LEN;
    pub(super) const FEE_EPOCH_OFFSET: usize = 0;
    pub(super) const FEE_MAXIMUM_OFFSET: usize = FEE_EPOCH_LEN;
    pub(super) const FEE_BPS_OFFSET: usize = FEE_EPOCH_LEN + FEE_MAXIMUM_LEN;
    pub(super) const OLDER_FEE_OFFSET: usize = AUTHORITY_LEN + AUTHORITY_LEN + WITHHELD_AMOUNT_LEN;
    pub(super) const NEWER_FEE_OFFSET: usize = OLDER_FEE_OFFSET + FEE_LEN;
    pub(super) const LEN: usize = NEWER_FEE_OFFSET + FEE_LEN;

    fn chunk<const N: usize>(bytes: &[u8], at: usize) -> Result<&[u8; N], TokenExtensionError> {
        bytes
            .get(at..)
            .and_then(|tail| tail.first_chunk::<N>())
            .ok_or(TokenExtensionError::MalformedTokenAccountData)
    }

    /// Mirrors `TransferFee::calculate_fee`: zero iff `bps == 0 || maximum_fee == 0`.
    fn fee_is_zero(fee: &[u8]) -> Result<bool, TokenExtensionError> {
        let maximum_fee = u64::from_le_bytes(*chunk(fee, FEE_MAXIMUM_OFFSET)?);
        let bps = u16::from_le_bytes(*chunk(fee, FEE_BPS_OFFSET)?);
        Ok(bps == 0 || maximum_fee == 0)
    }

    /// Mirrors `TransferFeeConfig::get_epoch_fee`: `newer` governs from its
    /// epoch on, `older` before that. Both the schedule charging now and the
    /// one scheduled next must be zero, so a `SetTransferFee` is rejected the
    /// moment it is scheduled, and a reverted fee is admitted again as soon
    /// as Token-2022 itself stops charging it.
    pub(crate) fn is_dormant(payload: &[u8], epoch: u64) -> Result<bool, TokenExtensionError> {
        if payload.len() != LEN {
            return Err(TokenExtensionError::MalformedTokenAccountData);
        }
        let older = &payload[OLDER_FEE_OFFSET..OLDER_FEE_OFFSET + FEE_LEN];
        let newer = &payload[NEWER_FEE_OFFSET..NEWER_FEE_OFFSET + FEE_LEN];
        let newer_epoch = u64::from_le_bytes(*chunk(newer, FEE_EPOCH_OFFSET)?);
        let older_governs = epoch < newer_epoch;
        Ok(fee_is_zero(newer)? && (!older_governs || fee_is_zero(older)?))
    }
}

/// `TransferHook` payload (type 14): `authority(32) | program_id(32)`; all-zero
/// encodes `None`.
pub(crate) mod transfer_hook {
    use super::TokenExtensionError;

    const AUTHORITY_LEN: usize = 32;
    const PROGRAM_ID_LEN: usize = 32;

    pub(super) const PROGRAM_ID_OFFSET: usize = AUTHORITY_LEN;
    pub(super) const LEN: usize = AUTHORITY_LEN + PROGRAM_ID_LEN;

    /// Token-2022 only invokes the hook, and demands its extra account metas,
    /// when `program_id` is set.
    pub(crate) fn is_dormant(payload: &[u8]) -> Result<bool, TokenExtensionError> {
        if payload.len() != LEN {
            return Err(TokenExtensionError::MalformedTokenAccountData);
        }
        Ok(payload[PROGRAM_ID_OFFSET..].iter().all(|&b| b == 0))
    }
}

/// Defines [`ExtensionType`] and its `TryFrom<u16>` together.
macro_rules! extension_types {
    ($( $(#[$doc:meta])* $name:ident = $id:literal ),+ $(,)?) => {
        /// Token-2022 extension ids the program recognizes (wire discriminants).
        /// Unknown ids are `UnsupportedTokenExtension`; see ADR-007 for the tiers.
        #[repr(u16)]
        #[derive(Clone, Copy, Eq, PartialEq, Debug)]
        pub(crate) enum ExtensionType {
            $( $(#[$doc])* $name = $id, )+
        }

        impl TryFrom<u16> for ExtensionType {
            type Error = TokenExtensionError;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $( $id => Ok(Self::$name), )+
                    _ => Err(TokenExtensionError::UnsupportedTokenExtension),
                }
            }
        }

        #[cfg(test)]
        impl ExtensionType {
            pub(crate) const ALL: &'static [ExtensionType] = &[ $( Self::$name, )+ ];
        }
    };
}

extension_types! {
    /// Mint; allowed while both fee schedules are zero.
    TransferFeeConfig = 1,
    /// Account; auto-added for fee mints, never touches `amount`.
    TransferFeeAmount = 2,
    /// Mint; inert while `supply > 0`.
    MintCloseAuthority = 3,
    /// Mint; the opt-in account extension is rejected, plain `amount` unaffected.
    ConfidentialTransferMint = 4,
    /// Account; locks `owner`.
    ImmutableOwner = 7,
    /// Mint; UI-only rescale.
    InterestBearingConfig = 10,
    /// Mint; issuer seize power, trusted like the freeze authority (ADR-007).
    PermanentDelegate = 12,
    /// Mint; allowed while no hook program is installed.
    TransferHook = 14,
    /// Account; auto-added for hook mints.
    TransferHookAccount = 15,
    /// Mint; confidential-fee bookkeeping, inert for plain transfers.
    ConfidentialTransferFeeConfig = 16,
    /// Mint; metadata pointer.
    MetadataPointer = 18,
    /// Mint; inline metadata.
    TokenMetadata = 19,
    /// Mint; group pointer.
    GroupPointer = 20,
    /// Mint; inline group.
    TokenGroup = 21,
    /// Mint; group-member pointer.
    GroupMemberPointer = 22,
    /// Mint; inline group member.
    TokenGroupMember = 23,
    /// Mint; UI-only rescale.
    ScaledUiAmount = 25,
    /// Mint; issuer pause switch, trusted like the freeze authority (ADR-007).
    Pausable = 26,
    /// Account; zero-length marker auto-added for pausable mints.
    PausableAccount = 27,
}

/// Per-account-kind allow-list with an optional state gate, driven through
/// `token::scan_tlv_extensions`.
pub(crate) trait ExtensionPolicy {
    fn allows(&self, kind: ExtensionType) -> bool;

    /// State gate for an allow-listed record; the default has none.
    fn gate(&self, _kind: ExtensionType, _payload: &[u8]) -> Result<(), TokenExtensionError> {
        Ok(())
    }

    fn check(&self, kind: ExtensionType, payload: &[u8]) -> Result<(), TokenExtensionError> {
        if !self.allows(kind) {
            return Err(TokenExtensionError::UnsupportedTokenExtension);
        }
        self.gate(kind, payload)
    }
}

/// Mint tiers (ADR-007): inert and trusted extensions pass; `TransferFeeConfig`
/// and `TransferHook` pass only while dormant at `epoch`, else
/// `ActiveTokenExtension`.
pub(crate) struct MintExtensionPolicy {
    pub(crate) epoch: u64,
}

/// `ImmutableOwner` plus the records Token-2022 auto-adds for allowed mint
/// extensions. Opt-in extensions that can reject a credit (`MemoTransfer`,
/// `CpiGuard`, `ConfidentialTransferAccount`) stay out so a poisoned
/// beneficiary redirects to treasury instead of bricking the crank. Stateless
/// by design: `payout_destination` redirects only `UnsupportedTokenExtension`.
pub(crate) struct TokenAccountExtensionPolicy;

impl ExtensionPolicy for MintExtensionPolicy {
    fn allows(&self, kind: ExtensionType) -> bool {
        matches!(
            kind,
            ExtensionType::TransferFeeConfig
                | ExtensionType::MintCloseAuthority
                | ExtensionType::ConfidentialTransferMint
                | ExtensionType::InterestBearingConfig
                | ExtensionType::PermanentDelegate
                | ExtensionType::TransferHook
                | ExtensionType::ConfidentialTransferFeeConfig
                | ExtensionType::MetadataPointer
                | ExtensionType::TokenMetadata
                | ExtensionType::GroupPointer
                | ExtensionType::TokenGroup
                | ExtensionType::GroupMemberPointer
                | ExtensionType::TokenGroupMember
                | ExtensionType::ScaledUiAmount
                | ExtensionType::Pausable,
        )
    }

    fn gate(&self, kind: ExtensionType, payload: &[u8]) -> Result<(), TokenExtensionError> {
        let dormant = match kind {
            ExtensionType::TransferFeeConfig => {
                transfer_fee_config::is_dormant(payload, self.epoch)?
            }
            ExtensionType::TransferHook => transfer_hook::is_dormant(payload)?,
            _ => true,
        };
        if dormant {
            Ok(())
        } else {
            Err(TokenExtensionError::ActiveTokenExtension)
        }
    }
}

impl ExtensionPolicy for TokenAccountExtensionPolicy {
    fn allows(&self, kind: ExtensionType) -> bool {
        matches!(
            kind,
            ExtensionType::ImmutableOwner
                | ExtensionType::TransferFeeAmount
                | ExtensionType::TransferHookAccount
                | ExtensionType::PausableAccount
        )
    }
}

#[cfg(test)]
mod token_2022_extension_id_tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::{ExtensionType, transfer_fee_config, transfer_hook};
    use core::mem::{offset_of, size_of};
    use spl_token_2022_interface::extension::{
        ExtensionType as Upstream,
        transfer_fee::{TransferFee, TransferFeeConfig},
        transfer_hook::TransferHook,
    };

    fn upstream(kind: ExtensionType) -> Upstream {
        match kind {
            ExtensionType::TransferFeeConfig => Upstream::TransferFeeConfig,
            ExtensionType::TransferFeeAmount => Upstream::TransferFeeAmount,
            ExtensionType::MintCloseAuthority => Upstream::MintCloseAuthority,
            ExtensionType::ConfidentialTransferMint => Upstream::ConfidentialTransferMint,
            ExtensionType::ImmutableOwner => Upstream::ImmutableOwner,
            ExtensionType::InterestBearingConfig => Upstream::InterestBearingConfig,
            ExtensionType::PermanentDelegate => Upstream::PermanentDelegate,
            ExtensionType::TransferHook => Upstream::TransferHook,
            ExtensionType::TransferHookAccount => Upstream::TransferHookAccount,
            ExtensionType::ConfidentialTransferFeeConfig => Upstream::ConfidentialTransferFeeConfig,
            ExtensionType::MetadataPointer => Upstream::MetadataPointer,
            ExtensionType::TokenMetadata => Upstream::TokenMetadata,
            ExtensionType::GroupPointer => Upstream::GroupPointer,
            ExtensionType::TokenGroup => Upstream::TokenGroup,
            ExtensionType::GroupMemberPointer => Upstream::GroupMemberPointer,
            ExtensionType::TokenGroupMember => Upstream::TokenGroupMember,
            ExtensionType::ScaledUiAmount => Upstream::ScaledUiAmount,
            ExtensionType::Pausable => Upstream::Pausable,
            ExtensionType::PausableAccount => Upstream::PausableAccount,
        }
    }

    #[test]
    fn mirrored_token_2022_extension_ids_match_upstream_wire_discriminants() {
        for &kind in ExtensionType::ALL {
            assert_eq!(kind as u16, upstream(kind) as u16, "{kind:?}");
            assert_eq!(ExtensionType::try_from(kind as u16).unwrap(), kind);
        }
    }

    #[test]
    fn transfer_fee_config_layout_matches_upstream() {
        assert_eq!(transfer_fee_config::LEN, size_of::<TransferFeeConfig>());
        assert_eq!(transfer_fee_config::FEE_LEN, size_of::<TransferFee>());
        assert_eq!(
            transfer_fee_config::OLDER_FEE_OFFSET,
            offset_of!(TransferFeeConfig, older_transfer_fee)
        );
        assert_eq!(
            transfer_fee_config::NEWER_FEE_OFFSET,
            offset_of!(TransferFeeConfig, newer_transfer_fee)
        );
        assert_eq!(
            transfer_fee_config::FEE_MAXIMUM_OFFSET,
            offset_of!(TransferFee, maximum_fee)
        );
        assert_eq!(
            transfer_fee_config::FEE_BPS_OFFSET,
            offset_of!(TransferFee, transfer_fee_basis_points)
        );
    }

    #[test]
    fn transfer_hook_layout_matches_upstream() {
        assert_eq!(transfer_hook::LEN, size_of::<TransferHook>());
        assert_eq!(
            transfer_hook::PROGRAM_ID_OFFSET,
            offset_of!(TransferHook, program_id)
        );
    }

    #[test]
    fn upstream_account_extensions_for_allowed_mint_extensions_are_allowed() {
        use super::{ExtensionPolicy, MintExtensionPolicy, TokenAccountExtensionPolicy};
        const MINT: MintExtensionPolicy = MintExtensionPolicy { epoch: 0 };
        // Every account-side record Token-2022 auto-adds for an allow-listed
        // mint extension must itself be allow-listed, or no ATA of such a
        // mint could ever pass validation.
        let allowed_mint: Vec<Upstream> = ExtensionType::ALL
            .iter()
            .copied()
            .filter(|&k| MINT.allows(k))
            .map(upstream)
            .collect();
        for required in Upstream::get_required_init_account_extensions(&allowed_mint) {
            let kind = ExtensionType::try_from(required as u16)
                .unwrap_or_else(|_| panic!("{required:?} is unknown to the program"));
            assert!(
                TokenAccountExtensionPolicy.allows(kind),
                "{required:?} is auto-added to token accounts but not allow-listed"
            );
        }
    }
}

#[cfg(test)]
mod policy_tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::instructions::helpers::token::scan_tlv_extensions;

    /// Evaluated at epoch 0: `fee_config` schedules `newer` at epoch 2, so
    /// `older` governs here.
    const MINT: MintExtensionPolicy = MintExtensionPolicy { epoch: 0 };
    /// Evaluated once `newer` governs.
    const MINT_LATER: MintExtensionPolicy = MintExtensionPolicy { epoch: 2 };

    fn header(extension_type: u16, value_len: u16) -> [u8; 4] {
        let t = extension_type.to_le_bytes();
        let l = value_len.to_le_bytes();
        [t[0], t[1], l[0], l[1]]
    }

    fn record(extension_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = header(extension_type, payload.len() as u16).to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn expect_err(result: Result<(), TokenExtensionError>, expected: TokenExtensionError) {
        match result {
            Ok(()) => panic!("expected error, got Ok"),
            Err(e) => assert_eq!(e as u32, expected as u32),
        }
    }

    /// `TransferFeeConfig` payload with the given `(maximum_fee, bps)` for
    /// the older and newer schedules, `newer` taking effect at epoch 2 (as a
    /// `SetTransferFee` issued at epoch 0 would); authorities and withheld zero.
    fn fee_config(older: (u64, u16), newer: (u64, u16)) -> [u8; transfer_fee_config::LEN] {
        let mut p = [0u8; transfer_fee_config::LEN];
        let newer_epoch_at =
            transfer_fee_config::NEWER_FEE_OFFSET + transfer_fee_config::FEE_EPOCH_OFFSET;
        p[newer_epoch_at..newer_epoch_at + 8].copy_from_slice(&2u64.to_le_bytes());
        for (offset, (maximum_fee, bps)) in [
            (transfer_fee_config::OLDER_FEE_OFFSET, older),
            (transfer_fee_config::NEWER_FEE_OFFSET, newer),
        ] {
            let max_at = offset + transfer_fee_config::FEE_MAXIMUM_OFFSET;
            let bps_at = offset + transfer_fee_config::FEE_BPS_OFFSET;
            p[max_at..max_at + 8].copy_from_slice(&maximum_fee.to_le_bytes());
            p[bps_at..bps_at + 2].copy_from_slice(&bps.to_le_bytes());
        }
        p
    }

    /// `TransferHook` payload with the given `program_id`.
    fn hook(program_id: [u8; 32]) -> [u8; transfer_hook::LEN] {
        let mut p = [0u8; transfer_hook::LEN];
        p[transfer_hook::PROGRAM_ID_OFFSET..].copy_from_slice(&program_id);
        p
    }

    const MINT_ONLY: &[ExtensionType] = &[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MintCloseAuthority,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::InterestBearingConfig,
        ExtensionType::PermanentDelegate,
        ExtensionType::TransferHook,
        ExtensionType::ConfidentialTransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::TokenMetadata,
        ExtensionType::GroupPointer,
        ExtensionType::TokenGroup,
        ExtensionType::GroupMemberPointer,
        ExtensionType::TokenGroupMember,
        ExtensionType::ScaledUiAmount,
        ExtensionType::Pausable,
    ];

    const ACCOUNT_ONLY: &[ExtensionType] = &[
        ExtensionType::ImmutableOwner,
        ExtensionType::TransferFeeAmount,
        ExtensionType::TransferHookAccount,
        ExtensionType::PausableAccount,
    ];

    #[test]
    fn every_known_extension_is_mint_only_or_account_only() {
        for &kind in ExtensionType::ALL {
            let mint = MINT.allows(kind);
            let account = TokenAccountExtensionPolicy.allows(kind);
            assert!(mint ^ account, "{kind:?} must belong to exactly one policy");
            assert_eq!(mint, MINT_ONLY.contains(&kind), "{kind:?}");
            assert_eq!(account, ACCOUNT_ONLY.contains(&kind), "{kind:?}");
        }
    }

    #[test]
    fn mint_policy_rejects_account_only_extensions() {
        for &kind in ACCOUNT_ONLY {
            expect_err(
                MINT.check(kind, &[]),
                TokenExtensionError::UnsupportedTokenExtension,
            );
        }
    }

    #[test]
    fn token_account_policy_rejects_mint_only_extensions() {
        for &kind in MINT_ONLY {
            expect_err(
                TokenAccountExtensionPolicy.check(kind, &[]),
                TokenExtensionError::UnsupportedTokenExtension,
            );
        }
    }

    #[test]
    fn token_account_policy_ignores_payload_state() {
        // Withheld fees on a beneficiary account never block a credit; the
        // escrow can only accrue them while a fee is live, which the mint
        // gate already rejects.
        assert!(
            TokenAccountExtensionPolicy
                .check(ExtensionType::TransferFeeAmount, &u64::MAX.to_le_bytes())
                .is_ok()
        );
        assert!(
            TokenAccountExtensionPolicy
                .check(ExtensionType::TransferHookAccount, &[1])
                .is_ok()
        );
        assert!(
            TokenAccountExtensionPolicy
                .check(ExtensionType::PausableAccount, &[])
                .is_ok()
        );
    }

    #[test]
    fn hard_rejected_ids_are_unknown_to_the_program() {
        // Spot-check the ids the policy deliberately leaves out; they must
        // fail at `TryFrom` so no future variant can slip in without an
        // explicit decision.
        for id in [
            5u16, // ConfidentialTransferAccount
            6,    // DefaultAccountState
            8,    // MemoTransfer
            9,    // NonTransferable
            11,   // CpiGuard
            13,   // NonTransferableAccount
            17,   // ConfidentialTransferFeeAmount
            24,   // ConfidentialMintBurn
            0xFFFF,
        ] {
            match ExtensionType::try_from(id) {
                Err(TokenExtensionError::UnsupportedTokenExtension) => {}
                other => panic!("id {id}: expected UnsupportedTokenExtension, got {other:?}"),
            }
        }
    }

    #[test]
    fn transfer_fee_config_dormant_when_both_schedules_cannot_charge() {
        use transfer_fee_config::is_dormant;
        for epoch in [0, 2] {
            // PYUSD/USDG shape: 0 bps, 0 max on both schedules.
            assert!(is_dormant(&fee_config((0, 0), (0, 0)), epoch).unwrap());
            // Mirrors `calculate_fee`: either zero bps or zero max is a zero fee.
            assert!(is_dormant(&fee_config((u64::MAX, 0), (u64::MAX, 0)), epoch).unwrap());
            assert!(is_dormant(&fee_config((0, 10_000), (0, 10_000)), epoch).unwrap());
        }
    }

    #[test]
    fn transfer_fee_config_live_when_a_governing_schedule_can_charge() {
        use transfer_fee_config::is_dormant;
        // A freshly scheduled fee is live from the moment it is set.
        assert!(!is_dormant(&fee_config((0, 0), (100, 1)), 0).unwrap());
        assert!(!is_dormant(&fee_config((0, 0), (100, 1)), 2).unwrap());
        assert!(!is_dormant(&fee_config((1, 1), (1, 1)), 0).unwrap());
    }

    #[test]
    fn transfer_fee_config_reverted_fee_is_dormant_once_newer_governs() {
        use transfer_fee_config::is_dormant;
        // Issuer reverts an active fee: Token-2022 moves it to `older` and
        // schedules zero in `newer`; `older` keeps charging until epoch 2.
        let reverted = fee_config((100, 1), (0, 0));
        assert!(!is_dormant(&reverted, 0).unwrap());
        assert!(!is_dormant(&reverted, 1).unwrap());
        assert!(is_dormant(&reverted, 2).unwrap());
        assert!(is_dormant(&reverted, u64::MAX).unwrap());
    }

    #[test]
    fn transfer_fee_config_wrong_length_is_malformed() {
        for len in [
            0,
            transfer_fee_config::LEN - 1,
            transfer_fee_config::LEN + 1,
        ] {
            match transfer_fee_config::is_dormant(&vec![0u8; len], 0) {
                Err(TokenExtensionError::MalformedTokenAccountData) => {}
                other => panic!("len {len}: expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn transfer_hook_dormant_iff_no_program_installed() {
        assert!(transfer_hook::is_dormant(&hook([0u8; 32])).unwrap());
        // Authority alone does not make the hook live.
        let mut p = hook([0u8; 32]);
        p[..32].copy_from_slice(&[7u8; 32]);
        assert!(transfer_hook::is_dormant(&p).unwrap());
        let mut installed = [0u8; 32];
        installed[31] = 1;
        assert!(!transfer_hook::is_dormant(&hook(installed)).unwrap());
    }

    #[test]
    fn transfer_hook_wrong_length_is_malformed() {
        for len in [0, transfer_hook::LEN - 1, transfer_hook::LEN + 1] {
            match transfer_hook::is_dormant(&vec![0u8; len]) {
                Err(TokenExtensionError::MalformedTokenAccountData) => {}
                other => panic!("len {len}: expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn mint_policy_gates_fee_and_hook_on_state() {
        assert!(
            MINT.check(
                ExtensionType::TransferFeeConfig,
                &fee_config((0, 0), (0, 0))
            )
            .is_ok()
        );
        expect_err(
            MINT.check(
                ExtensionType::TransferFeeConfig,
                &fee_config((0, 0), (5, 25)),
            ),
            TokenExtensionError::ActiveTokenExtension,
        );
        let reverted = fee_config((5, 25), (0, 0));
        expect_err(
            MINT.check(ExtensionType::TransferFeeConfig, &reverted),
            TokenExtensionError::ActiveTokenExtension,
        );
        assert!(
            MINT_LATER
                .check(ExtensionType::TransferFeeConfig, &reverted)
                .is_ok()
        );
        assert!(
            MINT.check(ExtensionType::TransferHook, &hook([0u8; 32]))
                .is_ok()
        );
        expect_err(
            MINT.check(ExtensionType::TransferHook, &hook([9u8; 32])),
            TokenExtensionError::ActiveTokenExtension,
        );
    }

    #[test]
    fn mint_policy_does_not_inspect_trusted_or_inert_payloads() {
        // Permanent delegate set, pausable currently paused, interest rate
        // nonzero — none of these are state-gated.
        assert!(
            MINT.check(ExtensionType::PermanentDelegate, &[0xFF; 32])
                .is_ok()
        );
        assert!(
            MINT.check(
                ExtensionType::Pausable,
                &[[0xFF; 32].as_slice(), &[1]].concat()
            )
            .is_ok()
        );
        assert!(
            MINT.check(ExtensionType::InterestBearingConfig, &[0xFF; 52])
                .is_ok()
        );
        assert!(
            MINT.check(ExtensionType::MintCloseAuthority, &[0xFF; 32])
                .is_ok()
        );
    }

    #[test]
    fn scan_accepts_paxos_stablecoin_shaped_trailer() {
        // PYUSD / USDG mainnet TLV order: close authority, permanent delegate,
        // dormant fee config, confidential mint, confidential fee config,
        // dormant hook, metadata pointer, (inline metadata omitted).
        let mut bytes = Vec::new();
        bytes.extend(record(ExtensionType::MintCloseAuthority as u16, &[1u8; 32]));
        bytes.extend(record(ExtensionType::PermanentDelegate as u16, &[1u8; 32]));
        bytes.extend(record(
            ExtensionType::TransferFeeConfig as u16,
            &fee_config((0, 0), (0, 0)),
        ));
        bytes.extend(record(
            ExtensionType::ConfidentialTransferMint as u16,
            &[0u8; 65],
        ));
        bytes.extend(record(
            ExtensionType::ConfidentialTransferFeeConfig as u16,
            &[0u8; 129],
        ));
        bytes.extend(record(ExtensionType::TransferHook as u16, &hook([0u8; 32])));
        bytes.extend(record(ExtensionType::MetadataPointer as u16, &[1u8; 64]));
        assert!(scan_tlv_extensions(&MINT, &bytes).is_ok());

        // Same trailer with a live fee: rejected as active, not unsupported.
        let mut live = Vec::new();
        live.extend(record(ExtensionType::MintCloseAuthority as u16, &[1u8; 32]));
        live.extend(record(
            ExtensionType::TransferFeeConfig as u16,
            &fee_config((0, 0), (1_000, 10)),
        ));
        live.extend(record(ExtensionType::TransferHook as u16, &hook([0u8; 32])));
        expect_err(
            scan_tlv_extensions(&MINT, &live),
            TokenExtensionError::ActiveTokenExtension,
        );
    }

    #[test]
    fn scan_accepts_paxos_stablecoin_shaped_token_account_trailer() {
        // What the ATA program produces for a fee+hook mint: immutable owner,
        // zero withheld amount, `transferring = false`.
        let mut bytes = Vec::new();
        bytes.extend(record(ExtensionType::ImmutableOwner as u16, &[]));
        bytes.extend(record(ExtensionType::TransferFeeAmount as u16, &[0u8; 8]));
        bytes.extend(record(ExtensionType::TransferHookAccount as u16, &[0]));
        assert!(scan_tlv_extensions(&TokenAccountExtensionPolicy, &bytes).is_ok());
    }

    #[test]
    fn scan_rejects_state_gated_record_with_wrong_length() {
        // A fee config whose declared length is not the upstream struct size
        // is malformed, not merely unsupported: the gate cannot be evaluated.
        let bytes = record(ExtensionType::TransferFeeConfig as u16, &[0u8; 16]);
        expect_err(
            scan_tlv_extensions(&MINT, &bytes),
            TokenExtensionError::MalformedTokenAccountData,
        );
    }
}
