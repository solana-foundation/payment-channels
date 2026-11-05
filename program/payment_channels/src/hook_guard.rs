//! Per-callback custody checks. Only accounts supplied to the operation are protected.
use core::mem::MaybeUninit;
use payment_channel_interface::sha256;
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::{
    PaymentChannelsError,
    helpers::{MAX_DISTRIBUTION_RECIPIENTS, accounts::view::ChannelContext},
    hooks::HookContext,
};

const MAX_ACCOUNTS: usize = MAX_DISTRIBUTION_RECIPIENTS + 4;
const BASE_LEN: usize = 165;
const SNAPSHOT_CHUNK: usize = 8;

fn invariant_error() -> ProgramError {
    PaymentChannelsError::HookInvariantViolation.into()
}

fn balance_rule(escrow: bool, payer: bool, phase: usize, refund: u64) -> BalanceRule {
    if escrow {
        BalanceRule::Exact
    } else if phase == 3 && payer {
        BalanceRule::Refund(refund)
    } else {
        BalanceRule::CreditOnly
    }
}

/// The balance exception removes only the refund credited immediately before
/// this callback, including when payer and merchant/treasury roles alias.
#[derive(Clone, Copy, Debug, PartialEq)]
enum BalanceRule {
    Exact,
    CreditOnly,
    Refund(u64),
}

impl BalanceRule {
    fn check(self, before: u64, after: u64) -> ProgramResult {
        let valid = match self {
            Self::Exact => after == before,
            Self::CreditOnly => after >= before,
            Self::Refund(refund) => before.saturating_sub(after) <= refund,
        };
        valid.then_some(()).ok_or_else(invariant_error)
    }
}

#[derive(Clone)]
struct Snapshot {
    owner: [u8; 32],
    controls: [u8; 32],
    extensions: [u8; 32],
    delegate: [u8; 36],
    amount: u64,
    allowance: u64,
    lamports: u64,
    data_len: usize,
    token: bool,
    native: bool,
}

impl Snapshot {
    #[inline(never)]
    fn read(account: &AccountView, ctx: &ChannelContext<'_>) -> Result<Self, ProgramError> {
        let data = account.try_borrow()?;
        Ok(Self::from_data(
            *account.owner().as_array(),
            account.lamports(),
            &data,
            account.owned_by(ctx.token_ctx.token_program.address()),
        ))
    }

    fn from_data(owner: [u8; 32], lamports: u64, data: &[u8], token_owned: bool) -> Self {
        let token = token_owned && data.len() >= BASE_LEN && matches!(data[108], 1 | 2);
        let mut snapshot = Self {
            owner,
            controls: [0; 32],
            extensions: [0; 32],
            delegate: [0; 36],
            amount: 0,
            allowance: 0,
            lamports,
            data_len: data.len(),
            token,
            native: false,
        };
        if token {
            snapshot.amount = u64::from_le_bytes(data[64..72].try_into().unwrap());
            snapshot.native = data[109..113] == [1, 0, 0, 0];
            snapshot.allowance = u64::from_le_bytes(data[121..129].try_into().unwrap());
            snapshot.delegate.copy_from_slice(&data[72..108]);
            // COption::None ignores its payload; token implementations may
            // leave the old key bytes in place when consuming an approval.
            if snapshot.delegate[..4] == [0; 4] {
                snapshot.delegate.fill(0);
            }
            let mut base = [0; BASE_LEN];
            base.copy_from_slice(&data[..BASE_LEN]);
            base[64..108].fill(0);
            base[121..129].fill(0);
            // Preserve extensions without interpreting or rejecting inert ones.
            // Existing ATA validation owns supported Token-2022 policy.
            snapshot.controls = sha256(&base);
            snapshot.extensions = sha256(&data[BASE_LEN..]);
        } else {
            snapshot.controls = sha256(data);
        }
        snapshot
    }

    fn check(&self, after: &Self, rule: BalanceRule) -> ProgramResult {
        let invalid = invariant_error;
        if self.owner != after.owner
            || self.token != after.token
            || self.controls != after.controls
            || self.extensions != after.extensions
            || self.data_len != after.data_len
        {
            return Err(invalid());
        }
        // Wrapped-native transfers move lamports together with token units.
        // Only an authorized refund may consume those lamports, never more
        // than its net token debit. The native flag and reserve remain hashed
        // controls; rent and all non-native lamports stay protected.
        let debit = self.amount.saturating_sub(after.amount);
        let lamport_allowance = if self.native && matches!(rule, BalanceRule::Refund(_)) {
            debit
        } else {
            0
        };
        if self.lamports.saturating_sub(after.lamports) > lamport_allowance {
            return Err(invalid());
        }
        if !self.token {
            return Ok(());
        }
        rule.check(self.amount, after.amount)?;
        if self.delegate == after.delegate && self.allowance == after.allowance {
            return Ok(());
        }
        // Transfer by a delegated payer authority consumes allowance. Never
        // permit approval increases, arbitrary revocation, or replacement.
        // Matching the net debit deliberately rejects refund+donation callbacks
        // whose incoming tokens mask their delegated spending.
        if !matches!(rule, BalanceRule::Refund(_))
            || debit == 0
            || self.allowance.checked_sub(debit) != Some(after.allowance)
        {
            return Err(invalid());
        }
        if self.delegate != after.delegate && !(after.allowance == 0 && after.delegate == [0; 36]) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Snapshots are taken immediately around one enabled CPI, never around the
/// core transfers. There are at most 36 accounts. Eight snapshots per recursive
/// frame bound stack use without requiring an allocator (at most five frames).
#[derive(Default)]
pub(crate) struct ProtectedAccounts<'a> {
    pub payer: Option<&'a AccountView>,
    pub payee: Option<&'a AccountView>,
    pub treasury: Option<&'a AccountView>,
    pub recipients: &'a [AccountView],
}

#[inline(never)]
pub(crate) fn invoke(
    ctx: &ChannelContext<'_>,
    tail: &[AccountView],
    context: &HookContext,
    phase: usize,
    protected: ProtectedAccounts<'_>,
) -> ProgramResult {
    let ProtectedAccounts {
        payer,
        payee,
        treasury,
        recipients,
    } = protected;
    if !crate::ChannelWithHooks::from_account(&ctx.channel)?
        .hooks
        .descriptors[phase]
        .enabled()
    {
        return Ok(());
    }
    if recipients.len() > MAX_DISTRIBUTION_RECIPIENTS {
        return Err(ProgramError::InvalidAccountData);
    }
    let iter = core::iter::once(&*ctx.channel_token_account)
        .chain(payer)
        .chain(payee)
        .chain(treasury)
        .chain(recipients.iter());
    let mut accounts = [&*ctx.channel_token_account; MAX_ACCOUNTS];
    let count = collect_unique(&mut accounts, iter)?;
    let channel_hash = sha256(&ctx.channel.try_borrow()?);
    let channel_owner = *ctx.channel.owner();
    let channel_lamports = ctx.channel.lamports();
    check_chunk(ctx, tail, context, phase, payer, &accounts[..count])?;
    if channel_owner != *ctx.channel.owner()
        || channel_hash != sha256(&ctx.channel.try_borrow()?)
        || ctx.channel.lamports() != channel_lamports
    {
        return Err(invariant_error());
    }
    Ok(())
}

fn collect_unique<'a>(
    accounts: &mut [&'a AccountView; MAX_ACCOUNTS],
    candidates: impl Iterator<Item = &'a AccountView>,
) -> Result<usize, ProgramError> {
    let mut count = 0;
    for account in candidates {
        // One physical balance is protected once even when roles alias.
        if accounts[..count]
            .iter()
            .any(|a| a.address() == account.address())
        {
            continue;
        }
        let slot = accounts.get_mut(count).ok_or_else(invariant_error)?;
        *slot = account;
        count += 1;
    }
    Ok(count)
}

#[inline(never)]
fn check_chunk(
    ctx: &ChannelContext<'_>,
    tail: &[AccountView],
    context: &HookContext,
    phase: usize,
    payer: Option<&AccountView>,
    accounts: &[&AccountView],
) -> ProgramResult {
    let count = accounts.len().min(SNAPSHOT_CHUNK);
    let (chunk, remaining) = accounts.split_at(count);
    let mut snapshots: [MaybeUninit<Snapshot>; SNAPSHOT_CHUNK] =
        [const { MaybeUninit::uninit() }; SNAPSHOT_CHUNK];
    for (slot, account) in snapshots.iter_mut().zip(chunk) {
        slot.write(Snapshot::read(account, ctx)?);
    }
    if remaining.is_empty() {
        crate::hooks::invoke(&ctx.channel, tail, context, phase)?;
    } else {
        check_chunk(ctx, tail, context, phase, payer, remaining)?;
    }
    for (account, before) in chunk.iter().zip(&snapshots) {
        // SAFETY: exactly the `count` entries paired with `chunk` were written.
        let before = unsafe { before.assume_init_ref() };
        let rule = balance_rule(
            account.address() == ctx.channel_token_account.address(),
            payer.is_some_and(|p| p.address() == account.address()),
            phase,
            context.refund_transferred_to_payer,
        );
        let after = Snapshot::read(account, ctx).map_err(|_| invariant_error())?;
        before.check(&after, rule)?;
        if matches!(rule, BalanceRule::Exact) {
            crate::hooks::revalidate(ctx, None, before.amount).map_err(|_| invariant_error())?;
        }
    }
    Ok(())
}

const _: () = {
    assert!(MAX_ACCOUNTS == 36);
    assert!(MAX_ACCOUNTS.div_ceil(SNAPSHOT_CHUNK) == 5);
    assert!(core::mem::size_of::<Snapshot>() * SNAPSHOT_CHUNK <= 2048);
};

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn data(amount: u64, allowance: u64) -> [u8; BASE_LEN] {
        let mut data = [0; BASE_LEN];
        data[..64].fill(3);
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        data[72] = 1;
        data[76..108].fill(5);
        data[108] = 1;
        data[121..129].copy_from_slice(&allowance.to_le_bytes());
        data
    }

    fn snapshot(data: &[u8]) -> Snapshot {
        Snapshot::from_data([1; 32], 100, data, true)
    }

    #[test]
    fn account_collection_deduplicates_aliases_and_bounds_maximum() {
        let mut raw: [pinocchio::account::RuntimeAccount; MAX_ACCOUNTS + 1] =
            core::array::from_fn(|i| pinocchio::account::RuntimeAccount {
                address: pinocchio::Address::new_from_array([i as u8; 32]),
                ..Default::default()
            });
        let views: Vec<_> = raw
            .iter_mut()
            .map(|account| {
                // SAFETY: raw stays live and unmoved; every data_len is zero.
                unsafe { AccountView::new_unchecked(account) }
            })
            .collect();
        for count in 1..=MAX_ACCOUNTS {
            let mut accounts = [&views[0]; MAX_ACCOUNTS];
            let unique = collect_unique(
                &mut accounts,
                views[..count].iter().chain(views[..count].iter()),
            )
            .unwrap();
            assert_eq!(unique, count);
            for (actual, expected) in accounts[..unique].iter().zip(&views[..count]) {
                assert_eq!(actual.address(), expected.address());
            }
            assert!(unique.div_ceil(SNAPSHOT_CHUNK) <= 5);
        }
        let mut accounts = [&views[0]; MAX_ACCOUNTS];
        assert_eq!(
            collect_unique(&mut accounts, views.iter()),
            Err(invariant_error()),
        );
        // Payer, payee and treasury can all name one physical account.
        assert_eq!(
            collect_unique(
                &mut accounts,
                [&views[0], &views[1], &views[1], &views[1]].into_iter()
            ),
            Ok(2),
        );
    }

    #[test]
    fn balance_boundaries_do_not_overflow_or_spend_prior_funds() {
        let values = [0, 1, 2, 99, 100, 101, u64::MAX - 1, u64::MAX];
        for before in values {
            for after in values {
                assert_eq!(
                    BalanceRule::Exact.check(before, after).is_ok(),
                    before == after
                );
                assert_eq!(
                    BalanceRule::CreditOnly.check(before, after).is_ok(),
                    after >= before
                );
                for refund in values {
                    let allowed = u128::from(after) + u128::from(refund) >= u128::from(before);
                    assert_eq!(
                        BalanceRule::Refund(refund).check(before, after).is_ok(),
                        allowed
                    );
                }
            }
        }
    }

    #[test]
    fn only_post_distribution_payer_gets_refund_and_escrow_wins_aliases() {
        for phase in 0..4 {
            for payer in [false, true] {
                for escrow in [false, true] {
                    for refund in [0, 1, u64::MAX] {
                        let rule = balance_rule(escrow, payer, phase, refund);
                        let expected = if escrow {
                            BalanceRule::Exact
                        } else if payer && phase == 3 {
                            BalanceRule::Refund(refund)
                        } else {
                            BalanceRule::CreditOnly
                        };
                        assert_eq!(rule, expected);
                    }
                }
            }
        }
        // Shared payer/payee/treasury balance: preserve original principal plus
        // merchant payout, removing only the 20 refund credited by the core.
        assert!(balance_rule(false, true, 3, 20).check(150, 130).is_ok());
        assert!(balance_rule(false, true, 3, 20).check(150, 129).is_err());
    }

    #[test]
    fn every_base_control_byte_is_protected() {
        let bytes = data(100, 50);
        let before = snapshot(&bytes);
        for offset in 0..BASE_LEN {
            if (64..72).contains(&offset) || (121..129).contains(&offset) {
                continue;
            }
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert_eq!(
                before.check(&snapshot(&changed), BalanceRule::CreditOnly),
                Err(invariant_error()),
                "offset {offset}",
            );
        }
    }

    #[test]
    fn delegated_refund_allowance_boundary_table() {
        for allowance in [0, 1, 5, 10, 100, u64::MAX] {
            let before = snapshot(&data(100, allowance));
            for debit in [0, 1, 5, 10, 100] {
                for refund in [0, 1, 5, 10, 100] {
                    for after_allowance in [0, 1, 5, 10, 100, u64::MAX] {
                        for delegate in [0, 1, 2] {
                            let mut after_data = data(100 - debit, after_allowance);
                            match delegate {
                                0 => after_data[72..108].fill(0),
                                2 => after_data[76..108].fill(9),
                                _ => {}
                            }
                            let unchanged = delegate == 1 && allowance == after_allowance;
                            let consumed = debit > 0
                                && allowance.checked_sub(debit) == Some(after_allowance)
                                && (delegate == 1 || (delegate == 0 && after_allowance == 0));
                            let expected = debit <= refund && (unchanged || consumed);
                            assert_eq!(
                                before
                                    .check(&snapshot(&after_data), BalanceRule::Refund(refund))
                                    .is_ok(),
                                expected,
                                "allowance={allowance} after={after_allowance} debit={debit} refund={refund} delegate={delegate}",
                            );
                            assert_eq!(
                                before
                                    .check(&snapshot(&after_data), BalanceRule::CreditOnly)
                                    .is_ok(),
                                debit == 0 && unchanged,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exhausted_delegate_coption_payload_is_not_authority() {
        let before = snapshot(&data(100, 20));
        let mut after = data(80, 0);
        after[72..76].fill(0);
        assert!(
            before
                .check(&snapshot(&after), BalanceRule::Refund(20))
                .is_ok()
        );
        after[72] = 1;
        after[76] ^= 1;
        assert!(
            before
                .check(&snapshot(&after), BalanceRule::Refund(20))
                .is_err()
        );
    }

    #[test]
    fn native_refund_lamports_are_bounded_by_net_token_debit() {
        for native in [false, true] {
            let mut bytes = data(100, 100);
            if native {
                bytes[109] = 1;
                bytes[113..121].copy_from_slice(&100_u64.to_le_bytes());
            }
            let before = Snapshot::from_data([1; 32], 200, &bytes, true);
            assert_eq!(before.native, native);
            for debit in [0_u64, 1, 20, 100] {
                for lamport_debit in [0, 1, 20, 100, 101, 200] {
                    for refund in [0, 1, 20, 100] {
                        let mut changed = bytes;
                        changed[64..72].copy_from_slice(&(100 - debit).to_le_bytes());
                        changed[121..129].copy_from_slice(&(100 - debit).to_le_bytes());
                        let after =
                            Snapshot::from_data([1; 32], 200 - lamport_debit, &changed, true);
                        let expected = debit <= refund
                            && (lamport_debit == 0 || (native && lamport_debit <= debit));
                        assert_eq!(
                            before.check(&after, BalanceRule::Refund(refund)).is_ok(),
                            expected,
                            "native={native} debit={debit} lamports={lamport_debit} refund={refund}",
                        );
                        for rule in [BalanceRule::Exact, BalanceRule::CreditOnly] {
                            assert_eq!(
                                before.check(&after, rule).is_ok(),
                                debit == 0 && lamport_debit == 0,
                            );
                        }
                    }
                }
            }
            // Even when lamport/token deltas match, changing the native
            // designation or rent reserve is not part of a refund.
            for offset in 109..121 {
                let mut changed = bytes;
                changed[offset] ^= 1;
                let after = Snapshot::from_data([1; 32], 200, &changed, true);
                assert!(before.check(&after, BalanceRule::Refund(100)).is_err());
            }
        }
    }

    #[test]
    fn owner_rent_layout_and_token_classification_are_protected() {
        let before = snapshot(&data(100, 20));
        let mut after = before.clone();
        after.owner[0] ^= 1;
        assert!(before.check(&after, BalanceRule::CreditOnly).is_err());
        after = before.clone();
        after.lamports -= 1;
        assert!(before.check(&after, BalanceRule::CreditOnly).is_err());
        after = before.clone();
        after.lamports += 1;
        assert!(before.check(&after, BalanceRule::CreditOnly).is_ok());
        after = before.clone();
        after.data_len += 1;
        assert!(before.check(&after, BalanceRule::CreditOnly).is_err());
        after = before.clone();
        after.token = false;
        assert!(before.check(&after, BalanceRule::CreditOnly).is_err());
    }

    #[test]
    fn inert_extensions_are_accepted_but_cannot_change() {
        let mut bytes = Vec::from(data(100, 0));
        bytes.extend_from_slice(&[2, 7, 0, 0, 0, 0, 0, 0]);
        let before = snapshot(&bytes);
        assert!(
            before
                .check(&snapshot(&bytes), BalanceRule::CreditOnly)
                .is_ok()
        );
        for offset in BASE_LEN..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                before
                    .check(&snapshot(&changed), BalanceRule::CreditOnly)
                    .is_err()
            );
        }
    }

    #[test]
    fn poisoned_beneficiaries_preserve_redirect_without_becoming_mutable() {
        for len in 0..BASE_LEN {
            let bytes = alloc::vec![0; len];
            let before = snapshot(&bytes);
            assert!(!before.token);
            assert!(
                before
                    .check(&snapshot(&bytes), BalanceRule::CreditOnly)
                    .is_ok()
            );
            let mut changed = bytes;
            changed.push(1);
            assert!(
                before
                    .check(&snapshot(&changed), BalanceRule::CreditOnly)
                    .is_err()
            );
        }
        let frozen = {
            let mut bytes = data(100, 0);
            bytes[108] = 2;
            bytes
        };
        assert!(
            snapshot(&frozen)
                .check(&snapshot(&frozen), BalanceRule::CreditOnly)
                .is_ok()
        );
    }
}
