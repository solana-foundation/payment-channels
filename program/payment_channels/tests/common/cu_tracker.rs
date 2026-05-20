//! Compute-unit profiler for LiteSVM tests.
//!
//! Gated on `CU_REPORT=1`. The aggregate test binary's `#[ctor::dtor]` writes
//! a single `cu_report.md` next to `Cargo.toml` on process exit.
//!
//! Use [`send_and_record`] at every site that builds and sends a
//! `Transaction`. The helper sends, then — only when `CU_REPORT=1` — derives
//! the instruction label from the program's
//! [`PaymentChannelsInstruction`] enum, so report labels track the on-chain
//! dispatch table without a parallel mapping in test code.
//!
//! ```ignore
//! let tx = Transaction::new_signed_with_payer(&[ix], ...);
//! cu_tracker::send_and_record(&mut svm, tx).expect("ok");
//! ```

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use litesvm::LiteSVM;
use litesvm::types::TransactionResult;
use payment_channels::PaymentChannelsInstruction;
use solana_transaction::Transaction;
use solana_transaction::versioned::VersionedTransaction;
use tabled::{Table, Tabled, settings::Style};

const PROGRAM_ID_BYTES: [u8; 32] = *payment_channels::ID.as_array();

static TRACKER: OnceLock<Mutex<CuTracker>> = OnceLock::new();

fn is_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("CU_REPORT").is_ok())
}

fn tracker() -> &'static Mutex<CuTracker> {
    TRACKER.get_or_init(|| Mutex::new(CuTracker::default()))
}

/// Send the tx and, when `CU_REPORT=1`, record the program's outer-ix CU
/// against its [`PaymentChannelsInstruction::name`] label. Failures are
/// dropped — `compute_units_consumed` on an aborted tx isn't a useful
/// sample.
///
/// The `tx` is consumed by `send_transaction`; we extract the label first so
/// no clone is needed even when tracking is enabled.
#[allow(clippy::result_large_err)]
pub fn send_and_record(svm: &mut LiteSVM, tx: Transaction) -> TransactionResult {
    send_versioned_and_record(svm, tx.into())
}

/// Versioned-transaction variant of [`send_and_record`].
#[allow(clippy::result_large_err)]
pub fn send_versioned_and_record(svm: &mut LiteSVM, tx: VersionedTransaction) -> TransactionResult {
    if !is_enabled() {
        return svm.send_transaction(tx);
    }
    let label = first_program_ix_label_versioned(&tx);
    let res = svm.send_transaction(tx);
    if let (Some(l), Ok(meta)) = (label, res.as_ref())
        && let Ok(mut t) = tracker().lock()
    {
        t.samples
            .entry(l)
            .or_default()
            .push(meta.compute_units_consumed);
    }
    res
}

/// Walk the tx's compiled instructions, find the first one targeting our
/// program, and route its data through the program's instruction enum to
/// derive the report label. Returns `None` if the tx has no payment-channels
/// ix or its data fails to parse.
fn first_program_ix_label_versioned(tx: &VersionedTransaction) -> Option<&'static str> {
    let keys = tx.message.static_account_keys();
    tx.message.instructions().iter().find_map(|ci| {
        let prog = keys.get(ci.program_id_index as usize)?;
        if prog.to_bytes() != PROGRAM_ID_BYTES {
            return None;
        }
        PaymentChannelsInstruction::from_bytes(&ci.data)
            .ok()
            .map(|i| i.name())
    })
}

const BASE_FEE_LAMPORTS: u64 = 5_000;
const MICRO_LAMPORTS_PER_LAMPORT: u64 = 1_000_000;
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;
const RATE_LOW: u64 = 300;
const RATE_MED: u64 = 40_000;
const RATE_HIGH: u64 = 500_000;

fn sol_cost(cu: u64, rate: u64) -> f64 {
    let priority_micro = cu.saturating_mul(rate);
    let priority_lamports = priority_micro / MICRO_LAMPORTS_PER_LAMPORT;
    let total_lamports = BASE_FEE_LAMPORTS + priority_lamports;
    total_lamports as f64 / LAMPORTS_PER_SOL
}

#[derive(Default)]
struct CuTracker {
    samples: HashMap<&'static str, Vec<u64>>,
}

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Instruction")]
    instruction: &'static str,
    #[tabled(rename = "Samples")]
    samples: usize,
    #[tabled(rename = "Min CUs")]
    min: u64,
    #[tabled(rename = "Max CUs")]
    max: u64,
    #[tabled(rename = "Avg CUs")]
    avg: u64,
    #[tabled(rename = "Est Cost (Low) [SOL]")]
    cost_low: String,
    #[tabled(rename = "Est Cost (Med) [SOL]")]
    cost_med: String,
    #[tabled(rename = "Est Cost (High) [SOL]")]
    cost_high: String,
}

fn write_report() -> std::io::Result<()> {
    let t = tracker()
        .lock()
        .map_err(|_| std::io::Error::other("tracker mutex poisoned"))?;
    if t.samples.is_empty() {
        return Ok(());
    }
    let report_date = std::env::var("CU_REPORT_DATE").unwrap_or_default();

    let mut rows: Vec<Row> = t
        .samples
        .iter()
        .map(|(label, cus)| {
            let count = cus.len();
            let min = *cus.iter().min().unwrap_or(&0);
            let max = *cus.iter().max().unwrap_or(&0);
            let sum: u64 = cus.iter().sum();
            let avg = if count > 0 { sum / count as u64 } else { 0 };
            Row {
                instruction: label,
                samples: count,
                min,
                max,
                avg,
                cost_low: format!("{:.9}", sol_cost(avg, RATE_LOW)),
                cost_med: format!("{:.9}", sol_cost(avg, RATE_MED)),
                cost_high: format!("{:.9}", sol_cost(avg, RATE_HIGH)),
            }
        })
        .collect();
    rows.sort_by_key(|r| r.instruction);

    let table = Table::new(&rows).with(Style::markdown()).to_string();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/cu_report.md");
    let mut f = File::create(&path)?;
    writeln!(f, "# Compute Unit Report")?;
    writeln!(f)?;
    writeln!(f, "{table}")?;
    if !report_date.is_empty() {
        writeln!(f)?;
        writeln!(f, "*Generated: {report_date}*")?;
    }
    eprintln!("cu_tracker: wrote {path}");
    Ok(())
}

#[ctor::dtor]
fn flush() {
    if !is_enabled() {
        return;
    }
    if let Err(e) = write_report() {
        eprintln!("cu_tracker: failed to write report: {e}");
    }
}
