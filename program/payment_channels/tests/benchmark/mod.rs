//! Parameterized CU benchmark harness for `payment_channels`.
//!
//! Gated on `BENCH=1`. Each scenario in [`scenarios`] is a `#[test]` that
//! drives one focal instruction along its canonical happy path and calls
//! [`record`] with a display label like `distribute[n=16,tok=t22,open]`.
//! On process exit, a `#[ctor::dtor]` writes `bench_report.md` next to
//! `Cargo.toml` with one row per scenario (CUs + estimated SOL cost at
//! three priority-fee rates), sorted lexicographically by label.
//!
//! CU in LiteSVM is deterministic for the same accounts + ix-data, so a
//! single run per scenario is enough.

pub mod fixtures;
mod scenarios;

use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use litesvm::LiteSVM;
use litesvm::types::TransactionResult;
use solana_transaction::Transaction;
use tabled::{Table, Tabled, settings::Style};

static SAMPLES: OnceLock<Mutex<Vec<(String, u64)>>> = OnceLock::new();

fn is_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("BENCH").is_ok())
}

fn samples() -> &'static Mutex<Vec<(String, u64)>> {
    SAMPLES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Send `tx` and, when `BENCH=1`, record `(label, CU)` for the focal
/// scenario. Failures drop the sample — `compute_units_consumed` on an
/// aborted tx is not a useful number.
#[allow(clippy::result_large_err)]
pub fn record(svm: &mut LiteSVM, tx: Transaction, label: impl Into<String>) -> TransactionResult {
    if !is_enabled() {
        return svm.send_transaction(tx);
    }
    let res = svm.send_transaction(tx);
    if let Ok(meta) = res.as_ref()
        && let Ok(mut v) = samples().lock()
    {
        v.push((label.into(), meta.compute_units_consumed));
    }
    res
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

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Scenario")]
    scenario: String,
    #[tabled(rename = "CUs")]
    cus: u64,
    #[tabled(rename = "Est Cost (Low) [SOL]")]
    cost_low: String,
    #[tabled(rename = "Est Cost (Med) [SOL]")]
    cost_med: String,
    #[tabled(rename = "Est Cost (High) [SOL]")]
    cost_high: String,
}

fn write_report() -> std::io::Result<()> {
    let v = samples()
        .lock()
        .map_err(|_| std::io::Error::other("bench samples mutex poisoned"))?;
    if v.is_empty() {
        return Ok(());
    }
    let report_date = std::env::var("BENCH_DATE").unwrap_or_default();

    let mut rows: Vec<Row> = v
        .iter()
        .map(|(label, cu)| Row {
            scenario: label.clone(),
            cus: *cu,
            cost_low: format!("{:.9}", sol_cost(*cu, RATE_LOW)),
            cost_med: format!("{:.9}", sol_cost(*cu, RATE_MED)),
            cost_high: format!("{:.9}", sol_cost(*cu, RATE_HIGH)),
        })
        .collect();
    // Labels are crafted (zero-padded numerics) so lexicographic order
    // groups by instruction and ascends by parameter — see `scenarios.rs`.
    rows.sort_by(|a, b| a.scenario.cmp(&b.scenario));

    let table = Table::new(&rows).with(Style::markdown()).to_string();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/bench_report.md");
    let mut f = File::create(&path)?;
    writeln!(f, "# CU Benchmark Report")?;
    writeln!(f)?;
    writeln!(f, "{table}")?;
    if !report_date.is_empty() {
        writeln!(f)?;
        writeln!(f, "*Generated: {report_date}*")?;
    }
    eprintln!("benchmark: wrote {path}");
    Ok(())
}

#[ctor::dtor]
fn flush() {
    if !is_enabled() {
        return;
    }
    if let Err(e) = write_report() {
        eprintln!("benchmark: failed to write report: {e}");
    }
}
