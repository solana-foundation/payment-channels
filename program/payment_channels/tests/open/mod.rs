//! `open` instruction test suite. Helpers live in `tests/common/open.rs`
//! so other suites can reuse them without compiling our `#[test]` fns into
//! their binary.

mod accounts;
mod bounds;
mod distribution;
mod e2e;

pub(super) use crate::common::open::{
    ATA_PROGRAM, EVENT_AUTHORITY, SPL_TOKEN, SYSTEM_PROGRAM, SYSVAR_RENT, TOKEN_2022, derive_pdas,
    derive_pdas_with_token_program, load_mollusk, open_ix, open_ix_data,
    open_ix_with_token_program, run_open, setup_funded_svm, setup_funded_svm_with_token_program,
};
