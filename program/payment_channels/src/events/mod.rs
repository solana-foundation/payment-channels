//! On-chain events emitted via Anchor-compatible self-CPI.

pub mod opened;
pub mod payout_redirected;
pub use opened::Opened;
pub use payout_redirected::PayoutRedirected;
