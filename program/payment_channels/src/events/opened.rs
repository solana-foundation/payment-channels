use borsh::BorshSerialize;
#[cfg(feature = "idl")]
use codama::CodamaEvent;
use pinocchio::Address;

use crate::event_engine::{EventDiscriminator, EventSerialize};

#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "idl", derive(CodamaEvent))]
#[cfg_attr(feature = "idl", codama(discriminator(bytes = "a6ac61094d4cbd6d")))]
pub struct Opened {
    pub channel: Address,
    /// The channel's per-incarnation epoch (client-supplied, window-validated
    /// at `open`). Surfaced so voucher issuers and indexers get the epoch
    /// without an extra account fetch. Appended last so prefix-readers of the
    /// original 32-byte payload keep working.
    pub open_slot: u64,
}

impl EventDiscriminator for Opened {
    const DISCRIMINATOR: [u8; 8] = crate::anchor_event_disc!("Opened");
}

impl EventSerialize for Opened {
    const DATA_LEN: usize = 40;
}
