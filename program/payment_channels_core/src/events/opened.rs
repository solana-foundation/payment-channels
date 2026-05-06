use borsh::BorshSerialize;
#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::Address;

use crate::event_engine::{EventDiscriminator, EventSerialize};

#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct Opened {
    pub channel: Address,
}

impl EventDiscriminator for Opened {
    const DISCRIMINATOR: [u8; 8] = crate::anchor_event_disc!("Opened");
}

impl EventSerialize for Opened {
    const DATA_LEN: usize = 32;
}
