//! Decode on-chain self-CPI events emitted during a transaction.
//!
//! Events are emitted as Anchor-compatible self-CPIs whose inner-instruction
//! data is `EVENT_IX_TAG_LE (8) | discriminator (8) | borsh body`. [`events`]
//! scans a [`TransactionMetadata`]'s inner instructions and decodes the body
//! straight into the generated client event struct, so a test can assert with a
//! single `assert_eq!(events::<E>(&meta), vec![expected])` against a fully-typed
//! value — count and contents in one shot.

use borsh::BorshDeserialize;
use litesvm::types::TransactionMetadata;
use payment_channels::event_engine::{
    EVENT_DISCRIMINATOR_LEN, EVENT_IX_TAG_LE, EventDiscriminator,
};
use payment_channels_client::types::{Opened, PayoutRedirected};

/// A decodable on-chain event: a generated client struct paired with the
/// program-defined Anchor discriminator that tags it on the wire. Binding the
/// discriminator to the type keeps callers from pairing the wrong two.
pub trait TestEvent: BorshDeserialize {
    const DISCRIMINATOR: [u8; 8];
}

impl TestEvent for Opened {
    const DISCRIMINATOR: [u8; 8] =
        <payment_channels::events::Opened as EventDiscriminator>::DISCRIMINATOR;
}

impl TestEvent for PayoutRedirected {
    const DISCRIMINATOR: [u8; 8] =
        <payment_channels::events::PayoutRedirected as EventDiscriminator>::DISCRIMINATOR;
}

/// Every `E` emitted as a self-CPI in `meta`, in emission order.
pub fn events<E: TestEvent>(meta: &TransactionMetadata) -> Vec<E> {
    meta.inner_instructions
        .iter()
        .flatten()
        .filter_map(|ix| {
            let data = &ix.instruction.data;
            (data.len() >= EVENT_DISCRIMINATOR_LEN
                && data.starts_with(&EVENT_IX_TAG_LE)
                && data[EVENT_IX_TAG_LE.len()..EVENT_DISCRIMINATOR_LEN] == E::DISCRIMINATOR)
                .then(|| {
                    E::try_from_slice(&data[EVENT_DISCRIMINATOR_LEN..]).expect("decode event body")
                })
        })
        .collect()
}
