//! Helpers for encoding/decoding the cookie session payload format.
//!
//! This is primarily useful for testing and debugging.
//!
//! Note: the on-wire format is versioned, but it is still considered an implementation detail and
//! may evolve.

use tower_sessions_core::{session::Record, session_store};

use crate::codec;

/// Encode a session [`Record`] into the cookie value.
pub fn encode_record(record: &Record) -> session_store::Result<String> {
    codec::encode_record(record)
}

/// Decode a cookie value into a session [`Record`].
pub fn decode_record(value: &str) -> session_store::Result<Record> {
    codec::decode_record(value)
}
