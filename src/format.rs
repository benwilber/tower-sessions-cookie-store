//! Helpers for encoding/decoding the cookie session payload format.
//!
//! This is primarily useful for testing and debugging.
//!
//! Note: the on-wire format is versioned, but it is still considered an implementation detail and
//! may evolve.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tower_sessions_core::{session::Record, session_store};

const VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    v: u8,
    record: Record,
}

/// Encode a session [`Record`] into the cookie value.
pub fn encode_record(record: &Record) -> session_store::Result<String> {
    let envelope = Envelope {
        v: VERSION,
        record: record.clone(),
    };

    let bytes = serde_json::to_vec(&envelope)
        .map_err(|err| session_store::Error::Encode(err.to_string()))?;

    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Decode a cookie value into a session [`Record`].
pub fn decode_record(value: &str) -> session_store::Result<Record> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| session_store::Error::Decode(err.to_string()))?;

    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|err| session_store::Error::Decode(err.to_string()))?;

    if envelope.v != VERSION {
        return Err(session_store::Error::Decode(format!(
            "Unsupported cookie session version: {}",
            envelope.v
        )));
    }

    Ok(envelope.record)
}
