# tower-sessions-cookie-store

Cookie-backed session persistence for [`tower-sessions`](https://crates.io/crates/tower-sessions).

This crate provides `CookieSessionManagerLayer`, a Tower layer for cookie-backed sessions. It
integrates with `tower-sessions` and works with Axum extractors.

## Features

- `signed` (default): integrity-protected cookies (tamper-evident). Cookie contents are readable by
  the client.
- `private`: encrypted + authenticated cookies (confidentiality + integrity).
- `dangerous-plaintext`: plaintext cookies (no integrity, no confidentiality). Intended only for
  testing/debugging.

## Security notes

- Cookie sessions are bearer tokens. If a cookie is stolen, it can be replayed until it expires.
- The `dangerous-plaintext` feature offers **no tamper resistance**. A client can trivially edit
  the cookie to escalate privileges and impersonate other users (including staff/admin). Do not
  enable or use it in real applications.

## Usage (Axum)

### Signed cookies (default)

```rust
use axum::{routing::get, Router};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};

async fn handler(session: Session) -> String {
    let n: usize = session.get("n").await.expect("session get succeeds").unwrap_or(0);
    session.insert("n", n + 1).await.expect("session insert succeeds");
    format!("n={n}")
}

let key = Key::generate();
let config = CookieSessionConfig::default()
    .with_secure(false); // set true in production (HTTPS)
let app = Router::new()
    .route("/", get(handler))
    .layer(CookieSessionManagerLayer::signed(key).with_config(config));
```

### Private cookies (encrypted)

```rust
use axum::{routing::get, Router};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key};

let key = Key::generate();
let config = CookieSessionConfig::default();
let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(CookieSessionManagerLayer::private(key).with_config(config));
```

### Dangerous plaintext cookies (testing/debugging only)

```rust
use axum::{routing::get, Router};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer};

let config = CookieSessionConfig::default().with_secure(false);
let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(CookieSessionManagerLayer::dangerous_plaintext().with_config(config));
```

## Configuration

`CookieSessionConfig` controls cookie attributes and session persistence behavior:

- `name` (default: `"session"`)
- `http_only` (default: `true`)
- `same_site` (default: `SameSite::Strict`)
- `secure` (default: `true`)
- `path` (default: `"/"`)
- `domain` (default: none)
- `expiry` (default: none)
  - `Expiry::OnSessionEnd`: no `Max-Age` is set
  - `Expiry::OnInactivity(d)`: `Max-Age` is set from the record expiry (sliding when saved)
  - `Expiry::AtDateTime(t)`: `Max-Age` is set from the record expiry (absolute unless changed)
- `always_save` (default: `false`): when `true`, refreshes cookie/expiry on every request even if
  the session is not modified
- `max_cookie_bytes` (default: `4096`): maximum encoded cookie value size
- `clear_on_decode_error` (default: `true`): clears invalid/expired/undecodable cookies

## Cookie format

The cookie value encodes the full session record using a versioned, base64url-encoded JSON
envelope. The format is an implementation detail and may change between releases.

For testing/debugging, the crate exposes `tower_sessions_cookie_store::format::{encode_record,
decode_record}`.

## Re-exports

This crate re-exports commonly used types to avoid requiring direct dependency alignment:

- `tower_sessions_cookie_store::Session`
- `tower_sessions_cookie_store::Expiry`
- `tower_sessions_cookie_store::SameSite`
- `tower_sessions_cookie_store::Key` (when `signed` and/or `private` are enabled)
- `tower_sessions_cookie_store::session_store` (including `session_store::Error`)

## License

MIT. See `LICENSE`.
