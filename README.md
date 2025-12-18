# tower-sessions-cookie-store

[![crates.io](https://img.shields.io/crates/v/tower-sessions-cookie-store.svg)](https://crates.io/crates/tower-sessions-cookie-store)
[![docs.rs](https://docs.rs/tower-sessions-cookie-store/badge.svg)](https://docs.rs/tower-sessions-cookie-store)

Cookie-backed session persistence for [`tower-sessions`](https://crates.io/crates/tower-sessions).

This crate provides `CookieSessionManagerLayer`, a Tower layer for cookie-backed sessions. It
integrates with `tower-sessions` and works with Axum extractors.

## Install

```bash
cargo add tower-sessions-cookie-store
```

## Features

- `signed` (default): integrity-protected cookies (tamper-evident). Cookie contents are readable by
  the client. Provided by [`cookie`](https://crates.io/crates/cookie).
- `private`: encrypted + authenticated cookies (confidentiality + integrity). Provided by
  [`cookie`](https://crates.io/crates/cookie).
- `key-expansion`: enables `Key::derive_from()` for deriving a cookie `Key` from a 32-byte master
  key. Requires `signed` and/or `private`. Provided by
  [`cookie`](https://crates.io/crates/cookie).
- `dangerous-plaintext`: plaintext cookies (no integrity, no confidentiality). Intended only for
  testing/debugging.

## Usage (Axum)

For more usage examples, see the [`examples/`](examples/) directory.

### Signed cookies (default)

```rust
use axum::{routing::get, Router};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};

async fn handler(session: Session) -> String {
    let n: usize = session.get("n").await.expect("session get succeeds").unwrap_or(0);
    session.insert("n", n + 1).await.expect("session insert succeeds");
    format!("n={n}")
}

let secret_key = Key::generate(); // store this someplace safe
let config = CookieSessionConfig::default()
    .with_secure(false); // set true in production (HTTPS)
let router = Router::new()
    .route("/", get(handler))
    .layer(CookieSessionManagerLayer::signed(secret_key).with_config(config));
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
  - `Expiry::OnInactivity(d)`: expiration is computed from the last time the session was modified
    (reads do not count). If you need sliding expiry on every request, set `always_save = true`.
  - `Expiry::AtDateTime(t)`: `Max-Age` is set from the record expiry (absolute unless changed)
- `always_save` (default: `false`): when `true`, refreshes cookie/expiry on every request even if
  the session is not modified
- `max_cookie_bytes` (default: `4096`): maximum encoded cookie value size
- `clear_on_decode_error` (default: `true`): clears invalid/expired/undecodable cookies

## Behavior notes

- Saves happen after your handler returns. If encoding the cookie fails (e.g., the encoded session
  exceeds `max_cookie_bytes`), the layer responds with `500` and does not emit `Set-Cookie`.
- When `clear_on_decode_error` is `true`, a bad/expired/undecodable incoming cookie is actively
  cleared so the client stops sending it.

## Cookie format

The cookie value encodes the full session record using a versioned, base64url-encoded JSON
envelope. The format is an implementation detail and may change between releases.

For testing/debugging, the crate exposes `tower_sessions_cookie_store::{encode_record,
decode_record}`.

## Benefits of cookie-backed session storage

- Stateless: no server-side session store to operate.
- No per-request database/network I/O to load session state.
- No backend database/table/indexes/migrations needed for session storage.

## Security notes

- Cookie sessions are bearer tokens. If a cookie is stolen, it can be replayed until it expires.
- Unlike server-side session stores (e.g. Redis), cookie-backed sessions have no server-side state
  to revoke. Any previously issued cookie remains valid until it expires, even if the application
  later rotates the session ID, updates session data, or "logs out" the user by clearing the cookie
  (the client will stop sending it, but an attacker holding a copy can still replay it until
  expiry).
- The `dangerous-plaintext` feature offers **no tamper resistance**. A client can trivially edit
  the cookie to escalate privileges and impersonate other users (including staff/admin). Do not
  enable or use it in real applications.

## FAQ

- How can I log everyone out at once?
  - Rotate the signing/encryption key. All existing cookies will fail verification and be rejected.
- How can I revoke one user’s session?
  - You can’t centrally revoke a single cookie-only session. One option: store a version/token on
    the user record and also in the session; reject the session when they don’t match and force the
    client to reauthenticate. See the security notes above.
- Why did I get a 500 when saving a session?
  - The encoded cookie likely exceeded `max_cookie_bytes` (default 4096) or failed to
    encode/verify; the layer returns 500 and does not set a cookie.
- Can I store large objects or lots of data?
  - No. Cookies are limited (~4 KB by default). Use a server-side store if you need larger
    payloads.
- Can I use this cross-site?
  - Set `SameSite::None` and `secure = true` (required by browsers).  It is very unlikely that you actually want to do this.  Use caution.
- Do I need HTTPS in production?
  - Yes; leave `secure = true` so browsers only send the cookie over HTTPS. Only disable it locally
    for development.
- Can I allow JavaScript to read my session cookies?
  - Strongly discouraged. Disabling HttpOnly (via `config.with_http_only(false)`) lets any
    injected script read and exfiltrate the bearer token, enabling replay. Only do this if you have
    a very specific, XSS-hardened reason.

## License

MIT. See `LICENSE`.
