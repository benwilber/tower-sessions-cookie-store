# Plan: Cookie-Backed Session Store for `tower-sessions`

## Goal

Build a session “store” that keeps the entire session record (ID, expiry, key/value data) inside an HTTP cookie, optionally **signed** (integrity) and/or **encrypted** (confidentiality), while keeping the handler-facing API the same (`tower_sessions::Session`).

## Development approach (test-first)

We will develop this crate by first establishing a baseline of behavior using `tower-sessions`’ built-in `MemoryStore`, then methodically swapping out the backing implementation for the cookie-backed store.

- Start with integration-style tests that exercise `Session` behavior through an `axum::Router` (cookie set, persistence across requests, cookie removal on flush).
- Implement the cookie-backed layer/service.
- Update the same tests to use `CookieSessionManagerLayer` instead of `SessionManagerLayer<MemoryStore>`, keeping test logic as stable as possible.

### Test conventions
- Do not use `.unwrap()` in tests; always use `.expect("…")`.
- `expect` messages should describe what we expect to happen (e.g. “response sets a session cookie”), not what went wrong or instructions.

## Key Constraint (Drivable Design Decision)

`tower_sessions_core::SessionStore` has no access to the request/response cookie jar, so a “cookie store” cannot be implemented as a standalone `SessionStore` that you plug into `tower_sessions::SessionManagerLayer`.

To persist session data into cookies, we will implement a **new middleware layer/service** (similar to `SessionManagerLayer`) that:

- Parses the incoming cookie value into a `tower_sessions_core::session::Record` (if present).
- Constructs a per-request `Session` whose `store` implementation can read/write that cookie via `tower_cookies::Cookies`.
- On the way out, persists modifications by calling `session.save()` (so cookie writes happen even if handlers don’t explicitly call `save()`).

This keeps compatibility with `Session` as an extension/extractor, but requires a dedicated layer (e.g. `CookieSessionManagerLayer`) provided by this crate.

## Scope

### In scope
- A cookie-backed session implementation supporting:
  - Plaintext (debug/dev only).
  - Signed cookies (tamper-evident).
  - Encrypted cookies (private).
- Configurable cookie attributes: name, path, domain, `SameSite`, `HttpOnly`, `Secure`, expiry semantics aligned with `tower-sessions` (`Expiry`).
- Robust decoding behavior: malformed/oversized/expired cookies handled safely.
- Tests covering round-trips and edge cases.
- Documentation + examples for Axum usage.

### Out of scope (initially)
- Server-side session invalidation lists / global logout.
- Transparent key rotation with multiple active keys (can be a follow-up).
- Chunking large sessions across multiple cookies (optional follow-up; see “Size”).

## Architecture

### Public API (proposed)
- `CookieSessionManagerLayer<C = PlaintextCookie>`: a `tower::Layer` that provides `tower_sessions::Session` via request extensions/extractors, persisted to a cookie.
  - Wraps `tower_cookies::CookieManager` internally so applications don’t have to add it separately.
  - Reads and writes *one cookie* (by default) whose value encodes the full session record.
- `CookieSessionConfig`: cookie attribute configuration + session semantics.
  - Cookie attributes: `name`, `path`, `domain`, `same_site`, `secure`, `http_only`.
  - Session semantics: `expiry`, `always_save`.
  - Limits/policy: `max_cookie_bytes` (and optionally a “clear on decode error” toggle).
- Cookie controllers (same conceptual naming as `tower-sessions` uses internally):
  - `PlaintextCookie`: stores the cookie value as-is.
  - `SignedCookie { key: tower_cookies::Key }`: tamper-evident cookie value (feature-gated).
  - `PrivateCookie { key: tower_cookies::Key }`: encrypted + authenticated cookie value (feature-gated).
- `CookieController` (trait): abstracts “get/add/remove cookie by name” over `tower_cookies::Cookies` and signed/private jars.
- `CookieStore` (internal): a per-request `tower_sessions_core::SessionStore` implementation that performs cookie I/O.
  - `load(id)`: returns the decoded record (if present, valid, and unexpired).
  - `create(record)`: writes a new cookie value from the record (and may adjust `record.id` if needed).
  - `save(record)`: writes updated cookie value.
  - `delete(id)`: removes the cookie.

### Planned crate layout (modules)
- `config`: `CookieSessionConfig` + builder-style `with_*` methods.
- `controller`: `CookieController`, `PlaintextCookie`, `SignedCookie`, `PrivateCookie`.
- `codec`: `encode_record` / `decode_record` (versioned payload).
- `layer` / `service`: `CookieSessionManagerLayer` and the `Service` implementation.
- `error`: decode/encode/size errors mapped into `tower_sessions_core::session_store::Error`.

### Planned type documentation (Rustdoc-style summaries)
- `CookieSessionManagerLayer<C>`
  - “A Tower layer that stores `tower_sessions::Session` state in an HTTP cookie.”
  - “Inserts `Session` into request extensions so `Session` can be used as an Axum extractor.”
  - “Persists changes after the inner service returns (mirrors `tower_sessions::SessionManagerLayer` behavior).”
- `CookieSessionConfig`
  - “Cookie attributes + session persistence behavior.”
  - “Defaults are conservative (`Secure`, `HttpOnly`, `SameSite::Strict`, path `/`).”
  - “`max_cookie_bytes` prevents oversized cookie writes.”
- `PlaintextCookie` / `SignedCookie` / `PrivateCookie`
  - “Selects how the cookie value is stored (plaintext / signed / encrypted).”
  - “`SignedCookie` and `PrivateCookie` use `tower_cookies::Key`.”
- `codec` module
  - “Encodes/decodes a versioned `tower_sessions_core::session::Record` to/from a cookie-safe string.”
  - “Decode validates expiry and returns `None` for expired records (treated as no session).”

### Data format
Cookie value contains an encoded `Record` plus a small envelope:

- `version`: for forward compatibility.
- `record`: `{ id, expiry_date, data }`

Encoding choices to decide early:
- Serialization: `rmp-serde` (MessagePack) or JSON.
- Byte-to-string: URL-safe base64 (no padding) to keep cookie value ASCII.

Signing/encryption:
- Leave cryptography to `tower_cookies` signed/private jars via `CookieController`; do not implement custom crypto.

### Request/response flow
1. `CookieManager` populates `Cookies` in request extensions.
2. Our layer:
   - Reads the configured cookie name via the chosen controller.
   - If present, decodes into a `Record` (and validates expiry).
   - Creates a per-request `CookieStore` holding:
     - `Cookies` handle
     - controller
     - config
     - decoded record (if any)
   - Creates `Session::new(session_id, Arc<CookieStore>, config.expiry)` and inserts it into request extensions.
3. After inner service returns:
   - If session is empty -> delete cookie.
   - Else if modified or `always_save` -> call `session.save()` (which triggers `CookieStore::create/save` to write the cookie).
   - Avoid writing on server error responses (match `tower-sessions` behavior).

## Integration with Axum (what it should look like)

### Dependencies (application `Cargo.toml`)
- `tower-sessions = { version = "...", features = ["axum-core"] }` (for the `Session` extractor)
- `tower-sessions-cookie-store = "..."` (this crate)
- `tower-cookies = { version = "...", features = ["signed", "private"] }` (if using signed/private)

### Plaintext cookie sessions (dev/testing only)
```rust
use axum::{routing::get, Router};
use tower_sessions::Session;
use tower_sessions_cookie_store::CookieSessionManagerLayer;

async fn handler(session: Session) -> String {
    let n: usize = session.get("n").await.unwrap().unwrap_or(0);
    session.insert("n", n + 1).await.unwrap();
    format!("n={n}")
}

let app = Router::new()
    .route("/", get(handler))
    .layer(CookieSessionManagerLayer::new());
```

### Signed cookies (tamper-evident, readable by the client)
```rust
use axum::{routing::get, Router};
use tower_cookies::Key;
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, SignedCookie};

let key = Key::generate();

let layer = CookieSessionManagerLayer::new()
    .with_config(CookieSessionConfig::default().with_name("sid"))
    .with_controller(SignedCookie::new(key));

let app = Router::new().route("/", get(|| async { "ok" })).layer(layer);
```

### Private cookies (encrypted + authenticated)
```rust
use axum::{routing::get, Router};
use tower_cookies::Key;
use tower_sessions_cookie_store::{CookieSessionManagerLayer, PrivateCookie};

let key = Key::generate();
let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(CookieSessionManagerLayer::new().with_controller(PrivateCookie::new(key)));
```

### Notes for Axum extractors
- No new extractor should be required: `tower_sessions::Session` already extracts from request extensions.
- If we add any new extractors, they should be purely ergonomic (e.g. a typed wrapper) and should delegate to `Session` internally.

## Security and Correctness Considerations

### Integrity/confidentiality
- **Signed** cookies protect against tampering, but data is readable by the client.
- **Private** cookies protect both confidentiality and integrity.
- Plaintext should be documented as unsafe for production.

### Replay / stale sessions
- Cookie sessions are inherently bearer tokens; if stolen, attacker can replay until expiry.
- Recommend `Secure`, `HttpOnly`, and appropriate `SameSite` defaults; document CSRF implications.

### Expiry semantics
- Enforce `Record.expiry_date` on decode (`load` should return `None` when expired).
- Align inactivity expiry semantics with `tower-sessions` expectations: expiry is computed from last modification time (i.e., when the record is saved).

### Size limits
- Typical per-cookie limits are ~4096 bytes (varies by browser and includes name/attributes).
- Add a `max_cookie_bytes` config:
  - On write: refuse to write and return a structured store error (surfaces as 500 unless we choose a different policy).
  - Optionally provide “fail closed” vs “truncate” policy (default: fail closed).
- Follow-up: cookie chunking (multiple cookies) if needed.

### Malformed cookies
- If decoding fails:
  - Treat as no session (start fresh).
  - Optionally delete the cookie to stop repeated decode work.
  - Log at `warn` with rate-limiting guidance (avoid noisy logs).

## Implementation Steps

1. **Project scaffolding**
   - Decide crate dependencies and feature flags (`signed`, `private`, maybe `compression`).
   - Add README outline and example target(s) (Axum).

2. **Define config + controller abstractions**
   - `CookieSessionConfig` with defaults mirroring `tower-sessions` (name, `SameSite::Strict`, `Secure=true`, `HttpOnly=true`, path `/`, etc.).
   - `CookieController` trait compatible with plaintext/signed/private.

3. **Implement encoding/decoding module**
   - `encode_record(record) -> String`
   - `decode_record(str) -> Result<Record, DecodeError>`
   - Add version byte/field for format evolution.

4. **Implement per-request `CookieStore`**
   - Holds `Cookies`, controller, config, and maybe a cached decoded record.
   - Implements `tower_sessions_core::SessionStore`.
   - Implements collision strategy for `create` (usually irrelevant, but keep correct).

5. **Implement `CookieSessionManagerLayer` + service**
   - Mirror `tower-sessions` middleware behavior:
     - Load cookie at request start.
     - Insert `Session` extension.
     - Save/delete cookie after response depending on session state and status code.
   - Ensure `CookieManager` wrapping is handled internally (like `tower-sessions`).

6. **Testing**
   - Unit tests for encoding/decoding, expiry checks, and size handling.
   - Integration-style tests using `axum` + `tower::ServiceExt`:
     - Set value in session -> response contains cookie.
     - Next request with cookie -> session value is present.
     - Signed/private variants (feature-gated) reject tampering.
     - Empty session deletes cookie.
     - Malformed cookie yields fresh session (and optionally clears).

7. **Docs and examples**
   - `README.md`: quickstart for plaintext/signed/private, config knobs, security notes.
   - Example app demonstrating login-like session data stored fully in cookie.

8. **Upstream coordination (optional but recommended)**
   - Consider proposing an extension point in `tower-sessions` to customize cookie value storage, but do not depend on it for this crate.
   - Document trade-offs vs server-side stores (revocation, size, replay risk).

## Deliverables
- `CookieSessionManagerLayer` API with plaintext + signed/private controllers.
- Configurable, tested cookie-backed persistence with safe defaults.
- Documentation that makes security implications explicit.

## Status (work completed so far)

- Added baseline Axum integration tests using `tower-sessions` `MemoryStore`:
  - Cookie is set on first request and persists across requests.
  - `Session::flush()` causes a removal cookie to be set.
- Added the dev-dependencies needed to run those tests.
- Enforced test style conventions: no `.unwrap()`, and `expect` messages phrased as expectations.
