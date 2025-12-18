//! Cookie-backed session persistence for `tower-sessions`.
//!
//! This crate provides a layer that inserts `tower_sessions_core::Session` into request
//! extensions and persists the session record into a cookie.
//!
//! # Security
//! The default format is a signed cookie (`signed` feature).
//!
//! The `dangerous-plaintext` feature enables a plaintext cookie controller. This offers **no tamper
//! resistance** and should only be used for **testing and debugging**. Never enable or use this in
//! a real application: a client can trivially edit the cookie to escalate privileges and
//! impersonate other users (including staff/admin).
//!
//! ## Example (Axum, signed cookies)
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};
//!
//! async fn handler(session: Session) -> String {
//!     let n: usize = session.get("n").await.expect("session get succeeds").unwrap_or(0);
//!     session.insert("n", n + 1).await.expect("session insert succeeds");
//!     format!("n={n}")
//! }
//!
//! let key = Key::generate();
//! let config = CookieSessionConfig::default().with_secure(false);
//! let app = Router::<()>::new()
//!     .route("/", get(handler))
//!     .layer(CookieSessionManagerLayer::signed(key).with_config(config));
//! ```

#[cfg(all(
    feature = "key-expansion",
    not(any(feature = "signed", feature = "private"))
))]
compile_error!("feature `key-expansion` requires `signed` and/or `private`.");

mod codec;
mod config;
mod controller;
pub mod format;
/// Tower layer for cookie-backed sessions.
pub mod layer;
mod store;

pub use tower_cookies::cookie::SameSite;
pub use tower_sessions_core::{Session, session::Expiry, session_store};

#[cfg(any(feature = "signed", feature = "private"))]
pub use tower_cookies::Key;

pub use crate::config::CookieSessionConfig;
pub use crate::config::DEFAULT_COOKIE_NAME;
pub use crate::controller::CookieController;
pub use crate::format::{decode_record, encode_record};
pub use crate::layer::CookieSessionManagerLayer;

#[cfg(feature = "signed")]
pub use crate::controller::SignedCookie;

#[cfg(feature = "private")]
pub use crate::controller::PrivateCookie;

#[cfg(feature = "dangerous-plaintext")]
pub use crate::controller::DangerousPlaintextCookie;
