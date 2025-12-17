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

mod codec;
mod config;
mod controller;
pub mod format;
pub mod layer;
mod store;

pub use tower_cookies::cookie::SameSite;
pub use tower_sessions_core::{Session, session::Expiry, session_store};

#[cfg(any(feature = "signed", feature = "private"))]
pub use tower_cookies::Key;

pub use crate::config::CookieSessionConfig;
pub use crate::controller::CookieController;
pub use crate::layer::CookieSessionManagerLayer;

#[cfg(feature = "signed")]
pub use crate::controller::SignedCookie;

#[cfg(feature = "private")]
pub use crate::controller::PrivateCookie;

#[cfg(feature = "dangerous-plaintext")]
pub use crate::controller::DangerousPlaintextCookie;
