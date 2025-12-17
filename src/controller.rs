//! Cookie controller implementations.
//!
//! A [`CookieController`] defines how a session cookie is read/written/removed from
//! [`tower_cookies::Cookies`]. This crate provides controllers for plaintext, signed, and private
//! cookies (feature-gated).

use std::fmt::Debug;

use tower_cookies::{Cookie, Cookies};

/// Reads/writes/removes a session cookie from a [`Cookies`] jar.
///
/// The controller determines whether the cookie is stored as plaintext, signed, or encrypted.
pub trait CookieController: Debug + Clone + Send + Sync + 'static {
    /// Reads the named session cookie from the jar.
    fn get(&self, cookies: &Cookies, name: &str) -> Option<Cookie<'static>>;

    /// Adds a session cookie to the jar.
    fn add(&self, cookies: &Cookies, cookie: Cookie<'static>);

    /// Removes a session cookie from the jar.
    fn remove(&self, cookies: &Cookies, cookie: Cookie<'static>);
}

#[cfg(feature = "dangerous-plaintext")]
#[derive(Debug, Clone, Copy, Default)]
/// A controller that stores session state in plaintext cookies.
///
/// # Security warning
/// This offers **no tamper resistance** and should only be used for **testing and debugging**.
/// Never enable or use this in a real application: a client can trivially edit the cookie to
/// escalate privileges and impersonate other users (including staff/admin).
pub struct DangerousPlaintextCookie;

#[cfg(feature = "dangerous-plaintext")]
impl CookieController for DangerousPlaintextCookie {
    fn get(&self, cookies: &Cookies, name: &str) -> Option<Cookie<'static>> {
        cookies.get(name).map(Cookie::into_owned)
    }

    fn add(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.add(cookie);
    }

    fn remove(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.remove(cookie);
    }
}

#[cfg(feature = "signed")]
#[derive(Debug, Clone)]
/// A controller that stores session state in signed cookies.
///
/// Signed cookies provide integrity (tamper evidence) but do not provide confidentiality.
pub struct SignedCookie {
    key: crate::Key,
}

#[cfg(feature = "signed")]
impl SignedCookie {
    /// Creates a signed cookie controller using `key`.
    pub fn new(key: crate::Key) -> Self {
        Self { key }
    }
}

#[cfg(feature = "signed")]
impl CookieController for SignedCookie {
    fn get(&self, cookies: &Cookies, name: &str) -> Option<Cookie<'static>> {
        cookies.signed(&self.key).get(name).map(Cookie::into_owned)
    }

    fn add(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.signed(&self.key).add(cookie);
    }

    fn remove(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.signed(&self.key).remove(cookie);
    }
}

#[cfg(feature = "private")]
#[derive(Debug, Clone)]
/// A controller that stores session state in private (encrypted + authenticated) cookies.
pub struct PrivateCookie {
    key: crate::Key,
}

#[cfg(feature = "private")]
impl PrivateCookie {
    /// Creates a private cookie controller using `key`.
    pub fn new(key: crate::Key) -> Self {
        Self { key }
    }
}

#[cfg(feature = "private")]
impl CookieController for PrivateCookie {
    fn get(&self, cookies: &Cookies, name: &str) -> Option<Cookie<'static>> {
        cookies.private(&self.key).get(name).map(Cookie::into_owned)
    }

    fn add(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.private(&self.key).add(cookie);
    }

    fn remove(&self, cookies: &Cookies, cookie: Cookie<'static>) {
        cookies.private(&self.key).remove(cookie);
    }
}
