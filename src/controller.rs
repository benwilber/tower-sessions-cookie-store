use std::fmt::Debug;

use tower_cookies::{Cookie, Cookies};

pub trait CookieController: Debug + Clone + Send + Sync + 'static {
    fn get(&self, cookies: &Cookies, name: &str) -> Option<Cookie<'static>>;
    fn add(&self, cookies: &Cookies, cookie: Cookie<'static>);
    fn remove(&self, cookies: &Cookies, cookie: Cookie<'static>);
}

#[cfg(feature = "dangerous-plaintext")]
#[derive(Debug, Clone, Copy, Default)]
pub struct PlaintextCookie;

#[cfg(feature = "dangerous-plaintext")]
impl CookieController for PlaintextCookie {
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
pub struct SignedCookie {
    key: crate::Key,
}

#[cfg(feature = "signed")]
impl SignedCookie {
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
pub struct PrivateCookie {
    key: crate::Key,
}

#[cfg(feature = "private")]
impl PrivateCookie {
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
