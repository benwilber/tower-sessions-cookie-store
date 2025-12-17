use std::borrow::Cow;

use time::{Duration, OffsetDateTime};
use tower_cookies::Cookie;

use crate::{Expiry, SameSite};

#[derive(Debug, Clone)]
pub struct CookieSessionConfig {
    pub(crate) name: Cow<'static, str>,
    pub(crate) http_only: bool,
    pub(crate) same_site: SameSite,
    pub(crate) expiry: Option<Expiry>,
    pub(crate) secure: bool,
    pub(crate) path: Cow<'static, str>,
    pub(crate) domain: Option<Cow<'static, str>>,
    pub(crate) always_save: bool,
    pub(crate) max_cookie_bytes: usize,
    pub(crate) clear_on_decode_error: bool,
}

impl Default for CookieSessionConfig {
    fn default() -> Self {
        Self {
            name: "id".into(),
            http_only: true,
            same_site: SameSite::Strict,
            expiry: None,
            secure: true,
            path: "/".into(),
            domain: None,
            always_save: false,
            max_cookie_bytes: 4096,
            clear_on_decode_error: true,
        }
    }
}

impl CookieSessionConfig {
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    #[must_use]
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    #[must_use]
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    #[must_use]
    pub fn with_expiry(mut self, expiry: Expiry) -> Self {
        self.expiry = Some(expiry);
        self
    }

    #[must_use]
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    #[must_use]
    pub fn with_path<P: Into<Cow<'static, str>>>(mut self, path: P) -> Self {
        self.path = path.into();
        self
    }

    #[must_use]
    pub fn with_domain<D: Into<Cow<'static, str>>>(mut self, domain: D) -> Self {
        self.domain = Some(domain.into());
        self
    }

    #[must_use]
    pub fn without_domain(mut self) -> Self {
        self.domain = None;
        self
    }

    #[must_use]
    pub fn with_always_save(mut self, always_save: bool) -> Self {
        self.always_save = always_save;
        self
    }

    #[must_use]
    pub fn with_max_cookie_bytes(mut self, max_cookie_bytes: usize) -> Self {
        self.max_cookie_bytes = max_cookie_bytes;
        self
    }

    #[must_use]
    pub fn with_clear_on_decode_error(mut self, clear_on_decode_error: bool) -> Self {
        self.clear_on_decode_error = clear_on_decode_error;
        self
    }

    pub(crate) fn build_cookie(
        &self,
        value: String,
        expiry: Option<Expiry>,
        record_expiry_date: OffsetDateTime,
    ) -> Cookie<'static> {
        let mut cookie_builder = Cookie::build((self.name.clone(), value))
            .http_only(self.http_only)
            .same_site(self.same_site)
            .secure(self.secure)
            .path(self.path.clone());

        match expiry {
            Some(Expiry::OnInactivity(_)) | Some(Expiry::AtDateTime(_)) => {
                let max_age = std::cmp::max(
                    record_expiry_date - OffsetDateTime::now_utc(),
                    Duration::ZERO,
                );
                cookie_builder = cookie_builder.max_age(max_age);
            }
            Some(Expiry::OnSessionEnd) | None => {}
        }

        if let Some(domain) = self.domain.clone() {
            cookie_builder = cookie_builder.domain(domain);
        }

        cookie_builder.build()
    }

    pub(crate) fn apply_removal_attributes(&self, cookie: &mut Cookie<'static>) {
        cookie.set_path(self.path.clone());
        if let Some(domain) = self.domain.clone() {
            cookie.set_domain(domain);
        }
    }
}
