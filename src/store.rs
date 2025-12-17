use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use time::OffsetDateTime;
use tower_cookies::{Cookie, Cookies};
use tower_sessions_core::{
    SessionStore,
    session::{Id, Record},
    session_store,
};

use crate::{codec, config::CookieSessionConfig, controller::CookieController};

#[derive(Debug)]
pub(crate) struct CookieStore<C: CookieController> {
    cookies: Cookies,
    controller: C,
    config: CookieSessionConfig,
    decoded_record: Mutex<Option<Record>>,
    expiry_hint: Mutex<Option<tower_sessions_core::session::Expiry>>,
    cookie_written: AtomicBool,
    cookie_removed: AtomicBool,
}

impl<C: CookieController> CookieStore<C> {
    pub(crate) fn new(
        cookies: Cookies,
        controller: C,
        config: CookieSessionConfig,
        decoded_record: Option<Record>,
        initial_cookie_removed: bool,
    ) -> Self {
        Self {
            cookies,
            controller,
            config,
            decoded_record: Mutex::new(decoded_record),
            expiry_hint: Mutex::new(None),
            cookie_written: AtomicBool::new(false),
            cookie_removed: AtomicBool::new(initial_cookie_removed),
        }
    }

    pub(crate) fn set_expiry_hint(&self, expiry: Option<tower_sessions_core::session::Expiry>) {
        if let Ok(mut guard) = self.expiry_hint.lock() {
            *guard = expiry;
        }
    }

    pub(crate) fn did_write_cookie(&self) -> bool {
        self.cookie_written.load(Ordering::Acquire)
    }

    pub(crate) fn did_remove_cookie(&self) -> bool {
        self.cookie_removed.load(Ordering::Acquire)
    }

    pub(crate) fn remove_cookie(&self) {
        let mut cookie = Cookie::new(self.config.name.clone(), "");
        self.config.apply_removal_attributes(&mut cookie);
        self.controller.remove(&self.cookies, cookie);
        self.cookie_removed.store(true, Ordering::Release);
    }

    fn record_is_active(record: &Record) -> bool {
        record.expiry_date > OffsetDateTime::now_utc()
    }

    fn load_cached_record(&self, session_id: &Id) -> Option<Record> {
        let guard = self
            .decoded_record
            .lock()
            .map_err(|_| session_store::Error::Backend("cookie store lock is poisoned".into()))
            .ok()?;

        guard
            .as_ref()
            .filter(|record| record.id == *session_id)
            .filter(|record| Self::record_is_active(record))
            .cloned()
    }

    fn persist_record(&self, record: &Record) -> session_store::Result<()> {
        let value = codec::encode_record(record)?;
        if value.len() > self.config.max_cookie_bytes {
            return Err(session_store::Error::Encode(format!(
                "Cookie value exceeds max_cookie_bytes ({} > {})",
                value.len(),
                self.config.max_cookie_bytes
            )));
        }

        let expiry_hint = (*self
            .expiry_hint
            .lock()
            .map_err(|_| session_store::Error::Backend("cookie store lock is poisoned".into()))?)
        .or(self.config.expiry);

        let cookie = self
            .config
            .build_cookie(value, expiry_hint, record.expiry_date);
        self.controller.add(&self.cookies, cookie);
        self.cookie_written.store(true, Ordering::Release);

        let mut guard = self
            .decoded_record
            .lock()
            .map_err(|_| session_store::Error::Backend("cookie store lock is poisoned".into()))?;
        *guard = Some(record.clone());

        Ok(())
    }
}

#[async_trait]
impl<C: CookieController> SessionStore for CookieStore<C> {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        self.persist_record(record)?;
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.persist_record(record)?;
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        Ok(self.load_cached_record(session_id))
    }

    async fn delete(&self, _session_id: &Id) -> session_store::Result<()> {
        self.remove_cookie();

        let mut guard = self
            .decoded_record
            .lock()
            .map_err(|_| session_store::Error::Backend("cookie store lock is poisoned".into()))?;
        *guard = None;

        Ok(())
    }
}
