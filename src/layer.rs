use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions_core::Session;

use crate::{
    codec,
    config::CookieSessionConfig,
    controller::{CookieController, PlaintextCookie},
    store::CookieStore,
};

#[derive(Debug, Clone)]
pub struct CookieSessionManagerLayer<C: CookieController = PlaintextCookie> {
    config: CookieSessionConfig,
    controller: C,
}

impl CookieSessionManagerLayer<PlaintextCookie> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: CookieSessionConfig::default(),
            controller: PlaintextCookie,
        }
    }
}

impl<C: CookieController> CookieSessionManagerLayer<C> {
    #[must_use]
    pub fn with_config(mut self, config: CookieSessionConfig) -> Self {
        self.config = config;
        self
    }

    #[must_use]
    pub fn with_controller<C2: CookieController>(
        self,
        controller: C2,
    ) -> CookieSessionManagerLayer<C2> {
        CookieSessionManagerLayer {
            config: self.config,
            controller,
        }
    }
}

impl Default for CookieSessionManagerLayer<PlaintextCookie> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CookieSessionManager<S, C: CookieController> {
    inner: S,
    config: CookieSessionConfig,
    controller: C,
}

impl<S, C: CookieController> Layer<S> for CookieSessionManagerLayer<C> {
    type Service = CookieManager<CookieSessionManager<S, C>>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieManager::new(CookieSessionManager {
            inner,
            config: self.config.clone(),
            controller: self.controller.clone(),
        })
    }
}

impl<ReqBody, ResBody, S, C> Service<Request<ReqBody>> for CookieSessionManager<S, C>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send,
    C: CookieController,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let controller = self.controller.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let cookies = match req.extensions().get::<tower_cookies::Cookies>().cloned() {
                Some(cookies) => cookies,
                None => {
                    let mut res = Response::default();
                    *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                }
            };

            let session_cookie = controller.get(&cookies, &config.name);
            let mut initial_cookie_removed = false;

            let decoded_record = match session_cookie.as_ref() {
                Some(cookie) => match codec::decode_record(cookie.value()) {
                    Ok(record) if record.expiry_date > time::OffsetDateTime::now_utc() => {
                        Some(record)
                    }
                    Ok(_expired) => {
                        if config.clear_on_decode_error {
                            let store = CookieStore::new(
                                cookies.clone(),
                                controller.clone(),
                                config.clone(),
                                None,
                                false,
                            );
                            store.remove_cookie();
                            initial_cookie_removed = true;
                        }
                        None
                    }
                    Err(err) => {
                        tracing::warn!(err = %err, "cookie session decode failed");
                        if config.clear_on_decode_error {
                            let store = CookieStore::new(
                                cookies.clone(),
                                controller.clone(),
                                config.clone(),
                                None,
                                false,
                            );
                            store.remove_cookie();
                            initial_cookie_removed = true;
                        }
                        None
                    }
                },
                None => None,
            };

            let session_id = decoded_record.as_ref().map(|r| r.id);
            let cookie_store = Arc::new(CookieStore::new(
                cookies,
                controller,
                config.clone(),
                decoded_record,
                initial_cookie_removed,
            ));

            let session = Session::new(session_id, cookie_store.clone(), config.expiry);
            req.extensions_mut().insert(session.clone());

            let res = inner.call(req).await?;

            let modified = session.is_modified();
            let empty = session.is_empty().await;
            let had_cookie = session_cookie.is_some();

            if empty {
                if had_cookie && !cookie_store.did_remove_cookie() {
                    cookie_store.remove_cookie();
                }
                return Ok(res);
            }

            if (modified || config.always_save)
                && !res.status().is_server_error()
                && !cookie_store.did_write_cookie()
                && {
                    cookie_store.set_expiry_hint(session.expiry());
                    true
                }
                && let Err(err) = session.save().await
            {
                tracing::error!(err = %err, "cookie session save failed");
                let mut res = Response::default();
                *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(res);
            }

            Ok(res)
        })
    }
}
