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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::Body;
    use http::{Request, Response};
    use tower::{ServiceBuilder, ServiceExt as _};
    use tower_service::Service as _;

    use crate::{CookieSessionConfig, CookieSessionManagerLayer, Expiry, SameSite, Session};

    async fn handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let session = req
            .extensions()
            .get::<Session>()
            .cloned()
            .expect("request includes Session extension");

        session
            .insert("foo", 42)
            .await
            .expect("session insert succeeds");

        Ok(Response::new(Body::empty()))
    }

    async fn noop_handler(_: Request<Body>) -> Result<Response<Body>, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    #[cfg(feature = "signed")]
    mod service_tests {
        use http::header;
        use time::{Duration, OffsetDateTime};
        use tower_cookies::{Cookie, cookie::CookieJar};
        use tower_sessions_core::session::Record;

        use super::*;

        fn make_layer() -> (crate::Key, CookieSessionManagerLayer<crate::SignedCookie>) {
            let key = crate::Key::generate();
            let layer = CookieSessionManagerLayer::signed(key.clone());
            (key, layer)
        }

        fn get_session_cookie(res: &Response<Body>) -> Cookie<'static> {
            let set_cookie = res
                .headers()
                .get(header::SET_COOKIE)
                .expect("response includes set-cookie header");
            let set_cookie = set_cookie
                .to_str()
                .expect("set-cookie header is valid utf-8");
            Cookie::parse_encoded(set_cookie)
                .expect("set-cookie parses successfully")
                .into_owned()
        }

        fn cookie_header_value(cookie: &Cookie<'_>) -> String {
            cookie.encoded().to_string()
        }

        fn assert_max_age_seconds_close(cookie: &Cookie<'_>, expected_seconds: i64) {
            let actual_seconds = cookie
                .max_age()
                .expect("session cookie has max-age")
                .whole_seconds();
            assert!((actual_seconds - expected_seconds).abs() <= 1);
        }

        fn get_record(cookie: Cookie<'static>, key: &crate::Key, name: &str) -> Record {
            let mut jar = CookieJar::new();
            jar.add_original(cookie);
            let unsigned_value = jar
                .signed(key)
                .get(name)
                .expect("signed jar returns session cookie")
                .value()
                .to_string();
            crate::codec::decode_record(&unsigned_value)
                .expect("cookie record decodes successfully")
        }

        #[tokio::test]
        async fn basic_service_test() {
            let (_key, session_layer) = make_layer();
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            let req = Request::builder()
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");

            assert!(res.headers().get(header::SET_COOKIE).is_none());
        }

        #[tokio::test]
        async fn bogus_cookie_test() {
            let (_key, session_layer) = make_layer();
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .header(header::COOKIE, "session=bogus")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");

            assert!(res.headers().get(header::SET_COOKIE).is_some());
        }

        #[tokio::test]
        async fn no_set_cookie_test() {
            let (_key, session_layer) = make_layer();
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(noop_handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");

            assert!(res.headers().get(header::SET_COOKIE).is_none());
        }

        #[tokio::test]
        async fn name_test() {
            let config = CookieSessionConfig::default().with_name("my.sid");
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.name(), "my.sid");
        }

        #[tokio::test]
        async fn http_only_test() {
            let (_key, session_layer) = make_layer();
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.http_only(), Some(true));

            let config = CookieSessionConfig::default().with_http_only(false);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.http_only(), None);
        }

        #[tokio::test]
        async fn same_site_strict_test() {
            let config = CookieSessionConfig::default().with_same_site(SameSite::Strict);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.same_site(), Some(SameSite::Strict));
        }

        #[tokio::test]
        async fn same_site_lax_test() {
            let config = CookieSessionConfig::default().with_same_site(SameSite::Lax);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.same_site(), Some(SameSite::Lax));
        }

        #[tokio::test]
        async fn same_site_none_test() {
            let config = CookieSessionConfig::default().with_same_site(SameSite::None);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.same_site(), Some(SameSite::None));
        }

        #[tokio::test]
        async fn expiry_on_session_end_test() {
            let config = CookieSessionConfig::default().with_expiry(Expiry::OnSessionEnd);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert!(session_cookie.max_age().is_none());
        }

        #[tokio::test]
        async fn expiry_on_inactivity_test() {
            let inactivity_duration = Duration::hours(2);
            let config = CookieSessionConfig::default()
                .with_expiry(Expiry::OnInactivity(inactivity_duration));
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_max_age_seconds_close(&session_cookie, inactivity_duration.whole_seconds());
        }

        #[tokio::test]
        async fn expiry_at_date_time_test() {
            let expiry_time = OffsetDateTime::now_utc() + Duration::weeks(1);
            let config =
                CookieSessionConfig::default().with_expiry(Expiry::AtDateTime(expiry_time));
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            let expected = (expiry_time - OffsetDateTime::now_utc()).whole_seconds();
            assert_max_age_seconds_close(&session_cookie, expected);
        }

        #[tokio::test]
        async fn expiry_on_session_end_always_save_test() {
            let config = CookieSessionConfig::default()
                .with_expiry(Expiry::OnSessionEnd)
                .with_always_save(true);
            let (key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let mut svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req1 = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res1 = svc.call(req1).await.expect("service call succeeds");
            let cookie1 = get_session_cookie(&res1);
            let rec1 = get_record(cookie1.clone(), &key, "session");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "session");

            assert!(cookie2.max_age().is_none());
            assert_eq!(rec1.id, rec2.id);
            assert!(rec1.expiry_date < rec2.expiry_date);
        }

        #[tokio::test]
        async fn expiry_on_inactivity_always_save_test() {
            let inactivity_duration = Duration::hours(2);
            let config = CookieSessionConfig::default()
                .with_expiry(Expiry::OnInactivity(inactivity_duration))
                .with_always_save(true);
            let (key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let mut svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req1 = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res1 = svc.call(req1).await.expect("service call succeeds");
            let cookie1 = get_session_cookie(&res1);
            let rec1 = get_record(cookie1.clone(), &key, "session");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "session");

            assert_max_age_seconds_close(&cookie2, inactivity_duration.whole_seconds());
            assert_eq!(rec1.id, rec2.id);
            assert!(rec1.expiry_date < rec2.expiry_date);
        }

        #[tokio::test]
        async fn expiry_at_date_time_always_save_test() {
            let expiry_time = OffsetDateTime::now_utc() + Duration::weeks(1);
            let config = CookieSessionConfig::default()
                .with_expiry(Expiry::AtDateTime(expiry_time))
                .with_always_save(true);
            let (key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let mut svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req1 = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res1 = svc.call(req1).await.expect("service call succeeds");
            let cookie1 = get_session_cookie(&res1);
            let rec1 = get_record(cookie1.clone(), &key, "session");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "session");

            let expected = (expiry_time - OffsetDateTime::now_utc()).whole_seconds();
            assert_max_age_seconds_close(&cookie2, expected);
            assert_eq!(rec1.id, rec2.id);
            assert_eq!(rec1.expiry_date, rec2.expiry_date);
        }

        #[tokio::test]
        async fn secure_test() {
            let config = CookieSessionConfig::default().with_secure(true);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.secure(), Some(true));

            let config = CookieSessionConfig::default().with_secure(false);
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.secure(), None);
        }

        #[tokio::test]
        async fn path_test() {
            let config = CookieSessionConfig::default().with_path("/foo/bar");
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.path(), Some("/foo/bar"));
        }

        #[tokio::test]
        async fn domain_test() {
            let config = CookieSessionConfig::default().with_domain("example.com");
            let (_key, session_layer) = make_layer();
            let session_layer = session_layer.with_config(config);
            let svc = ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(handler);

            let req = Request::builder()
                .body(Body::empty())
                .expect("request builds successfully");
            let res = svc.oneshot(req).await.expect("service call succeeds");
            let session_cookie = get_session_cookie(&res);

            assert_eq!(session_cookie.domain(), Some("example.com"));
        }
    }

    #[cfg(feature = "private")]
    #[tokio::test]
    async fn private_test() {
        use http::header;

        let key = crate::Key::generate();
        let session_layer = CookieSessionManagerLayer::private(key);
        let svc = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(handler);

        let req = Request::builder()
            .body(Body::empty())
            .expect("request builds successfully");
        let res = svc.oneshot(req).await.expect("service call succeeds");

        assert!(res.headers().get(header::SET_COOKIE).is_some());
    }
}
