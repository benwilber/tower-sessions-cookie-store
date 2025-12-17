//! Cookie-backed session persistence for `tower-sessions`.
//!
//! This crate provides a layer that inserts `tower_sessions_core::Session` into request
//! extensions and persists the session record into a cookie.

mod codec;
mod config;
mod controller;
pub mod layer;
mod store;

pub use tower_cookies::cookie::SameSite;
pub use tower_sessions_core::{Session, session::Expiry};

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
pub use crate::controller::PlaintextCookie;

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
                .header(header::COOKIE, "id=bogus")
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
            let rec1 = get_record(cookie1.clone(), &key, "id");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "id");

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
            let rec1 = get_record(cookie1.clone(), &key, "id");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "id");

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
            let rec1 = get_record(cookie1.clone(), &key, "id");

            let req2 = Request::builder()
                .header(header::COOKIE, cookie_header_value(&cookie1))
                .body(Body::empty())
                .expect("request builds successfully");
            let res2 = svc.call(req2).await.expect("service call succeeds");
            let cookie2 = get_session_cookie(&res2);
            let rec2 = get_record(cookie2.clone(), &key, "id");

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

    #[cfg(feature = "signed")]
    mod route_tests {
        use axum::{Router, body::Body, routing::get};
        use http::{HeaderMap, Request, StatusCode, header};
        use http_body_util::BodyExt as _;
        use time::{Duration, OffsetDateTime};
        use tower::ServiceExt as _;
        use tower_cookies::Cookie;

        use crate::{CookieSessionConfig, CookieSessionManagerLayer, Expiry, SameSite, Session};

        fn routes() -> Router {
            Router::new()
                .route("/", get(|_: Session| async move { "Hello, world!" }))
                .route(
                    "/insert",
                    get(|session: Session| async move {
                        session
                            .insert("foo", 42)
                            .await
                            .expect("session insert succeeds");
                    }),
                )
                .route(
                    "/get",
                    get(|session: Session| async move {
                        let value: usize = session
                            .get::<usize>("foo")
                            .await
                            .expect("session get succeeds")
                            .expect("session contains foo");
                        format!("{value}")
                    }),
                )
                .route(
                    "/get_value",
                    get(|session: Session| async move {
                        format!(
                            "{:?}",
                            session
                                .get_value("foo")
                                .await
                                .expect("session get_value succeeds")
                        )
                    }),
                )
                .route(
                    "/remove",
                    get(|session: Session| async move {
                        session
                            .remove::<usize>("foo")
                            .await
                            .expect("session remove succeeds");
                    }),
                )
                .route(
                    "/remove_value",
                    get(|session: Session| async move {
                        session
                            .remove_value("foo")
                            .await
                            .expect("session remove_value succeeds");
                    }),
                )
                .route(
                    "/cycle_id",
                    get(|session: Session| async move {
                        session.cycle_id().await.expect("session cycle_id succeeds");
                    }),
                )
                .route(
                    "/flush",
                    get(|session: Session| async move {
                        session.flush().await.expect("session flush succeeds");
                    }),
                )
                .route(
                    "/set_expiry",
                    get(|session: Session| async move {
                        let expiry =
                            Expiry::AtDateTime(OffsetDateTime::now_utc() + Duration::days(1));
                        session.set_expiry(Some(expiry));
                    }),
                )
                .route(
                    "/remove_expiry",
                    get(|session: Session| async move {
                        session.set_expiry(Some(Expiry::OnSessionEnd));
                    }),
                )
        }

        async fn body_string(body: Body) -> String {
            let bytes = body
                .collect()
                .await
                .expect("body collects successfully")
                .to_bytes();
            String::from_utf8_lossy(&bytes).into_owned()
        }

        fn get_session_cookie(headers: &HeaderMap) -> Cookie<'static> {
            let set_cookie = headers
                .get_all(header::SET_COOKIE)
                .iter()
                .flat_map(|header| header.to_str())
                .next()
                .expect("response includes set-cookie header");
            Cookie::parse_encoded(set_cookie)
                .expect("set-cookie parses successfully")
                .into_owned()
        }

        fn cookie_header_value(cookie: &Cookie<'_>) -> String {
            cookie.encoded().to_string()
        }

        fn assert_duration_close(actual: Duration, expected: Duration) {
            let tolerance = Duration::seconds(1);
            assert!(
                actual >= expected - tolerance && actual <= expected + tolerance,
                "duration is close to expected: {actual:?}"
            );
        }

        async fn app(max_age: Option<Duration>, domain: Option<String>) -> Router {
            let mut config = CookieSessionConfig::default().with_secure(true);
            if let Some(max_age) = max_age {
                config = config.with_expiry(Expiry::OnInactivity(max_age));
            }
            if let Some(domain) = domain {
                config = config.with_domain(domain);
            }
            let key = crate::Key::generate();
            let session_manager = CookieSessionManagerLayer::signed(key).with_config(config);
            routes().layer(session_manager)
        }

        #[tokio::test]
        async fn no_session_set() {
            let req = Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app(Some(Duration::hours(1)), None)
                .await
                .oneshot(req)
                .await
                .expect("service call succeeds");

            assert!(
                res.headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .next()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn bogus_session_cookie() {
            let session_cookie = Cookie::new("id", "AAAAAAAAAAAAAAAAAAAAAA");
            let req = Request::builder()
                .uri("/insert")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app(Some(Duration::hours(1)), None)
                .await
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(res.status(), StatusCode::OK);
            assert_ne!(session_cookie.value(), "AAAAAAAAAAAAAAAAAAAAAA");
        }

        #[tokio::test]
        async fn malformed_session_cookie() {
            let session_cookie = Cookie::new("id", "malformed");
            let req = Request::builder()
                .uri("/")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app(Some(Duration::hours(1)), None)
                .await
                .oneshot(req)
                .await
                .expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());
            assert_ne!(session_cookie.value(), "malformed");
            assert_eq!(res.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn insert_session() {
            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app(Some(Duration::hours(1)), None)
                .await
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(session_cookie.name(), "id");
            assert_eq!(session_cookie.http_only(), Some(true));
            assert_eq!(session_cookie.same_site(), Some(SameSite::Strict));
            assert!(
                session_cookie
                    .max_age()
                    .is_some_and(|dt| dt <= Duration::hours(1))
            );
            assert_eq!(session_cookie.secure(), Some(true));
            assert_eq!(session_cookie.path(), Some("/"));
        }

        #[tokio::test]
        async fn session_max_age() {
            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app(None, None)
                .await
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(session_cookie.name(), "id");
            assert_eq!(session_cookie.http_only(), Some(true));
            assert_eq!(session_cookie.same_site(), Some(SameSite::Strict));
            assert!(session_cookie.max_age().is_none());
            assert_eq!(session_cookie.secure(), Some(true));
            assert_eq!(session_cookie.path(), Some("/"));
        }

        #[tokio::test]
        async fn get_session() {
            let app = app(Some(Duration::hours(1)), None).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/get")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");
            assert_eq!(res.status(), StatusCode::OK);

            assert_eq!(body_string(res.into_body()).await, "42");
        }

        #[tokio::test]
        async fn get_no_value() {
            let app = app(Some(Duration::hours(1)), None).await;

            let req = Request::builder()
                .uri("/get_value")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            assert_eq!(body_string(res.into_body()).await, "None");
        }

        #[tokio::test]
        async fn remove_last_value() {
            let app = app(Some(Duration::hours(1)), None).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let mut session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/remove_value")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/get_value")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            assert_eq!(body_string(res.into_body()).await, "None");
        }

        #[tokio::test]
        async fn cycle_session_id() {
            let app = app(Some(Duration::hours(1)), None).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let first_session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/cycle_id")
                .header(header::COOKIE, cookie_header_value(&first_session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let second_session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/get")
                .header(header::COOKIE, cookie_header_value(&second_session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            assert_ne!(first_session_cookie.value(), second_session_cookie.value());
            assert_eq!(body_string(res.into_body()).await, "42");
        }

        #[tokio::test]
        async fn flush_session() {
            let app = app(Some(Duration::hours(1)), None).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/flush")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(session_cookie.value(), "");
            assert_eq!(session_cookie.max_age(), Some(Duration::ZERO));
            assert_eq!(session_cookie.path(), Some("/"));
        }

        #[tokio::test]
        async fn flush_with_domain() {
            let app = app(Some(Duration::hours(1)), Some("localhost".to_string())).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            let req = Request::builder()
                .uri("/flush")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(session_cookie.value(), "");
            assert_eq!(session_cookie.max_age(), Some(Duration::ZERO));
            assert_eq!(session_cookie.domain(), Some("localhost"));
            assert_eq!(session_cookie.path(), Some("/"));
        }

        #[tokio::test]
        async fn set_expiry() {
            let app = app(Some(Duration::hours(1)), Some("localhost".to_string())).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_duration_close(
                session_cookie
                    .max_age()
                    .expect("session cookie has max-age"),
                Duration::hours(1),
            );

            let req = Request::builder()
                .uri("/set_expiry")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app.oneshot(req).await.expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());

            assert_duration_close(
                session_cookie
                    .max_age()
                    .expect("session cookie has max-age"),
                Duration::days(1),
            );
        }

        #[tokio::test]
        async fn change_expiry_type() {
            let app_router = app(None, Some("localhost".to_string())).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app_router
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_eq!(session_cookie.max_age(), None);

            let req = Request::builder()
                .uri("/set_expiry")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app_router
                .oneshot(req)
                .await
                .expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());
            assert_duration_close(
                session_cookie
                    .max_age()
                    .expect("session cookie has max-age"),
                Duration::days(1),
            );

            let app2 = app(Some(Duration::hours(1)), Some("localhost".to_string())).await;

            let req = Request::builder()
                .uri("/insert")
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app2
                .clone()
                .oneshot(req)
                .await
                .expect("service call succeeds");
            let session_cookie = get_session_cookie(res.headers());

            assert_duration_close(
                session_cookie
                    .max_age()
                    .expect("session cookie has max-age"),
                Duration::hours(1),
            );

            let req = Request::builder()
                .uri("/remove_expiry")
                .header(header::COOKIE, cookie_header_value(&session_cookie))
                .body(Body::empty())
                .expect("request builds successfully");
            let res = app2.oneshot(req).await.expect("service call succeeds");

            let session_cookie = get_session_cookie(res.headers());
            assert_eq!(session_cookie.max_age(), None);
        }
    }
}
