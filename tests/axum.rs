#![cfg(feature = "signed")]

// End-to-end tests using an Axum `Router` layered with `CookieSessionManagerLayer::signed`.
// These cover cookie issuance, persistence across requests, and session lifecycle operations.
mod common;

use axum::{Router, body::Body, routing::get};
use http::{Request, StatusCode, header};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use tower_cookies::Cookie;
use tower_sessions_cookie_store::{
    CookieSessionConfig, CookieSessionManagerLayer, Expiry, Key, SameSite, Session,
};

fn routes() -> Router {
    // Minimal routes to exercise the `Session` extractor and mutations.
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
                let expiry = Expiry::AtDateTime(OffsetDateTime::now_utc() + Duration::days(1));
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

fn assert_duration_close(actual: Duration, expected: Duration) {
    let tolerance = Duration::seconds(1);
    assert!(
        actual >= expected - tolerance && actual <= expected + tolerance,
        "duration is close to expected: {actual:?}"
    );
}

async fn app(max_age: Option<Duration>, domain: Option<String>) -> Router {
    // Helper to build a router with configurable expiry and domain attributes.
    let mut config = CookieSessionConfig::default().with_secure(true);
    if let Some(max_age) = max_age {
        config = config.with_expiry(Expiry::OnInactivity(max_age));
    }
    if let Some(domain) = domain {
        config = config.with_domain(domain);
    }
    let key = Key::generate();
    let session_manager = CookieSessionManagerLayer::signed(key).with_config(config);
    routes().layer(session_manager)
}

#[tokio::test]
async fn no_session_set() {
    // Exercise: handler extracts `Session` but does not write to it.
    // Expectation: no `Set-Cookie` header is emitted.
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
    // Exercise: client sends a cookie with the correct name but a value that won't verify/decode.
    // Expectation: the layer overwrites the invalid cookie by issuing a new session cookie value.
    let session_cookie = Cookie::new("session", "AAAAAAAAAAAAAAAAAAAAAA");
    let req = Request::builder()
        .uri("/insert")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app(Some(Duration::hours(1)), None)
        .await
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(res.status(), StatusCode::OK);
    assert_ne!(session_cookie.value(), "AAAAAAAAAAAAAAAAAAAAAA");
}

#[tokio::test]
async fn malformed_session_cookie() {
    // Exercise: client sends a cookie value that cannot be decoded as a session record.
    // Expectation: the layer recovers by issuing a fresh cookie when the session is used.
    let session_cookie = Cookie::new("session", "malformed");
    let req = Request::builder()
        .uri("/")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app(Some(Duration::hours(1)), None)
        .await
        .oneshot(req)
        .await
        .expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());
    assert_ne!(session_cookie.value(), "malformed");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn insert_session() {
    // Exercise: handler inserts a value into the session.
    // Expectation: response includes a session cookie with expected default attributes.
    let req = Request::builder()
        .uri("/insert")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app(Some(Duration::hours(1)), None)
        .await
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(session_cookie.name(), "session");
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
    // Exercise: no expiry configured (session cookie semantics).
    // Expectation: emitted cookie has no Max-Age.
    let req = Request::builder()
        .uri("/insert")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app(None, None)
        .await
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(session_cookie.name(), "session");
    assert_eq!(session_cookie.http_only(), Some(true));
    assert_eq!(session_cookie.same_site(), Some(SameSite::Strict));
    assert!(session_cookie.max_age().is_none());
    assert_eq!(session_cookie.secure(), Some(true));
    assert_eq!(session_cookie.path(), Some("/"));
}

#[tokio::test]
async fn get_session() {
    // Exercise: insert a value on one request, then read it back on a second request by sending
    // the cookie returned from the first response.
    // Expectation: the value persists via the cookie-backed store.
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/get")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");
    assert_eq!(res.status(), StatusCode::OK);

    assert_eq!(common::body_string(res.into_body()).await, "42");
}

#[tokio::test]
async fn get_no_value() {
    // Exercise: read a missing key via `get_value`.
    // Expectation: handler returns `None`.
    let app = app(Some(Duration::hours(1)), None).await;

    let req = Request::builder()
        .uri("/get_value")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(common::body_string(res.into_body()).await, "None");
}

#[tokio::test]
async fn remove_last_value() {
    // Exercise: insert then remove the last key in the session.
    // Expectation: removing the final value results in a "no session" state.
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
    let mut session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/remove_value")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/get_value")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(common::body_string(res.into_body()).await, "None");
}

#[tokio::test]
async fn cycle_session_id() {
    // Exercise: insert a value, call `Session::cycle_id()`, then read the value again.
    // Expectation: session data persists while the session identifier is rotated.
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
    let first_session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/cycle_id")
        .header(
            header::COOKIE,
            common::cookie_header_value(&first_session_cookie),
        )
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let second_session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/get")
        .header(
            header::COOKIE,
            common::cookie_header_value(&second_session_cookie),
        )
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_ne!(first_session_cookie.value(), second_session_cookie.value());
    assert_eq!(common::body_string(res.into_body()).await, "42");
}

#[tokio::test]
async fn flush_session() {
    // Exercise: insert a value, then call `Session::flush()` to clear the session.
    // Expectation: response sets a removal cookie (empty value + Max-Age=0).
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/flush")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(session_cookie.value(), "");
    assert_eq!(session_cookie.max_age(), Some(Duration::ZERO));
    assert_eq!(session_cookie.path(), Some("/"));
}

#[tokio::test]
async fn flush_with_domain() {
    // Exercise: flush with a configured cookie Domain.
    // Expectation: the removal cookie includes Domain so the browser will delete it.
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/flush")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(session_cookie.value(), "");
    assert_eq!(session_cookie.max_age(), Some(Duration::ZERO));
    assert_eq!(session_cookie.domain(), Some("localhost"));
    assert_eq!(session_cookie.path(), Some("/"));
}

#[tokio::test]
async fn set_expiry() {
    // Exercise: start with inactivity expiry then call `Session::set_expiry()` to change expiry.
    // Expectation: cookie Max-Age reflects the new expiry.
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_duration_close(
        session_cookie
            .max_age()
            .expect("session cookie has max-age"),
        Duration::hours(1),
    );

    let req = Request::builder()
        .uri("/set_expiry")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_duration_close(
        session_cookie
            .max_age()
            .expect("session cookie has max-age"),
        Duration::days(1),
    );
}

#[tokio::test]
async fn change_expiry_type() {
    // Exercise: start with no Max-Age, set an absolute expiry (Max-Age appears), then remove it
    // by switching to `OnSessionEnd` (Max-Age disappears).
    // Expectation: cookie Max-Age tracks the configured expiry policy.
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_eq!(session_cookie.max_age(), None);

    let req = Request::builder()
        .uri("/set_expiry")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app_router
        .oneshot(req)
        .await
        .expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());
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
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    assert_duration_close(
        session_cookie
            .max_age()
            .expect("session cookie has max-age"),
        Duration::hours(1),
    );

    let req = Request::builder()
        .uri("/remove_expiry")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app2.oneshot(req).await.expect("service call succeeds");

    let session_cookie = common::get_session_cookie_from_headers(res.headers());
    assert_eq!(session_cookie.max_age(), None);
}
