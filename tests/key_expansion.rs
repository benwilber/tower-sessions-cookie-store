mod common;

// Tests for the `key-expansion` feature, which enables `Key::derive_from()` for deterministic key
// derivation from a master key.
use axum::{Router, body::Body, routing::get};
use http::{Request, header};
use tower::ServiceExt as _;

use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};

fn routes() -> Router {
    // Routes to write and read a single session key.
    Router::new()
        .route(
            "/set",
            get(|session: Session| async move {
                session
                    .insert("foo", 42usize)
                    .await
                    .expect("session insert succeeds");
            }),
        )
        .route(
            "/get",
            get(|session: Session| async move {
                session
                    .get::<usize>("foo")
                    .await
                    .expect("session get succeeds")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            }),
        )
}

#[cfg(all(feature = "key-expansion", feature = "signed"))]
#[tokio::test]
async fn signed_roundtrips_with_derived_key() {
    // Exercise: derive a `Key` from a 32-byte master key and use it for signed cookies.
    // Expectation: session data round-trips correctly across requests.
    let master_key = [42u8; 32];
    let key = Key::derive_from(&master_key);
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::signed(key).with_config(config);
    let app = routes().layer(layer);

    let req = Request::builder()
        .uri("/set")
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

    assert_eq!(common::body_string(res.into_body()).await, "42");
}

#[cfg(all(feature = "key-expansion", feature = "private"))]
#[tokio::test]
async fn private_roundtrips_with_derived_key() {
    // Exercise: derive a `Key` from a 32-byte master key and use it for private cookies.
    // Expectation: session data round-trips correctly across requests.
    let master_key = [7u8; 32];
    let key = Key::derive_from(&master_key);
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::private(key).with_config(config);
    let app = routes().layer(layer);

    let req = Request::builder()
        .uri("/set")
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

    assert_eq!(common::body_string(res.into_body()).await, "42");
}
