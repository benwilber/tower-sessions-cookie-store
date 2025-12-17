#![cfg(feature = "dangerous-plaintext")]

mod common;

use axum::{Router, body::Body, routing::get};
use http::{Request, header};
use tower::ServiceExt as _;
use tower_sessions_cookie_store::{
    CookieSessionConfig, CookieSessionManagerLayer, Session, format,
};

fn app() -> Router {
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::dangerous_plaintext().with_config(config);

    Router::new()
        .route(
            "/set-user",
            get(|session: Session| async move {
                session
                    .insert("user", "alice")
                    .await
                    .expect("session insert succeeds");
            }),
        )
        .route(
            "/get-user",
            get(|session: Session| async move {
                session
                    .get::<String>("user")
                    .await
                    .expect("session get succeeds")
                    .expect("session contains user")
            }),
        )
        .layer(layer)
}

#[tokio::test]
async fn plaintext_roundtrip() {
    let app = app();

    let req = Request::builder()
        .uri("/set-user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = common::get_session_cookie_from_headers(res.headers());

    let req = Request::builder()
        .uri("/get-user")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(common::body_string(res.into_body()).await, "alice");
}

#[tokio::test]
async fn plaintext_allows_tampering() {
    let app = app();

    let req = Request::builder()
        .uri("/set-user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let mut session_cookie = common::get_session_cookie_from_headers(res.headers());

    let mut record =
        format::decode_record(session_cookie.value()).expect("cookie record decodes successfully");
    record.data.insert(
        "user".to_string(),
        serde_json::Value::String("admin".to_string()),
    );
    let tampered_value =
        format::encode_record(&record).expect("cookie record encodes successfully");
    session_cookie.set_value(tampered_value);

    let req = Request::builder()
        .uri("/get-user")
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(common::body_string(res.into_body()).await, "admin");
}
