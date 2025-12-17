#![cfg(feature = "dangerous-plaintext")]

use axum::{Router, body::Body, routing::get};
use http::{Request, header};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use tower_cookies::Cookie;
use tower_sessions_cookie_store::{
    CookieSessionConfig, CookieSessionManagerLayer, Session, format,
};

fn app() -> Router {
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::dangerous_plaintext().with_config(config);

    Router::new()
        .route(
            "/set_user",
            get(|session: Session| async move {
                session
                    .insert("user", "alice")
                    .await
                    .expect("session insert succeeds");
            }),
        )
        .route(
            "/get_user",
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

async fn body_string(body: Body) -> String {
    let bytes = body
        .collect()
        .await
        .expect("body collects successfully")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn get_session_cookie(headers: &http::HeaderMap) -> Cookie<'static> {
    let set_cookie = headers
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

#[tokio::test]
async fn plaintext_roundtrip() {
    let app = app();

    let req = Request::builder()
        .uri("/set_user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = get_session_cookie(res.headers());

    let req = Request::builder()
        .uri("/get_user")
        .header(header::COOKIE, cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(body_string(res.into_body()).await, "alice");
}

#[tokio::test]
async fn plaintext_allows_tampering() {
    let app = app();

    let req = Request::builder()
        .uri("/set_user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let mut session_cookie = get_session_cookie(res.headers());

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
        .uri("/get_user")
        .header(header::COOKIE, cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(body_string(res.into_body()).await, "admin");
}
