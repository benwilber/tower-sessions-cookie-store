use axum::{Router, body::Body, routing::get};
use http::{Request, header};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use tower_cookies::Cookie;
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};

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

fn tamper_cookie_value(cookie: &mut Cookie<'_>) {
    let mut value = cookie.value().to_string();
    let last = value
        .pop()
        .expect("cookie value has at least one character");
    let replacement = if last == 'A' { 'B' } else { 'A' };
    value.push(replacement);
    cookie.set_value(value);
}

fn routes() -> Router {
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
                    .unwrap_or_else(|| "none".to_string())
            }),
        )
}

#[cfg(feature = "signed")]
#[tokio::test]
async fn signed_rejects_tampering() {
    let key = Key::generate();
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::signed(key).with_config(config);
    let app = routes().layer(layer);

    let req = Request::builder()
        .uri("/set-user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let mut session_cookie = get_session_cookie(res.headers());

    tamper_cookie_value(&mut session_cookie);

    let req = Request::builder()
        .uri("/get-user")
        .header(header::COOKIE, cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(body_string(res.into_body()).await, "none");
}

#[cfg(feature = "private")]
#[tokio::test]
async fn private_rejects_tampering() {
    let key = Key::generate();
    let config = CookieSessionConfig::default().with_secure(false);
    let layer = CookieSessionManagerLayer::private(key).with_config(config);
    let app = routes().layer(layer);

    let req = Request::builder()
        .uri("/set-user")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let mut session_cookie = get_session_cookie(res.headers());

    tamper_cookie_value(&mut session_cookie);

    let req = Request::builder()
        .uri("/get-user")
        .header(header::COOKIE, cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = app.oneshot(req).await.expect("service call succeeds");

    assert_eq!(body_string(res.into_body()).await, "none");
}
