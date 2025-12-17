#![allow(dead_code)]

use std::convert::Infallible;

use axum::body::Body;
use http::{HeaderMap, Request, Response, header};
use http_body_util::BodyExt as _;
use tower_cookies::{Cookie, Key, cookie::CookieJar};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Session};
use tower_sessions_core::session::Record;

pub async fn body_string(body: Body) -> String {
    let bytes = body
        .collect()
        .await
        .expect("body collects successfully")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub async fn handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
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

pub async fn noop_handler(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::empty()))
}

pub fn make_signed_layer(
    config: CookieSessionConfig,
) -> (
    Key,
    CookieSessionManagerLayer<tower_sessions_cookie_store::SignedCookie>,
) {
    let key = Key::generate();
    let layer = CookieSessionManagerLayer::signed(key.clone()).with_config(config);
    (key, layer)
}

pub fn get_session_cookie(res: &Response<Body>) -> Cookie<'static> {
    get_session_cookie_from_headers(res.headers())
}

pub fn get_session_cookie_from_headers(headers: &HeaderMap) -> Cookie<'static> {
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

pub fn cookie_header_value(cookie: &Cookie<'_>) -> String {
    cookie.encoded().to_string()
}

pub fn unsigned_cookie_value(cookie: Cookie<'static>, key: &Key, name: &str) -> String {
    let mut jar = CookieJar::new();
    jar.add_original(cookie);
    jar.signed(key)
        .get(name)
        .expect("signed jar returns session cookie")
        .value()
        .to_string()
}

pub fn decode_record(unsigned_value: &str) -> Record {
    tower_sessions_cookie_store::format::decode_record(unsigned_value)
        .expect("cookie record decodes successfully")
}
