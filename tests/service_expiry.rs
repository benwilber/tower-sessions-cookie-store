#![cfg(feature = "signed")]

// Tests for expiry policy behavior and how expiry settings map to cookie Max-Age semantics.
mod common;

use axum::body::Body;
use http::Request;
use time::{Duration, OffsetDateTime};
use tower::{ServiceBuilder, ServiceExt as _};
use tower_service::Service as _;

use tower_sessions_cookie_store::{CookieSessionConfig, DEFAULT_COOKIE_NAME, Expiry};

fn assert_max_age_seconds_close(cookie: &tower_cookies::Cookie<'_>, expected_seconds: i64) {
    // Max-Age is computed relative to "now", so assertions allow a small amount of clock drift.
    let actual_seconds = cookie
        .max_age()
        .expect("session cookie has max-age")
        .whole_seconds();
    assert!((actual_seconds - expected_seconds).abs() <= 1);
}

#[tokio::test]
async fn expiry_on_session_end() {
    // Exercise: `Expiry::OnSessionEnd`.
    // Expectation: cookie has no Max-Age (session cookie).
    let config = CookieSessionConfig::default().with_expiry(Expiry::OnSessionEnd);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert!(session_cookie.max_age().is_none());
}

#[tokio::test]
async fn expiry_on_inactivity() {
    // Exercise: `Expiry::OnInactivity(d)`.
    // Expectation: cookie Max-Age is approximately `d`.
    let inactivity = Duration::hours(2);
    let config = CookieSessionConfig::default().with_expiry(Expiry::OnInactivity(inactivity));
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_max_age_seconds_close(&session_cookie, inactivity.whole_seconds());
}

#[tokio::test]
async fn expiry_at_date_time() {
    // Exercise: `Expiry::AtDateTime(t)`.
    // Expectation: cookie Max-Age is approximately `t - now`.
    let expiry_time = OffsetDateTime::now_utc() + Duration::weeks(1);
    let config = CookieSessionConfig::default().with_expiry(Expiry::AtDateTime(expiry_time));
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    let expected = (expiry_time - OffsetDateTime::now_utc()).whole_seconds();
    assert_max_age_seconds_close(&session_cookie, expected);
}

#[tokio::test]
async fn expiry_on_session_end_always_save() {
    // Exercise: `always_save=true` with a session cookie expiry policy.
    // Expectation: subsequent requests refresh the record expiry date (in the cookie payload) even
    // though Max-Age is absent and the session ID stays the same.
    let config = CookieSessionConfig::default()
        .with_expiry(Expiry::OnSessionEnd)
        .with_always_save(true);
    let (key, layer) = common::make_signed_layer(config);
    let mut svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req1 = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res1 = svc.call(req1).await.expect("service call succeeds");
    let cookie1 = common::get_session_cookie(&res1);
    let rec1 = common::decode_record(&common::unsigned_cookie_value(
        cookie1.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    let req2 = Request::builder()
        .header(http::header::COOKIE, common::cookie_header_value(&cookie1))
        .body(Body::empty())
        .expect("request builds successfully");
    let res2 = svc.call(req2).await.expect("service call succeeds");
    let cookie2 = common::get_session_cookie(&res2);
    let rec2 = common::decode_record(&common::unsigned_cookie_value(
        cookie2.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    assert!(cookie2.max_age().is_none());
    assert_eq!(rec1.id, rec2.id);
    assert!(rec1.expiry_date < rec2.expiry_date);
}

#[tokio::test]
async fn expiry_on_inactivity_always_save() {
    // Exercise: `always_save=true` with inactivity expiry.
    // Expectation: subsequent requests refresh the record expiry date and Max-Age stays near the
    // configured inactivity duration.
    let inactivity = Duration::hours(2);
    let config = CookieSessionConfig::default()
        .with_expiry(Expiry::OnInactivity(inactivity))
        .with_always_save(true);
    let (key, layer) = common::make_signed_layer(config);
    let mut svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req1 = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res1 = svc.call(req1).await.expect("service call succeeds");
    let cookie1 = common::get_session_cookie(&res1);
    let rec1 = common::decode_record(&common::unsigned_cookie_value(
        cookie1.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    let req2 = Request::builder()
        .header(http::header::COOKIE, common::cookie_header_value(&cookie1))
        .body(Body::empty())
        .expect("request builds successfully");
    let res2 = svc.call(req2).await.expect("service call succeeds");
    let cookie2 = common::get_session_cookie(&res2);
    let rec2 = common::decode_record(&common::unsigned_cookie_value(
        cookie2.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    assert_max_age_seconds_close(&cookie2, inactivity.whole_seconds());
    assert_eq!(rec1.id, rec2.id);
    assert!(rec1.expiry_date < rec2.expiry_date);
}

#[tokio::test]
async fn expiry_at_date_time_always_save() {
    // Exercise: `always_save=true` with an absolute expiry.
    // Expectation: subsequent requests refresh the cookie but keep the same absolute record expiry
    // date (so Max-Age stays near `t - now`).
    let expiry_time = OffsetDateTime::now_utc() + Duration::weeks(1);
    let config = CookieSessionConfig::default()
        .with_expiry(Expiry::AtDateTime(expiry_time))
        .with_always_save(true);
    let (key, layer) = common::make_signed_layer(config);
    let mut svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req1 = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res1 = svc.call(req1).await.expect("service call succeeds");
    let cookie1 = common::get_session_cookie(&res1);
    let rec1 = common::decode_record(&common::unsigned_cookie_value(
        cookie1.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    let req2 = Request::builder()
        .header(http::header::COOKIE, common::cookie_header_value(&cookie1))
        .body(Body::empty())
        .expect("request builds successfully");
    let res2 = svc.call(req2).await.expect("service call succeeds");
    let cookie2 = common::get_session_cookie(&res2);
    let rec2 = common::decode_record(&common::unsigned_cookie_value(
        cookie2.clone(),
        &key,
        DEFAULT_COOKIE_NAME,
    ));

    let expected = (expiry_time - OffsetDateTime::now_utc()).whole_seconds();
    assert_max_age_seconds_close(&cookie2, expected);
    assert_eq!(rec1.id, rec2.id);
    assert_eq!(rec1.expiry_date, rec2.expiry_date);
}
