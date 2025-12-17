#![cfg(feature = "signed")]

mod common;

use axum::body::Body;
use http::{Request, header};
use tower::{ServiceBuilder, ServiceExt as _};

use tower_sessions_cookie_store::{CookieSessionConfig, SameSite};

const COOKIE_NAME: &str = "session";

#[tokio::test]
async fn basic_service() {
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc
        .clone()
        .oneshot(req)
        .await
        .expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    let req = Request::builder()
        .header(header::COOKIE, common::cookie_header_value(&session_cookie))
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");

    assert!(res.headers().get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn bogus_cookie() {
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .header(header::COOKIE, "session=bogus")
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");

    assert!(res.headers().get(header::SET_COOKIE).is_some());
}

#[tokio::test]
async fn no_set_cookie_when_unused() {
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::noop_handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");

    assert!(res.headers().get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn name() {
    let config = CookieSessionConfig::default().with_name("my.sid");
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.name(), "my.sid");
}

#[tokio::test]
async fn http_only() {
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.http_only(), Some(true));

    let config = CookieSessionConfig::default().with_http_only(false);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.http_only(), None);
}

#[tokio::test]
async fn same_site_strict() {
    let config = CookieSessionConfig::default().with_same_site(SameSite::Strict);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.same_site(), Some(SameSite::Strict));
}

#[tokio::test]
async fn same_site_lax() {
    let config = CookieSessionConfig::default().with_same_site(SameSite::Lax);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.same_site(), Some(SameSite::Lax));
}

#[tokio::test]
async fn same_site_none() {
    let config = CookieSessionConfig::default().with_same_site(SameSite::None);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.same_site(), Some(SameSite::None));
}

#[tokio::test]
async fn secure() {
    let config = CookieSessionConfig::default().with_secure(true);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.secure(), Some(true));

    let config = CookieSessionConfig::default().with_secure(false);
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.secure(), None);
}

#[tokio::test]
async fn path() {
    let config = CookieSessionConfig::default().with_path("/foo/bar");
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.path(), Some("/foo/bar"));
}

#[tokio::test]
async fn domain() {
    let config = CookieSessionConfig::default().with_domain("example.com");
    let (_key, layer) = common::make_signed_layer(config);
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.domain(), Some("example.com"));
}

#[tokio::test]
async fn cookie_name_default() {
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.name(), COOKIE_NAME);
}
