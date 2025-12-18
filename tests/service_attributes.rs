#![cfg(feature = "signed")]

// Tests for how `CookieSessionConfig` maps to emitted cookie attributes when using the signed
// cookie backend.
mod common;

use axum::body::Body;
use http::{Request, header};
use tower::{ServiceBuilder, ServiceExt as _};

use tower_sessions_cookie_store::{CookieSessionConfig, DEFAULT_COOKIE_NAME, SameSite};

#[tokio::test]
async fn basic_service() {
    // Exercise: first request writes to the session (causing a cookie to be set), then the second
    // request sends that cookie back.
    // Expectation: the second request is "session read only" for the handler, so no `Set-Cookie`
    // should be emitted.
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
    // Exercise: the client sends a `Cookie` header with the session cookie name but an invalid
    // value ("bogus") which cannot be decoded/verified.
    // Expectation: the layer should recover by issuing a `Set-Cookie` (clearing/overwriting the
    // broken cookie) so the client doesn't keep sending an invalid value forever.
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
    // Exercise: handler does not touch session state at all.
    // Expectation: no `Set-Cookie` should be emitted.
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
    // Exercise: configure a custom cookie name via `with_name`.
    // Expectation: emitted cookie name matches the configured value.
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
    // Exercise: default `HttpOnly=true`, then toggle to `HttpOnly=false`.
    // Expectation: attribute is present by default and absent when disabled.
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
    // Exercise: explicitly set SameSite=Strict.
    // Expectation: emitted cookie contains SameSite=Strict.
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
    // Exercise: set SameSite=Lax.
    // Expectation: emitted cookie contains SameSite=Lax.
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
    // Exercise: set SameSite=None.
    // Expectation: emitted cookie contains SameSite=None.
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
    // Exercise: set `Secure=true`, then set `Secure=false`.
    // Expectation: attribute is present when enabled and absent when disabled.
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
    // Exercise: set a custom cookie Path.
    // Expectation: emitted cookie contains the configured Path.
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
    // Exercise: set a cookie Domain.
    // Expectation: emitted cookie contains the configured Domain.
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
    // Exercise: default configuration.
    // Expectation: cookie name defaults to `session`.
    let (_key, layer) = common::make_signed_layer(CookieSessionConfig::default());
    let svc = ServiceBuilder::new()
        .layer(layer)
        .service_fn(common::handler);

    let req = Request::builder()
        .body(Body::empty())
        .expect("request builds successfully");
    let res = svc.oneshot(req).await.expect("service call succeeds");
    let session_cookie = common::get_session_cookie(&res);

    assert_eq!(session_cookie.name(), DEFAULT_COOKIE_NAME);
}
