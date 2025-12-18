#![cfg(feature = "private")]

// Smoke test for the private-cookie backend: writing to the session should emit `Set-Cookie`.
use axum::body::Body;
use http::{Request, header};
use tower::{ServiceBuilder, ServiceExt as _};

use tower_sessions_cookie_store::{CookieSessionManagerLayer, Key};

#[tokio::test]
async fn private_cookie_sets_set_cookie() {
    // Exercise: handler inserts a value into the session with private cookies enabled.
    // Expectation: response includes a `Set-Cookie` header.
    async fn handler(req: Request<Body>) -> Result<http::Response<Body>, std::convert::Infallible> {
        let session = req
            .extensions()
            .get::<tower_sessions_cookie_store::Session>()
            .cloned()
            .expect("request includes Session extension");
        session
            .insert("foo", 42)
            .await
            .expect("session insert succeeds");
        Ok(http::Response::new(Body::empty()))
    }

    let key = Key::generate();
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
