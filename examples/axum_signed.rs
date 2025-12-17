use std::net::SocketAddr;

use axum::{Router, routing::get};
use tower_sessions_cookie_store::{CookieSessionConfig, CookieSessionManagerLayer, Key, Session};

async fn index(session: Session) -> String {
    let n: usize = session
        .get("n")
        .await
        .expect("session get succeeds")
        .unwrap_or(0);
    session
        .insert("n", n + 1)
        .await
        .expect("session insert succeeds");
    format!("n={n}")
}

#[tokio::main]
async fn main() {
    let key = Key::generate();
    let session_config = CookieSessionConfig::default().with_secure(false);
    let session_layer = CookieSessionManagerLayer::signed(key).with_config(session_config);

    let app = Router::new().route("/", get(index)).layer(session_layer);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("tcp listener binds successfully");

    axum::serve(listener, app)
        .await
        .expect("server runs successfully");
}
