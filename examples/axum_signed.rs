use std::net::SocketAddr;

use axum::{Router, routing::get};
use time::Duration;
use tower_sessions_cookie_store::{
    CookieSessionConfig, CookieSessionManagerLayer, Expiry, Key, SameSite, Session,
};

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
    let session_config = CookieSessionConfig::default()
        // Default: "session"
        .with_name("session")
        // Default: true
        .with_http_only(true)
        // Default: SameSite::Strict
        .with_same_site(SameSite::Strict)
        // Default: None
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
        // Default: true (set to false for local HTTP development)
        .with_secure(false)
        // Default: "/"
        .with_path("/")
        // Default: None
        .without_domain()
        // Default: false
        .with_always_save(false)
        // Default: 4096
        .with_max_cookie_bytes(4096)
        // Default: true
        .with_clear_on_decode_error(true);
    let session_layer = CookieSessionManagerLayer::signed(key).with_config(session_config);

    let app = Router::new().route("/", get(index)).layer(session_layer);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("tcp listener binds successfully");
    let local_addr = listener.local_addr().expect("local address is available");
    println!("listening at http://{local_addr}");

    axum::serve(listener, app)
        .await
        .expect("server runs successfully");
}
