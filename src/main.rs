use std::net::SocketAddr;

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;

mod tls;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Listening on http://{}/", addr);

    let app1 = app.clone();
    tokio::spawn(async move { axum::serve(listener, app1).await.unwrap() });

    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));
    let tls_config = tls::server_config21("127.0.0.1:3002".to_string());
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Listening on https://{}/", addr);
    axum_server::from_tcp_rustls(
        listener.into_std().unwrap(),
        RustlsConfig::from_config(tls_config),
    )
    .serve(app.into_make_service())
    .await
    .unwrap()
}
