use std::{net::SocketAddr, path::PathBuf};

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;

mod tls;

#[derive(clap::Parser)]
struct Opt {
    #[clap(short, long, default_value = ":memory:")]
    sqlite3: String,
    #[clap(short, long, requires("private_key"))]
    cert: Option<PathBuf>,
    #[clap(short, long, requires("cert"))]
    private_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Opt::parse();

    if let (Some(cert), Some(private_key)) = (args.cert, args.private_key) {
        let param = rcgen::CertificateParams::from_ca_cert_pem(
            &std::fs::read_to_string(cert).unwrap(),
            rcgen::KeyPair::from_pem(&std::fs::read_to_string(private_key).unwrap()).unwrap(),
        )
        .unwrap();
        tls::ROOT_CERT
            .set(rcgen::Certificate::from_params(param).unwrap())
            .map_err(|_| anyhow::anyhow!("failed to set root cert"))
            .unwrap();
    }

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
