use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Context;
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response, Server};

use hyper_tls::HttpsConnector;
use tokio_rustls::TlsAcceptor;

use crate::server_config;

type HttpsClient = Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

pub async fn run_proxy() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3003));

    let https = HttpsConnector::new();
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build::<_, hyper::Body>(https);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| proxy(client.clone(), req))) }
    });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn proxy(client: HttpsClient, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("req: {:?}", req);

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        tokio::task::spawn(async move {
            let uri = req.uri().clone();
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(client, upgraded, &uri).await {
                        eprintln!("server io error: {}", e);
                    };
                }
                Err(e) => eprintln!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else {
        client.request(req).await
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(client: HttpsClient, upgraded: Upgraded, uri: &http::Uri) -> anyhow::Result<()> {
    let server_config = server_config(uri.host().context("no host on path")?.to_string());
    let tls_acceptor = TlsAcceptor::from(server_config);
    let conn = tls_acceptor.accept(upgraded).await?;

    let authority = uri.authority().unwrap().to_string();

    Http::new()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve_connection(
            conn,
            service_fn(move |req| mitm(client.clone(), authority.clone(), req)),
        )
        .await?;

    Ok(())
}

async fn mitm(
    client: HttpsClient,
    authority: String,
    mut req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    println!("req: {:?}", req);

    let uri = req.uri().clone();
    let mut parts = uri.into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTPS);
    parts.authority = Some(http::uri::Authority::from_str(&authority).unwrap());
    *req.uri_mut() = http::Uri::from_parts(parts).unwrap();

    client.request(req).await
}
