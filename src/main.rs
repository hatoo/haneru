use askama::Template;
use axum::{
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use futures::{stream, Stream, StreamExt};
use hyper::Uri;
use rustls::{Certificate, OwnedTrustAnchor, PrivateKey, ServerConfig, ServerName};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast::{self, Receiver, Sender},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel(16);
    let txs = tx.clone();
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route(
            "/sse",
            get(|| async move { sse_req(txs.subscribe()).await }),
        )
        .nest_service("/static", ServeDir::new("static"));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    println!("Listening on http://{}/", addr);
    tokio::spawn(run_proxy(tx));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Template)]
#[template(path = "index.html")]
struct Index;

// basic handler that responds with a static string
async fn root() -> Index {
    Index
}

async fn tunnel(upgraded: TcpStream, uri: Uri, tx: Sender<Vec<u8>>) -> std::io::Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec![uri.host().unwrap().to_string()]).unwrap();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(cert.serialize_der().unwrap())],
            PrivateKey(cert.serialize_private_key_der()),
        )
        .unwrap();

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut stream_from_client = tls_acceptor.accept(upgraded).await?;

    // Connect to remote server

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth(); // i guess this was previously the default?
    let connector = TlsConnector::from(Arc::new(config));
    let server = TcpStream::connect(uri.authority().unwrap().to_string()).await?;
    let mut stream_to_server = connector
        .connect(ServerName::try_from(uri.host().unwrap()).unwrap(), server)
        .await?;

    let mut resp = Vec::new();
    let mut forward = [0u8; 4 * 1024];

    let req = read_req(&mut stream_from_client).await.unwrap();
    let _ = tx.send(req.clone());

    stream_to_server.write_all(&req).await.unwrap();

    loop {
        tokio::select! {
            res = stream_to_server.read_buf(&mut resp) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    let _ = stream_from_client.write_all(&resp[resp.len() - n..]).await;
                }else {
                    break;
                }
            }
            res = stream_from_client.read(&mut forward) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    let _ = stream_to_server.write_all(&forward[..n]).await;
                }else {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn parse_path(buf: &[u8]) -> Option<Vec<String>> {
    let mut i = 0;

    while *buf.get(i)? != b'\r' {
        i += 1;
    }

    let first_line = std::str::from_utf8(&buf[..i]).ok()?;

    Some(
        first_line
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
    )
}

fn replace_path(buf: Vec<u8>) -> Option<Vec<u8>> {
    let mut i = 0;

    while *buf.get(i)? != b'\r' {
        i += 1;
    }

    let first_line = std::str::from_utf8(&buf[..i]).ok()?;

    let fst = first_line.split_whitespace().collect::<Vec<_>>();
    let uri = Uri::try_from(fst[1]).ok()?;

    let mut ret = Vec::new();

    ret.extend(fst[0].as_bytes());
    ret.push(b' ');
    ret.extend(uri.path_and_query().unwrap().as_str().as_bytes());
    ret.push(b' ');
    ret.extend(fst[2].as_bytes());
    ret.extend(&buf[i..]);

    Some(ret)
}

async fn read_req<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf).unwrap().is_partial()
    } {
        stream.read_buf(&mut buf).await?;
    }
    Ok(buf)
}

async fn read_resp<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        !resp.parse(&buf).unwrap().is_complete()
    } {
        stream.read_buf(&mut buf).await?;
    }
    Ok(buf)
}

async fn proxy_conn(mut stream: TcpStream, tx: Sender<Vec<u8>>) -> anyhow::Result<()> {
    let buf = read_req(&mut stream).await?;

    let fst = parse_path(&buf).unwrap();

    if fst[0].as_str() == "CONNECT" {
        dbg!(&fst);
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await?;
        tunnel(stream, fst[1].parse().unwrap(), tx).await?;
    } else {
        let uri = Uri::try_from(fst[1].as_str()).unwrap();
        let buf = replace_path(buf).unwrap();
        let _ = tx.send(buf.clone());
        let mut server = TcpStream::connect(format!(
            "{}:{}",
            uri.authority().unwrap(),
            uri.port_u16().unwrap_or(80)
        ))
        .await?;

        server.write_all(buf.as_ref()).await?;
        server.shutdown().await?;

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await?;

        stream.write_all(&buf).await?;
        stream.shutdown().await?;
    }
    Ok(())
}

async fn run_proxy(tx: Sender<Vec<u8>>) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));

    let tcp_listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let tx = tx.clone();
        tokio::spawn(async move {
            proxy_conn(stream, tx).await.unwrap();
        });
    }
}

#[derive(Template)]
#[template(path = "request.html")]
struct RequestText<'a> {
    content: &'a str,
}

async fn sse_req(rx: Receiver<Vec<u8>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold(rx, |mut rx| async {
        let req = rx.recv().await.unwrap();

        let text = String::from_utf8(req).unwrap();
        Some((
            Event::default().event("request").data(
                RequestText { content: &text }
                    .to_string()
                    .replace("\r", "&#x0D;")
                    .replace("\n", "&#x0A;"),
            ),
            rx,
        ))
    })
    .map(Ok);

    Sse::new(stream)
}
