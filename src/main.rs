use askama::Template;
use askama_axum::IntoResponse;
use async_cell::sync::AsyncCell;
use axum::{
    extract::Path,
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use futures::{stream, Stream, StreamExt};
use hyper::{header, Uri};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use rcgen::{CertificateParams, KeyPair};
use rustls::{OwnedTrustAnchor, PrivateKey, ServerConfig, ServerName};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast::{self, Receiver, Sender},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower_http::services::ServeDir;

const ROOT_CERT: Lazy<rcgen::Certificate> = Lazy::new(|| {
    rcgen::Certificate::from_params(
        rcgen::CertificateParams::from_ca_cert_pem(
            include_str!("../certs/ca.crt"),
            KeyPair::from_pem(include_str!("../certs/ca.key")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
});

fn make_cert(hosts: Vec<String>) -> (rustls::Certificate, PrivateKey) {
    let cert_params = CertificateParams::new(hosts);
    let cert = rcgen::Certificate::from_params(cert_params).unwrap();

    (
        rustls::Certificate(cert.serialize_der_with_signer(&ROOT_CERT).unwrap()),
        PrivateKey(cert.serialize_private_key_der()),
    )
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel(16);
    let txs = tx.clone();

    let state = Arc::new(Proxy {
        tx,
        id_counter: AtomicUsize::new(0),
        map: Cache::new(2048),
    });

    let state_app = state.clone();
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/cert", get(cert))
        .route(
            "/response/:id",
            get(move |id| response(id, state_app.clone())),
        )
        .route(
            "/sse",
            get(|| async move { sse_req(txs.subscribe()).await }),
        )
        .nest_service("/static", ServeDir::new("static"));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    println!("Listening on http://{}/", addr);
    tokio::spawn(run_proxy(state));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn cert() -> impl IntoResponse {
    let headers = axum::http::HeaderMap::from_iter([(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"ca.crt\"".try_into().unwrap(),
    )]);

    (headers, ROOT_CERT.serialize_pem().unwrap())
}

#[derive(Template)]
#[template(path = "index.html")]
struct Index;

// basic handler that responds with a static string
async fn root() -> Index {
    Index
}

async fn tunnel<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    upgraded: S,
    uri: Uri,
    state: Arc<Proxy>,
) -> std::io::Result<()> {
    let (cert, private_key) = make_cert(vec![uri.host().unwrap().to_string()]);
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], private_key)
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

    let req = read_req(&mut stream_from_client).await.unwrap();
    let cell = state.new_req(req.clone());

    stream_to_server.write_all(&req).await.unwrap();

    let resp = sniff(stream_from_client, stream_to_server).await;

    cell.set(resp);

    Ok(())
}

fn parse_path(buf: &[u8]) -> Option<[String; 3]> {
    let mut i = 0;

    while *buf.get(i)? != b'\r' {
        i += 1;
    }

    let first_line = std::str::from_utf8(&buf[..i]).ok()?;

    first_line
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
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

async fn proxy<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    state: Arc<Proxy>,
) -> anyhow::Result<()> {
    let buf = read_req(&mut stream).await?;

    let [method, path, _version] = parse_path(&buf).unwrap();

    if method == "CONNECT" {
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await?;
        tunnel(stream, path.parse().unwrap(), state).await?;
    } else {
        let uri = Uri::try_from(path.as_str()).unwrap();
        let buf = replace_path(buf).unwrap();
        let cell = state.new_req(buf.clone());
        let mut server = TcpStream::connect(format!(
            "{}:{}",
            uri.host().unwrap(),
            uri.port_u16().unwrap_or(80)
        ))
        .await
        .unwrap();

        server.write_all(buf.as_ref()).await?;
        let resp = sniff(stream, server).await;
        cell.set(resp);
    }
    Ok(())
}

async fn sniff<
    S1: AsyncReadExt + AsyncWriteExt + Unpin,
    S2: AsyncReadExt + AsyncWriteExt + Unpin,
>(
    mut client: S1,
    mut server: S2,
) -> Vec<u8> {
    let mut resp = Vec::new();
    let mut forward = [0u8; 4 * 1024];
    loop {
        tokio::select! {
            res = server.read_buf(&mut resp) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    if client.write_all(&resp[resp.len() - n..]).await.is_err() {
                        break;
                    }
                    client.flush().await.unwrap();
                } else {
                    break;
                }
            }
            res = client.read(&mut forward) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    if server.write_all(&forward[..n]).await.is_err() {
                        break;
                    }
                    server.flush().await.unwrap();
                } else {
                    break;
                }
            }
        }
    }
    resp
}

struct Proxy {
    tx: Sender<(usize, Vec<u8>)>,
    id_counter: AtomicUsize,
    map: Cache<usize, Arc<AsyncCell<Vec<u8>>>>,
}

impl Proxy {
    fn new_req(&self, req: Vec<u8>) -> Arc<AsyncCell<Vec<u8>>> {
        let id = self
            .id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = self.tx.send((id, req));
        let cell = Arc::new(AsyncCell::default());
        self.map.insert(id, cell.clone());
        cell
    }
}

async fn run_proxy(state: Arc<Proxy>) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));

    let tcp_listener = TcpListener::bind(addr).await?;
    println!("HTTP Proxy is Listening on http://{}/", addr);

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            proxy(stream, state).await.unwrap();
        });
    }
}

#[derive(Template)]
#[template(path = "request.html")]
struct RequestText<'a> {
    id: usize,
    content: &'a str,
}

async fn sse_req(
    rx: Receiver<(usize, Vec<u8>)>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold(rx, |mut rx| async {
        let (id, req) = rx.recv().await.unwrap();

        let text = String::from_utf8(req).unwrap();
        Some((
            Event::default().event("request").data(
                RequestText { id, content: &text }
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

#[derive(Template)]
#[template(path = "response.html")]
struct ResponseText {
    content: String,
}
async fn response(Path(id): Path<usize>, state: Arc<Proxy>) -> impl IntoResponse {
    let Some(cell) = state.map.get(&id) else {
        return ResponseText {
            content: "Not Found".to_string(),
        };
    };
    let resp = cell.get().await;
    let content = String::from_utf8(resp).unwrap_or_else(|_| "Not Found".to_string());

    ResponseText { content }
}
