use anyhow::Context;
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
use http::{read_req, read_resp};
use hyper::{client::conn, header, Uri};
use moka::sync::Cache;
use rcgen::CertificateParams;
use rustls::{OwnedTrustAnchor, ServerConfig, ServerName};
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

mod http;

async fn root_cert() -> &'static rcgen::Certificate {
    static ONCE: tokio::sync::OnceCell<rcgen::Certificate> = tokio::sync::OnceCell::const_new();

    ONCE.get_or_init(|| async {
        let mut param = rcgen::CertificateParams::default();

        param.distinguished_name = rcgen::DistinguishedName::new();
        param.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("<HANERU CA>".to_string()),
        );
        param.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rcgen::Certificate::from_params(param).unwrap()
    })
    .await
}

fn make_cert(hosts: Vec<String>) -> rcgen::Certificate {
    let mut cert_params = CertificateParams::new(hosts);
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let cert = rcgen::Certificate::from_params(cert_params).unwrap();

    cert
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel(128);
    let txs = tx.clone();

    let state = Arc::new(Proxy {
        tx,
        id_counter: AtomicUsize::new(0),
        map: Cache::new(128),
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
        header::HeaderValue::from_static("attachment; filename=\"ca.crt\""),
    )]);

    (headers, root_cert().await.serialize_pem().unwrap())
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
) -> anyhow::Result<()> {
    let cert = make_cert(vec![uri.host().unwrap().to_string()]);
    let signed = cert.serialize_der_with_signer(root_cert().await)?;
    let private_key = cert.get_key_pair().serialize_der();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(signed)],
            rustls::PrivateKey(private_key),
        )?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client = tls_acceptor.accept(upgraded).await?;

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
    let server = TcpStream::connect(uri.authority().context("no authority")?.to_string()).await?;
    let server = connector
        .connect(
            ServerName::try_from(uri.host().context("no host")?)?,
            server,
        )
        .await?;

    conn_loop(client, server, state).await?;

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

async fn proxy<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    state: Arc<Proxy>,
) -> anyhow::Result<()> {
    let (buf, has_upgrade) = read_req(&mut stream).await?;

    let [method, path, _version] = parse_path(&buf).context("failed to parse the first line")?;

    if method == "CONNECT" {
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
        tunnel(stream, path.parse()?, state).await?;
    } else {
        let uri = Uri::try_from(path.as_str())?;
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

        if has_upgrade {
            let resp = sniff(stream, server).await;
            cell.set(resp);
        } else {
            let resp = read_resp(&mut server).await?;
            stream.write_all(resp.as_ref()).await?;
            cell.set(resp);

            conn_loop(stream, server, state).await?;
        };
    }
    Ok(())
}

async fn conn_loop<
    S1: AsyncReadExt + AsyncWriteExt + Unpin,
    S2: AsyncReadExt + AsyncWriteExt + Unpin,
>(
    mut client: S1,
    mut server: S2,
    state: Arc<Proxy>,
) -> anyhow::Result<()> {
    loop {
        let (req, has_upgrade) = read_req(&mut client).await?;
        let cell = state.new_req(req.clone());

        if has_upgrade {
            let resp = sniff(client, server).await;
            cell.set(resp);
            break;
        } else {
            server.write_all(&req).await?;
            let resp = read_resp(&mut server).await?;
            client.write_all(resp.as_ref()).await?;
            cell.set(resp);
        }
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

    let tcp_listener = TcpListener::bind(addr)
        .await
        .expect(&format!("failed to bind {}", &addr));
    println!("HTTP Proxy is Listening on http://{}/", addr);

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = proxy(stream, state).await {
                eprintln!("Error: {}", err);
            }
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
    let content = String::from_utf8(resp).unwrap_or_else(|_| "Not Valid UTF-8 string".to_string());

    ResponseText { content }
}
