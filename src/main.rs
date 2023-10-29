use anyhow::Context;
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Path, State},
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use clap::Parser;
use futures::{stream, Stream, StreamExt};
use http::parse_path;
use hyper::header;
use rcgen::CertificateParams;
use sse::replace_cr;
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{
        broadcast::{self, Receiver},
        Mutex,
    },
};
use tower_http::services::ServeDir;

use crate::{log_chan::LogChan, proxy::Proxy};

mod http;
mod log_chan;
mod proxy;
mod sse;

static ROOT_CERT: tokio::sync::OnceCell<rcgen::Certificate> = tokio::sync::OnceCell::const_new();
async fn root_cert() -> &'static rcgen::Certificate {
    ROOT_CERT
        .get_or_init(|| async {
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

    rcgen::Certificate::from_params(cert_params).unwrap()
}

#[derive(clap::Parser)]
struct Opt {
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
        ROOT_CERT
            .set(rcgen::Certificate::from_params(param).unwrap())
            .map_err(|_| anyhow::anyhow!("failed to set root cert"))
            .unwrap();
    }
    let (tx, _) = broadcast::channel::<Arc<Request>>(128);
    let txs = tx.clone();

    let state = Arc::new(Proxy::default());

    let log_chan = Arc::new(Mutex::new(LogChan::default()));

    let mut rx = txs.subscribe();
    let lc = log_chan.clone();
    tokio::spawn(async move {
        loop {
            let req = rx.recv().await.unwrap();

            let mut lock = lc.lock().await;
            lock.push(req.clone());
        }
    });

    let state_app = state.clone();
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(|| async { Live }))
        .route("/log", get(|| async { RequestLog }))
        .route("/log/:id", get(request_log_serial))
        .route("/cert", get(cert))
        .route("/response/:id", get(response))
        .route(
            "/sse/live",
            get(|| async move { sse_req(txs.subscribe()).await }),
        )
        .route(
            "/sse/log",
            get(|state| async move { request_log(log_chan.clone(), state).await }),
        )
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state_app);

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
#[template(path = "live.html")]
struct Live;

#[derive(Debug, Clone)]
pub struct Request {
    serial: usize,
    timestamp: std::time::Instant,
    method: String,
    host: String,
    path: String,
    data: Vec<u8>,
}

impl Request {
    fn new(serial: usize, host: String, data: Vec<u8>) -> anyhow::Result<Self> {
        let [method, path, _version] =
            parse_path(&data).context("failed to parse the first line")?;
        Ok(Self {
            serial,
            timestamp: std::time::Instant::now(),
            method,
            host,
            path,
            data,
        })
    }
}

async fn run_proxy(state: Arc<Proxy>) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));

    let tcp_listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|_| panic!("failed to bind {}", &addr));
    println!("HTTP Proxy is Listening on http://{}/", addr);

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = proxy::proxy(stream, state).await {
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

async fn sse_req(rx: Receiver<Arc<Request>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold(rx, |mut rx| async {
        let req = rx.recv().await.unwrap();

        let text =
            String::from_utf8(req.data.clone()).unwrap_or_else(|_| "invalid utf-8".to_string());
        Some((
            Event::default().event("request").data(replace_cr(
                RequestText {
                    id: req.serial,
                    content: &text,
                }
                .to_string()
                .as_str(),
            )),
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
async fn response(Path(id): Path<usize>, state: State<Arc<Proxy>>) -> impl IntoResponse {
    let Some(resp) = state.response(id).await else {
        return ResponseText {
            content: "Not Found".to_string(),
        };
    };
    let content = String::from_utf8(resp.as_ref().clone())
        .unwrap_or_else(|_| "Not Valid UTF-8 string".to_string());

    ResponseText { content }
}

#[derive(Template)]
#[template(path = "request_tr.html")]
struct RequestTR {
    request: Arc<Request>,
    response_size: Option<usize>,
}

fn req_to_event(req: Arc<Request>, state: &Proxy) -> Event {
    let response_size = state
        .try_response(req.serial)
        .map(|resp| response_body_size(&resp));

    Event::default().event("request").data(replace_cr(
        RequestTR {
            request: req,
            response_size,
        }
        .to_string()
        .as_str(),
    ))
}

fn response_body_size(response: &[u8]) -> usize {
    let mut headers = [httparse::EMPTY_HEADER; 64];

    if let httparse::Status::Complete(n) = httparse::Response::new(&mut headers)
        .parse(response)
        .unwrap()
    {
        n
    } else {
        0
    }
}

async fn request_log(
    log_chan: Arc<Mutex<LogChan<Arc<Request>>>>,
    state: State<Arc<Proxy>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let state2 = state.clone();
    let (log, rx) = log_chan.lock().await.now_and_future();
    let stream = stream::iter(log.into_iter().map(move |req| req_to_event(req, &state)))
        .chain(stream::unfold(
            (rx, state2),
            move |(mut rx, state)| async move {
                let req = rx.recv().await.unwrap();

                Some((req_to_event(req, &state), (rx, state)))
            },
        ))
        .map(Ok);

    Sse::new(stream)
}

#[derive(Template)]
#[template(path = "request_log.html")]
struct RequestLog;

async fn request_log_serial(Path(id): Path<usize>, state: State<Arc<Proxy>>) -> impl IntoResponse {
    let Some(req) = state.request(id) else {
        return "NOT FOUND".to_string();
    };

    let response_size = if let Some(data) = state.response(id).await {
        Some(response_body_size(&data))
    } else {
        Some(0)
    };

    RequestTR {
        request: req,
        response_size,
    }
    .to_string()
}
