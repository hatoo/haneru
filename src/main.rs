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
use httparse::Status;
use hyper::{header, HeaderMap};
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
    let (tx, _) = broadcast::channel::<Arc<RequestLog>>(128);

    let state = Arc::new(Proxy::new(tx.clone()));

    let log_chan = Arc::new(Mutex::new(LogChan::default()));

    let mut rx = tx.subscribe();
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
        .route("/", get(|| async { Live }))
        .route("/log", get(|| async { Log }))
        .route("/log/:id", get(request_log_serial))
        .route("/cert", get(cert))
        .route("/response/:id", get(response))
        .route(
            "/sse/live",
            get(|| async move { sse_req(tx.subscribe()).await }),
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
pub struct RequestLog {
    serial: usize,
    timestamp: std::time::Instant,
    method: String,
    host: String,
    path: String,
    data: Vec<u8>,
}

impl RequestLog {
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

async fn sse_req(
    rx: Receiver<Arc<RequestLog>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
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

#[derive(Debug, Clone)]
pub enum Server<T> {
    Some(T),
    Ongoing,
    Expired,
}

impl<T> Server<T> {
    pub fn is_ongoing(&self) -> bool {
        matches!(self, Self::Ongoing)
    }

    pub fn map<D>(self, f: impl FnOnce(T) -> D) -> Server<D> {
        match self {
            Self::Some(t) => Server::Some(f(t)),
            Self::Ongoing => Server::Ongoing,
            Self::Expired => Server::Expired,
        }
    }
}

pub struct ResponseLog {
    body_length: usize,
    content_type: String,
}

impl ResponseLog {
    pub fn parse(buf: &[u8]) -> Self {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        if let Status::Complete(n) = resp.parse(buf).unwrap() {
            let mut header_map = HeaderMap::new();

            for header in headers.iter().take_while(|h| h != &&httparse::EMPTY_HEADER) {
                header_map.insert(
                    header::HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
                    header::HeaderValue::from_bytes(header.value).unwrap(),
                );
            }

            Self {
                body_length: buf[n..].len(),
                content_type: header_map
                    .get(header::CONTENT_TYPE)
                    .map(|v| v.to_str().unwrap().to_string())
                    .unwrap_or_default(),
            }
        } else {
            todo!()
        }
    }
}

impl Server<ResponseLog> {
    pub fn body_length(&self) -> String {
        match self {
            Server::Some(res) => res.body_length.to_string(),
            _ => "N/A".to_string(),
        }
    }

    pub fn content_type(&self) -> String {
        match self {
            Server::Some(res) => res.content_type.clone(),
            _ => "N/A".to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "request_tr.html")]
struct RequestTR {
    request: Arc<RequestLog>,
    response: Server<ResponseLog>,
}

fn req_to_event(req: Arc<RequestLog>, state: &Proxy) -> Event {
    let response = state
        .try_response(req.serial)
        .map(|resp| ResponseLog::parse(&resp));

    Event::default().event("request").data(replace_cr(
        RequestTR {
            request: req,
            response,
        }
        .to_string()
        .as_str(),
    ))
}

async fn request_log(
    log_chan: Arc<Mutex<LogChan<Arc<RequestLog>>>>,
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
struct Log;

async fn request_log_serial(Path(id): Path<usize>, state: State<Arc<Proxy>>) -> impl IntoResponse {
    let Some(req) = state.request(id) else {
        return "NOT FOUND".to_string();
    };

    let response = if let Some(data) = state.response(id).await {
        Server::Some(ResponseLog::parse(&data))
    } else {
        Server::Expired
    };

    RequestTR {
        request: req,
        response,
    }
    .to_string()
}
