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
use http::ParsedRequest;
use httparse::Status;
use hyper::{header, HeaderMap};
use rcgen::CertificateParams;
use sqlx::SqlitePool;
use sse::replace_cr;
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::broadcast::{self},
};
use tower_http::services::ServeDir;

use crate::proxy::Proxy;

mod db;
mod http;
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
        ROOT_CERT
            .set(rcgen::Certificate::from_params(param).unwrap())
            .map_err(|_| anyhow::anyhow!("failed to set root cert"))
            .unwrap();
    }
    let (request_tx, _) = broadcast::channel::<i64>(128);
    let (response_tx, _) = broadcast::channel::<i64>(128);

    let pool = SqlitePool::connect(&format!("sqlite:{}", &args.sqlite3))
        .await
        .unwrap();
    db::add_schema(&pool).await.unwrap();
    let state = Arc::new(Proxy::new(request_tx.clone(), response_tx.clone(), pool));

    let state_app = state.clone();
    // build our application with a route
    let app = Router::new()
        .route("/", get(|| async { Live }))
        .route("/cert", get(cert))
        .route("/log", get(|| async { LogHtml }))
        .route("/log/:id", get(request_log_serial))
        .route("/detail/:id", get(detail))
        .route("/response/:id", get(response))
        .route("/sse/live", get(sse_req))
        .route(
            "/sse/log",
            get(|state| async move { request_log(state).await }),
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
    timestamp: chrono::DateTime<chrono::Local>,
    host: String,
    parsed_request: ParsedRequest,
}

impl RequestLog {
    fn new(serial: usize, host: String, data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            serial,
            timestamp: chrono::Local::now(),
            host,
            parsed_request: ParsedRequest::new(data)?,
        })
    }

    pub fn timestamp(&self) -> String {
        self.timestamp.format("%H:%M:%S").to_string()
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
                eprintln!("Error: {:?}", err);
            }
        });
    }
}

#[derive(Template)]
#[template(path = "request.html")]
struct RequestHtml<'a> {
    id: i64,
    content: &'a str,
}

async fn sse_req(state: State<Arc<Proxy>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.request_tx.subscribe();
    let state = state.0.clone();
    let stream = stream::unfold((rx, state), |(mut rx, state)| async {
        let id = rx.recv().await.unwrap();
        let req = state.request(id).await.unwrap().unwrap();

        let text =
            String::from_utf8(req.data.clone()).unwrap_or_else(|_| "invalid utf-8".to_string());
        Some((
            Event::default().event("request").data(replace_cr(
                RequestHtml {
                    id: req.id,
                    content: &text,
                }
                .to_string()
                .as_str(),
            )),
            (rx, state),
        ))
    })
    .map(Ok);

    Sse::new(stream)
}

#[derive(Template)]
#[template(path = "response.html")]
struct ResponseHtml {
    content: String,
}
async fn response(Path(id): Path<i64>, state: State<Arc<Proxy>>) -> impl IntoResponse {
    let Ok(resp) = state.response(id).await else {
        return ResponseHtml {
            content: "Not Found".to_string(),
        };
    };
    let content =
        String::from_utf8(resp.data).unwrap_or_else(|_| "Not Valid UTF-8 string".to_string());

    ResponseHtml { content }
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
struct RequestTrHtml {
    request: db::Request,
    response: Option<ResponseLog>,
}

fn req_to_event(req: db::Request, state: &Proxy) -> Event {
    Event::default().event("request").data(replace_cr(
        RequestTrHtml {
            request: req,
            response: None,
        }
        .to_string()
        .as_str(),
    ))
}

async fn request_log(
    state: State<Arc<Proxy>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let state2 = state.clone();
    let (log, rx) = state.now_and_future().await.unwrap();
    let stream = stream::iter(log.into_iter().map(move |req| req_to_event(req, &state)))
        .chain(stream::unfold(
            (rx, state2),
            move |(mut rx, state)| async move {
                let id = rx.recv().await.unwrap();
                let req = state.request(id).await.unwrap().unwrap();

                Some((req_to_event(req, &state), (rx, state)))
            },
        ))
        .map(Ok);

    Sse::new(stream)
}

#[derive(Template)]
#[template(path = "request_log.html")]
struct LogHtml;

async fn request_log_serial(Path(id): Path<i64>, state: State<Arc<Proxy>>) -> impl IntoResponse {
    let Ok(Some(req)) = state.request(id).await else {
        return "NOT FOUND".to_string();
    };

    let Ok(response) = state.response(id).await else {
        return "NOT FOUND".to_string();
    };

    RequestTrHtml {
        request: req,
        response: Some(ResponseLog::parse(&response.data)),
    }
    .to_string()
}

#[derive(Template)]
#[template(path = "detail.html")]
struct DetailHtml {
    request: String,
}

async fn detail(Path(id): Path<i64>, state: State<Arc<Proxy>>) -> DetailHtml {
    let request = state.request(id).await.unwrap();
    let request = request
        .map(|r| String::from_utf8_lossy(r.data.as_slice()).to_string())
        .unwrap_or_default();
    DetailHtml { request }
}
