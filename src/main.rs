use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use clap::Parser;
use futures::{stream, Stream, StreamExt};
use hyper::header;
use rcgen::CertificateParams;
use rustls::ServerConfig;
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
mod template;

static ROOT_CERT: std::sync::OnceLock<rcgen::Certificate> = std::sync::OnceLock::new();
fn root_cert() -> &'static rcgen::Certificate {
    ROOT_CERT.get_or_init(|| {
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
}

fn server_config(host: String) -> Arc<ServerConfig> {
    use moka::sync::Cache;
    static CACHE: std::sync::OnceLock<Cache<String, Arc<ServerConfig>>> =
        std::sync::OnceLock::new();

    CACHE
        .get_or_init(|| Cache::new(256))
        .get_with(host.clone(), || {
            let mut cert_params = CertificateParams::new(vec![host.into()]);
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
            let signed = cert.serialize_der_with_signer(root_cert()).unwrap();
            let private_key = cert.get_key_pair().serialize_der();
            let server_config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::Certificate(signed)],
                    rustls::PrivateKey(private_key),
                )
                .unwrap();
            Arc::new(server_config)
        })
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
        .route("/log", get(|q: Query<Q>| async move { LogHtml { q: q.0 } }))
        .route("/log/:id", get(request_log_serial))
        .route("/detail/:id", get(detail))
        .route("/response/:id", get(response))
        .route("/sse/live", get(sse_req))
        .route("/sse/log", get(request_log))
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

    (headers, root_cert().serialize_pem().unwrap())
}

#[derive(Template)]
#[template(path = "live.html")]
struct Live;

async fn run_proxy(proxy: Arc<Proxy>) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));

    let tcp_listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|_| panic!("failed to bind {}", &addr));
    println!("HTTP Proxy is Listening on http://{}/", addr);

    loop {
        if let Ok((stream, _)) = tcp_listener.accept().await {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                if let Err(err) = proxy.proxy(stream).await {
                    eprintln!("Error: {:?}", err);
                }
            });
        }
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
        let req = state.request(id, None).await.unwrap().unwrap();

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

#[derive(Template)]
#[template(path = "request_tr.html")]
struct RequestTrHtml {
    request: db::Request,
    response: template::OngoingResponse,
}

async fn req_to_event(req: db::Request, state: &Proxy) -> anyhow::Result<Event> {
    let response = state.try_response(req.id).await?;
    Ok(Event::default().event("request").data(replace_cr(
        RequestTrHtml {
            request: req,
            response: template::OngoingResponse(response),
        }
        .to_string()
        .as_str(),
    )))
}

#[derive(serde::Deserialize, Clone)]
struct Q {
    q: Option<String>,
}

impl Q {
    fn query(&self) -> String {
        self.q
            .as_deref()
            .map(|q| format!("?q={}", q))
            .unwrap_or_default()
    }

    fn value(&self) -> String {
        self.q.as_deref().unwrap_or("").to_string()
    }
}

#[derive(Template)]
#[template(path = "blank_request.html")]
struct BlankRequestHtml {
    id: i64,
    q: Q,
}
async fn request_log(
    state: State<Arc<Proxy>>,
    Query(q): Query<Q>,
) -> Sse<impl Stream<Item = anyhow::Result<Event>>> {
    let state2 = state.clone();

    let (log, rx) = state.now_and_future(q.q.as_deref()).await.unwrap();

    let mut log_event = Vec::new();

    // TODO: bulk select
    for req in log {
        if let Ok(event) = req_to_event(req, &state).await {
            log_event.push(event);
        }
    }

    let stream = stream::iter(log_event.into_iter())
        .chain(stream::unfold(
            (rx, state2, q),
            move |(mut rx, state, q)| async move {
                let id = rx.recv().await.unwrap();
                let req = state.request(id, q.q.as_deref()).await.unwrap();

                if let Some(req) = req {
                    Some((req_to_event(req, &state).await.unwrap(), (rx, state, q)))
                } else {
                    Some((
                        Event::default().event("request").data(replace_cr(
                            &BlankRequestHtml { id, q: q.clone() }.to_string(),
                        )),
                        (rx, state, q),
                    ))
                }
            },
        ))
        .map(Ok);

    Sse::new(stream)
}

#[derive(Template)]
#[template(path = "request_log.html")]
struct LogHtml {
    q: Q,
}

async fn request_log_serial(
    Path(id): Path<i64>,
    Query(q): Query<Q>,
    state: State<Arc<Proxy>>,
) -> impl IntoResponse {
    let Ok(response) = state.response(id).await else {
        return "NOT FOUND".to_string();
    };

    let Ok(Some(req)) = state.request(id, q.q.as_deref()).await else {
        return "".to_string();
    };

    RequestTrHtml {
        request: req,
        response: template::OngoingResponse(Some(response)),
    }
    .to_string()
}

#[derive(Template)]
#[template(path = "detail.html")]
struct DetailHtml {
    request: db::Request,
    request_raw: String,
}

async fn detail(Path(id): Path<i64>, state: State<Arc<Proxy>>) -> DetailHtml {
    let request = state.request(id, None).await.unwrap().unwrap();
    let request_raw = String::from_utf8_lossy(request.data.as_slice()).to_string();
    DetailHtml {
        request,
        request_raw,
    }
}
