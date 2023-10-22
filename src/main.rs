use askama::Template;
use axum::{
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use bytes::BytesMut;
use futures::{stream, Stream, StreamExt};
use hyper::{
    body::{to_bytes, Bytes},
    client::HttpConnector,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Request, Response, Server, Uri,
};
use rustls::{Certificate, OwnedTrustAnchor, PrivateKey, ServerConfig, ServerName};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
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

async fn proxy(
    req: Request<Body>,
    client: Client<HttpConnector>,
    tx: Sender<Arc<Request<Bytes>>>,
) -> Result<Response<Body>, hyper::Error> {
    // tx.send(req.clone()).unwrap();
    let (p, body) = req.into_parts();
    let body: Bytes = to_bytes(body).await.unwrap();

    {
        let mut builder = Request::builder()
            .method(p.method.clone())
            .uri(p.uri.clone())
            .version(p.version.clone());

        builder.headers_mut().unwrap().clone_from(&p.headers);
        let new_req = builder.body(body.clone()).unwrap();
        let _ = tx.send(Arc::new(new_req));
    }
    let req = Request::from_parts(p, Body::from(body));

    if req.method() == hyper::Method::CONNECT {
        tokio::task::spawn(async move {
            let uri = req.uri().clone();
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, uri).await {
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
fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

async fn tunnel(upgraded: Upgraded, uri: Uri) -> std::io::Result<()> {
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

    let (mut rxc, mut txc) = tokio::io::split(stream_from_client);
    let (mut rxs, mut txs) = tokio::io::split(stream_to_server);

    let forward = tokio::spawn(async move {
        dbg!(tokio::io::copy(&mut rxc, &mut txs).await);
    });

    let mut buf = BytesMut::new();
    loop {
        if let Ok(n) = rxs.read_buf(&mut buf).await {
            if n == 0 {
                break;
            }
            let res = txc.write_all(&buf[buf.len() - n..]).await;
        } else {
            break;
        }
    }

    dbg!(buf);

    Ok(())
}

async fn run_proxy(tx: Sender<Arc<Request<Bytes>>>) -> anyhow::Result<()> {
    let addr = ([127, 0, 0, 1], 3002).into();
    let client = Client::new();

    let service = make_service_fn(move |_| {
        let tx = tx.clone();
        let client = client.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                proxy(req, client.clone(), tx.clone())
            }))
        }
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

async fn sse_req(
    rx: Receiver<Arc<Request<Bytes>>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold(rx, |mut rx| async {
        let req = rx.recv().await.unwrap();

        Some((
            Event::default()
                .event("request")
                .data(format!("<p>{:?}</p>", req.headers().len())),
            rx,
        ))
    })
    .map(Ok);

    Sse::new(stream)
}
