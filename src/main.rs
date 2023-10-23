use askama::Template;
use axum::{
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use bytes::{buf, BytesMut};
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
        /*
        .route(
            "/sse",
            get(|| async move { sse_req(txs.subscribe()).await }),
        )
        */
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

/*
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
*/

async fn tunnel(upgraded: TcpStream, uri: Uri) -> std::io::Result<()> {
    dbg!(uri.host());
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
    dbg!("tls");

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

    let mut buf = BytesMut::new();
    let mut forward = [0u8; 1024];
    loop {
        tokio::select! {
            res = stream_to_server.read_buf(&mut buf) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    let _ = stream_from_client.write_all(&buf[buf.len() - n..]).await;
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

    dbg!(buf);

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

async fn read_req(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
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

async fn proxy_conn(mut stream: TcpStream) -> anyhow::Result<()> {
    let buf = read_req(&mut stream).await?;

    let fst = parse_path(&buf).unwrap();

    if fst[0].as_str() == "CONNECT" {
        dbg!(&fst);
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await?;
        tunnel(stream, fst[1].parse().unwrap()).await?;
    } else {
        let uri = Uri::try_from(fst[1].as_str()).unwrap();
        let mut server = TcpStream::connect(format!(
            "{}:{}",
            uri.authority().unwrap(),
            uri.port_u16().unwrap_or(80)
        ))
        .await?;

        let buf = replace_path(buf).unwrap();
        server.write_all(buf.as_ref()).await?;
        server.shutdown().await?;

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await?;

        stream.write_all(&buf).await?;
        stream.shutdown().await?;
    }
    Ok(())
}

async fn run_proxy(tx: Sender<Arc<Request<Bytes>>>) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));

    let tcp_listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        tokio::spawn(async move {
            proxy_conn(stream).await.unwrap();
        });
    }
}

/*
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

*/
