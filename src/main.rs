use askama::Template;
use axum::{
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use futures::{stream, Stream, StreamExt};
use hyper::{
    body::{to_bytes, Bytes},
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::sync::broadcast::{self, Receiver, Sender};
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
        todo!()
    }

    let client = Client::new();
    client.request(req).await
}

async fn run_proxy(tx: Sender<Arc<Request<Bytes>>>) -> anyhow::Result<()> {
    let addr = ([127, 0, 0, 1], 3002).into();

    let service = make_service_fn(move |_| {
        let tx = tx.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| proxy(req, tx.clone()))) }
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
