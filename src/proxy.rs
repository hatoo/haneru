use std::sync::{atomic::AtomicUsize, Arc};

use anyhow::Context;
use async_cell::sync::AsyncCell;
use axum::http::uri;
use hyper::Uri;
use moka::sync::Cache;
use rustls::{OwnedTrustAnchor, ServerConfig, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast::Sender,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    http::{parse_path, read_req, read_resp, replace_path},
    make_cert, root_cert, RequestLog, Server,
};

pub struct Proxy {
    tx: Sender<Arc<RequestLog>>,
    serial_counter: AtomicUsize,
    response_map: Cache<usize, Arc<AsyncCell<Arc<Vec<u8>>>>>,
    request_map: Cache<usize, Arc<RequestLog>>,
}

impl Proxy {
    pub fn new(tx: Sender<Arc<RequestLog>>) -> Self {
        Self {
            tx,
            serial_counter: AtomicUsize::new(1),
            response_map: Cache::new(2048),
            request_map: Cache::new(2048),
        }
    }

    pub fn new_req(&self, host: String, req: Vec<u8>) -> Arc<AsyncCell<Arc<Vec<u8>>>> {
        let id = self
            .serial_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req = Arc::new(RequestLog::new(id, host, req).unwrap());
        let _ = self.tx.send(req.clone());
        let cell = Arc::new(AsyncCell::default());
        self.response_map.insert(id, cell.clone());
        self.request_map.insert(id, req);
        cell
    }

    pub fn request(&self, serial: usize) -> Option<Arc<RequestLog>> {
        self.request_map.get(&serial)
    }

    pub async fn response(&self, serial: usize) -> Option<Arc<Vec<u8>>> {
        let cell = self.response_map.get(&serial)?;
        let resp = cell.get().await;
        Some(resp)
    }

    pub fn try_response(&self, serial: usize) -> Server<Arc<Vec<u8>>> {
        if let Some(cell) = self.response_map.get(&serial) {
            if let Some(resp) = cell.try_get() {
                Server::Some(resp)
            } else {
                Server::Ongoing
            }
        } else {
            Server::Expired
        }
    }
}

pub async fn proxy<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    state: Arc<Proxy>,
) -> anyhow::Result<()> {
    let Some((buf, has_upgrade)) = read_req(&mut stream).await? else {
        return Ok(());
    };

    let [method, path, _version] = parse_path(&buf).context("failed to parse the first line")?;

    if method == "CONNECT" {
        let uri: Uri = path.parse()?;
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
        tunnel(stream, uri, state).await?;
    } else {
        let uri = Uri::try_from(path.as_str())?;
        let buf = replace_path(buf).unwrap();
        let cell = state.new_req(format!("http://{}", uri.host().unwrap()), buf.clone());
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
            cell.set(Arc::new(resp));
        } else {
            let resp = read_resp(&mut server).await?.context("no resp")?;
            stream.write_all(resp.as_ref()).await?;
            cell.set(Arc::new(resp));

            conn_loop(stream, server, uri::Scheme::HTTP, uri, state).await?;
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
    scheme: uri::Scheme,
    base: Uri,
    state: Arc<Proxy>,
) -> anyhow::Result<()> {
    loop {
        let Some((req, has_upgrade)) = read_req(&mut client).await? else {
            return Ok(());
        };
        let cell = state.new_req(
            format!("{}://{}", scheme, base.host().unwrap()),
            req.clone(),
        );
        dbg!("here");

        if has_upgrade {
            let resp = sniff(client, server).await;
            cell.set(Arc::new(resp));
            break;
        } else {
            server.write_all(&req).await?;
            let resp = read_resp(&mut server).await?.context("no resp")?;
            client.write_all(resp.as_ref()).await?;
            cell.set(Arc::new(resp));
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
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server = TcpStream::connect(uri.authority().context("no authority")?.to_string()).await?;
    let server = connector
        .connect(
            ServerName::try_from(uri.host().context("no host")?)?,
            server,
        )
        .await?;

    conn_loop(client, server, uri::Scheme::HTTPS, uri, state).await?;

    Ok(())
}
