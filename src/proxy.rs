use std::sync::Arc;

use anyhow::Context;
use axum::http::{uri, HeaderName, HeaderValue};
use hyper::{HeaderMap, Uri};
use rustls::{OwnedTrustAnchor, ServerConfig, ServerName};
use sqlx::SqlitePool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast::{self, Sender},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    db,
    http::{parse_path, read_req, read_resp, replace_path},
    make_cert, root_cert,
};

pub struct Proxy {
    pub request_tx: Sender<i64>,
    pub response_tx: Sender<i64>,
    pool: SqlitePool,
}

impl Proxy {
    pub fn new(request_tx: Sender<i64>, response_tx: Sender<i64>, pool: SqlitePool) -> Self {
        Self {
            request_tx,
            response_tx,
            pool,
        }
    }

    pub async fn new_req(&self, scheme: &str, host: &str, req: &[u8]) -> anyhow::Result<i64> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parser = httparse::Request::new(&mut headers);
        parser.parse(req)?;

        let headers = parser
            .headers
            .iter()
            .take_while(|h| h != &&httparse::EMPTY_HEADER)
            .map(|h| {
                Ok::<_, anyhow::Error>((
                    HeaderName::try_from(h.name)?,
                    HeaderValue::from_bytes(h.value)?,
                ))
            })
            .collect::<Result<HeaderMap, _>>()?;

        let id = db::save_request(
            &self.pool,
            scheme,
            host,
            parser.method.context("no method")?,
            parser.path.context("no path")?,
            "HTTP/1.1",
            &headers,
            req,
        )
        .await?;
        let _ = self.request_tx.send(id);

        Ok(id)
    }

    pub async fn request(
        &self,
        id: i64,
        filter: Option<&str>,
    ) -> sqlx::Result<Option<db::Request>> {
        db::get_request(&self.pool, id, filter).await
    }

    pub async fn response(&self, id: i64) -> anyhow::Result<db::Response> {
        let mut rx = self.response_tx.subscribe();

        if let Some(res) = db::get_response(&self.pool, id).await? {
            Ok(res)
        } else {
            while rx.recv().await? != id {}
            Ok(db::get_response(&self.pool, id).await?.unwrap())
        }
    }

    pub async fn try_response(&self, id: i64) -> sqlx::Result<Option<db::Response>> {
        db::get_response(&self.pool, id).await
    }

    pub async fn now_and_future(
        &self,
        filter: Option<&str>,
    ) -> anyhow::Result<(Vec<db::Request>, broadcast::Receiver<i64>)> {
        let mut rx = self.request_tx.subscribe();
        let mut now = db::get_all_request(&self.pool, filter).await?;

        if let Some(last) = now.last() {
            let last_id = last.id;
            loop {
                if let Ok(next) = rx.try_recv() {
                    if next > last_id {
                        now.push(db::get_request(&self.pool, next, filter).await?.unwrap());
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        Ok((now, rx))
    }

    async fn save_response(&self, id: i64, data: &[u8]) -> anyhow::Result<()> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parser = httparse::Response::new(&mut headers);
        parser.parse(data)?;

        let headers = parser
            .headers
            .iter()
            .take_while(|h| h != &&httparse::EMPTY_HEADER)
            .map(|h| {
                Ok::<_, anyhow::Error>((
                    HeaderName::try_from(h.name)?,
                    HeaderValue::from_bytes(h.value)?,
                ))
            })
            .collect::<Result<HeaderMap, _>>()?;

        db::save_response(
            &self.pool,
            id,
            parser.code.context("no code")? as _,
            &headers,
            data,
        )
        .await?;
        let _ = self.response_tx.send(id);
        Ok(())
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
        let id = state
            .new_req("http", uri.authority().unwrap().as_str(), &buf)
            .await?;
        let mut server =
            TcpStream::connect((uri.host().unwrap(), uri.port_u16().unwrap_or(80))).await?;

        server.write_all(buf.as_ref()).await?;

        if has_upgrade {
            dbg!("go sniff");
            let resp = sniff(stream, server).await;
            state.save_response(id, &resp).await?;
            let _ = state.response_tx.send(id);
        } else {
            if let Some(resp) = read_resp(&mut server).await? {
                stream.write_all(resp.as_ref()).await?;
                state.save_response(id, &resp).await?;
            } else {
                db::save_response(&state.pool, id, 0, &HeaderMap::default(), &[]).await?;
                stream.shutdown().await?;
                return Ok(());
            }
            let _ = state.response_tx.send(id);
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
        let Ok(Some((req, has_upgrade))) = read_req(&mut client).await else {
            return Ok(());
        };
        let req = replace_path(req).unwrap();
        let id = state
            .new_req(scheme.as_str(), base.authority().unwrap().as_str(), &req)
            .await?;

        if has_upgrade {
            let resp = sniff(client, server).await;
            state.save_response(id, &resp).await?;
            let _ = state.response_tx.send(id);
            break;
        } else {
            server.write_all(&req).await?;
            if let Some(resp) = read_resp(&mut server).await? {
                client.write_all(&resp).await?;
                state.save_response(id, &resp).await?;
                let _ = state.response_tx.send(id);
            } else {
                db::save_response(&state.pool, id, 0, &HeaderMap::default(), &[]).await?;
                let _ = state.response_tx.send(id);
                client.shutdown().await?;
                return Ok(());
            }
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
    let cert = make_cert(vec![uri.host().context("no host on path")?.to_string()]);
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
