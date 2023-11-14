use anyhow::Context;
use axum::http::{uri, HeaderName, HeaderValue};
use hyper::{HeaderMap, Uri};
use sqlx::SqlitePool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast::{self, Sender},
};
use tokio_rustls::TlsAcceptor;

use crate::{
    db,
    http::{parse_path, read_req, read_resp, replace_path},
    server_config,
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
        let mut headers = [httparse::EMPTY_HEADER; crate::http::MAX_HEADERS];
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
            while let Ok(next) = rx.try_recv() {
                if next > last_id {
                    now.push(db::get_request(&self.pool, next, filter).await?.unwrap());
                    break;
                }
            }
        }

        Ok((now, rx))
    }

    async fn save_response(&self, id: i64, data: &[u8]) -> anyhow::Result<()> {
        let mut headers = [httparse::EMPTY_HEADER; crate::http::MAX_HEADERS];
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

    async fn no_resp(&self, id: i64) -> anyhow::Result<()> {
        db::save_response(&self.pool, id, 0, &HeaderMap::default(), &[]).await?;
        let _ = self.response_tx.send(id);
        Ok(())
    }

    pub async fn proxy<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        mut stream: S,
    ) -> anyhow::Result<()> {
        let Some((buf, has_upgrade)) = read_req(&mut stream).await? else {
            return Ok(());
        };

        let [method, path, _version] =
            parse_path(&buf).context("failed to parse the first line")?;

        if method == "CONNECT" {
            let uri: Uri = path.parse()?;
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            stream.flush().await?;
            self.tunnel(stream, uri).await?;
        } else {
            let uri = Uri::try_from(path.as_str())?;
            let buf = replace_path(buf).unwrap();
            let id = self
                .new_req("http", uri.authority().unwrap().as_str(), &buf)
                .await?;
            let mut server =
                TcpStream::connect((uri.host().unwrap(), uri.port_u16().unwrap_or(80))).await?;

            server.write_all(buf.as_ref()).await?;
            server.flush().await?;

            if has_upgrade {
                let resp = sniff(stream, server).await;
                self.save_response(id, &resp).await?;
            } else {
                if let Some(resp) = read_resp(&mut server).await? {
                    stream.write_all(resp.as_ref()).await?;
                    stream.flush().await?;
                    self.save_response(id, &resp).await?;
                } else {
                    self.no_resp(id).await?;
                    return Ok(());
                }
                self.conn_loop(stream, server, uri::Scheme::HTTP, uri)
                    .await?;
            };
        }
        Ok(())
    }
    async fn conn_loop<
        S1: AsyncReadExt + AsyncWriteExt + Unpin,
        S2: AsyncReadExt + AsyncWriteExt + Unpin,
    >(
        &self,
        mut client: S1,
        mut server: S2,
        scheme: uri::Scheme,
        base: Uri,
    ) -> anyhow::Result<()> {
        loop {
            let Ok(Some((req, has_upgrade))) = read_req(&mut client).await else {
                return Ok(());
            };
            let req = replace_path(req).unwrap();
            let id = self
                .new_req(scheme.as_str(), base.authority().unwrap().as_str(), &req)
                .await?;

            if has_upgrade {
                server.write_all(&req).await?;
                server.flush().await?;
                let resp = sniff(client, server).await;
                self.save_response(id, &resp).await?;
                break;
            } else {
                server.write_all(&req).await?;
                server.flush().await?;
                if let Ok(Some(resp)) = read_resp(&mut server).await {
                    client.write_all(&resp).await?;
                    client.flush().await?;
                    self.save_response(id, &resp).await?;
                } else {
                    self.no_resp(id).await?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn tunnel<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        upgraded: S,
        uri: Uri,
    ) -> anyhow::Result<()> {
        let server_config = server_config(uri.host().context("no host on path")?.to_string());
        let tls_acceptor = TlsAcceptor::from(server_config);
        let client = tls_acceptor.accept(upgraded).await?;

        // Connect to remote server

        let server = TcpStream::connect(uri.authority().context("no authority")?.as_str()).await?;
        let native_tls_connector = tokio_native_tls::native_tls::TlsConnector::new().unwrap();
        let connector = tokio_native_tls::TlsConnector::from(native_tls_connector);
        let server = connector.connect(uri.host().unwrap(), server).await?;

        self.conn_loop(client, server, uri::Scheme::HTTPS, uri)
            .await?;

        Ok(())
    }
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
