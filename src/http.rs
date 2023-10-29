use anyhow::Context;
use axum::http::{HeaderName, HeaderValue};
use httparse::Status;
use hyper::{HeaderMap, Uri};
use tokio::io::AsyncReadExt;

fn is_request_end(buf: &[u8]) -> anyhow::Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(Status::Complete(n)) => {
            let body = &buf[n..];

            for header in headers
                .into_iter()
                .take_while(|h| h != &httparse::EMPTY_HEADER)
            {
                if header.name.to_lowercase().as_str() == "content-length" {
                    let len: usize = std::str::from_utf8(header.value)?.parse()?;
                    return Ok(body.len() >= len);
                }
            }

            Ok(true)
        }
        Ok(Status::Partial) => Ok(false),
        Err(err) => Err(err.into()), // End communication
    }
}

pub async fn read_req<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> anyhow::Result<Option<(Vec<u8>, bool)>> {
    let mut buf = Vec::new();
    while !is_request_end(&buf)? {
        if stream.read_buf(&mut buf).await? == 0 {
            return Ok(None);
        };
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf).unwrap();
    let has_upgrade = headers.iter().any(|h| {
        h.name.to_lowercase().as_str() == "connection"
            && std::str::from_utf8(h.value).map(|s| s.to_lowercase().contains("upgrade"))
                == Ok(true)
    });
    Ok(Some((buf, has_upgrade)))
}

fn is_response_end(buf: &[u8]) -> anyhow::Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(Status::Complete(n)) => {
            let body = &buf[n..];

            for header in headers
                .into_iter()
                .take_while(|h| h != &httparse::EMPTY_HEADER)
            {
                match header.name.to_lowercase().as_str() {
                    "content-length" => {
                        let len: usize = std::str::from_utf8(header.value)?.parse()?;
                        return Ok(body.len() >= len);
                    }
                    "transfer-encoding" => {
                        let enc = std::str::from_utf8(header.value)?;
                        if enc.to_lowercase().contains("chunked") {
                            let mut body = body;

                            loop {
                                let httparse::Status::Complete((offset, len)) =
                                    httparse::parse_chunk_size(body)
                                        .ok()
                                        .context("parse chunk size")?
                                else {
                                    return Ok(false);
                                };

                                let next = offset + len as usize + 2;
                                if body.len() < next {
                                    return Ok(false);
                                }
                                if len == 0 {
                                    return Ok(true);
                                }
                                body = &body[next..];
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(true)
        }
        Ok(Status::Partial) => Ok(false),
        Err(err) => Err(err.into()), // End communication
    }
}

pub async fn read_resp<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    while !is_response_end(&buf)? {
        if stream.read_buf(&mut buf).await? == 0 {
            return Ok(None);
        }
    }
    Ok(Some(buf))
}

pub fn parse_path(buf: &[u8]) -> Option<[String; 3]> {
    let mut i = 0;

    while *buf.get(i)? != b'\r' {
        i += 1;
    }

    let first_line = std::str::from_utf8(&buf[..i]).ok()?;

    first_line
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
}

pub fn replace_path(buf: Vec<u8>) -> Option<Vec<u8>> {
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

pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HeaderMap,
    pub body_start: usize,
    pub data: Vec<u8>,
}

impl ParsedRequest {
    pub fn new(data: Vec<u8>) -> anyhow::Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let Status::Complete(n) = req.parse(&data)? else {
            anyhow::bail!("invalid request");
        };
        let headers = req
            .headers
            .iter()
            .take_while(|h| h != &&httparse::EMPTY_HEADER)
            .map(|h| {
                Ok((
                    HeaderName::from_bytes(h.name.as_bytes()).context("invalid header name")?,
                    HeaderValue::from_bytes(h.value).context("invalid header value")?,
                ))
            })
            .collect::<anyhow::Result<HeaderMap>>()?;

        Ok(Self {
            method: req.method.context("invalid request")?.to_string(),
            path: req.path.context("invalid request")?.to_string(),
            version: req.version.context("invalid request")?.to_string(),
            headers,
            body_start: n,
            data,
        })
    }
}
