use anyhow::Context;
use httparse::Status;
use tokio::io::AsyncReadExt;

fn is_request_end(buf: &[u8]) -> anyhow::Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf) {
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
                    _ => {}
                }
            }

            Ok(true)
        }
        Ok(Status::Partial) => Ok(false),
        Err(err) => Err(err.into()), // End communication
    }
}

pub async fn read_req<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    while !is_request_end(&buf)? {
        stream.read_buf(&mut buf).await?;
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf).unwrap();
    let has_upgrade = headers.iter().any(|h| {
        h.name.to_lowercase().as_str() == "connection"
            && std::str::from_utf8(h.value).map(|s| s.to_lowercase().contains("upgrade"))
                == Ok(true)
    });
    Ok((buf, has_upgrade))
}

fn is_response_end(buf: &[u8]) -> anyhow::Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&buf) {
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

pub async fn read_resp<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while !is_response_end(&buf)? {
        stream.read_buf(&mut buf).await?;
    }
    Ok(buf)
}
