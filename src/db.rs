use std::{collections::BTreeMap, ops::DerefMut};

use axum::http::HeaderName;
use futures::StreamExt;
use hyper::HeaderMap;
use sqlx::{Executor, Sqlite};

const SCHEMA_SQL: &str = include_str!("../schema.sql");

#[derive(sqlx::FromRow)]
pub struct Request {
    pub id: i64,
    pub timestamp: String,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HeaderMap,
    pub data: Vec<u8>,
}

impl Request {
    pub fn timestamp(&self) -> &str {
        self.timestamp.split_whitespace().nth(1).unwrap()
    }
}

#[derive(sqlx::FromRow)]
struct Req {
    pub id: i64,
    pub timestamp: String,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub version: String,
    pub data: Vec<u8>,
}

struct Header {
    pub name: String,
    pub value: String,
}

#[derive(sqlx::FromRow)]
pub struct Response {
    pub request_id: i64,
    pub status: i64,
    pub headers: HeaderMap,
    pub data: Vec<u8>,
}

pub async fn add_schema(executor: impl Executor<'_, Database = Sqlite>) -> sqlx::Result<()> {
    sqlx::query(SCHEMA_SQL).execute(executor).await?;
    Ok(())
}

pub async fn save_request(
    conn: impl sqlx::Acquire<'_, Database = Sqlite>,
    scheme: &str,
    host: &str,
    method: &str,
    path: &str,
    version: &str,
    headers: &HeaderMap,
    data: &[u8],
) -> sqlx::Result<i64> {
    let mut tx = conn.begin().await?;
    let id = sqlx::query!(
        "INSERT INTO requests (scheme, host, method, path, version, data) VALUES (?, ?, ?, ?, ?, ?)",
        scheme,
        host,
        method,
        path,
        version,
        data
    )
    .execute( tx.deref_mut())
    .await
    .map(|r| r.last_insert_rowid())?;

    for (k, v) in headers {
        let k = k.as_str();
        let v = v.to_str().unwrap();
        sqlx::query!(
            "INSERT INTO request_headers (request_id, name, value) VALUES (?, ?, ?)",
            id,
            k,
            v
        )
        .execute(tx.deref_mut())
        .await?;
    }

    tx.commit().await?;
    Ok(id)
}

pub async fn get_request(
    executor: impl Executor<'_, Database = Sqlite> + Clone,
    id: i64,
    filter: Option<&str>,
) -> sqlx::Result<Option<Request>> {
    let query = if let Some(filter) = filter {
        format!(
            "SELECT id, requests.timestamp as timestamp, scheme, host, method, path, version, requests.data as data FROM requests
        JOIN request_headers ON requests.id = request_headers.request_id
        LEFT JOIN responses ON requests.id = responses.request_id
        LEFT JOIN response_headers ON requests.id = response_headers.request_id
        WHERE id = ? AND {}",
            filter
        )
    } else {
        "SELECT id, timestamp, scheme, host, method, path, version, data FROM requests WHERE id = ?"
            .to_string()
    };

    let req = sqlx::query_as::<_, Req>(&query)
        .bind(id)
        .fetch_optional(executor.clone())
        .await?;

    if let Some(req) = req {
        let headers = sqlx::query_as!(
            Header,
            "SELECT name, value FROM request_headers WHERE request_id = ?",
            id,
        )
        .fetch_all(executor)
        .await?;

        Ok(Some(Request {
            id: req.id,
            timestamp: req.timestamp,
            scheme: req.scheme,
            host: req.host,
            method: req.method,
            path: req.path,
            version: req.version,
            headers: headers
                .into_iter()
                .map(|h| {
                    (
                        HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
                        h.value.parse().unwrap(),
                    )
                })
                .collect(),
            data: req.data,
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_all_request(
    executor: impl Executor<'_, Database = Sqlite> + Clone,
    filter: Option<&str>,
) -> sqlx::Result<Vec<Request>> {
    // Yes, Self SQL injection here :)
    let ids = if let Some(filter) = filter {
        format!(
            "SELECT DISTINCT id FROM requests 
        JOIN request_headers ON requests.id = request_headers.request_id
        LEFT JOIN responses ON requests.id = responses.request_id
        LEFT JOIN response_headers ON requests.id = response_headers.request_id
        WHERE {} ORDER BY id ASC",
            filter
        )
    } else {
        "SELECT id FROM requests ORDER BY id ASC".to_string()
    };

    let query = format!(
        "SELECT id, timestamp, scheme, host, method, path, version, data FROM requests WHERE id IN ({}) ORDER BY id ASC",
        ids
    );
    let mut reqs = sqlx::query_as::<_, Req>(&query).fetch(executor.clone());

    let mut map = BTreeMap::new();
    while let Some(r) = reqs.next().await {
        let r = r?;
        map.insert(
            r.id,
            Request {
                id: r.id,
                timestamp: r.timestamp,
                scheme: r.scheme,
                host: r.host,
                method: r.method,
                path: r.path,
                version: r.version,
                headers: HeaderMap::new(),
                data: r.data,
            },
        );
    }

    struct Header {
        pub request_id: i64,
        pub name: String,
        pub value: String,
    }
    let mut headers = sqlx::query_as!(
        Header,
        "SELECT request_id, name, value FROM request_headers",
    )
    .fetch(executor);

    while let Some(h) = headers.next().await {
        let h = h?;
        if let Some(hs) = map.get_mut(&h.request_id) {
            hs.headers.insert(
                HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
                h.value.parse().unwrap(),
            );
        }
    }

    Ok(map.into_values().collect())
}

pub async fn get_response(
    executor: impl Executor<'_, Database = Sqlite> + Clone,
    id: i64,
) -> sqlx::Result<Option<Response>> {
    pub struct Res {
        pub request_id: i64,
        pub status: i64,
        pub data: Vec<u8>,
    }

    let resp = sqlx::query_as!(
        Res,
        "SELECT request_id, status, data FROM responses WHERE request_id = ?",
        id,
    )
    .fetch_optional(executor.clone())
    .await?;

    if let Some(resp) = resp {
        let mut headers = sqlx::query_as!(
            Header,
            "SELECT name, value FROM response_headers WHERE request_id = ?",
            id,
        )
        .fetch(executor);

        let mut header_map = HeaderMap::new();

        while let Some(h) = headers.next().await {
            let h = h?;
            header_map.insert(
                HeaderName::from_bytes(h.name.as_bytes()).unwrap(),
                h.value.parse().unwrap(),
            );
        }

        Ok(Some(Response {
            request_id: resp.request_id,
            status: resp.status,
            headers: header_map,
            data: resp.data,
        }))
    } else {
        Ok(None)
    }
}

pub async fn save_response(
    conn: impl sqlx::Acquire<'_, Database = Sqlite>,
    id: i64,
    status: i64,
    headers: &HeaderMap,
    data: &[u8],
) -> sqlx::Result<()> {
    let mut tx = conn.begin().await?;
    sqlx::query!(
        "INSERT INTO responses (request_id, status, data) VALUES (?, ?, ?)",
        id,
        status,
        data
    )
    .execute(tx.as_mut())
    .await?;

    for (k, v) in headers.into_iter() {
        let k = k.as_str();
        let v = v.to_str().unwrap();
        sqlx::query!(
            "INSERT INTO response_headers (request_id, name, value) VALUES (?, ?, ?)",
            id,
            k,
            v
        )
        .execute(tx.as_mut())
        .await?;
    }
    tx.commit().await?;

    Ok(())
}
