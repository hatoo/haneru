use std::{
    collections::{BTreeMap, HashMap},
    ops::DerefMut,
};

use axum::http::HeaderName;
use futures::StreamExt;
use hyper::HeaderMap;
use sqlx::{Connection, Executor, Sqlite};

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
    headers: &HashMap<String, String>,
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
) -> sqlx::Result<Option<Request>> {
    let req = sqlx::query_as!(
        Req,
        "SELECT id, timestamp, scheme, host, method, path, version, data FROM requests WHERE id = ?",
        id,
    )
    .fetch_optional(executor.clone())
    .await?;

    if let Some(req) = req {
        struct Header {
            pub name: String,
            pub value: String,
        }
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
) -> sqlx::Result<Vec<Request>> {
    let mut reqs = sqlx::query_as!(
        Req,
        "SELECT id, timestamp, scheme, host, method, path, version, data FROM requests ORDER BY id ASC",
    )
    .fetch(executor.clone());

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
