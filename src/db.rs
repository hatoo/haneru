use sqlx::{Executor, Sqlite};

const SCHEMA_SQL: &str = include_str!("../schema.sql");

#[derive(sqlx::FromRow)]
pub struct Request {
    pub id: i64,
    pub timestamp: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub data: Vec<u8>,
}

pub async fn add_schema(executor: impl Executor<'_, Database = Sqlite>) -> sqlx::Result<()> {
    sqlx::query(SCHEMA_SQL).execute(executor).await?;
    Ok(())
}

pub async fn save_request(
    executor: impl Executor<'_, Database = Sqlite>,
    method: &str,
    scheme: &str,
    host: &str,
    data: &[u8],
) -> sqlx::Result<i64> {
    sqlx::query!(
        "INSERT INTO requests (method, scheme, host, data) VALUES (?, ?, ?, ?)",
        method,
        scheme,
        host,
        data,
    )
    .execute(executor)
    .await
    .map(|r| r.last_insert_rowid())
}

pub async fn get_request(
    executor: impl Executor<'_, Database = Sqlite>,
    id: i64,
) -> sqlx::Result<Option<Request>> {
    sqlx::query_as!(
        Request,
        "SELECT id, timestamp, method, scheme, host, data FROM requests WHERE id = ?",
        id,
    )
    .fetch_optional(executor)
    .await
}

pub async fn get_all_request(
    executor: impl Executor<'_, Database = Sqlite>,
) -> sqlx::Result<Vec<Request>> {
    sqlx::query_as!(
        Request,
        "SELECT id, timestamp, method, scheme, host, data FROM requests ORDER BY id ASC",
    )
    .fetch_all(executor)
    .await
}
