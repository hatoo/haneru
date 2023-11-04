use std::borrow::Cow;

use hyper::header;

use crate::db;

pub struct OngoingResponse(pub Option<db::Response>);

impl OngoingResponse {
    pub fn length(&self) -> Cow<str> {
        self.0
            .as_ref()
            .map(|r| r.data.len().to_string().into())
            .unwrap_or(Cow::Borrowed("Ongoing"))
    }

    pub fn content_type(&self) -> Cow<str> {
        self.0
            .as_ref()
            .map(|r| {
                r.headers
                    .get(header::CONTENT_TYPE)
                    .map(|h| h.to_str().unwrap())
                    .unwrap_or("")
                    .into()
            })
            .unwrap_or(Cow::Borrowed("Ongoing"))
    }
}
