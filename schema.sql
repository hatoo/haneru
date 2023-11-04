CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    version TEXT NOT NULL,
    data blob NOT NULL
);

CREATE TABLE IF NOT EXISTS headers (
    request_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    foreign key(request_id) references requests(id)
);