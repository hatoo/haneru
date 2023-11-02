CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
    method TEXT NOT NULL,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    data blob NOT NULL
);