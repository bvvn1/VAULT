-- Add migration script here
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    ecrypted_password BLOB NOT NULL,
    nonce BLOB NOT NULL
);
