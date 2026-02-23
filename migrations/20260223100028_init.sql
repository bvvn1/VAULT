CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL UNIQUE,
    nonce BLOB NOT NULL,
    checksum BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS vault (
    id TEXT PRIMARY KEY,
    service TEXT NOT NULL,
    nonce BLOB NOT NULL,
    salt BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    FOREIGN KEY (salt) REFERENCES config(salt)
);
