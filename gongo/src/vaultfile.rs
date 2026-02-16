use crate::crypto;
use log::error;
use serde::{Deserialize, Serialize};
use url::Host;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC_BYTES: &'static [u8; 4] = b"RVLT";

#[derive(Serialize, Deserialize, Debug)] //naprai zeroizeondrop
struct Entry {
    id: [u8; 16],
    service: Host,
    username: String,
    password: String,
}

impl Entry {
    fn new(service: Host, username: String, password: String) -> Self {
        Self {
            id: Uuid::new_v4().to_bytes_le(),
            service,
            username,
            password,
        }
    }
}

struct Vault {
    magic_bytes: [u8; 4],
    salt: [u8; 16],
    aes_nonce: [u8; 12],
    entries: Vec<Entry>,
}

impl Vault {}
//finish
