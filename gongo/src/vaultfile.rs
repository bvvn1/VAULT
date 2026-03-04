use std::vec;

use exn::{OptionExt, Result, ResultExt};
use serde::{Deserialize, Serialize};
use url::Host;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{crypto::crypto::encrypt_with_pswd, error::VaultError};

const MAGIC_BYTES: &'static [u8; 4] = b"RVLT";

#[derive(Serialize, Deserialize, Debug)] //naprai zeroizeondrop
struct Entry {
    id: [u8; 16],
    service: Host,
    username: String,
    password: Zeroizing<String>,
}

impl Entry {
    fn new(service: Host, username: String, password: Zeroizing<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_bytes_le(),
            service,
            username,
            password,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Vault {
    magic_bytes: [u8; 4],
    salt: [u8; 16],
    aes_nonce: [u8; 12],
    entries: Vec<Entry>,
}

impl Vault {
    fn new(password: Zeroizing<String>) -> Result<Vault, VaultError> {
        let pswd = encrypt_with_pswd(&password, "goy".as_bytes().to_vec()) //
            .map_err(|_| VaultError::VaultCreation)?;
        let salt_bytes = pswd
            .salt
            .clone()
            .ok_or_raise(|| VaultError::VaultCreation)?;
        let arr: [u8; 16] = salt_bytes.as_bytes().try_into().unwrap(); //remove this unwrap later
        Ok(Self {
            magic_bytes: *MAGIC_BYTES,
            salt: arr,
            aes_nonce: (*pswd.nonce).try_into().unwrap(),
            entries: Vec::new(),
        })
    }
}

//dobavi add entry fn koito vrushta serializiran, sushto i ima problem s deserializaciq na cyphertext i dekriptirane, moje bi trqbva da se vrushta kato Vec<Entry>
