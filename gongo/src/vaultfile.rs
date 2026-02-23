use serde::{Deserialize, Serialize};
use url::Host;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::encrypt_with_password;

// const MAGIC_BYTES: &'static [u8; 4] = b"RVLT";

// #[derive(Serialize, Deserialize, Debug)] //naprai zeroizeondrop
// struct Entry {
//     id: [u8; 16],
//     service: Host,
//     username: String,
//     password: Zeroizing<String>,
// }

// impl Entry {
//     fn new(service: Host, username: String, password: Zeroizing<String>) -> Self {
//         Self {
//             id: Uuid::new_v4().to_bytes_le(),
//             service,
//             username,
//             password,
//         }
//     }
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct Vault {
//     magic_bytes: [u8; 4],
//     salt: [u8; 16],
//     aes_nonce: [u8; 12],
//     entries: Vec<u8>,
// }

// impl Vault {
//     fn new(password: Zeroizing<String>) -> Vault {
//         let pswd = encrypt_with_password(&password);
//         let salt_bytes = pswd.salt.as_bytes();
//         let mut arr = [0u8; 16];

//         Self {
//             magic_bytes: *MAGIC_BYTES,
//             salt: pswd.salt.as_bytes().try_into().unwrap(),
//             aes_nonce: (*pswd.nonce).try_into().unwrap(),
//             entries: pswd.ciphertext.to_vec(),
//         }
//     }
// }
struct Entry {
    id: Uuid,
    service: String,
}

//dobavi add entry fn koito vrushta serializiran, sushto i ima problem s deserializaciq na cyphertext i dekriptirane, moje bi trqbva da se vrushta kato Vec<Entry>
