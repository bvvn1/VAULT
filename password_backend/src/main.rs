use std::ffi::OsStr;

use aes_gcm::aead::OsRng;
use env_logger::Env;
use exn::ResultExt;
use gongo::{
    self,
    crypto::{
        self,
        generation::{self, generate_recovery_phrase},
    },
    vaultfile,
};

use sqlx::{SqlitePool, query};
use zeroize::Zeroizing;
pub mod api;

#[tokio::main]
async fn main() {
    //let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let dek = generation::generate_dek(&mut OsRng);
    dbg!(&dek);
    let recovery_phrase = generate_recovery_phrase(&mut OsRng).unwrap();
    dbg!(&recovery_phrase);

    let dek_ciphertext =
        crypto::crypto::encrypt_dek_with_pswd(&Zeroizing::new("huicho".to_string()), &dek);
}
