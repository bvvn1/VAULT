use std::ffi::OsStr;

use aes_gcm::aead::OsRng;
use env_logger::Env;
use exn::ResultExt;

use gongo::crypto;

use sqlx::{SqlitePool, query};
use zeroize::Zeroizing;
pub mod api;

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
}
