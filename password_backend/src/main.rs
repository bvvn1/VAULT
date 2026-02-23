use env_logger::Env;
use exn::ResultExt;
use gongo::{
    self,
    crypto::{self, decrypt_with_password, encrypt_with_password},
    vaultfile,
};

use sqlx::{SqlitePool, query};
use zeroize::Zeroizing;
pub mod api;

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    let password = Zeroizing::new("gongo".to_string());
    let sex = encrypt_with_password(&password);
    query!(
        "INSERT INTO config VALUES($1, $2, $3, $4)",
        1,
        sex.salt,
        sex.nonce,
        sex.ciphertext
    )
    .execute(&pool)
    .await
    .unwrap();
}
