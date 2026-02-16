use env_logger::Env;
use gongo::{
    self,
    crypto::{self, decrypt_with_password},
    vaultfile,
};

use sqlx::SqlitePool;
pub mod api;

#[tokio::main]
async fn main() {
    //let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let mut nig = String::from("sdadsadadadsda");
    let sex = crypto::encrypt_with_password(&mut nig);
    dbg!(&sex);
    let blehh = decrypt_with_password(&mut nig, sex);
}
