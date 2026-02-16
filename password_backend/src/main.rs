use env_logger::Env;
use gongo::{
    self,
    crypto::{self, decrypt_with_password},
    vaultfile,
};

use sqlx::SqlitePool;
use zeroize::Zeroizing;
pub mod api;

#[tokio::main]
async fn main() {
    //let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    let mut nig = String::from("sdadsadadadsda");
    let gogo = Zeroizing::new(nig);
    let sex = crypto::encrypt_with_password(&gogo);

    dbg!(&sex);
    let blehh = decrypt_with_password(&gogo, sex);
    dbg!(blehh);
}
