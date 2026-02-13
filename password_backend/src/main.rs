use env_logger::Env;
use gongo::{self, crypto};
use sqlx::SqlitePool;
pub mod api;

#[tokio::main]
async fn main() {
    //let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    dbg!(crypto::encrypt_password("bateznaemse"));

    let gog = crypto::derive_key_with_salt("bateznaemse", "pjoCwb7kw1lLjxQnyfRBqA");
    dbg!(gog);
}
