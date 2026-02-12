use sqlx::SqlitePool;
use gongo::{self, crypto};
pub mod api;

#[tokio::main]
async fn main() {
    //let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();

    dbg!(crypto::encrypt_password("sex"));

}
