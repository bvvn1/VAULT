use sqlx::SqlitePool;

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite:vault.db").await.unwrap();
}
