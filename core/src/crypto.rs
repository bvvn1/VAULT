use aes_gcm::aead::{OsRng, rand_core::RngCore};
use sqlx::{Sqlite, SqlitePool};

//initialisation logic
async fn setup_vault(pool: &SqlitePool) -> bool {
    let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM config")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count == 0
}
