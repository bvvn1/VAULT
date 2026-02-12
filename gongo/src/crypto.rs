use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::{Aead, OsRng, generic_array, rand_core::RngCore}};
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, password_hash::SaltString};
use sqlx::SqlitePool;
use tokio::task::spawn_blocking;

#[derive(Debug)]
pub struct PasswordTopki {
    pub salt: String,
    pub nonce: Box<[u8]>,
    pub ciphertext: Box<[u8]>
}


//initialisation logic
async fn is_initalized(pool: &SqlitePool) -> bool {
    let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM config")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count == 0
}


//spawn second thread
fn derive_key(password: &str) -> (Vec<u8>, String){

    let parameters = Params::new(Params::DEFAULT_M_COST, Params::DEFAULT_T_COST, Params::DEFAULT_P_COST, Some(32usize)).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, parameters);
    let salt = SaltString::generate(&mut OsRng);

    return tokio::task::block_in_place(move || {
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let salt_as_string = salt.to_string();
        let raw_key = password_hash.hash.expect("failed access hash").as_bytes().to_vec();

        
        return (raw_key, salt_as_string);
        
        
    });

    
}

pub fn encrypt_password(password: &str) -> PasswordTopki{
    let derived_key_tuple = derive_key(password);

    let key = derived_key_tuple.0.as_slice();
    let salt_as_string = derived_key_tuple.1;
    //let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new_from_slice(key).expect("trq da e 32 byta");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, password.as_ref()).unwrap().into_boxed_slice(); // EVENTUALNO handle error

    PasswordTopki {
        salt: salt_as_string,
        nonce: nonce.to_vec().into_boxed_slice(),
        ciphertext: ciphertext
    }
}

