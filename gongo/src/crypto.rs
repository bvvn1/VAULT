use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray},
};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use log::{error, info};
use sqlx::SqlitePool;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptographyError;
use exn::{self, OptionExt, Result, ResultExt};

#[derive(Debug, ZeroizeOnDrop)]
pub struct PasswordTopki {
    pub salt: String,
    pub nonce: Box<[u8]>,
    pub ciphertext: Box<[u8]>,
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
fn derive_key(password: &Zeroizing<String>) -> (Vec<u8>, String) {
    //
    let parameters = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32usize),
    )
    .unwrap(); //narpavi static
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        parameters,
    );
    let salt = SaltString::generate(&mut OsRng); // 16 bytes

    return tokio::task::block_in_place(move || {
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let salt_as_string = salt.to_string();
        let raw_key = password_hash
            .hash
            .expect("failed access hash")
            .as_bytes()
            .to_vec();

        return (raw_key, salt_as_string);
    });
}

pub fn derive_key_with_salt(
    password: &Zeroizing<String>,
    salt: &str,
) -> Result<Vec<u8>, CryptographyError> {
    let parameters = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32usize),
    )
    .unwrap(); //make static
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        parameters,
    );

    let saltb64 = SaltString::encode_b64(salt.as_bytes())
        .or_raise(|| CryptographyError::Base64EncodingError)?;

    return tokio::task::block_in_place(move || {
        let password_hash = argon2
            .hash_password(password.as_bytes(), &saltb64)
            .or_raise(|| CryptographyError::KeyDeriveError)?;

        info!("passwordhashed successfully");
        //let salt_as_string = salt.to_string();
        let raw_key = password_hash
            .hash
            .ok_or_raise(|| CryptographyError::HashingError)?
            .as_bytes()
            .to_vec();

        return Ok(raw_key);
    });
}

pub fn encrypt_with_password(password: &Zeroizing<String>) -> PasswordTopki {
    let derived_key_tuple = derive_key(password);

    let key = derived_key_tuple.0.as_slice();
    let salt_as_string = derived_key_tuple.1;
    //let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new_from_slice(key).expect("trq da e 32 byta");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_ref())
        .unwrap()
        .into_boxed_slice(); // EVENTUALNO handle error

    PasswordTopki {
        salt: salt_as_string,
        nonce: nonce.to_vec().into_boxed_slice(),
        ciphertext: ciphertext,
    }
}

pub fn decrypt_with_password(
    password: &Zeroizing<String>,
    password_struct: PasswordTopki,
) -> Result<Vec<u8>, CryptographyError> {
    let key = derive_key_with_salt(password, &password_struct.salt)
        .or_raise(|| CryptographyError::KeyDeriveError)?;
    log::debug!("{:?}", key);

    let cipher = Aes256Gcm::new_from_slice(&key).or_raise(|| CryptographyError::InvalidLenght)?;

    let nonce = GenericArray::from_slice(&password_struct.nonce);

    let ciphertext = password_struct.ciphertext.as_ref();

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .or_raise(|| CryptographyError::DecryptError)?; // ima errori po descripciqta

    return Ok(decrypted);
}
