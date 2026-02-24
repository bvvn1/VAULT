use crate::{
    crypto::key_deriving::{derive_key, derive_key_with_salt},
    error::CryptographyError,
};
use aes_gcm::{
    AeadCore, Aes256Gcm, AesGcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray, rand_core::RngCore},
};

use exn::{self, Result, ResultExt};

use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Debug, ZeroizeOnDrop)]
pub struct PasswordTopki {
    pub salt: String,
    pub nonce: Box<[u8]>,
    pub ciphertext: Box<[u8]>,
}

//initialisation logic
// async fn is_initalized(pool: &SqlitePool) -> bool {
//     let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM config")
//         .fetch_one(pool)
//         .await
//         .unwrap_or(0);
//     count == 0
// }

pub fn encrypt_dek_with_pswd(
    password: &Zeroizing<String>,
    dek: &Zeroizing<[u8; 32]>,
) -> Result<PasswordTopki, CryptographyError> {
    let key_tuple = derive_key(password);

    let cipher = Aes256Gcm::new_from_slice(key_tuple.0.as_slice())
        .or_raise(|| CryptographyError::InvalidLenght)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_ref())
        .or_raise(|| CryptographyError::EncryptError)?;
    Ok(PasswordTopki {
        salt: key_tuple.1,
        nonce: nonce.to_vec().into_boxed_slice(),
        ciphertext: ciphertext.into_boxed_slice(),
    })
}

pub fn decrypt_dek_with_pswd(
    password: &Zeroizing<String>,
    password_struct: PasswordTopki,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    let key = derive_key_with_salt(password, &password_struct.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).or_raise(|| CryptographyError::InvalidLenght)?;

    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(&password_struct.nonce),
            password_struct.ciphertext.as_ref(),
        )
        .or_raise(|| CryptographyError::DecryptError)?;
    Ok(Zeroizing::new(plaintext))
}
