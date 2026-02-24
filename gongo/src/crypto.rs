use crate::error::CryptographyError;
use aes_gcm::{
    AeadCore, Aes256Gcm, AesGcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray, rand_core::RngCore},
};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use bip39::{Language, Mnemonic};
use exn::{self, OptionExt, Result, ResultExt};
use log::{error, info};
use sqlx::SqlitePool;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

    let saltb64 = SaltString::from_b64(salt).or_raise(|| CryptographyError::Base64EncodingError)?;

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

fn generate_dek(rng: &mut OsRng) -> Zeroizing<[u8; 32]> {
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);
    info!("dek generated");
    Zeroizing::new(dek)
}

fn generate_recovery_phrase(rng: &mut OsRng) -> Result<Zeroizing<String>, CryptographyError> {
    let mut buf = [0u8; 4];
    rng.fill_bytes(&mut buf);
    let mnemonic =
        Mnemonic::from_entropy(&buf).or_raise(|| CryptographyError::MnemonicGenerationError)?;
    buf.zeroize();
    info!("recovery phrase generated");
    Ok(Zeroizing::new(mnemonic.to_string()))
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

    let cipher = Aes256Gcm::new_from_slice(&key).or_raise(|| CryptographyError::InvalidLenght)?;

    let nonce = GenericArray::from_slice(&password_struct.nonce);

    let ciphertext = password_struct.ciphertext.as_ref();

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .or_raise(|| CryptographyError::DecryptError)?; // ima errori po descripciqta

    return Ok(decrypted);
}

fn encrypt_dek_with_pswd(
    password: &Zeroizing<String>,
    dek: &Zeroizing<String>,
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

fn decrypt_dek_with_pswd(
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
