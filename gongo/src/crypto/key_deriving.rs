use aes_gcm::aead::OsRng;
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use exn::Result;
use exn::{OptionExt, ResultExt};
use log::info;
use zeroize::Zeroizing;

use crate::error::CryptographyError;

pub fn derive_key(password: &Zeroizing<String>) -> (Vec<u8>, String) {
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
