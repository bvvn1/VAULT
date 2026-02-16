use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray},
    aes::cipher::InvalidLength,
};
use argon2::{
    Argon2, Params, PasswordHasher,
    password_hash::{Salt, SaltString},
};
use log::{error, info};
use sqlx::SqlitePool;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
fn derive_key(password: &mut str) -> (Vec<u8>, String) {
    let parameters = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32usize),
    )
    .unwrap();
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

pub fn derive_key_with_salt(password: &mut String, salt: &str) -> Vec<u8> {
    let parameters = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32usize),
    )
    .unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        parameters,
    );

    let saltb64 = SaltString::encode_b64(salt.as_bytes()).unwrap();

    return tokio::task::block_in_place(move || {
        let password_hash = argon2.hash_password(password.as_bytes(), &saltb64).unwrap();
        info!("passwordhashed successfully");
        //let salt_as_string = salt.to_string();
        let raw_key = password_hash
            .hash
            .expect("failed access hash")
            .as_bytes()
            .to_vec();

        password.zeroize();
        return raw_key;
    });
}

pub fn encrypt_with_password(password: &mut String) -> PasswordTopki {
    let derived_key_tuple = derive_key(password.as_mut_str());

    let key = derived_key_tuple.0.as_slice();
    let salt_as_string = derived_key_tuple.1;
    //let key: &Key<Aes256Gcm> = key.into();

    let cipher = Aes256Gcm::new_from_slice(key).expect("trq da e 32 byta");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_ref())
        .unwrap()
        .into_boxed_slice(); // EVENTUALNO handle error

    password.zeroize();
    PasswordTopki {
        salt: salt_as_string,
        nonce: nonce.to_vec().into_boxed_slice(),
        ciphertext: ciphertext,
    }
}

pub fn decrypt_with_password(
    password: &mut String,
    password_struct: PasswordTopki,
) -> Result<Vec<u8>, InvalidLength> {
    let key = derive_key_with_salt(password, &password_struct.salt);
    let mut cipher = Aes256Gcm::new_from_slice(&key);
    let cipher = match cipher {
        Ok(x) => x,
        Err(err) => {
            error!("failed to create cipher: {}", err);
            return Err(err);
        }
    };
    let nonce = GenericArray::from_slice(&password_struct.nonce);

    let ciphertext = password_struct.ciphertext.as_ref();

    let decrypted = cipher.decrypt(nonce, ciphertext);

    return Ok(decrypted);
} // napravi funkciqta da vrushta result i napravi custom error type po kusno
