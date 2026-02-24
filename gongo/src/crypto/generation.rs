use aes_gcm::aead::{OsRng, rand_core::RngCore};
use bip39::Mnemonic;
use exn::{Result, ResultExt};
use log::info;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptographyError;

pub fn generate_dek(rng: &mut OsRng) -> Zeroizing<[u8; 32]> {
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);
    info!("dek generated");
    Zeroizing::new(dek)
}

pub fn generate_recovery_phrase(rng: &mut OsRng) -> Result<Zeroizing<String>, CryptographyError> {
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    let mnemonic =
        Mnemonic::from_entropy(&buf).or_raise(|| CryptographyError::MnemonicGenerationError)?;
    buf.zeroize();
    info!("recovery phrase generated");
    Ok(Zeroizing::new(mnemonic.to_string()))
}
