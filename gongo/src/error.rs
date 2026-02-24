use thiserror::Error;

use crate::error;

#[derive(Debug, Error)]
pub enum CryptographyError {
    #[error("Invalid key lenght")]
    InvalidLenght,
    #[error("Error during decryption")]
    DecryptError,
    #[error("Error during encryption")]
    EncryptError,
    #[error("Error during key deriving")]
    KeyDeriveError,
    #[error("Error during hashing")]
    HashingError,
    #[error("Error during Base 64 encodig")]
    Base64EncodingError,
    #[error("Error during the generation of the mnemonic phrase")]
    MnemonicGenerationError,
}
