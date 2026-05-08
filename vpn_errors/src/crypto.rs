use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed, packet was corrupted or incorrect key")]
    DecryptionFailed,

    #[error("Invalid sized key: {actual} bytes, waiting for {expected} bytes")]
    InvalidKeySize { actual: usize, expected: usize },

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Packet authentication failed")]
    AuthenticationFailed,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}