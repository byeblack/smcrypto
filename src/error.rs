use base64::DecodeError;
use hex::FromHexError;
use num_bigint::ParseBigIntError;
use pem::PemError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum SMError {
    #[error(transparent)]
    Base64DecodeError(#[from] DecodeError),
    #[error(transparent)]
    HexFromHexError(#[from] FromHexError),
    // #[error("unknown error: {0}")]
    // Unknown(String),
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("InvalidFieldLen")]
    InvalidFieldLen,
    #[error("ZeroFiled: {0}")]
    ZeroFiled(String),
    #[error(transparent)]
    ParseBigIntError(#[from] ParseBigIntError),
    #[error(transparent)]
    PemError(#[from] PemError),
}
