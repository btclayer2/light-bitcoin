use super::*;
use core::result;
use hex::FromHexError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MastError {
    /// Indicates whether the MAST build error
    MastBuildError,
    /// Mast generate merkle proof error
    MastGenProofError,
    /// Mast generate address error
    MastGenAddrError,
    /// Invalid constructed mast
    /// Example: When partial merkle tree contains no pubkey
    InvalidMast(String),
    /// Format error of hex
    FromHexError(String),
    // Mainly used to handle io errors of encode
    IoError(String),
    /// Error which may occur by musig2
    Musig2Error(String),
    /// Error which encode to bench32
    EncodeToBech32Error,
}

impl From<io::Error> for MastError {
    fn from(err: io::Error) -> Self {
        MastError::IoError(err.to_string())
    }
}

impl From<FromHexError> for MastError {
    fn from(e: FromHexError) -> Self {
        match e {
            FromHexError::InvalidHexCharacter { c, index } => {
                MastError::FromHexError(format!("InvalidHexCharacter {}, {}", c, index))
            }
            FromHexError::OddLength => MastError::FromHexError("OddLength".to_owned()),
            FromHexError::InvalidStringLength => {
                MastError::FromHexError("InvalidStringLength".to_owned())
            }
        }
    }
}

impl From<hashes::hex::Error> for MastError {
    fn from(e: hashes::hex::Error) -> Self {
        match e {
            hashes::hex::Error::InvalidChar(c) => {
                MastError::FromHexError(format!("InvalidChar {}", c))
            }
            hashes::hex::Error::OddLengthString(c) => {
                MastError::FromHexError(format!("OddLengthString {}", c))
            }
            hashes::hex::Error::InvalidLength(a, b) => {
                MastError::FromHexError(format!("InvalidLength {},{}", a, b))
            }
        }
    }
}

impl From<musig2::error::Error> for MastError {
    fn from(e: musig2::error::Error) -> Self {
        MastError::Musig2Error(format!("Musig2Error({:?})", e))
    }
}

pub type Result<T> = result::Result<T, MastError>;
