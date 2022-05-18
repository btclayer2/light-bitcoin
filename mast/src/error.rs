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
    /// Error which encode to bench32
    EncodeToBech32Error,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid input length
    InvalidInputLength,
    /// Invalid hex character
    InvalidHexCharacter,
    /// Xcoordinate not exist
    XCoordinateNotExist,
    /// Invalid string length
    InvalidStringLength,
    /// Invalid Pubkeys length
    InvalidPubkeysLength,
    // Invalid redeem script length
    InvalidRedeemLength,
    // Invalid redeem script threshold
    InvalidThreshold,
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

pub type Result<T> = result::Result<T, MastError>;
