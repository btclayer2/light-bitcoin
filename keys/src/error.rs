
use hex::FromHexError;

#[derive(Debug, PartialEq, scale_info::TypeInfo)]
pub enum Error {
    // public key
    InvalidPublic,
    // xonly error
    InvalidXOnly,
    XCoordinateNotExist,
    InvalidNoncePoint,
    InvalidSecret,
    InvalidMessage,
    // sig error
    InvalidSignature,
    SignatureOverflow,
    InvalidNetwork,
    InvalidChecksum,
    InvalidPrivate,
    InvalidAddress,
    FailedKeyGeneration,
    // hex error
    InvalidHexCharacter,
    InvalidStringLength,
    OddLength,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match *self {
            Error::InvalidPublic => "Invalid Public",
            Error::InvalidXOnly => "Invalid XOnly",
            Error::XCoordinateNotExist => "X Coordinate Not Exist",
            Error::InvalidNoncePoint => "Invalid nonce point R",
            Error::InvalidSecret => "Invalid Secret",
            Error::InvalidMessage => "Invalid Message",
            Error::InvalidSignature => "Invalid Signature",
            Error::SignatureOverflow => "Signature Overflow",
            Error::InvalidNetwork => "Invalid Network",
            Error::InvalidChecksum => "Invalid Checksum",
            Error::InvalidPrivate => "Invalid Private",
            Error::InvalidAddress => "Invalid Address",
            Error::FailedKeyGeneration => "Key generation failed",
            Error::InvalidHexCharacter => "Invalid hex character",
            Error::InvalidStringLength => "Invalid string length",
            Error::OddLength => "Hex odd length",
        };

        msg.fmt(f)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        match e {
            secp256k1::Error::InvalidSignature => Error::InvalidSignature,
            secp256k1::Error::InvalidPublicKey => Error::InvalidPublic,
            secp256k1::Error::InvalidSecretKey => Error::InvalidSecret,
            secp256k1::Error::InvalidMessage => Error::InvalidMessage,
            _ => Error::InvalidSignature,
        }
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        match e {
            FromHexError::InvalidHexCharacter { .. } => Error::InvalidHexCharacter,
            FromHexError::InvalidStringLength => Error::InvalidStringLength,
            FromHexError::OddLength => Error::OddLength,
        }
    }
}
