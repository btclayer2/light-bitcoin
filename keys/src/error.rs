use ustd::{fmt, prelude::*};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPublic,
    InvalidSecret,
    InvalidMessage,
    InvalidSignature,
    InvalidNetwork,
    InvalidChecksum,
    InvalidPrivate,
    InvalidAddress,
    FailedKeyGeneration,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            Error::InvalidPublic => "Invalid Public",
            Error::InvalidSecret => "Invalid Secret",
            Error::InvalidMessage => "Invalid Message",
            Error::InvalidSignature => "Invalid Signature",
            Error::InvalidNetwork => "Invalid Network",
            Error::InvalidChecksum => "Invalid Checksum",
            Error::InvalidPrivate => "Invalid Private",
            Error::InvalidAddress => "Invalid Address",
            Error::FailedKeyGeneration => "Key generation failed",
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
