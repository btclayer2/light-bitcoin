pub type Result<T> = core::result::Result<T, Error>;

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    //    NotFound,
    //    PermissionDenied,
    //    ConnectionRefused,
    //    ConnectionReset,
    //    ConnectionAborted,
    //    NotConnected,
    //    AddrInUse,
    //    AddrNotAvailable,
    //    BrokenPipe,
    //    AlreadyExists,
    //    WouldBlock,
    //    InvalidInput,
    InvalidData,
    //    TimedOut,
    WriteZero,
    Interrupted,
    Other,
    UnexpectedEof,

    ReadMalformedData,
    UnreadData,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error {
    #[allow(dead_code)]
    pub(crate) fn as_str(&self) -> &'static str {
        match *self {
            //            ErrorKind::NotFound => "entity not found",
            //            ErrorKind::PermissionDenied => "permission denied",
            //            ErrorKind::ConnectionRefused => "connection refused",
            //            ErrorKind::ConnectionReset => "connection reset",
            //            ErrorKind::ConnectionAborted => "connection aborted",
            //            ErrorKind::NotConnected => "not connected",
            //            ErrorKind::AddrInUse => "address in use",
            //            ErrorKind::AddrNotAvailable => "address not available",
            //            ErrorKind::BrokenPipe => "broken pipe",
            //            ErrorKind::AlreadyExists => "entity already exists",
            //            ErrorKind::WouldBlock => "operation would block",
            //            ErrorKind::InvalidInput => "invalid input parameter",
            Error::InvalidData => "invalid data",
            //            ErrorKind::TimedOut => "timed out",
            Error::WriteZero => "write zero",
            Error::Interrupted => "operation interrupted",
            Error::Other => "other os error",
            Error::UnexpectedEof => "unexpected end of file",

            Error::ReadMalformedData => "read malformed data",
            Error::UnreadData => "unread data",
        }
    }
}
