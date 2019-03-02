use rstd::{result, str};

pub type Result<T> = result::Result<T, Error>;

pub type Error = ErrorKind;

#[derive(Eq, PartialEq)]
pub enum ErrorKind {
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
    //    ErrorKind,
    WriteZero,
    Interrupted,
    Other,
    UnexpectedEof,
}

impl ErrorKind {
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
            ErrorKind::InvalidData => "invalid data",
            //            ErrorKind::TimedOut => "timed out",
            ErrorKind::WriteZero => "write zero",
            ErrorKind::Interrupted => "operation interrupted",
            ErrorKind::Other => "other os error",
            ErrorKind::UnexpectedEof => "unexpected end of file",
        }
    }
}
