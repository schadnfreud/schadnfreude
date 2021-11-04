//Custom err for nicer result handling
use crate::innermain::*;
use std::fmt::Display;

#[derive(Debug)]
pub enum SfErr {
    IoErr(io::Error),
    AddrErr(net::AddrParseError),
    DisallowedAddr(net::IpAddr),
    BsonDecErr(bson::DecoderError),
    BsonEncErr(bson::EncoderError),
    MutexErr(String),
    AlreadyJoinedErr,
    BadBsonErr,
    BadSignatureErr,
    NoneErr,
    DuplicateChatMeet,
    TooManyErr,
    BadHop,
    BadMeet,
    OidExists,
    NoRoutesErr,
    NotFound,
    Resend,
    BadTime,
    BackupButPrimaryErr,
    NotAllowed,
    OutOfOrderErr,
    InvalidOp,
    BadLen,
    BadMessage,
    MtuFail,
    DoneErr,
    LockFailed,
    BadOffset,
    BadId,
    BadPath,
    ProxyFailed,
    SendError,
    DeletedError,
    B64Err(base64::DecodeError),
    ValErr(bson::ordered::ValueAccessError),
    NumErr(num::ParseIntError),
    IntConvErr(num::TryFromIntError),
    SerdJErr(serde_json::Error),
    TimeoutErr(crossbeam_channel::RecvTimeoutError),
    TrySendErr(crossbeam_channel::TrySendError<Vec<u8>>),
    SledErr(sled::Error),
    StringError(std::string::FromUtf8Error),
    StrError(std::str::Utf8Error),
    NodeError((String, bson::Document)),
    UnexpectedAckErr([u8; 32]),
    StreamFail(String),
}
impl Display for SfErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            SfErr::IoErr(e) => e.fmt(f),
            SfErr::AddrErr(e) => e.fmt(f),
            SfErr::BsonDecErr(e) => e.fmt(f),
            SfErr::MutexErr(e) => e.fmt(f),
            SfErr::B64Err(e) => e.fmt(f),
            SfErr::ValErr(e) => e.fmt(f),
            SfErr::BsonEncErr(e) => e.fmt(f),
            SfErr::NumErr(e) => e.fmt(f),
            SfErr::IntConvErr(e) => e.fmt(f),
            SfErr::SerdJErr(e) => e.fmt(f),
            SfErr::TimeoutErr(e) => e.fmt(f),
            SfErr::TrySendErr(e) => e.fmt(f),
            SfErr::SledErr(e) => e.fmt(f),
            SfErr::StringError(e) => e.fmt(f),
            SfErr::StrError(e) => e.fmt(f),
            SfErr::BadHop => "Bad hop (hop is destination)".fmt(f),
            SfErr::BadOffset => "Bad offset".fmt(f),
            SfErr::SendError => "Crossbeam SendError".fmt(f),
            SfErr::DeletedError => "File is deleted".fmt(f),
            SfErr::BadBsonErr => "Bad BSON".fmt(f),
            SfErr::AlreadyJoinedErr => "Already joined".fmt(f),
            SfErr::BadSignatureErr => "Bad signature".fmt(f),
            SfErr::TooManyErr => "Too many specified".fmt(f),
            SfErr::BadMeet => "Bad meet address".fmt(f),
            SfErr::BadTime => "Bad time".fmt(f),
            SfErr::OidExists => "OID exists".fmt(f),
            SfErr::NoRoutesErr => "No routes".fmt(f),
            SfErr::NotFound => "Not found".fmt(f),
            SfErr::LockFailed => "Lock failed".fmt(f),
            SfErr::InvalidOp => "Invalid operation".fmt(f),
            SfErr::MtuFail => "Too big for MTU".fmt(f),
            SfErr::BadLen => "Bad length".fmt(f),
            SfErr::BadMessage => "Bad message".fmt(f),
            SfErr::DoneErr => "Done".fmt(f),
            SfErr::BadId => "Bad ID".fmt(f),
            SfErr::BadPath => "Bad path".fmt(f),
            SfErr::ProxyFailed => "Proxy failed".fmt(f),
            SfErr::Resend => "Resend".fmt(f),
            SfErr::BackupButPrimaryErr => "Asked to be backup, but we're primary".fmt(f),
            SfErr::NoneErr => "None".fmt(f),
            SfErr::DuplicateChatMeet => "Duplicate chat meet".fmt(f),
            SfErr::NotAllowed => "Not allowed".fmt(f),
            SfErr::OutOfOrderErr => "Out of Order".fmt(f),
            SfErr::NodeError(e) => e.1.fmt(f),
            SfErr::StreamFail(s) => s.fmt(f),
            SfErr::DisallowedAddr(a) => {
                "Disallowed Address ".fmt(f)?;
                a.fmt(f)
            }
            SfErr::UnexpectedAckErr(a) => {
                "Unexpected ack ".fmt(f)?;
                b64spk(a).fmt(f)
            }
        }
    }
}

impl<T> From<sync::PoisonError<T>> for SfErr {
    fn from(e: sync::PoisonError<T>) -> SfErr {
        SfErr::MutexErr(e.to_string())
    }
}
impl<T> From<crossbeam_channel::SendError<T>> for SfErr {
    fn from(_e: crossbeam_channel::SendError<T>) -> SfErr {
        SfErr::SendError
    }
}
macro_rules! generate_from {
    {$l:ty; $m:path} => {
        impl From<$l> for SfErr {
            fn from(e: $l) -> SfErr {
                $m(e)
            }
        }
    }
}
generate_from! {io::Error; SfErr::IoErr}
generate_from! {bson::DecoderError; SfErr::BsonDecErr}
generate_from! {bson::EncoderError; SfErr::BsonEncErr}
generate_from! {net::AddrParseError; SfErr::AddrErr}
generate_from! {base64::DecodeError; SfErr::B64Err}
generate_from! {bson::ordered::ValueAccessError; SfErr::ValErr}
generate_from! {num::ParseIntError; SfErr::NumErr}
generate_from! {num::TryFromIntError; SfErr::IntConvErr}
generate_from! {serde_json::Error; SfErr::SerdJErr}
generate_from! {crossbeam_channel::RecvTimeoutError; SfErr::TimeoutErr}
generate_from! {sled::Error; SfErr::SledErr}
generate_from! {std::str::Utf8Error; SfErr::StrError}
generate_from! {std::string::FromUtf8Error; SfErr::StringError}
generate_from! {crossbeam_channel::TrySendError<Vec<u8>>; SfErr::TrySendErr}
generate_from! {(String, bson::Document); SfErr::NodeError}

pub fn sfnone() -> SfErr {
    SfErr::NoneErr
}
