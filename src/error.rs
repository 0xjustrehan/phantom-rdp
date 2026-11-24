/// RDP Credential Verifier — unified error type.
use std::fmt;

#[derive(Debug)]
pub enum RdpError {
    Io(std::io::Error),
    Protocol(&'static str),
    ProtocolMsg(String),
    AuthFailed,
    Timeout,
    InvalidCredentials,
    EngineSwap(Box<RdpError>),
}

impl fmt::Display for RdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RdpError::Io(e) => write!(f, "I/O error: {e}"),
            RdpError::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            RdpError::ProtocolMsg(msg) => write!(f, "Protocol error: {msg}"),
            RdpError::AuthFailed => write!(f, "Authentication failed"),
            RdpError::Timeout => write!(f, "Connection timed out"),
            RdpError::InvalidCredentials => write!(f, "Invalid credentials"),
            RdpError::EngineSwap(e) => write!(f, "Engine swap triggered by: {e}"),
        }
    }
}

impl std::error::Error for RdpError {}

impl From<std::io::Error> for RdpError {
    fn from(e: std::io::Error) -> Self {
        RdpError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, RdpError>;
