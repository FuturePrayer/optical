use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpticalError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("frame decode error: {0}")]
    FrameDecode(String),

    #[error("AEAD decrypt failed (possible tampering or replay)")]
    AeadDecrypt,

    #[error("stream {0} not found")]
    #[allow(dead_code)]
    StreamNotFound(u32),

    #[error("stream {0} closed")]
    #[allow(dead_code)]
    StreamClosed(u32),

    #[error("handshake replay detected")]
    #[allow(dead_code)]
    ReplayDetected,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, OpticalError>;
