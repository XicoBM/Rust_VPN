use thiserror::Error;
use std::io::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Failed to bind socket to {addr}: {source}")]
    BindFailed { addr: String, #[source] source: Error },

    #[error("Failed to connect to {addr}: {source}")]
    ConnectFailed { addr: String, #[source] source: Error },

    #[error("Failed to send packet: {source}")]
    SendFailed { #[source] source: Error },

    #[error("Timeout, failed to receive data")]
    ReceiveTimeout,

    #[error("Unknown peer, failed to complete handshake")]
    UnknownPeer,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}