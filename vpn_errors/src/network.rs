use thiserror::Error;
use std::{io::Error, net::IpAddr};

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Failed to bind socket to {addr}: {source}")]
    BindFailed { addr: IpAddr, #[source] source: Error },

    #[error("Failed to connect to {addr}")]
    ConnectFailed { addr: String },

    #[error("Failed to send packet")]
    SendFailed,

    #[error("Timeout, failed to receive data")]
    ReceiveTimeout,

    #[error("Unknown peer, failed to complete handshake")]
    UnknownPeer,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}