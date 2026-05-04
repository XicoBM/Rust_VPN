use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error(transparent)]
    Packet(#[from] PacketError),

    #[error(transparent)]
    Packet(#[from] NetworkError),

    #[error(transparent)]
    Packet(#[from] CryptoError),

    #[error(transparent)]
    Packet(#[from] TunError),
}