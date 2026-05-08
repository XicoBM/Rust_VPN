pub mod crypto;
pub mod network;
pub mod packet;
pub mod tun;

use thiserror::Error;
use crypto::CryptoError;
use network::NetworkError;
use packet::PacketError;
use tun::TunError;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error(transparent)]
    Packet(#[from] PacketError), 

    #[error(transparent)]
    Network(#[from] NetworkError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Tun(#[from] TunError),
}