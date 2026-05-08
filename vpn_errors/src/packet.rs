use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Packet too short: {0} bytes, the minimum requirement is: {1} bytes")]
    TooShort(usize, usize),

    #[error("Unknown Ip version: {0}")]
    UnknownIpVersion(u8),

    #[error("Unknown protocol: {0}")]
    UnknownProtocol(u8),

    #[error("Invalid checksum, data compromised or altered")]
    InvalidChecksum,

    #[error("Size declared in header: ({0}) bytes does not match real size: ({1}) bytes")]
    LengthMismatch(usize, usize),
}
