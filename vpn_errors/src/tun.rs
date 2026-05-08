use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("Wintun DLL not found")]
    DllNotFound,

    #[error("Failed to create adapter '{name}': {reason}")]
    AdapterCreationFailed { name: String, reason: String },

    #[error("Failed to start session: {0}")]
    SessionStartFailed(String),

    #[error("Failed to alocate exit packet: {0}")]
    PacketAllocationFailed(String),

    #[error("Failed to config IP address of '{adapter}': {reason}")]
    IpConfigFailed { adapter: String, reason: String },

    #[error("Session interrupted abruptly")]
    SessionClosed,
}