use std::{
    net::{IpAddr, Ipv4Addr},
    process::Command,
    result::Result,
    sync::Arc,
};
use tokio::{
    join,
    net::UdpSocket,
    task::{spawn, spawn_blocking, JoinHandle},
};
use vpn_core::packet::{parse_data, PacketFormat, Protocol};
use vpn_errors::{network::NetworkError, packet::PacketError, tun::TunError};
use wintun::{load, Adapter, Packet, Session};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TUN interface config
    let wintun = unsafe { load() }.map_err(|_| TunError::DllNotFound)?;
    let wintun_adapter: Arc<Adapter> = Adapter::create(&wintun, "MyTun", "WireGuard", None)
        .map_err(|e| TunError::AdapterCreationFailed {
            name: "MyTun".to_string(),
            reason: e.to_string(),
        })?;

    // Wintun IP config
    let _output: Result<std::process::Output, std::io::Error> = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "address",
            "MyTun",
            "static",
            "10.0.0.9",
            "255.255.255.0",
        ])
        .output();

    let session: Session = wintun_adapter
        .start_session(wintun::MAX_RING_CAPACITY)
        .map_err(|e| TunError::SessionStartFailed(e.to_string()))?;
    let session: Arc<Session> = Arc::new(session);

    // UDP socket config
    let socket: UdpSocket =
        UdpSocket::bind("0.0.0.0:8080")
            .await
            .map_err(|e| NetworkError::BindFailed {
                addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                source: e,
            })?;
    let addr: &str = "127.0.0.1:12345"; // The address of the server goes here (still not defined)
    socket
        .connect(addr)
        .await
        .map_err(|_| NetworkError::ConnectFailed {
            addr: addr.to_string(),
        })?;
    let socket: Arc<UdpSocket> = Arc::new(socket);

    let session_a: Arc<Session> = Arc::clone(&session);
    let socket_a: Arc<UdpSocket> = Arc::clone(&socket);
    let handle_task_a: JoinHandle<anyhow::Result<()>> = spawn(tun_to_udp(session_a, socket_a));

    let session_b: Arc<Session> = Arc::clone(&session);
    let socket_b: Arc<UdpSocket> = Arc::clone(&socket);
    let handle_task_b: JoinHandle<anyhow::Result<()>> = spawn(udp_to_tun(session_b, socket_b));

    let (res_a, res_b) = join!(handle_task_a, handle_task_b);
    res_a??;
    res_b??;

    Ok(())
}

// Receives TUN (wintun in this case) package and converts it into an UDP package - task a
async fn tun_to_udp(wintun_session: Arc<Session>, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
    loop {
        let current_session: Arc<Session> = wintun_session.clone();
        let packet: Result<Packet, wintun::Error> =
            spawn_blocking(move || current_session.receive_blocking())
                .await
                .map_err(|_| TunError::SessionClosed)?;
        let temp_value: Packet = packet.map_err(|_| PacketError::InvalidChecksum)?;
        let data: &[u8] = temp_value.bytes();

        let ans: Result<PacketFormat, PacketError> = parse_data(data);
        match ans {
            Ok(packet_format) => {
                let len: usize = socket
                    .send(data)
                    .await
                    .map_err(|_| NetworkError::SendFailed)?;
                let origin_ip: IpAddr = packet_format.ip_origin;
                let destin_ip: IpAddr = packet_format.ip_destination;
                let protocol: Protocol = packet_format.protocol;
                println!(
                    "{:?} bytes sent from {} to {} using {:?} protocol",
                    len, origin_ip, destin_ip, protocol
                );
            }
            Err(e) => {
                eprintln!("Invalid packet: {e}");
                continue;
            }
        }
    }
}

// Receives the server response and converts it into a TUN package - task b
async fn udp_to_tun(wintun_session: Arc<Session>, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
    loop {
        let mut buf: [u8; 1504] = [0; 1504];
        let res: usize = socket
            .recv(&mut buf)
            .await
            .map_err(|_| NetworkError::ReceiveTimeout)?;
        let size: u16 = u16::try_from(res).map_err(|_| PacketError::BufferProb(res))?;
        let temp: Result<Packet, wintun::Error> = wintun_session.allocate_send_packet(size);
        let mut packet_out: Packet = temp.map_err(|_| TunError::PacketAllocationFailed())?;
        let packat_bytes: &mut [u8] = packet_out.bytes_mut();
        packat_bytes.copy_from_slice(&buf[..res]);
        wintun_session.send_packet(packet_out);
    }
}
