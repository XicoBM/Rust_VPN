use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    result::Result,
    sync::{Arc, Mutex},
};
use tokio::{
    join,
    net::UdpSocket,
    task::{spawn, spawn_blocking, JoinHandle},
};
use vpn_core::packet::{parse_data, PacketFormat, Protocol};
use vpn_errors::{network::NetworkError, packet::PacketError, tun::TunError};
use wintun::{load, Adapter, Packet, Session};

const INITIAL_IP_VALUE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let wintun = unsafe { load() }.map_err(|_| TunError::DllNotFound)?;
    let wintun_adapter: Arc<Adapter> = Adapter::create(&wintun, "OtherTun", "WireGuard", None)
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
            "OtherTun",
            "static",
            "10.0.0.10",
            "255.255.255.0",
        ])
        .output();

    let session: Session = wintun_adapter
        .start_session(wintun::MAX_RING_CAPACITY)
        .map_err(|e| TunError::SessionStartFailed(e.to_string()))?;
    let session: Arc<Session> = Arc::new(session);

    let socket: UdpSocket =
        UdpSocket::bind("127.0.0.1:12345")
            .await
            .map_err(|e| NetworkError::BindFailed {
                addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                source: e,
            })?;
    let socket: Arc<UdpSocket> = Arc::new(socket);

    let session_a: Arc<Session> = Arc::clone(&session);
    let socket_a: Arc<UdpSocket> = Arc::clone(&socket);

    let session_b: Arc<Session> = Arc::clone(&session);
    let socket_b: Arc<UdpSocket> = Arc::clone(&socket);

    let client_addr: Arc<Mutex<SocketAddr>> = Arc::new(Mutex::new(INITIAL_IP_VALUE));
    let client_addr_a: Arc<Mutex<SocketAddr>> = Arc::clone(&client_addr);
    let client_addr_b: Arc<Mutex<SocketAddr>> = Arc::clone(&client_addr);

    let handle_task_b: JoinHandle<anyhow::Result<()>> =
        spawn(udp_to_tun(session_a, socket_a, client_addr_a));
    let handle_task_a: JoinHandle<anyhow::Result<()>> =
        spawn(tun_to_udp(session_b, socket_b, client_addr_b));

    let (res_a, res_b) = join!(handle_task_a, handle_task_b);
    res_a??;
    res_b??;

    Ok(())
}

// Task a -
async fn udp_to_tun(
    wintun_session: Arc<Session>,
    socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<SocketAddr>>,
) -> anyhow::Result<()> {
    loop {
        let mut buf: [u8; 1504] = [0; 1504];
        let res: (usize, SocketAddr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|_| NetworkError::ReceiveTimeout)?;
        let size: u16 = u16::try_from(res.0).map_err(|_| PacketError::BufferProb(res.0))?;

        update_addr(&client_addr, res.1);

        let temp: Result<Packet, wintun::Error> = wintun_session.allocate_send_packet(size);
        let mut packet_out: Packet = temp.map_err(|_| TunError::PacketAllocationFailed)?;
        let packet_bytes: &mut [u8] = packet_out.bytes_mut();

        packet_bytes.copy_from_slice(&buf[..res.0]);
        wintun_session.send_packet(packet_out);
    }
}

// Task b -
async fn tun_to_udp(
    wintun_session: Arc<Session>,
    socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<SocketAddr>>,
) -> anyhow::Result<()> {
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
                let addr: SocketAddr = {
                    *client_addr
                        .lock()
                        .map_err(|e| NetworkError::InvalidAddress(e.to_string()))?
                };
                if addr == INITIAL_IP_VALUE {
                    continue;
                }
                let len: usize = socket
                    .send_to(data, addr)
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

fn update_addr(pointer: &Arc<Mutex<SocketAddr>>, new_addr: SocketAddr) -> () {
    if let Ok(mut a) = pointer.lock() {
        *a = new_addr;
    }
}
