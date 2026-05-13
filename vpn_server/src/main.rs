use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use tokio::{
    join,
    net::UdpSocket,
    task::{spawn, spawn_blocking, JoinHandle},
};
use vpn_core::packet::{parse_data, PacketFormat, Protocol};
use vpn_errors::packet::PacketError;
use wintun::{load, Adapter, Packet, Session};

const INITIAL_IP_VALUE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

#[tokio::main]
async fn main() {
    let wintun = unsafe { load() }.expect("Wintun DDL not found");
    let wintun_adapter: Arc<Adapter> =
        Adapter::create(&wintun, "OtherTun", "WireGuard", None).unwrap();

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
        .unwrap();
    let session: Arc<Session> = Arc::new(session);

    let socket: UdpSocket = UdpSocket::bind("127.0.0.1:12345")
        .await
        .expect("Failed to power up server.");
    let socket: Arc<UdpSocket> = Arc::new(socket);

    let session_a: Arc<Session> = Arc::clone(&session);
    let socket_a: Arc<UdpSocket> = Arc::clone(&socket);

    let session_b: Arc<Session> = Arc::clone(&session);
    let socket_b: Arc<UdpSocket> = Arc::clone(&socket);

    let client_addr: Arc<Mutex<SocketAddr>> = Arc::new(Mutex::new(INITIAL_IP_VALUE));
    let client_addr_a: Arc<Mutex<SocketAddr>> = Arc::clone(&client_addr);
    let client_addr_b: Arc<Mutex<SocketAddr>> = Arc::clone(&client_addr);

    let handle_task_b: JoinHandle<()> = spawn(udp_to_tun(session_a, socket_a, client_addr_a));
    let handle_task_a: JoinHandle<()> = spawn(tun_to_udp(session_b, socket_b, client_addr_b));

    join!(handle_task_a, handle_task_b);
}

// Task a -
async fn udp_to_tun(
    wintun_session: Arc<Session>,
    socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<SocketAddr>>,
) -> () {
    loop {
        let mut buf: [u8; 1504] = [0; 1504];
        let res: (usize, SocketAddr) = socket
            .recv_from(&mut buf)
            .await
            .expect("Failed to receive server answer.");
        let size: u16 = Result::expect(
            u16::try_from(res.0),
            "Could not convert buffer size into the correct numeric type",
        );

        update_addr(&client_addr, res.1);

        let temp: Result<Packet, wintun::Error> = wintun_session.allocate_send_packet(size);
        let mut packet_out: Packet =
            Result::expect(temp, "Could not convert outing packet correctly");
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
) -> () {
    loop {
        let current_session: Arc<Session> = wintun_session.clone();
        let packet: Result<Packet, wintun::Error> =
            spawn_blocking(move || current_session.receive_blocking())
                .await
                .expect("Could not convert package.");
        let temp_value: Packet = packet.expect("Could not extract the packet data");
        let data: &[u8] = temp_value.bytes();

        let ans: Result<PacketFormat, PacketError> = parse_data(data);
        match ans {
            Ok(packet_format) => {
                let addr: SocketAddr = { *client_addr.lock().unwrap() };
                if addr == INITIAL_IP_VALUE {
                    continue;
                }
                let len: usize = socket
                    .send_to(data, addr)
                    .await
                    .expect("Could not send data through UDP tunnel.");
                let origin_ip: IpAddr = packet_format.ip_origin;
                   let destin_ip: IpAddr = packet_format.ip_destination;
                let protocol: Protocol = packet_format.protocol;
                println!(
                    "{:?} bytes sent from {} to {} using {:?} protocol",
                    len, origin_ip, destin_ip, protocol
                );
            }
            Err(_) => println!("Invalid packet"),
        }
    }
}

fn update_addr(pointer: &Arc<Mutex<SocketAddr>>, new_addr: SocketAddr) -> () {
    if let Ok(mut a) = pointer.lock() {
        *a = new_addr;
    }
}
