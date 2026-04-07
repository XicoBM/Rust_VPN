use std::{net::Ipv4Addr, result::Result, sync::Arc};
use tokio::{
    join,
    net::UdpSocket,
    task::{spawn, spawn_blocking, JoinHandle},
};
use wintun::{load, Adapter, Packet, Session};

#[tokio::main]
async fn main() -> () {
    // TUN interface config
    let wintun = unsafe { load() }.expect("Wintun DDL not found");
    let wintun_adapter: Arc<Adapter> =
        Adapter::create(&wintun, "MyTun", "WireGuard", None).unwrap();
    let session: Session = wintun_adapter
        .start_session(wintun::MAX_RING_CAPACITY)
        .unwrap();
    let session: Arc<Session> = Arc::new(session);

    // UDP socket config
    let socket: UdpSocket = UdpSocket::bind("0.0.0.0:8080")
        .await
        .expect("Could not config the UDP socket.");
    let addr: &str = "127.0.0.1:12345"; // The address of the server goes here (still not defined)
    socket
        .connect(addr)
        .await
        .expect("It was not possible to connect to server specified.");
    let socket: Arc<UdpSocket> = Arc::new(socket);

    let session_a: Arc<Session> = Arc::clone(&session);
    let socket_a: Arc<UdpSocket> = Arc::clone(&socket);
    let handle_task_a: JoinHandle<()> = spawn(tun_to_udp(session_a, socket_a));

    let session_b: Arc<Session> = Arc::clone(&session);
    let socket_b: Arc<UdpSocket> = Arc::clone(&socket);
    let handle_task_b: JoinHandle<()> = spawn(udp_to_tun(session_b, socket_b));

    join!(handle_task_a, handle_task_b);
}

// Receives TUN (wintun in this case) package and converts it into an UDP package
async fn tun_to_udp(wintun_session: Arc<Session>, socket: Arc<UdpSocket>) -> () {
    loop {
        let current_session: Arc<Session> = wintun_session.clone();
        let packet: Result<Packet, wintun::Error> =
            spawn_blocking(move || current_session.receive_blocking())
                .await
                .expect("Could not convert package.");
        let temp_value: Packet = packet.expect("Could not extract the packet data");
        let data: &[u8] = temp_value.bytes();

        process_packet(data);

        let len: usize = socket
            .send(data)
            .await
            .expect("Could not send data through UDP tunnel.");
        println!("{:?} bytes sent", len);
    }
}

// Receives the server response and converts it into a TUN package
async fn udp_to_tun(wintun_session: Arc<Session>, socket: Arc<UdpSocket>) -> () {
    loop {
        let mut buf: [u8; 1504] = [0; 1504];
        let res: usize = socket
            .recv(&mut buf)
            .await
            .expect("Failed to receive server answer.");
        let size: u16 = Result::expect(
            u16::try_from(res),
            "Could not convert buffer size into the correct numeric type",
        );

        let temp: Result<Packet, wintun::Error> = wintun_session.allocate_send_packet(size);
        let mut packet_out: Packet =
            Result::expect(temp, "Could not convert outing packet correctly");
        let packat_bytes: &mut [u8] = packet_out.bytes_mut();
        packat_bytes.copy_from_slice(&buf[..res]);
        wintun_session.send_packet(packet_out);
    }
}

fn process_packet(data: &[u8]) {
    if data.len() < 20 {
        println!("Invalid packet! ({} bytes)", data.len());
        return;
    }

    let ip_version: u8 = (data[0] >> 4) & 0xF;

    if ip_version == 4 {
        let origin_ip: Ipv4Addr = Ipv4Addr::from(
            <[u8; 4]>::try_from(&data[12..16]).expect("Couldn't reach the IP of origin"),
        );
        let destin_ip: Ipv4Addr = Ipv4Addr::from(
            <[u8; 4]>::try_from(&data[16..20]).expect("Couldn't reach the IP of destination"),
        );
        let protocol: u8 = data[9];

        println!(
            "Packet: {} → {} [{}]",
            origin_ip,
            destin_ip,
            match protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                p => {
                    println!("Unknown protocol: {p}");
                    return;
                }
            }
        );
    }
}
