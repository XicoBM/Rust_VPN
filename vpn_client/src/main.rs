use std::{error::Error, net::Ipv4Addr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use wintun::{load, Adapter, Packet, Session};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
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

    loop {
        let packet: Packet = session.clone().receive_blocking()?;
        let sock: UdpSocket = socket.clone();

        // Shows the TUN Interface working
        let data: &[u8] = packet.bytes();
        process_packet(data);

        // UDP Tunneling
        tun_to_udp(packet, sock);

        // UDP tunneling answer/response
        udp_to_tun();
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

// Receives TUN (wintun in this case) package and converts it into an UDP package
async fn tun_to_udp(packet: Packet, socket: UdpSocket) -> () {
    let data: &[u8] = packet.bytes();
    let len: usize = socket
        .send(data)
        .await
        .expect("Could not send data through UDP tunnel.");
    println!("{:?} bytes sent", len);
}

// Receives the server response and converts it into a TUN package
async fn udp_to_tun() -> () {}
