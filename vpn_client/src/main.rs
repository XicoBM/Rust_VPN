use std::{error::Error, net::Ipv4Addr, sync::Arc};
use wintun::{load, Adapter, Packet, Session};

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let wintun = unsafe { load() }.expect("Wintun DDL not found");
    let wintun_adapter: Arc<Adapter> =
        Adapter::create(&wintun, "MyTun", "WireGuard", None).unwrap();
    let session: Session = wintun_adapter
        .start_session(wintun::MAX_RING_CAPACITY)
        .unwrap();
    let session: Arc<wintun::Session> = Arc::new(session);

    loop {
        let packet: Packet = session.clone().receive_blocking()?;
        let data: &[u8] = packet.bytes();
        process_packet(data);
    }
}

fn process_packet(data: &[u8]) {
    if data.len() < 20 {
        println!("Invalid packet! ({} bytes)", data.len());
        return;
    }

    let ip_version: u8 = (data[0] >> 4) & 0xF;

    if ip_version == 4 {
        let origin_ip = Ipv4Addr::from(
            <[u8; 4]>::try_from(&data[12..16]).expect("Couldn't reach the IP of origin"),
        );
        let destin_ip = Ipv4Addr::from(
            <[u8; 4]>::try_from(&data[16..20]).expect("Couldn't reach the IP of destination"),
        );
        let protocol = data[9];

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
