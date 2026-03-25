use std::{error::Error, io::Read, net::Ipv4Addr};
use tun::create;
use tun::Configuration;
use tun::Device;

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut tun0: Configuration = Configuration::default();

    tun0.address((10, 0, 0, 9))
        .netmask((255, 255, 255, 255)) // /32 for P2P
        .destination((10, 0, 0, 1))
        .mtu(1420)
        .up();

    let mut dev: Device = create(&tun0)?;
    let mut buf: [u8; 1504] = [0; 1504];

    loop {
        let n_bytes: usize = dev.read(&mut buf)?;

        if n_bytes >= 20 {
            let origin: [u8; 4] = buf[12..16].try_into().unwrap();
            let origin_ip: Ipv4Addr = Ipv4Addr::from_octets(origin);

            let destin: [u8; 4] = buf[16..20].try_into().unwrap();
            let destin_ip: Ipv4Addr = Ipv4Addr::from_octets(destin);

            let protocol: u8 = buf[9];

            println!(
                "The packet originates from {} directed to {} using [{}].",
                origin_ip,
                destin_ip,
                match protocol {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    _ => "Invalid Protocol",
                },
            )
        } else {
            println!("Invalid packet!");
        }
    }
}
