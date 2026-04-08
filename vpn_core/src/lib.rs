use std::net::{IpAddr};

pub struct Packet {
    ip_origin: IpAddr,
    ip_destination: IpAddr,
    protocol: u8,
}

pub fn parse_data(data: &[u8]) -> Option<Packet> {
    if data.len() < 20 {
        println!("Invalid packet! ({} bytes)", data.len());
        return None;
    }

    let ip_version: u8 = (data[0] >> 4) & 0xF;
    let origin_ip: IpAddr;
    let destin_ip: IpAddr;
    let protocol: u8;

    if ip_version == 4 {
        origin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[12..16]).expect("Couldn't reach the IP of origin"),
        );
        destin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[16..20]).expect("Couldn't reach the IP of destination"),
        );
        protocol = data[9];
    } else if ip_version == 6 {
        origin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[8..24]).expect("Couldn't reach the IP of origin"),
        );
        destin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[24..=40]).expect("Couldn't reach the IP of destination"),
        );
        protocol = data[6];
    } else {
        return None;
    }
    return Some(Packet {
        ip_origin: (origin_ip),
        ip_destination: (destin_ip),
        protocol: (protocol),
    });
}
