use std::net::IpAddr;
use vpn_errors::packet::PacketError;

pub struct PacketFormat {
    pub ip_origin: IpAddr,
    pub ip_destination: IpAddr,
    pub protocol: Protocol,
}

#[derive(Debug)]
pub enum Protocol {
    ICMP,
    IGMP,
    TCP,
    UDP,
    IPv6,
    GRE,
    ESP,
    AH,
    ICMPv6,
    OSPF,
    Unknown(u8),
}

const MINIMUM_PACKET_SIZE: usize = 20;

pub fn parse_data(data: &[u8]) -> Result<PacketFormat, PacketError> {
    if data.len() < 20 {
        return Err(PacketError::TooShort(data.len(), MINIMUM_PACKET_SIZE));
    }

    let ip_version: u8 = (data[0] >> 4) & 0xF;
    let origin_ip: IpAddr;
    let destin_ip: IpAddr;
    let protocol: Protocol;

    if ip_version == 4 {
        origin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[12..16]).expect("Couldn't reach the IP of origin"),
        );
        destin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[16..20]).expect("Couldn't reach the IP of destination"),
        );
        protocol = parse_protocol(data[9]);
    } else if ip_version == 6 {
        origin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[8..24]).expect("Couldn't reach the IP of origin"),
        );
        destin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[24..40]).expect("Couldn't reach the IP of destination"),
        );
        protocol = parse_protocol(data[6]);
    } else {
        return Err(PacketError::UnknownIpVersion(ip_version));
    }

    return Ok(PacketFormat {
        ip_origin: (origin_ip),
        ip_destination: (destin_ip),
        protocol: (protocol),
    });
}

fn parse_protocol(protocol: u8) -> Protocol {
    match protocol {
        1 => Protocol::ICMP,
        2 => Protocol::IGMP,
        6 => Protocol::TCP,
        17 => Protocol::UDP,
        41 => Protocol::IPv6,
        47 => Protocol::GRE,
        50 => Protocol::ESP,
        51 => Protocol::AH,
        58 => Protocol::ICMPv6,
        89 => Protocol::OSPF,
        other => Protocol::Unknown(other),
    }
}
