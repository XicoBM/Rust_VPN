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
const IPV4_ADDR_SIZE: usize = 4;
const IPV6_ADDR_SIZE: usize = 6;

pub fn parse_data(data: &[u8]) -> Result<PacketFormat, PacketError> {
    if data.len() < 20 {
        return Err(PacketError::TooShort(data.len(), MINIMUM_PACKET_SIZE));
    }

    let ip_version: u8 = (data[0] >> 4) & 0xF;
    let origin_ip: IpAddr;
    let destin_ip: IpAddr;
    let protocol: Protocol;

    if ip_version == 4 {
        let origin_size: usize = data[12..16].len();
        origin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[12..16])
                .map_err(|_| PacketError::TooShort(origin_size, IPV4_ADDR_SIZE))?,
        );
        let destin_size: usize = data[16..20].len();
        destin_ip = IpAddr::from(
            <[u8; 4]>::try_from(&data[16..20])
                .map_err(|_| PacketError::TooShort(destin_size, IPV4_ADDR_SIZE))?,
        );
        protocol = parse_protocol(data[9]);
    } else if ip_version == 6 {
        let origin_size: usize = data[8..24].len();
        origin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[8..24])
                .map_err(|_| PacketError::TooShort(origin_size, IPV6_ADDR_SIZE))?,
        );
        let destin_size: usize = data[24..40].len();
        destin_ip = IpAddr::from(
            <[u8; 16]>::try_from(&data[24..40])
                .map_err(|_| PacketError::TooShort(destin_size, IPV6_ADDR_SIZE))?,
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
