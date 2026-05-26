use std::net::{IpAddr, UdpSocket};

const ROUTE_PROBE_TARGET: &str = "1.1.1.1:80";

pub fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(ROUTE_PROBE_TARGET).ok()?;
    let local_address = socket.local_addr().ok()?;
    Some(local_address.ip())
}
