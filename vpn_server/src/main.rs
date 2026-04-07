use std::net::{SocketAddr};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let socket: UdpSocket = UdpSocket::bind("127.0.0.1:12345")
        .await
        .expect("Failed to power up server.");

    loop {
        let mut buf: [u8; 1504] = [0; 1504];

        let bytes: (usize, SocketAddr) = socket.recv_from(&mut buf).await.expect("Failed to get the number of bytes and/or origin IP.");
        let n_bytes: usize = bytes.0;
        let origin_ip: SocketAddr = bytes.1;

        let res_final = socket.send_to(&buf[..n_bytes], origin_ip).await.expect("Could not send response to client.");
        println!("Received {} bytes from {}.", n_bytes, origin_ip);
    }
}
