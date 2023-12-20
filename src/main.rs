#![allow(dead_code)]

use std::sync::Arc;
use tokio::net::UdpSocket; 

use crate::packet::BytePacketBuffer;


mod header;
mod packet;
mod response; 



// async fn resolver(server: SocketAddr,bytes: &mut BytePacketBuffer,  ) -> Result<()> { 
//     let socket = UdpSocket::bind(("0.0.0.0", 43210)).await?;


// }


#[tokio::main]
async fn main() {

    println!("Logs from your program will appear here!");
    
    let udp_socket = UdpSocket::bind("0.0.0.0:2053")
        .await
        .expect("Failed to bind to address");
    
    let shared_udp_socket = Arc::new(udp_socket); 
    
    'thread_spawner: loop {
        //header section size definition for reading
        let mut buf = [0; 512];  
        
        match  shared_udp_socket.recv_from(&mut buf).await {
            Ok((size, socket)) => {

                let cloned_udp_socket = shared_udp_socket.clone(); 
                
                let _handle = tokio::task::spawn(async move { 

                    let mut packet_buffer = BytePacketBuffer::new(buf); 
                    
                    let _response = match packet::from_buffer(&mut packet_buffer) {
                        Ok(mut dns_packet) => {
                            let mut _local_buffer = [0_u8; 512]; 

                            dns_packet.header.response = true; 

                            let ans_record = packet::DnsRecord::A{ 
                                    domain: "codecrafters.io".to_string(), 
                                    addr: [8,8,8,8].into(), 
                                    ttl: 60
                                };

                            dns_packet.answers.push(ans_record);
                            println!("DNS req: {:#?} \n", dns_packet);

                            let mut buffer = BytePacketBuffer::new(_local_buffer); 

                            // println!("DNS res: {:#?}", buffer); 

                            let _ = dns_packet.write(&mut buffer);

                            Ok(buffer)
                        },
                        Err(_e) => {Err(_e)}
                    }.unwrap(); 


                    // let _received_data = String::from_utf8_lossy(&buf[0..size]);
                    println!("Received {} bytes from {}",size, socket);
                    // println!("data: {:?}", _received_data); 

                    cloned_udp_socket
                        .send_to(&_response.buf, socket)
                        .await
                        .expect("Failed to send the response");
                });

            } 
            Err(e) => { 
                eprintln!("Error receiving data: {}", e);
                break 'thread_spawner; 
            }
        }
    }
    
}
