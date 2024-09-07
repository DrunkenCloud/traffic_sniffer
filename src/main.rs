use pnet::datalink;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::datalink::Channel::Ethernet;
use std::fs::{File, create_dir_all};
use std::io::{self};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use pnet::datalink::DataLinkReceiver;
use csv::Writer;
use ctrlc;
use std::path::Path;

fn main() {
    let interfaces = datalink::interfaces();
    let mut handles = vec![];

    // Use an Arc and Mutex to share stop flag between threads
    let stop_flag = Arc::new(Mutex::new(false));
    let stop_flag_clone = Arc::clone(&stop_flag);

    // Setup signal handler for CTRL+C
    ctrlc::set_handler(move || {
        let mut stop = stop_flag_clone.lock().unwrap();
        *stop = true;
    }).expect("Error setting Ctrl-C handler");

    for interface in interfaces {
        let stop_flag_thread = Arc::clone(&stop_flag);
        let (tx, rx) = mpsc::channel::<()>();
        let interface_name = sanitize_filename(&interface.name);

        let handle = thread::spawn(move || {
            let mut rx_channel = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(_, rx_channel)) => rx_channel,
                Ok(_) => {
                    eprintln!("Unhandled channel type for interface: {}", interface.name);
                    return;
                }
                Err(e) => {
                    eprintln!("Error creating channel for interface {}: {}", interface.name, e);
                    return;
                }
            };

            // Ensure output directory exists
            let output_dir = "output";
            if !Path::new(output_dir).exists() {
                create_dir_all(output_dir).expect("Failed to create output directory");
            }

            // Open a CSV file to write packet data
            let file_name = format!("{}/{}_traffic.csv", output_dir, interface_name);
            let file = File::create(&file_name).expect("Could not create CSV file");
            let mut wtr = Writer::from_writer(file);

            // Write the CSV header with enhanced logging
            wtr.write_record(&[
                "Timestamp", "Ethertype", "Source MAC", "Destination MAC", 
                "Source IP", "Destination IP", "IP Protocol", "Source Port", 
                "Destination Port", "Packet Length", "Payload Length", "TCP Flags", 
                "TTL", "Fragment Offset", "Sequence Number", "Acknowledgment Number",
                "Flow Duration", "Packet Direction", "Application Layer Protocol", "Payload Hash", "Label"
            ]).expect("Failed to write CSV header");

            loop {
                if rx.try_recv().is_ok() || *stop_flag_thread.lock().unwrap() {
                    println!("Stopping listening on interface: {}", interface.name);
                    break;
                }

                match next_packet_with_timeout(&mut rx_channel, Duration::from_millis(100)) {
                    Some(Ok(packet)) => {
                        let ethernet = EthernetPacket::new(&packet).unwrap();
                        let timestamp = format!("{:?}", Instant::now());
                        let src_mac = ethernet.get_source().to_string();
                        let dst_mac = ethernet.get_destination().to_string();
                        let packet_length = packet.len().to_string();

                        let mut source_ip = String::new();
                        let mut destination_ip = String::new();
                        let mut ip_protocol = String::new();
                        let mut source_port = String::new();
                        let mut destination_port = String::new();
                        let mut payload_length = String::new();
                        let mut tcp_flags = String::new();
                        let mut ttl = String::new();
                        let mut fragment_offset = String::new();
                        let mut sequence_number = String::new();
                        let mut acknowledgment_number = String::new();
                        let application_layer_protocol = String::new();
                        let payload_hash = String::new(); // This could be an actual hash for deeper inspection
                        let label = String::new(); // For supervised learning, you can specify a label

                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                    source_ip = ipv4.get_source().to_string();
                                    destination_ip = ipv4.get_destination().to_string();
                                    ttl = ipv4.get_ttl().to_string();
                                    fragment_offset = ipv4.get_fragment_offset().to_string();
                                    ip_protocol = ipv4.get_next_level_protocol().to_string();

                                    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                            source_port = tcp.get_source().to_string();
                                            destination_port = tcp.get_destination().to_string();
                                            sequence_number = tcp.get_sequence().to_string();
                                            acknowledgment_number = tcp.get_acknowledgement().to_string();
                                            tcp_flags = format!("{:?}", tcp.get_flags());
                                            payload_length = (ipv4.payload().len() - tcp.get_data_offset() as usize * 4).to_string();
                                        }
                                    } else if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                            source_port = udp.get_source().to_string();
                                            destination_port = udp.get_destination().to_string();
                                            payload_length = udp.get_length().to_string();
                                        }
                                    }

                                    // Application layer protocol detection can be added here based on ports or deeper packet inspection
                                }
                            }
                            EtherTypes::Ipv6 => {
                                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                                    source_ip = ipv6.get_source().to_string();
                                    destination_ip = ipv6.get_destination().to_string();
                                    ip_protocol = ipv6.get_next_header().to_string();

                                    if ipv6.get_next_header() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                            source_port = tcp.get_source().to_string();
                                            destination_port = tcp.get_destination().to_string();
                                            sequence_number = tcp.get_sequence().to_string();
                                            acknowledgment_number = tcp.get_acknowledgement().to_string();
                                            tcp_flags = format!("{:?}", tcp.get_flags());
                                            payload_length = (ipv6.payload().len() - tcp.get_data_offset() as usize * 4).to_string();
                                        }
                                    } else if ipv6.get_next_header() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                        if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                            source_port = udp.get_source().to_string();
                                            destination_port = udp.get_destination().to_string();
                                            payload_length = udp.get_length().to_string();
                                        }
                                    }

                                    // Application layer protocol detection can be added here based on ports or deeper packet inspection
                                }
                            }
                            _ => {
                                // Handle other packet types if necessary
                            }
                        }

                        wtr.write_record(&[
                            timestamp, ethernet.get_ethertype().to_string(), src_mac, dst_mac, 
                            source_ip, destination_ip, ip_protocol, source_port, destination_port, 
                            packet_length, payload_length, tcp_flags, ttl, fragment_offset, 
                            sequence_number, acknowledgment_number, "0".to_string(), "in".to_string(), 
                            application_layer_protocol, payload_hash, label
                        ]).expect("Failed to write CSV record");
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading packet on {}: {}", interface.name, e);
                    }
                    None => {}
                }
                thread::sleep(Duration::from_millis(10));
            }

            // Ensure the CSV file is written and closed properly
            wtr.flush().expect("Failed to flush CSV writer");
        });

        handles.push((handle, tx));
    }

    // Wait for all threads to finish
    for (handle, _) in handles {
        handle.join().expect("Thread panicked");
    }
}

fn next_packet_with_timeout(
    rx: &mut Box<dyn DataLinkReceiver>,
    timeout: Duration,
) -> Option<Result<Vec<u8>, io::Error>> {
    let start = Instant::now();

    while start.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => return Some(Ok(packet.to_vec())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Some(Err(e)),
        }
    }
    None
}

// Helper function to sanitize filenames by removing invalid characters
fn sanitize_filename(filename: &str) -> String {
    filename.replace(|c: char| !c.is_alphanumeric(), "_")
}
