use std::env::{self, args};

use log::{error, info};

use pnet::{
    datalink::{self, channel, Channel},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        icmp::echo_reply,
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
};

use rspacp::packets::GettableEndPoints;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let arg: Vec<String> = args().collect();

    let interfaces = datalink::interfaces();

    let interface = interfaces
        .iter()
        .find(|interface| interface.name == arg[1])
        .expect("failed to get nic name");

    let (_tx, mut rx) = match channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("failed to handle channel");
            std::process::exit(-1);
        }
        Err(e) => {
            println!("error caused : {}", e);
            std::process::exit(-1);
        }
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = EthernetPacket::new(frame).unwrap();

                match frame.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        handle_ipv4(&frame);
                    }
                    EtherTypes::Ipv6 => {
                        handle_ipv6(&frame);
                    }
                    _ => {
                        info!("No match IPv4 or IPv6");
                    }
                }
            }
            Err(e) => {
                error!("failed read: {}", e);
            }
        }
    }
}

fn handle_ipv4(ethernet_packet: &EthernetPacket) {
    if let Some(packet) = Ipv4Packet::new(ethernet_packet.payload()) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(&packet.get_payload());
                handle_layer4(&packet, &tcp, "TCP");
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(&packet.get_payload());
                handle_layer4(&packet, &udp, "UDP");
            }
            IpNextHeaderProtocols::Icmp => {
                handle_icmp(&packet);
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

fn handle_ipv6(ethermet_packet: &EthernetPacket) {
    if let Some(packet) = Ipv6Packet::new(ethermet_packet.payload()) {
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(&packet.get_payload());
                handle_layer4(&packet, &tcp, "TCP");
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(&packet.get_payload());
                handle_layer4(&packet, &udp, "UDP");
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

fn handle_layer4<T: GettableEndPoints>(packet: &dyn GettableEndPoints, protocol: &Option<T>, pname: &str) {
    if let Some(protocol) = protocol {
        print_packet_info(packet, protocol, pname);
    }
}

fn print_packet_info(
    layer_3: &dyn GettableEndPoints,
    layer_4: &dyn GettableEndPoints,
    protocol: &str,
) {
    println!(
        "Captured a {} packet from {} | {} to {}|{}|\n",
        protocol,
        layer_3.get_source(),
        layer_4.get_source(),
        layer_3.get_destination(),
        layer_4.get_destination()
    );

    let payload = layer_4.get_payload();
    let length = payload.len();

    (0..length).for_each(|i| {
        print!("{:<02X}", payload[i]);

        let width = 20;
        if i % width == width - 1 || i == length - 1 {
            (0..(width - 1 - (i % width))).for_each(|_i| {
                print!(" ");
            });

            print!("| ");
            ((i - i % width)..=i).for_each(|n| {
                if payload[n].is_ascii_alphabetic() {
                    print!("{}", payload[n] as char);
                } else {
                    print!(".");
                }
            });
            println!();
        }
    });

    println!("{}", "=".repeat(60));
    println!();
}

fn handle_icmp(packet: &Ipv4Packet) {
    let icmp = echo_reply::EchoReplyPacket::new(packet.get_payload());

    if let Some(icmp) = icmp {
        print_packet_info_icmp(packet, &icmp);
    }
}

fn print_packet_info_icmp(layer_3: &Ipv4Packet, icmp: &echo_reply::EchoReplyPacket) {
    println!(
        "{} bytes from {}: icmp_seq={} ttl={}\n",
        icmp.payload().len(),
        layer_3.get_source(),
        icmp.get_sequence_number(),
        layer_3.get_ttl()
    );
}
