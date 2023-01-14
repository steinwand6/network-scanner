use std::fmt::Display;
use std::net::Ipv4Addr;
use std::{env, thread};

use datalink::Channel::Ethernet;
use datalink::{DataLinkReceiver, NetworkInterface};
use ipnet::Ipv4Net;
use pnet::packet::arp::{ArpHardwareType, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet_datalink as datalink;
use tokio::sync::mpsc;

const ARP_PACKET_SIZE: usize = 28;
const ETHER_PACKET_SIZE: usize = 42;

#[derive(Debug)]
enum InterfaceError {
    NotFound(String),
    DoNotHaveIp(String),
    DoNotHaveMac(String),
}

impl Display for InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceError::NotFound(interface_name) => {
                write!(f, "InterfaceError: {interface_name} is not found.")
            }
            InterfaceError::DoNotHaveIp(interface_name) => {
                write!(
                    f,
                    "InterfaceError: {interface_name} doesn't have IP address."
                )
            }
            InterfaceError::DoNotHaveMac(interface_name) => {
                write!(
                    f,
                    "InterfaceError: {interface_name} doesn't have MAC address."
                )
            }
        }
    }
}

#[derive(Debug)]
enum HostInfo {
    Info { ip: Ipv4Addr, mac: MacAddr },
    None,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("usege: network_scanner <network_interface>");
        return;
    }
    let interface_name = args[1].to_string();
    let interface = match get_interface(&interface_name) {
        Ok(i) => i,
        Err(e) => {
            println!("{e}");
            return;
        }
    };
    let (_, ipv4_addr, ipv4_prefix) = match get_ipv4addr_info_from_interface(&interface) {
        Ok((a, b, c)) => (a, b, c),
        Err(e) => {
            println!("{e}");
            return;
        }
    };

    let target_network = Ipv4Net::new(ipv4_addr, ipv4_prefix).expect("failed");

    let hosts = target_network.hosts();

    let (tx, mut rx) = mpsc::channel(32);
    let manager = tokio::spawn(async move {
        println!("scan start");
        let mut count = 0;
        while let Some(host_info) = rx.recv().await {
            match host_info {
                HostInfo::Info { ip, mac } => println!("{ip}\t\t{mac}"),
                HostInfo::None => (),
            }
            count += 1;
            // without the following break, the loop won't end...
            if count >= 254 {
                break;
            }
        }
        println!("scan finished");
    });

    for host in hosts {
        let interface = interface.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            match scan_host(host, &interface) {
                Some((ip, mac)) => {
                    let info = HostInfo::Info { ip, mac };
                    tx_clone.send(info).await.expect("failed to send result");
                }
                None => tx_clone
                    .send(HostInfo::None)
                    .await
                    .expect("failed to send none result"),
            };
        });
        // sleep 30~50 msec
        thread::sleep(std::time::Duration::from_millis(50));
    }

    manager.await.expect("failed to wait for results");
}

fn scan_host(host: Ipv4Addr, interface: &NetworkInterface) -> Option<(Ipv4Addr, MacAddr)> {
    let (mac, ipv4_addr, _) = match get_ipv4addr_info_from_interface(interface) {
        Ok((a, b, c)) => (a, b, c),
        Err(e) => {
            println!("{e}");
            return None;
        }
    };
    let mut arp_packet = [0; ARP_PACKET_SIZE];
    let mut eth_packet = [0; ETHER_PACKET_SIZE];
    let mut arp_packet = MutableArpPacket::new(&mut arp_packet).expect("failed to make arp packet");
    make_arp_req(&mut arp_packet, mac, ipv4_addr, MacAddr::zero(), ipv4_addr);
    let mut ether_packet =
        MutableEthernetPacket::new(&mut eth_packet).expect("failed to make ether packet");
    ether_packet.set_destination(MacAddr::broadcast());
    ether_packet.set_source(mac);
    ether_packet.set_ethertype(EtherTypes::Arp);

    arp_packet.set_target_proto_addr(host);
    ether_packet.set_payload(arp_packet.packet());
    let (mut ds, dr) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(ds, dr)) => (ds, dr),
        Ok(_) => panic!("not channel"),
        Err(e) => {
            panic!("error {}", e);
        }
    };
    let _ = ds
        .send_to(ether_packet.packet(), None)
        .expect(format!("failed to send packet to {host}").as_str());
    recieve_reply(dr)
}

fn recieve_reply(mut dr: Box<dyn DataLinkReceiver>) -> Option<(Ipv4Addr, MacAddr)> {
    match dr.next() {
        Ok(p) => {
            let Some(res) = EthernetPacket::new(p) else {return None};
            let Some(arp_reply) = ArpPacket::new(res.payload()) else {return None};
            if arp_reply.get_operation() == ArpOperations::Reply {
                return Some((
                    arp_reply.get_sender_proto_addr(),
                    arp_reply.get_sender_hw_addr(),
                ));
            }
        }
        Err(e) => print!("{e}"),
    }
    None
}

fn get_ipv4addr_info_from_interface(
    interface: &NetworkInterface,
) -> Result<(MacAddr, Ipv4Addr, u8), InterfaceError> {
    let Some(inet) = interface.ips.iter().find(|i| i.is_ipv4()) else {
        return Err(InterfaceError::DoNotHaveIp(interface.name.to_string()));
    };
    let Some(mac) = interface.mac else {
		return Err(InterfaceError::DoNotHaveMac(interface.name.to_string()));
	};
    Ok((
        mac,
        inet.ip().to_string().parse().expect("failed parse ipaddr"),
        inet.prefix(),
    ))
}

fn get_interface(name: &String) -> Result<NetworkInterface, InterfaceError> {
    let interfaces = datalink::interfaces();
    let interface: Vec<NetworkInterface> =
        interfaces.into_iter().filter(|i| i.name == *name).collect();
    if interface.is_empty() {
        return Err(InterfaceError::NotFound(name.to_string()));
    }
    Ok(interface[0].clone())
}

fn make_arp_req(
    packet: &mut MutableArpPacket,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) {
    packet.set_hardware_type(ArpHardwareType::new(1));
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Request);
    packet.set_sender_hw_addr(sender_mac);
    packet.set_sender_proto_addr(sender_ip);
    packet.set_target_hw_addr(target_mac);
    packet.set_target_proto_addr(target_ip);
}
