use pnet::datalink;
use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use colored::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PortType {
    TCP,
    UDP,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConnectionType {
    Client,
    Server,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortInfo {
    number: u16,
    port_type: PortType,
    process_name: String,
    connection_type: ConnectionType,
    state: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interfaces = datalink::interfaces();
    let open_ports = get_open_ports()?;

    for interface in interfaces {
        println!("{}", format!("Interface: {}", interface.name).green().bold());
        
        let mut interface_ports: HashSet<PortInfo> = HashSet::new();

        for ip in &interface.ips {
            println!("  {}", format!("IP: {}", ip).cyan());
            
            if let Some(ports) = open_ports.get(&ip.ip()) {
                interface_ports.extend(ports.iter().cloned());
            }
        }

        if !interface_ports.is_empty() {
            println!("  {}", "Open ports:".yellow());
            for port in interface_ports {
                let port_type_color = if port.port_type == PortType::TCP { "TCP".blue() } else { "UDP".magenta() };
                let conn_type_color = match port.connection_type {
                    ConnectionType::Server => "Server".green(),
                    ConnectionType::Client => "Client".yellow(),
                    ConnectionType::Unknown => "Unknown".red(),
                };
                println!("    {} ({}) - {} - {} ({})", 
                         port.number.to_string().white().bold(), 
                         port_type_color,
                         port.process_name.cyan(),
                         conn_type_color,
                         port.state.white());
            }
        } else {
            println!("  {}", "No open ports found".red());
        }
        
        println!();
    }

    Ok(())
}

fn get_open_ports() -> Result<HashMap<IpAddr, HashSet<PortInfo>>, Box<dyn std::error::Error>> {
    let mut inode_to_pid = HashMap::new();
    let mut open_ports = HashMap::new();

    // Map inodes to PIDs
    for entry in read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(pid) = path.file_name().and_then(|n| n.to_str()).and_then(|s| s.parse::<u32>().ok()) {
                let fd_dir = path.join("fd");
                if fd_dir.is_dir() {
                    for fd_entry in read_dir(fd_dir)? {
                        let fd_entry = fd_entry?;
                        let fd_path = fd_entry.path();
                        if let Ok(target) = std::fs::read_link(&fd_path) {
                            let target_str = target.to_string_lossy();
                            if target_str.starts_with("socket:[") {
                                let inode = target_str.trim_start_matches("socket:[").trim_end_matches(']');
                                inode_to_pid.insert(inode.to_string(), pid);
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse TCP and UDP connections
    parse_connections("/proc/net/tcp", &mut open_ports, &inode_to_pid, PortType::TCP, false)?;
    parse_connections("/proc/net/tcp6", &mut open_ports, &inode_to_pid, PortType::TCP, true)?;
    parse_connections("/proc/net/udp", &mut open_ports, &inode_to_pid, PortType::UDP, false)?;
    parse_connections("/proc/net/udp6", &mut open_ports, &inode_to_pid, PortType::UDP, true)?;

    Ok(open_ports)
}

fn parse_connections(
    file_path: &str,
    open_ports: &mut HashMap<IpAddr, HashSet<PortInfo>>,
    inode_to_pid: &HashMap<String, u32>,
    port_type: PortType,
    is_ipv6: bool
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            let local_address = parts[1];
            let remote_address = parts[2];
            let state_hex = parts[3];
            let inode = parts[9];
            let address_parts: Vec<&str> = local_address.split(':').collect();
            if address_parts.len() == 2 {
                let ip = if is_ipv6 {
                    IpAddr::V6(parse_ipv6(address_parts[0])?)
                } else {
                    IpAddr::V4(parse_ipv4(address_parts[0])?)
                };
                let port = u16::from_str_radix(address_parts[1], 16)?;
                let process_name = get_process_name(inode_to_pid.get(inode))?;
                let (connection_type, state) = determine_connection_type(&port_type, state_hex, remote_address);
                let port_info = PortInfo { 
                    number: port, 
                    port_type: port_type.clone(), 
                    process_name,
                    connection_type,
                    state,
                };
                open_ports.entry(ip).or_insert_with(HashSet::new).insert(port_info);
            }
        }
    }
    Ok(())
}

fn determine_connection_type(port_type: &PortType, state_hex: &str, remote_address: &str) -> (ConnectionType, String) {
    let state = u8::from_str_radix(state_hex, 16).unwrap_or(0);
    match port_type {
        PortType::TCP => match state {
            1 => (ConnectionType::Client, "ESTABLISHED".to_string()),
            2 => (ConnectionType::Client, "SYN_SENT".to_string()),
            3 => (ConnectionType::Server, "SYN_RECV".to_string()),
            4 => (ConnectionType::Server, "FIN_WAIT1".to_string()),
            5 => (ConnectionType::Server, "FIN_WAIT2".to_string()),
            6 => (ConnectionType::Client, "TIME_WAIT".to_string()),
            7 => (ConnectionType::Server, "CLOSE".to_string()),
            8 => (ConnectionType::Server, "CLOSE_WAIT".to_string()),
            9 => (ConnectionType::Client, "LAST_ACK".to_string()),
            10 => (ConnectionType::Server, "LISTEN".to_string()),
            11 => (ConnectionType::Server, "CLOSING".to_string()),
            _ => (ConnectionType::Unknown, format!("UNKNOWN ({})", state)),
        },
        PortType::UDP => {
            if remote_address == "00000000:0000" {
                (ConnectionType::Server, "UNCONN".to_string())
            } else {
                (ConnectionType::Client, "ESTABLISHED".to_string())
            }
        },
    }
}

fn get_process_name(pid: Option<&u32>) -> Result<String, Box<dyn std::error::Error>> {
    match pid {
        Some(&pid) => {
            let comm_path = Path::new("/proc").join(pid.to_string()).join("comm");
            let mut name = std::fs::read_to_string(comm_path)?;
            name.truncate(name.trim_end().len());
            Ok(name)
        },
        None => Ok("Unknown".to_string()),
    }
}

fn parse_ipv4(hex: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let addr = u32::from_str_radix(hex, 16)?;
    Ok(Ipv4Addr::from(addr.to_be()))
}

fn parse_ipv6(hex: &str) -> Result<Ipv6Addr, Box<dyn std::error::Error>> {
    let mut groups = [0u16; 8];
    for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
        groups[i] = u16::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(Ipv6Addr::from(groups))
}
