import socket
import struct
import time
import csv
import os
import threading
from datetime import datetime

INTERFACE = "tun0"
LOG_DIR = "."

FILE_INTERNET = "camada_internet.csv"
FILE_TRANSPORT = "camada_transporte.csv"
FILE_APP = "camada_aplicacao.csv"

stats = {
    "packets_captured": 0,
    "protocols": {"IPv4": 0, "IPv6": 0, "ICMP": 0, "TCP": 0, "UDP": 0, "Other": 0},
    "app_protocols": {"HTTP": 0, "DNS": 0, "DHCP": 0, "NTP": 0, "Other": 0},
    "clients": {}
}

def init_csvs():
    with open(FILE_INTERNET, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Protocol", "Src IP", "Dst IP", "ID", "Info", "Size"])
        
    with open(FILE_TRANSPORT, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Protocol", "Src IP", "Src Port", "Dst IP", "Dst Port", "Size"])
        
    with open(FILE_APP, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Protocol", "Info"])

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def identify_app_protocol(src_port, dest_port, payload):
    if src_port == 80 or dest_port == 80:
        return "HTTP", f"Payload start: {str(payload[:20])}"
    elif src_port == 53 or dest_port == 53:
        return "DNS", "DNS Query/Response"
    elif src_port in [67, 68] or dest_port in [67, 68]:
        return "DHCP", "DHCP Discover/Offer"
    elif src_port == 123 or dest_port == 123:
        return "NTP", "Time Sync"
    else:
        return "Other", "Unknown Application Data"

def log_internet(timestamp, proto, src, dst, pid, info, size):
    with open(FILE_INTERNET, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto, src, dst, pid, info, size])

def log_transport(timestamp, proto, src_ip, src_port, dst_ip, dst_port, size):
    with open(FILE_TRANSPORT, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto, src_ip, src_port, dst_ip, dst_port, size])

def log_app(timestamp, proto, info):
    with open(FILE_APP, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto, info])

def update_client_stats(client_ip, remote_ip, port, proto, size):
    if client_ip.startswith("172.31.66"):
        if client_ip not in stats["clients"]:
            stats["clients"][client_ip] = {"remotes": set(), "ports": set(), "bytes": 0}
        
        stats["clients"][client_ip]["remotes"].add(remote_ip)
        stats["clients"][client_ip]["ports"].add(port)
        stats["clients"][client_ip]["bytes"] += size

def print_ui():
    while True:
        os.system('clear')
        print("="*50)
        print(f"NETWORK TRAFFIC MONITOR - INTERFACE: {INTERFACE}")
        print(f"Time: {datetime.now()}")
        print("="*50)
        print(f"Total Packets: {stats['packets_captured']}")
        print("-" * 20)
        print("Protocols (L3/L4):")
        for k, v in stats["protocols"].items():
            print(f"  {k}: {v}")
        print("-" * 20)
        print("Application Protocols:")
        for k, v in stats["app_protocols"].items():
            print(f"  {k}: {v}")
        print("-" * 20)
        print("Client Statistics (Tunnel IP -> Activity):")
        for client, data in stats["clients"].items():
            print(f"  Client {client}:")
            print(f"    - Remote Hosts Accessed: {len(data['remotes'])}")
            print(f"    - Unique Port/Proto: {len(data['ports'])}")
            print(f"    - Total Volume: {data['bytes']} bytes")
        
        time.sleep(2)

def main():
    init_csvs()
    
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((INTERFACE, 0))
    except PermissionError:
        print("Error: You must run this script with sudo!")
        return
    except OSError:
        print(f"Error: Interface {INTERFACE} not found. Is the tunnel running?")
        return

    ui_thread = threading.Thread(target=print_ui)
    ui_thread.daemon = True
    ui_thread.start()

    while True:
        raw_data, addr = conn.recvfrom(65535)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        stats["packets_captured"] += 1
        
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        packet_size = len(raw_data)

        if eth_proto == 8:
            stats["protocols"]["IPv4"] += 1
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            
            log_internet(timestamp, "IPv4", src, target, proto, f"TTL: {ttl}", packet_size)

            if proto == 1:
                stats["protocols"]["ICMP"] += 1
                icmp_type, code, checksum, _ = icmp_packet(data)
                log_internet(timestamp, "ICMP", src, target, 1, f"Type:{icmp_type} Code:{code}", packet_size)

            elif proto == 6:
                stats["protocols"]["TCP"] += 1
                src_port, dest_port, sequence, ack, payload = tcp_segment(data)
                log_transport(timestamp, "TCP", src, src_port, target, dest_port, packet_size)
                
                update_client_stats(src, target, dest_port, "TCP", packet_size)

                app_proto, info = identify_app_protocol(src_port, dest_port, payload)
                stats["app_protocols"][app_proto] += 1
                if app_proto != "Other":
                    log_app(timestamp, app_proto, info)

            elif proto == 17:
                stats["protocols"]["UDP"] += 1
                src_port, dest_port, length, payload = udp_segment(data)
                log_transport(timestamp, "UDP", src, src_port, target, dest_port, packet_size)
                
                update_client_stats(src, target, dest_port, "UDP", packet_size)

                app_proto, info = identify_app_protocol(src_port, dest_port, payload)
                stats["app_protocols"][app_proto] += 1
                if app_proto != "Other":
                    log_app(timestamp, app_proto, info)

            else:
                stats["protocols"]["Other"] += 1
        elif eth_proto == 0x86DD:
             stats["protocols"]["IPv6"] += 1
             log_internet(timestamp, "IPv6", "IPv6_Src", "IPv6_Dst", "N/A", "IPv6 Detected", packet_size)
        else:
             pass

if __name__ == "__main__":
    main()