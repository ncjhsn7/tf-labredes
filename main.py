import socket
import struct
import time
import csv
import os
import threading
from datetime import datetime

# Configurações
INTERFACE = "tun0" 
FILE_INTERNET = "camada_internet.csv"
FILE_TRANSPORT = "camada_transporte.csv"
FILE_APP = "camada_aplicacao.csv"

# Estrutura de Estatísticas
stats = {
    "packets_captured": 0,
    "protocols": {"IPv4": 0, "IPv6": 0, "ICMP": 0, "TCP": 0, "UDP": 0, "Other": 0},
    "app_protocols": {"HTTP": 0, "DNS": 0, "DHCP": 0, "NTP": 0, "Other": 0},
    # Armazena dados por IP de cliente da rede tunel (172.31.66.xxx)
    "clients": {} 
}

def init_csvs():
    """Inicializa os arquivos CSV com os cabeçalhos exigidos."""
    if not os.path.exists(FILE_INTERNET):
        with open(FILE_INTERNET, 'w', newline='') as f:
            csv.writer(f).writerow(["Data/Hora", "Protocolo", "IP Origem", "IP Destino", "ID Proto", "Info Extra", "Tamanho"])
        
    if not os.path.exists(FILE_TRANSPORT):
        with open(FILE_TRANSPORT, 'w', newline='') as f:
            csv.writer(f).writerow(["Data/Hora", "Protocolo", "IP Origem", "Porta Origem", "IP Destino", "Porta Destino", "Tamanho"])
        
    if not os.path.exists(FILE_APP):
        with open(FILE_APP, 'w', newline='') as f:
            csv.writer(f).writerow(["Data/Hora", "Protocolo", "Informacao"])

# --- Parsing de Endereços ---
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def get_ipv4(addr):
    return '.'.join(map(str, addr))

def get_ipv6(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)

# --- Parsing de Camadas ---

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return proto, get_ipv4(src), get_ipv4(target), data[header_length:]

def ipv6_packet(data):
    # Parsing do cabeçalho IPv6 (40 bytes fixos)
    if len(data) < 40:
        return None, None, None, None
    payload_len, next_header, hop_limit, src_addr, dst_addr = struct.unpack('! 4x H B B 16s 16s', data[:40])
    return next_header, get_ipv6(src_addr), get_ipv6(dst_addr), data[40:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, data[8:]

# --- Parsing de Aplicação (Heurísticas Avançadas) ---

def parse_dns_name(payload):
    """Tenta extrair o domínio de uma query DNS."""
    try:
        # Pula o cabeçalho DNS (12 bytes) e começa a ler o QNAME
        idx = 12
        domain = []
        while idx < len(payload):
            length = payload[idx]
            if length == 0: break
            if length > 63: return "DNS Comprimido/Complexo"
            idx += 1
            domain.append(payload[idx:idx+length].decode('utf-8', 'ignore'))
            idx += length
        return '.'.join(domain)
    except:
        return "Erro Parsing DNS"

def parse_http_header(payload):
    """Tenta extrair o método e host do HTTP."""
    try:
        text = payload.decode('utf-8', 'ignore').split('\r\n')
        request_line = text[0] # Ex: GET /index.html HTTP/1.1
        host_line = [line for line in text if line.startswith("Host:")]
        host = host_line[0].split(": ")[1] if host_line else ""
        return f"{request_line} | Host: {host}"
    except:
        return "Dados HTTP Binários/Fragmentados"

def identify_app_protocol(src_port, dest_port, payload, timestamp):
    info = ""
    proto_name = "Other"

    if src_port == 53 or dest_port == 53:
        proto_name = "DNS"
        info = f"Query/Resp: {parse_dns_name(payload)}"
    elif src_port == 80 or dest_port == 80:
        proto_name = "HTTP"
        if len(payload) > 0:
            info = parse_http_header(payload)
    elif src_port in [67, 68] or dest_port in [67, 68]:
        proto_name = "DHCP"
        info = "Transação DHCP (IP Assign)"
    elif src_port == 123 or dest_port == 123:
        proto_name = "NTP"
        info = "Sincronização NTP"
    
    if proto_name != "Other":
        log_app(timestamp, proto_name, info)
        stats["app_protocols"][proto_name] += 1
    else:
        # Tenta detectar HTTP em portas não padrão ou texto claro
        if b"HTTP" in payload[:20]:
            log_app(timestamp, "HTTP-Alt", parse_http_header(payload))

# --- Logging e Stats ---

def log_internet(timestamp, proto_name, src, dst, pid, info, size):
    with open(FILE_INTERNET, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto_name, src, dst, pid, info, size])

def log_app(timestamp, proto, info):
    with open(FILE_APP, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto, info])

def log_transport(timestamp, proto_name, src, sport, dst, dport, size):
    with open(FILE_TRANSPORT, 'a', newline='') as f:
        csv.writer(f).writerow([timestamp, proto_name, src, sport, dst, dport, size])

def update_client_stats(src_ip, dst_ip, dst_port, size):
    """Atualiza estatísticas exigidas para os clientes do túnel."""
    # Verifica se a origem é um cliente da rede 172.31.66.xxx
    if src_ip.startswith("172.31.66.") and src_ip != "172.31.66.1":
        client = src_ip
        remote = dst_ip
    # Verifica se o destino é um cliente (tráfego de retorno)
    elif dst_ip.startswith("172.31.66.") and dst_ip != "172.31.66.1":
        client = dst_ip
        remote = src_ip
    else:
        return

    if client not in stats["clients"]:
        stats["clients"][client] = {"remotes": set(), "ports": set(), "bytes": 0, "packets": 0}
    
    stats["clients"][client]["remotes"].add(remote)
    stats["clients"][client]["ports"].add(dst_port)
    stats["clients"][client]["bytes"] += size
    stats["clients"][client]["packets"] += 1

# --- Interface ---
def print_ui():
    while True:
        os.system('clear')
        print("="*60)
        print(f"MONITOR DE TRÁFEGO EM TEMPO REAL - {INTERFACE}")
        print(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print("="*60)
        
        print(f"Total de Pacotes Capturados: {stats['packets_captured']}")
        
        print("\n--- Protocolos de Rede/Transporte ---")
        for k, v in stats["protocols"].items():
            print(f"{k:<10}: {v}")
            
        print("\n--- Protocolos de Aplicação (Detetados) ---")
        for k, v in stats["app_protocols"].items():
            print(f"{k:<10}: {v}")

        print("\n--- Clientes do Túnel (172.31.66.xxx) ---")
        if not stats["clients"]:
            print(" * Nenhum cliente detetado ainda *")
        else:
            print(f"{'Cliente IP':<15} | {'Vol(KB)':<8} | {'Pkt':<5} | {'Remotos':<5} | {'Portas'}")
            print("-" * 60)
            for ip, data in stats["clients"].items():
                kb = data['bytes'] / 1024
                remotes_count = len(data['remotes'])
                ports_count = len(data['ports'])
                print(f"{ip:<15} | {kb:<8.2f} | {data['packets']:<5} | {remotes_count:<5} | {ports_count}")

        time.sleep(1)

# --- Loop Principal ---
def main():
    init_csvs()
    
    # Raw Socket capturando tudo (ETH_P_ALL = 0x0003)
    try:
        # socket.ntohs(3) garante que capturamos frames Ethernet recebidos
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((INTERFACE, 0))
    except Exception as e:
        print(f"Erro ao abrir socket na interface {INTERFACE}: {e}")
        return

    # Thread da Interface
    t = threading.Thread(target=print_ui)
    t.daemon = True
    t.start()

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            stats["packets_captured"] += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            packet_size = len(raw_data)

            # Ethernet L2
            eth_proto, data = ethernet_frame(raw_data)

            # L3 Logica
            src_ip, dst_ip, l4_proto, l4_payload = None, None, None, None
            
            # IPv4
            if eth_proto == 8: 
                stats["protocols"]["IPv4"] += 1
                l4_proto, src_ip, dst_ip, data = ipv4_packet(data)
                log_internet(timestamp, "IPv4", src_ip, dst_ip, l4_proto, "TTL/Header OK", packet_size)
            
            # IPv6
            elif eth_proto == 0x86DD: 
                stats["protocols"]["IPv6"] += 1
                l4_proto, src_ip, dst_ip, data = ipv6_packet(data)
                if src_ip: # Se o parsing funcionou
                    log_internet(timestamp, "IPv6", src_ip, dst_ip, l4_proto, "Flow Label OK", packet_size)

            # Se não extraímos IP, continuamos para o próximo
            if not src_ip:
                continue

            # L4 Logica
            src_port, dst_port = 0, 0
            
            if l4_proto == 1: # ICMPv4
                stats["protocols"]["ICMP"] += 1
                ic_type, ic_code = icmp_packet(data)
                # Atualiza log internet com detalhes ICMP
                log_internet(timestamp, "ICMP", src_ip, dst_ip, 1, f"Type:{ic_type} Code:{ic_code}", packet_size)
            
            elif l4_proto == 6: # TCP
                stats["protocols"]["TCP"] += 1
                src_port, dst_port, l4_payload = tcp_segment(data)
                log_transport(timestamp, "TCP", src_ip, src_port, dst_ip, dst_port, packet_size)
                # Atualiza Stats do Cliente
                update_client_stats(src_ip, dst_ip, dst_port, packet_size)
                # Analisa Aplicação
                identify_app_protocol(src_port, dst_port, l4_payload, timestamp)

            elif l4_proto == 17: # UDP
                stats["protocols"]["UDP"] += 1
                src_port, dst_port, l4_payload = udp_segment(data)
                log_transport(timestamp, "UDP", src_ip, src_port, dst_ip, dst_port, packet_size)
                # Atualiza Stats do Cliente
                update_client_stats(src_ip, dst_ip, dst_port, packet_size)
                # Analisa Aplicação
                identify_app_protocol(src_port, dst_port, l4_payload, timestamp)

        except Exception:
            # Captura erros de parsing para não derrubar o monitor
            continue

if __name__ == "__main__":
    main()