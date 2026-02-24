import numpy as np
import socket
import struct
from ddos_samurai import cpu_packet_engine, gpu_packet

target_ip = "192.168.1.100"
target_port = 80
payload_data = b"HYBRID_TEST_PAYLOAD"

cfg = cpu_packet_engine.PacketConfig(
    target_ip=target_ip,
    target_port=target_port,
    protocol="tcp",
    spoof=False,
    payload=payload_data,
    tcp_flags="PA",
    ttl=64,
    window=8192
)

template_pkt = cpu_packet_engine.create_packet(cfg)
template_bytes = bytes(template_pkt)

count = 10
out = gpu_packet.generate_packets_from_template(
    template_bytes=template_bytes,
    count=count,
    real_src_ip="192.168.1.100",
    spoof_ip=True,
    has_ethernet=False,
    spoof_subnet="1.0.0.0/8",
)
gpu_packets, packet_len = out
cpu_packets = np.asarray(gpu_packets.get(), dtype=np.uint8)

seen_src_ports = []
for i in range(count):
    offset = i * packet_len
    pkt_data = cpu_packets[offset : offset + packet_len]
    ip_header = pkt_data[0:20]
    ihl = (ip_header[0] & 0x0F) * 4
    tcp_header = pkt_data[ihl:ihl + 20]
    src_port = struct.unpack("!H", tcp_header[0:2])[0]
    seen_src_ports.append(src_port)
    print(f"Packet {i}: src_port = {src_port}")

print("Unique ports:", len(set(seen_src_ports)))
