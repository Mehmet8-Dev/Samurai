# GPU Packet CUDA Kernel Mapping (Python Reference -> CUDA C++)

This table locks field-level parity targets between the Python reference backend
(`gpu_packet_py_backend.py`) and the CUDA C++ implementation.

| Python Reference Kernel/Function | CUDA C++ Kernel/Function | Parity-Critical Fields |
|---|---|---|
| `create_tcp_packets_kernel_spoof` | `create_tcp_packets_kernel_spoof` | src/dst IP, src/dst port, TTL, IP ID, seq, TCP opts, IP/TCP checksum |
| `create_tcp_packets_kernel_nospoof` | `create_tcp_packets_kernel_nospoof` | src IP fixed, TTL, IP ID, seq, TCP opts, checksums |
| `create_udp_packets_kernel_spoof` | `create_udp_packets_kernel_spoof` | spoof subnet pick, ports, TTL, IP ID, UDP len/checksum |
| `create_udp_packets_kernel_nospoof` | `create_udp_packets_kernel_nospoof` | src IP fixed, ports, TTL, IP ID, UDP checksum |
| `template_kernel` | `template_kernel` | template copy path, constant/global fallback, incremental checksum updates |
| `pool_kernel` | `pool_kernel` | template indexing, src/dst patch, incremental IP/TCP/UDP checksum updates |
| `stateful_pool_kernel` | `stateful_pool_kernel` | seq/ack/state, TCP flags transitions, mss/window/ttl updates |
| `create_fragmented_packets_kernel` | `create_fragmented_packets_kernel` | frag offset math, MF flag, payload split/padding, checksums |
| `amplification_kernel_v2` | `amplification_kernel_v2` | victim src IP, reflector dst IP, IP ID, incremental checksums |
| `create_icmp_packets_kernel` | `create_icmp_packets_kernel` | ICMP type/code/id/seq, payload fill, IP/ICMP checksums |

## RNG Consumption Order

For byte-byte parity, each kernel must keep the same RNG draw order as the
Python reference implementation.

## Constant-Memory Rules

- Template and pool constants must respect capacity (`TEMPLATE_CONST_MAX`, `POOL_CONST_MAX`).
- If upload/update fails, global-memory fallback path must be taken with identical packet semantics.
