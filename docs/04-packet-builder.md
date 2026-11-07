# 04 - CPU Packet Builder & Traffic Synthesis Engine

In the CPU dataplane, high-speed packet synthesis, dynamic header encoding, and source address permutation are executed natively in C++ within the [`ddos_samurai/cpu_native/`](file://ddos_samurai/cpu_native/) module.

---

## 1. Subsystem Architecture

- **`engine.cpp` / `engine.hpp`:** Core packet synthesis engine, buffer ring lifecycle, and pacing governor.
- **`packets.cpp`:** Byte-level Ethernet, IPv4, TCP (SYN, ACK, FIN, RST, XMAS), UDP, ICMP, DNS, and HTTP frame construction.
- **`spoofing.cpp`:** Source IP randomization algorithms (Random, Subnet CIDR, Seeded List, Realistic Autonomous System distribution).
- **`amp.cpp`:** Amplification and reflection attack simulation templates (DNS ANY/TXT, NTP Monlist, SSDP M-SEARCH, SNMP, Memcached).
- **`pool.cpp`:** Pre-allocated zero-allocation packet pools eliminating runtime memory allocation overhead.

---

## 2. Supported Protocols & Vectors

### L4 Transport Protocols:
- **TCP:** SYN Floods, ACK Floods, RST Floods, SYN-ACK Floods, Custom Flag combinations.
- **UDP:** Generic UDP payload floods, high-rate randomized UDP streams, DNS query generation.
- **ICMP:** Echo Request (Ping), Destination Unreachable, Redirect simulations.

### L7 & Reflection/Amplification Vectors:
- **DNS Amplification:** Large ANY and TXT query response payloads.
- **NTP Monlist:** UDP port 123 administrative reflection requests.
- **SSDP M-SEARCH:** UDP port 1900 UPnP discovery frames.
- **Memcached:** UDP port 11211 multi-key retrieval commands.

---

## 3. Source IP Permutation Modes

1. **Random (`random`):** Full 32-bit pseudorandom IPv4 generation (excluding RFC 5735 reserved ranges).
2. **Subnet (`subnet`):** Constrained randomization within a designated CIDR network block (e.g. `192.168.10.0/24`).
3. **List (`list`):** Iterative or randomized selection from a pre-loaded IP inventory file.
4. **Realistic (`realistic`):** Weighted IP generation conforming to empirical global Internet Autonomous System (AS) distributions.
