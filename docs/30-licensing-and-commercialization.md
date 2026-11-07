# 30 - Licensing Architecture & Enterprise Tier Gates

Samurai incorporates cryptographically signed, hardware-bound licensing mechanisms and granular feature gates designed for enterprise and commercial multi-tenant environments.

![Samurai Security & Access Control Architecture](assets/diagrams/samurai_distributed_security.svg)

---

## 1. Native C++ Licensing Subsystem (`ddos_samurai/licensing/`)

- **`hwid.cpp` / `hwid.hpp`:** Derives immutable, collision-resistant hardware identifiers (HWID) from CPU model/microcode, primary NIC MAC addresses, and motherboard DMI/SMBIOS serial numbers.
- **`cache.cpp` / `cache.hpp`:** Manages encrypted local license caching on disk with tamper-detection checksums.
- **`gates.cpp` / `gates.hpp`:** Evaluates runtime capabilities against the active license tier (Community, Pro, Enterprise), enforcing limits on maximum RPS, concurrent worker count, GPU/DOCA acceleration, and distributed clustering.
- **`license_types.cpp` / `license_types.hpp`:** Core data structures and asymmetric ECDSA/RSA cryptographic signature verification.

---

## 2. Enterprise Tier Feature Matrix

| Feature / Subsystem | Community (Lab) | Professional | Enterprise |
| :--- | :---: | :---: | :---: |
| **Max Concurrent Workers** | 1 | 8 | Unlimited |
| **L4 Raw Sockets & AF_XDP Zero-Copy** | Yes | Yes | Yes |
| **DPDK PMD & NVIDIA CUDA Acceleration** | No | Yes | Yes |
| **Stateful L7 (HTTP/1.1, HTTP/2, QUIC/H3)** | No | Yes | Yes |
| **Stateful Persona Scenario Engine** | No | Yes | Yes |
| **Distributed Master / Slave Clustering** | No | No | Yes |
| **High Availability (HA) Failover** | No | No | Yes |
| **REST Management API (`:8089`) & RBAC** | No | No | Yes |
| **Multi-Master Geo-Federation** | No | No | Yes |

---

## 3. Subsystem Verification & Self-Test

The licensing engine includes a dedicated native test binary to verify HWID extraction and cryptographic signature validation:

```bash
./build/ddos_samurai/licensing/samurai_licensing_selftest
```
