# 25 - Core Runtime Subsystems & Module Reference

This document maps the core libraries, native C++ subsystems, and operational boundaries of the Samurai platform.

![Samurai System Architecture](assets/diagrams/samurai_system_architecture.svg)

---

## 1. Subsystem Map

| Subdirectory | Target Binary / Library | Responsibilities & Architectural Role |
| :--- | :--- | :--- |
| **`samurai/core/`** | `samurai_core` | High-speed JSON parsing (`json.hpp`), target allowlist validation (`target_safety.cpp`), thread-safe structured logging (`logging.hpp`). |
| **`samurai/cli/`** | `samurai` | Primary command-line front-end. Argument parsing, profile mapping, KPI gate verification, and RFC compliance suites. |
| **`samurai/control/`** | `samurai_control`<br>`samurai_master`<br>`samurai_slave` | Distributed Master/Slave ZMQ control plane, dynamic workload sharding, High-Availability leader election, REST API (`:8089`), HMAC-SHA256 JWT auth. |
| **`samurai/orchestrator/`** | Header + `supervisor.cpp` | ZMQ Supervisor engine. Spawns, monitors, and collects telemetry snapshots from native worker daemons via dedicated Unix domain sockets. |
| **`samurai/zmq/`** | `samurai_*_worker` | 8 distinct native dataplane worker binaries (`cpu`, `gpu`, `dpdk`, `afxdp`, `doca`, `l7`, `scenario`, `defense`). |
| **`samurai/l4/`** | `samurai_l4` | 64-shard lock-striped Userspace TCP Stack (`tcp_dataplane_core.cpp`), L4 flow table (`l4_state_engine_core.cpp`), hardware timestamping. |
| **`samurai/l7_emu_native/`**| `samurai_l7emu` | Stateful HTTP/1.1, HTTP/2 (nghttp2), QUIC/H3 (ngtcp2), DNS emulation engines, and L2/L3 protocol stack (ARP, DHCP, IGMP, ND). |
| **`samurai/scenario_engine_native/`** | `samurai_scenario_engine` | Web/Mobile persona DSL compiler (`compiler.cpp`), event-loop scheduler (`scheduler.cpp`), microsecond SLA compliance engine (`sla.cpp`). |
| **`samurai/cpu_native/`** | `cpu_native_static` | Optimized CPU raw socket and packet ring generators, dynamic spoofing pools, and amplification vectors. |

---

## 2. Unified Build Hierarchy

All modules build hermetically using modern CMake:

```bash
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```
