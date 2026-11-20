# Samurai v3.0.0 Release Notes

Samurai **v3.0.0** is a full native C++17 architectural overhaul. The platform has moved off legacy Python runtime loops and CPython extensions onto a unified CMake-built microservice architecture spanning kernel-bypass L4, stateful L7 (`io_uring` / kTLS / HTTP/2 / QUIC-H3), carrier-grade telecom protocols, consumer and enterprise GPU P2P dataplanes, DPU ARM CUPS offloading, and an RL-driven closed-loop distributed control plane.

> **Licensing:** Samurai v3.0.0 is 100% open source under the **GNU Affero General Public License v3.0 (AGPL-3.0)** ([`LICENSE`](LICENSE)). Commercial support, dedicated SLA/SLO agreements, sponsorship, and engineering integration partnerships are available via [@Mehmet8-Dev](https://github.com/Mehmet8-Dev) (`mehmetokur756@gmail.com`).

---

## Architecture Overview

```
[CLI (`samurai`) / HTTP REST API (`:8089`)]
       │  (ZMQ ABI v3 / HMAC-SHA256 JWT + RBAC)
       ▼
[Distributed Control Plane (`samurai_master` / `samurai_slave`)]
  ├── Multi-Master Region Federation & HA Leader Election (Static / File-Lease / Redis / K8s)
  ├── Closed-Loop Autopilot (`Mahoraga` 7-D RL Policy + AIMD/Binary Search + VAE Anomaly Defense)
  └── Dynamic Chaos Failover Rebalancing (`TASK-TEST-L5-01`) & Native SSH Agent Provisioner
       │  (ZMQ ROUTER/DEALER + `WarmWorkerPool` IPC)
       ▼
[Native C++17 Dataplane Workers (`samurai_*_worker`)]
  ├── `samurai_cpu_worker`       — Raw sockets, ring buffers, stateless/amplification generators
  ├── `samurai_afpacket_worker`  — AF_PACKET TPACKET_V3 memory-mapped TX rings
  ├── `samurai_afxdp_worker`     — Linux XSK / UMEM zero-copy kernel bypass (`xdp_sender`)
  ├── `samurai_dpdk_worker`      — DPDK PMD hardware rings + `rte_extmem` BAR1 zero-copy mbufs
  ├── `samurai_gpu_worker`       — NVIDIA CUDA persistent kernel, GeForce BAR1 P2P & GPU Doorbell
  ├── `samurai_doca_worker`      — NVIDIA BlueField DPU & DOCA GPUNetIO VRAM streaming
  ├── `samurai_l7_worker`        — Stateful HTTP/1.1, HTTP/2 (nghttp2 + kTLS), QUIC/H3 (ngtcp2), DNS
  ├── `samurai_scenario_worker`  — Web/Mobile persona DSL compiler & microsecond SLA verifier
  ├── `samurai_telco_worker`     — Carrier 4G/5G CUPS, PFCP N4, GTP-U, SCTP, Diameter, SIP/RTP/SRTP
  └── `samurai_defense_worker`   — Variational Autoencoder (VAE) traffic & anomaly evaluation
```

---

## New Architecture & Modules in v3.0.0

### 1. Native C++17 CLI & Core Safety Engine (`samurai/cli/`, `samurai/core/`)
- **Native `samurai` Binary:** Replaced legacy Python CLI entrypoints with a compiled C++17 front-end supporting YAML/built-in profiles, KPI pass/fail gates (`--kpi-*`), JSON/text run reports, and RFC 2544 / 3511 / 8219 compliance suites (`--run-rfc-suite`).
- **Secure-by-Default Target Safety Gate (`target_safety.cpp`):** Restricts traffic by default to private (RFC 1918 / RFC 6598) and loopback targets unless explicitly authorized via `--allow-public-target` or `--allow-target`, with `--deny-target` always winning.
- **Compiler Hardening:** All native targets compile with `-fvisibility=hidden`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and `-Wl,-z,relro,-z,now`.

### 2. Distributed Control Plane & Region Federation (`samurai/control/`)
- **Master/Slave Daemons (`samurai_master`, `samurai_slave`):** Asynchronous ZMQ ROUTER/DEALER RPC orchestration with `CURVE` transport encryption (`--gen-curve-keys`), live shard reconfigure RPC, and `WarmWorkerPool` worker lifecycle reuse.
- **High Availability & Multi-Master Federation:** Static, File-Lease, Redis KV, and Kubernetes lease-based leader election, plus hierarchical ASN/PoP `RegionTopology` weighting and isolated `TelcoLabSizingProfile` BNG/CGNAT pools.
- **Worker Chaos Failover (`TASK-TEST-L5-01`):** Automatic shard reclamation on heartbeat expiration with bounded retries, fast-failing status probes (`<= 1000 ms`), and packet-conserving rollup aggregation.
- **Management REST API (`:8089`) & SSH Provisioner:** Native POSIX HTTP REST API protected by HMAC-SHA256 JWT + RBAC, rate limiting, append-only SHA-256 RBAC audit chain, and `POST /v1/cluster/provision` native SSH agent deployment.

### 3. Carrier-Grade Telecom Engine & DPU-GPU CUPS Bridge (`samurai/telecom/`)
- **Protocol Suite (`samurai_telco_worker`):**
  - **Access & Mobility:** Stateful PPPoE FSM, DHCPv4 DORA / DHCPv6 SARR (with Option 82), RFC 5880/5881 BFD, and RFC 826 ARP/GARP generators.
  - **4G/5G Core & Signaling:** 4G/5G GTP-U (including 5G NR `0x85` QFI PDU Session Container) & N4 PFCP state machines, SCTP (multihoming, PR-SCTP `FORWARD_TSN`, ASCONF/ASCONF_ACK, SSE4.2 / ARM CRC32c), Diameter (RFC 6733 + 3GPP Ro/Gx dictionary), and SIP (RFC 3261 + RFC 2617 digest) / RTP (RFC 3550) / SRTP (RFC 3711 AES-128-CM).
- **DPU ARM (`aarch64`) & GPU CUPS Dataplane:** Hardware-partitioned Control/User Plane Separation (`DpuArmCupsSessionController`) synchronizing subscriber tunnel state over `/dev/shm` via lock-free Seqlock shared memory (`DpuCupsSharedRegionHeaderV1`) and `TELCO_TUNNEL_UPSERT` ZMQ control messages, paired with `HierarchicalTimingWheel` and `SessionManager` $O(1)$ lookup.

### 4. GeForce BAR1 P2P DMA, GPU-Initiated Doorbell & Persistent Kernel (`samurai/gpu_packet_cuda/`)
- **`GeforceP2pApiV1` & Vulkan-CUDA BAR1 Arena:** Enables zero-copy GPU $\leftrightarrow$ NIC DMA on consumer GeForce GPUs alongside enterprise DOCA GPUNetIO (`samurai_doca_worker`).
- **GPU-Initiated MMIO Doorbell & Autonomous Completion Reaper:** Maps NIC BAR MMIO registers (`cudaHostRegisterIoMemory`) for Realtek, Intel `e1000e`/`ixgbe`, and Mellanox `mlx5` descriptors directly into CUDA device space, eliminating the host CPU doorbell bottleneck.
- **Zero-CPU Persistent Dataplane Kernel:** Continuously running `persistent_dataplane_kernel` managing streams, quotas, and hardware backpressure in VRAM with 0% CPU bridge thread overhead.

### 5. L4 Userspace TCP Stack & L7 Stateful Reactors (`samurai/l4/`, `samurai/l7_emu_native/`, `samurai/scenario_engine_native/`)
- **64-Shard Userspace TCP (`tcp_dataplane_core`):** Reduced 1M-flow memory footprint by 63.3% (605 B/flow) with cache-line-aligned `PaddedMutex` sharding, out-of-order reassembly, RFC 2018 SACK, and RFC 6675 SACK loss recovery (`TASK-TEST-L2-02`).
- **Multi-Reactor `io_uring`, kTLS & QUIC/HTTP-3:** Sharded `io_uring` vs `epoll` reactors (`TASK-TEST-L3-01`), opt-in HTTP/2 kTLS Socket-BIO offload (`TASK-TEST-L3-02`), nghttp2/ngtcp2 protocol engines, QUIC CUDA crypto pipelining, and 12 HTTP normalization/evasion variants.
- **Scenario Engine:** Multi-step Web/Mobile persona DSL compiler, event-loop scheduler, and microsecond SLA compliance verification.

### 6. ZMQ Wire Protocol ABI v3, Live IPFIX Telemetry & RL Autopilot (`samurai/zmq/`, `samurai/telemetry/`, `samurai/models/`)
- **ZMQ Wire Protocol ABI v3 (`wire_protocol.h`):** Unified structured worker telemetry, async control decoupling, `ABORT`/`STOP_JOB` lifecycle management, and consolidated high-precision TSC pacing (`samurai/zmq/lib`).
- **Live IPFIX & NetFlow v9/v10 (`samurai/telemetry/`):** Wire-speed flow table and UDP collector exporter integrated into CLI reports and Prometheus (`/metrics`).
- **Closed-Loop RL (`Mahoraga`) & VAE Defense:** 7-D multi-head RL action space synchronized with native `kActionFields`, defense-aware served-throughput reward shaping, and Variational Autoencoder (VAE) anomaly scoring.

### 7. Packaging, Containers & Community Governance
- **Unified CMake & Containers:** Replaced `setup.py` and legacy CPython modules with pure CMake, multi-stage non-root `Dockerfile` / `Dockerfile.prod`, and `deploy/helm/samurai` Helm chart.
- **Governance & Security:** Added GNU AGPL-3.0 [`LICENSE`](LICENSE), [`SECURITY.md`](SECURITY.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), GitHub Issue/PR templates, Dependabot (`.github/dependabot.yml`), and automated Gitleaks/CodeQL security workflows (`.github/workflows/security.yml`).

---

## Upgrade & Breaking Notes
- Legacy Python entrypoints (`setup.py`, `dataplane_core.c`, legacy `pybind` wrappers) have been removed; build and run all binaries through CMake (`build/cli/samurai`, `build/control/daemon/samurai_master`, `build/control/daemon/samurai_slave`, `build/zmq/samurai_*_worker`).
- Project naming and namespaces are unified under `Samurai` / `samurai` (`v3.0.0`, retiring previous codenames).
- Full technical documentation is indexed in [`docs/README.md`](docs/README.md).
