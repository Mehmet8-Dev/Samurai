# Samurai Network Resilience & Line-Rate Stress Platform

Samurai (Release 3.0.0) is a high-performance network resilience, carrier-telecom emulation, and line-rate stress testing platform designed strictly for authorized lab and infrastructure validation environments.

The platform is engineered in modern **C++ (C++17)** with zero runtime Python latency, featuring a **ZeroMQ (ZMQ) binary IPC wire protocol (ABI v3)**, **Kernel-Bypass (`AF_XDP`, `DPDK`)** drivers, **NVIDIA CUDA (including GeForce BAR1 P2P & GPU-initiated doorbell) & DOCA GPUNetIO packet synthesis**, **DPU ARM/GPU CUPS offloading**, and a **64-shard Userspace TCP/L7 engine**.

---

## Why Samurai?

Modern infrastructure teams face a gap between low-level stateless packet blasters and high-level application load tools:

- **The Problem:** Traditional Python/scripting load testers hit GIL, memory-allocation, and syscall bottlenecks long before saturating 10G–100G links; conversely, raw packet generators lack stateful TCP loss recovery, HTTP/2–QUIC/H3 state machines, multi-step persona modeling, carrier-telecom signaling (PFCP/GTP-U/SCTP/Diameter/SIP), or adaptive feedback loops. Many GPU/DPU-accelerated dataplanes also lock developers behind expensive datacenter-only licenses.
- **How Samurai Differs:**
  - **Zero Python Dataplane Overhead:** Pure C++17 native daemons and worker binaries (`samurai_master`, `samurai_slave`, `samurai_*_worker`), keeping Python strictly for offline test harnesses and RL training scripts.
  - **Full-Stack L2–L7 + Carrier Telecom in One Runtime:** Combines RFC 6675 SACK userspace TCP, `io_uring`/kTLS HTTP/2 & QUIC/H3, stateful persona scenarios, and 4G/5G telecom protocols (`GTP-U`, `PFCP`, `SCTP`, `Diameter`, `SIP/RTP/SRTP`) with live IPFIX/NetFlow v9/v10 telemetry.
  - **Commodity & Enterprise Hardware Acceleration:** Supports consumer GeForce BAR1 P2P DMA + autonomous GPU-initiated doorbells alongside enterprise `AF_XDP`, `DPDK`, and BlueField `DOCA GPUNetIO` + `aarch64` DPU CUPS Seqlock shared memory.
  - **Closed-Loop Resilience & Safety Gates:** Built-in RL (`Mahoraga`) / AIMD autopilot, VAE anomaly defense verification, and fail-closed `ValidateTargetSafety` gates (private/loopback by default, explicit allowlist/denylist enforcement).

---

## Key Capabilities

- **Pure Native C++17 Runtime:** Zero Python runtime overhead; compiled microservice architecture with direct OS and hardware integration.
- **Native CLI Front-End (`samurai`):** Robust argument validation, strict KPI performance gates, RFC compliance benchmark suites, and profile management.
- **Distributed Control Plane (`samurai_master` & `samurai_slave`):**
  - Asynchronous ZMQ ROUTER/DEALER RPC message broker.
  - Dynamic workload sharding (even, capacity-based, and geo-locality aware).
  - High Availability (HA) leader election (Static and File-Lease).
  - Multi-Master and inter-region cluster federation.
  - Native POSIX-socket HTTP REST Management API (`:8089`).
  - Cryptographic HMAC-SHA256 JWT authentication and Role-Based Access Control (RBAC).
  - Tamper-evident SHA-256 audit logging.
- **High-Throughput Dataplane Engines:**
  - **L4 Userspace TCP Stack (`tcp_dataplane_core`):** 64-shard lock-striped connection flow table, out-of-order reassembly, timer-wheel fast retransmission.
  - **AF_XDP (Kernel-Bypass):** Linux XSK / UMEM zero-copy ring buffers delivering wire-rate Mpps throughput.
  - **DPDK:** Poll Mode Driver (PMD) hardware ring acceleration with hugepages.
  - **GPU CUDA & DOCA GPUNetIO:** Warp-parallel packet generation and DPU offloaded memory streaming.
  - **L7 Stateful Emulation (`l7_emu_native`):** Native HTTP/1.1, HTTP/2 (nghttp2), QUIC / HTTP/3 (ngtcp2), and DNS engines.
  - **Scenario Engine (`scenario_engine_native`):** Multi-step persona user emulation, stateful session workflows, and microsecond SLA compliance tracking.
  - **CPU Native Packet Engine (`cpu_native`):** Raw socket / packet ring optimization with dynamic spoofing and amplification generators.

---

## Architectural Topology

![Samurai End-to-End System Architecture](docs/assets/diagrams/samurai_system_architecture.svg)

<details>
<summary>System Dataflow Overview</summary>

```
[CLI / REST API] 
       │ (ZMQ / POSIX HTTP)
       ▼
[Master / Slave Control Plane]
       │ (ZMQ RPC Wire Protocol)
       ▼
[Native Worker Orchestrator & Supervisor]
       ├──> AF_XDP Worker  ──────> [Zero-Copy UMEM] ──> [NIC Ring]
       ├──> DPDK PMD Worker ─────> [Hugepages Ring] ───> [Physical Wire]
       ├──> GPU / DOCA Worker ───> [VRAM / GPUNetIO] ──> [PCIe Gen4/5 DPU]
       ├──> L7 Stateful Worker ──> [nghttp2/ngtcp2] ───> [Target App]
       └──> Scenario Worker ─────> [Stateful Persona] ─> [Target Service]
```
</details>

---

## Prerequisites & Compilation

### System Requirements
- **Operating System:** Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Compiler:** GCC 9+ or Clang 10+ (C++17 compliant)
- **Build System:** CMake 3.16+ and Make / Ninja
- **Core Libraries:** `libzmq3-dev`, `libssl-dev`, `pkg-config`, `build-essential`
- **Optional Acceleration Drivers:**
  - AF_XDP: `libbpf-dev`, `libelf-dev`
  - HTTP/2 & QUIC: `libnghttp2-dev`, `libngtcp2-dev`
  - DPDK: `libdpdk-dev`
  - CUDA: NVIDIA CUDA Toolkit (12.x+)

### Build Procedure

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y build-essential cmake pkg-config libzmq3-dev libssl-dev

# Configure and build all native targets from repository root
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The build produces the following native binaries under `build/`:
- `build/cli/samurai` (Primary CLI tool)
- `build/control/daemon/samurai_master` (Distributed Master daemon)
- `build/control/daemon/samurai_slave` (Distributed Worker node daemon)
- `build/zmq/samurai_*_worker` (All native dataplane worker engines)
- `build/control/samurai_control_selftest`, `build/l7_emu_native/test_*`, `build/l4/test_*` (Native unit and self-test verification suites)

---

## Usage Guide

### 1) Standalone CLI Execution (`samurai`)

```bash
# High-speed UDP packet test via CPU engine
./build/cli/samurai \
  --worker cpu \
  --target 192.168.1.100 \
  --port 80 \
  --protocol udp \
  --count 1000000 \
  --confirm

# AF_XDP Kernel-Bypass zero-copy line-rate test
./build/cli/samurai \
  --worker afxdp \
  --target 10.0.0.1 \
  --interface eth0 \
  --rate 5000000 \
  --duration 30 \
  --confirm

# Stateful HTTP/2 simulation test
./build/cli/samurai \
  --worker l7 \
  --target 10.0.0.50 \
  --port 443 \
  --l7-protocol h2 \
  --duration 60 \
  --confirm

# Multi-step stateful user scenario execution
./build/cli/samurai \
  --worker scenario \
  --scenario-file docs/scenario_web_mobile.yaml \
  --confirm
```

### 2) Distributed Multi-Node Cluster Execution

Scale workloads horizontally across multiple baremetal servers:

#### **Master Node (`samurai_master`):**
```bash
./build/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --api-listen 0.0.0.0:8089 \
  --target 10.0.0.50 \
  --port 443 \
  --worker afxdp \
  --count 50000000 \
  --duration 120
```

#### **Worker Node (`samurai_slave`):**
Run on each agent/generator machine:
```bash
./build/control/daemon/samurai_slave \
  --control-endpoints tcp://<MASTER_IP>:5099 \
  --worker afxdp \
  --interface eth0
```

### 3) Pre-Built Container Image (GHCR)

Pull and run the pre-built multi-stage native runtime image from GitHub Container Registry without compiling locally:

```bash
# Pull the latest release image (or pin a version tag such as :v3.0.0)
docker pull ghcr.io/mehmet8-dev/samurai:latest

# Inspect CLI and distributed daemon options
docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai --help
docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai_master --help

# Run a stateful L7 test inside the container (workers live in /usr/local/bin)
docker run --rm --network host ghcr.io/mehmet8-dev/samurai:latest \
  samurai --worker l7 --worker-dir /usr/local/bin \
  --target 127.0.0.1 --port 8080 --l7-protocol h2 --count 1000 --confirm
```

> **Note:** The container image ships `samurai`, `samurai_master`, `samurai_slave`, and commodity/telco workers (`cpu`, `afpacket`, `afxdp`, `l7`, `scenario`, `defense`, `telco`) under `/usr/local/bin`. For CUDA, DOCA GPUNetIO, or hardware DPDK PMD backends, compile natively from source on the target host.

### 4) Docker Compose Deployment

```bash
docker-compose -f docker-compose.distributed.yml up -d
```

---

## Dataplane Worker Types

| Worker Name (`--worker`) | Native Binary | Capabilities & Acceleration Path |
| :--- | :--- | :--- |
| `cpu` | `samurai_cpu_worker` | Raw sockets, memory ring buffer, dynamic header spoofing |
| `afpacket` | `samurai_afpacket_worker` | Linux AF_PACKET `TPACKET_V3` memory-mapped TX rings |
| `afxdp` | `samurai_afxdp_worker` | Linux XSK / UMEM zero-copy kernel bypass |
| `dpdk` | `samurai_dpdk_worker` | DPDK PMD hardware ring buffers and hugepages |
| `gpu` | `samurai_gpu_worker` | NVIDIA CUDA warp-parallel packet synthesis & GeForce BAR1 P2P |
| `doca` | `samurai_doca_worker` | NVIDIA BlueField DPU & GPUNetIO direct VRAM streaming |
| `l7` | `samurai_l7_worker` | Stateful HTTP/1.1, HTTP/2 (nghttp2), QUIC / HTTP/3 (ngtcp2) |
| `scenario` | `samurai_scenario_worker` | Persona-based multi-step user workflows and SLA tracking |
| `telco` | `samurai_telco_worker` | 4G/5G CUPS, PFCP N4, GTP-U, SCTP, Diameter, SIP/RTP/SRTP |
| `defense` | `samurai_defense_worker` | Variational Autoencoder (VAE) resilience evaluation |

---

## Native Self-Test Verification Suites

Run the built-in C++ validation binaries to verify subsystems in isolated environments:

```bash
# Verify Distributed Control Plane and RPC wire protocol
./build/control/samurai_control_selftest

# Verify L2/L3/ASTF and Stateful L7 Engines
./build/l7_emu_native/test_l2l3_astf
./build/l7_emu_native/test_kernel_threaded_l7

# Verify L4 Userspace TCP Sliding Window & SACK Recovery
./build/l4/test_tcp_sliding_window
```

---

## Documentation

| Area | Key Guides |
| :--- | :--- |
| **Architecture** | [System Overview](docs/00-overview.md) · [Core Runtime Modules](docs/25-core-runtime-modules.md) · [ZMQ Worker & ABI](docs/36-zmq-worker-architecture.md) · [DPU-GPU CUPS Telecom](docs/49-telecom-gpu-dpu-cups-dataplane-architecture.md) · [GeForce P2P & Doorbell](docs/46-gpu-initiated-doorbell-and-baremetal-pmd.md) |
| **Installation & Setup** | [Prerequisites & Compilation](#prerequisites--compilation) · [DPDK Environment Setup](docs/34-dpdk-environment-setup-guide.md) · [NUMA & DMA Tuning](docs/21-numa-tx-rx-afxdp-dpdk-dma-guide.md) · [Environment & CLI Reference](docs/20-env-cli-reference.md) |
| **Deployment** | [Docker & Containers](docs/11-docker.md) · [Distributed Control Plane](docs/40-distributed-control-plane-handbook.md) · [Production Operations Runbook](docs/32-production-operations-runbook.md) · [Monitoring & Dashboards](docs/12-dashboard.md) · [Helm Chart](deploy/helm/samurai) |
| **Benchmarking** | [Benchmark Profiles](docs/19-benchmark-profiles.md) · [Benchmark Acceptance Handbook](docs/23-benchmark-acceptance-handbook.md) · [RFC Baseline Runbook](docs/39-rfc-benchmark-baseline-runbook.md) · [L4 1M Flows Report](docs/benchmarks/43-tcpdp-1m-flows-benchmark-report.md) · [L7 Stateful Report](docs/benchmarks/44-l7-stateful-userspace-benchmark-report.md) |
| **Developer Guides** | [CMake Build & Native Testing](docs/09-dev-testing.md) · [Native Worker API](docs/39-native-architecture-and-worker-api.md) · [CLI Deep Map](docs/26-cli-package-deep-map.md) · [Target Safety Policy](docs/07-safety.md) · [Full Docs Index](docs/README.md) |

---

## Security & Authorized Use Policy

This software is strictly intended for network administrators, security researchers, and systems engineers conducting authorized resilience, scalability, and stress assessments on infrastructure they own or hold explicit written permission to test. Unauthorized generation of hostile traffic is illegal under international computer misuse statutes. The end user assumes all legal liability.

For coordinated vulnerability disclosure, supported versions, and secure-by-default controls (target allowlists/denylists, ZMQ CURVE, HMAC-SHA256 JWT RBAC, SHA-256 audit log chains), see [`SECURITY.md`](SECURITY.md).

---

## Community

- **GitHub Discussions:** Join architecture discussions, Q&A, RFC reviews, and benchmark sharing at [GitHub Discussions](https://github.com/Mehmet8-Dev/Samurai/discussions).
- **Issues & Proposals:** Use the structured templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) for bug reports, feature requests, and new PR proposals.

---

## Contributing

Contributions are welcome under our [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build instructions, open PR proposals for incoming developers, and [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) for the PR checklist.

---

## Contributors

- **Mehmet Okur** ([@Mehmet8-Dev](https://github.com/Mehmet8-Dev) · `mehmetokur756@gmail.com`) — Creator & Lead Architect
- **0x4nyroot** ([@0x4nyroot](https://github.com/0x4nyroot) · `sefakocyigit10@gmail.com`) — Contributor

---

## License & Support

Samurai is 100% open-source software licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [`LICENSE`](LICENSE) for the full text.

Under AGPL-3.0, all features remain open and any modified version deployed or operated over a network (including managed services and SaaS platforms) must disclose its complete source code under the same license.

For **commercial support, dedicated SLA / SLO agreements, custom integration engineering, or project sponsorship**, please contact the author directly via GitHub ([@Mehmet8-Dev](https://github.com/Mehmet8-Dev)) or `mehmetokur756@gmail.com`.
