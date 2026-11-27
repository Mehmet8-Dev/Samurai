# Samurai — Pure C++17 Line-Rate Load, Kernel-Bypass & AI Resilience Engine

## Why Samurai?

Modern infrastructure teams face a gap between low-level stateless packet blasters and high-level application load tools:

- **The Problem:** Traditional Python/scripting load testers hit GIL, memory-allocation, and syscall bottlenecks long before saturating 10G–100G links; conversely, raw packet generators lack stateful TCP loss recovery, HTTP/2–QUIC/H3 state machines, multi-step persona modeling, carrier-telecom signaling (PFCP/GTP-U/SCTP/Diameter/SIP), or adaptive feedback loops. Many GPU/DPU-accelerated dataplanes also lock developers behind expensive datacenter-only licenses.
- **How Samurai Differs:**
  - **Zero Python Dataplane Overhead:** Pure C++17 native daemons, MCP server, and worker binaries (`samurai`, `samurai_mcp`, `samurai_master`, `samurai_slave`, `samurai_*_worker`), keeping Python strictly for offline test harnesses and RL training scripts.
  - **Full-Stack L2–L7 + Carrier Telecom in One Runtime:** Combines RFC 6675 SACK userspace TCP, `io_uring`/kTLS HTTP/2 & QUIC/H3, stateful persona scenarios, and 4G/5G telecom protocols (`GTP-U`, `PFCP`, `SCTP`, `Diameter`, `SIP/RTP/SRTP`) with live IPFIX/NetFlow v9/v10 telemetry.
  - **Commodity & Enterprise Hardware Acceleration:** Supports consumer GeForce BAR1 P2P DMA + autonomous GPU-initiated doorbells alongside enterprise `AF_XDP`, `DPDK`, and BlueField `DOCA GPUNetIO` + `aarch64` DPU CUPS Seqlock shared memory.
  - **Closed-Loop Resilience & Safety Gates:** Built-in RL (`Mahoraga`) / AIMD autopilot, VAE anomaly defense verification, and fail-closed `ValidateTargetSafety` gates (private/loopback by default, explicit allowlist/denylist enforcement).

---

## Quick Start

### 1. Build Natively for Your Hardware (`npx`, `docker`, or `cmake`)
`samurai-net` downloads the Samurai source code and **automatically compiles all binaries and workers on your target machine** (`-march=native`, CUDA, DPDK, AF_XDP, `io_uring`, DOCA) into `~/.cache/samurai/` on first run:

```bash
# Option A: Install globally or compile natively on this machine via npm
npx -y samurai-net build
npm install -g samurai-net && samurai-net build

# Option B: Docker (`ghcr.io` source-runtime compiles natively on first run, OR local `docker build`)
docker run --rm -v samurai-build-cache:/var/cache/samurai ghcr.io/mehmet8-dev/samurai:latest samurai --help
# Or bake a standalone container image directly on your host:
docker build -t samurai:local .

# Option C: Build directly from a cloned repo (Linux C++17)
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release -DSAMURAI_NATIVE_ARCH=ON && cmake --build build -j"$(nproc)"
```

### 2. Connect AI Coding Agent (1-Command MCP Setup)
Automatically diagnose binaries and register Samurai MCP across **Claude Code, Cursor, Codex, Antigravity, Gemini CLI, Windsurf, VS Code, OpenCode, or Copilot CLI**:

```bash
# Check binaries, workers, and MCP client registration status
npx -y samurai-net mcp doctor

# Register every detected IDE / coding CLI in one command (.bak backup created automatically, omit --yes to inspect without modifying files):
# Supported clients: claude_code, claude_desktop, cursor, codex, gemini_cli, antigravity, windsurf, vscode, opencode, copilot_cli
npx -y samurai-net mcp setup --client all --yes
npx -y samurai-net mcp setup --client claude_code --yes

# Windows PowerShell (Docker Desktop + native %APPDATA% / %USERPROFILE% paths + local host-built image):
# Automatically builds `samurai:local-v3.5.0` on your machine (`SAMURAI_NATIVE_ARCH=ON`) and injects `--add-host host.docker.internal:host-gateway`.
npx -y samurai-net mcp setup --client antigravity --yes
npx -y samurai-net mcp setup --client vscode --yes
npx -y samurai-net mcp setup --client claude_desktop --yes

# Or force npx launcher (`npx.cmd` on Windows), local Docker build, or GHCR source-runtime (`--ghcr`):
npx -y samurai-net mcp setup --client cursor --npx --yes
npx -y samurai-net mcp setup --client cursor --docker --yes
npx -y samurai-net mcp setup --client cursor --docker --ghcr --yes
```

### 3. Choosing the Right Engine

Samurai separates traffic generation into specialized native workers so you can match the dataplane to your test objective:

- **Web, API & SLA Validation (`--worker l7`, `--worker scenario`):** Best starting point for application-layer testing. Use `--worker l7` for stateful HTTP/1.1, HTTP/2 (`nghttp2` + `io_uring`/kTLS), and QUIC/HTTP/3 (`ngtcp2`/`nghttp3`) benchmarks, or `--worker scenario` when you need multi-step user personas, session state, and microsecond SLA assertions.
- **High-Throughput L2–L4 & Kernel-Bypass Labs (`--worker afxdp`, `--worker dpdk`, `--worker gpu`):** Designed for 10G–100G line-rate stress tests and hardware-accelerated labs. Choose `afxdp` for Linux zero-copy XSK/UMEM, `dpdk` for PMD hugepage rings, or `gpu` for NVIDIA CUDA warp-parallel synthesis and GeForce BAR1 P2P DMA.
- **4G/5G Core & Carrier Telecom (`--worker telco`):** Tailored for EPC/5GC, BNG, and IMS infrastructure validation, supporting `GTP-U`, `PFCP`, `SCTP`, `Diameter`, and `SIP/SRTP` signaling and user-plane flows.

---

## Benchmarks & Comparison

- [Benchmarks Summary & Tool Comparison](docs/benchmarks/README.md) — `605 B/flow` across 1M stateful TCP flows (`-63.3%` RAM), `2.71M CPS` in-memory / `133.5k CPS` kernel `veth`, `189.9k RPS` stateful HTTP/2, and `129.3M masks/s` CUDA QUIC offload.
- [L4 1M Flows Report](docs/benchmarks/43-tcpdp-1m-flows-benchmark-report.md) · [L7 Stateful Userspace Report](docs/benchmarks/44-l7-stateful-userspace-benchmark-report.md) · [Reproduce Script (`reproduce-benchmarks.sh`)](scripts/reproduce-benchmarks.sh)

---

## Key Capabilities

- **Pure Native C++17 Runtime:** Zero Python runtime overhead; compiled microservice architecture with direct OS and hardware integration.
- **Native CLI (`samurai`) & MCP Server (`samurai_mcp`):** Argument validation, strict KPI performance gates, RFC 2544/3511/8219 compliance suites, profile management, automatic worker binary discovery, and native MCP `2024-11-05` agent integration.
- **Distributed Control Plane (`samurai_master` & `samurai_slave`):**
  - Asynchronous ZMQ ROUTER/DEALER RPC message broker with optional CURVE encryption.
  - Dynamic workload sharding (even, capacity-based, and geo-locality aware).
  - High Availability (HA) leader election (Static, File-Lease, and Redis).
  - Multi-Master and inter-region cluster federation.
  - Native POSIX-socket HTTP REST Management API (`:8089`).
  - Cryptographic HMAC-SHA256 JWT authentication and Role-Based Access Control (RBAC).
  - Tamper-evident SHA-256 audit logging.
- **High-Throughput Dataplane Engines:**
  - **L4 Userspace TCP Stack (`tcp_dataplane_core`):** 64-shard lock-striped connection flow table, out-of-order reassembly, timer-wheel fast retransmission, and RFC 6675 SACK recovery.
  - **AF_XDP (Kernel-Bypass):** Linux XSK / UMEM zero-copy ring buffers delivering wire-rate Mpps throughput.
  - **DPDK:** Poll Mode Driver (PMD) hardware ring acceleration with hugepages.
  - **GPU CUDA & DOCA GPUNetIO:** Warp-parallel packet generation, GeForce BAR1 P2P DMA, and DPU offloaded memory streaming.
  - **L7 Stateful Emulation (`l7_emu_native`):** Native HTTP/1.1, HTTP/2 (`nghttp2` + `io_uring`/kTLS), QUIC / HTTP/3 (`ngtcp2`/`nghttp3`), and DNS engines.
  - **Scenario Engine (`scenario_engine_native`):** Multi-step persona user emulation, stateful session workflows, and microsecond SLA compliance tracking.
  - **CPU Native Packet Engine (`cpu_native`):** Raw socket / packet ring optimization with dynamic spoofing and amplification generators.

---

## Architectural Topology

![Samurai End-to-End System Architecture](docs/assets/diagrams/samurai_system_architecture.svg)

<details>
<summary>System Dataflow Overview</summary>

```text
[CLI (`samurai`) / HTTP REST API (`:8089`) / Native MCP (`samurai_mcp`)]
       │ (ZMQ / POSIX HTTP / stdio JSON-RPC)
       ▼
[Master / Slave Control Plane (`samurai_master` / `samurai_slave`)]
       │ (ZMQ RPC Wire Protocol)
       ▼
[Native Worker Orchestrator & Supervisor]
       ├──> AF_XDP Worker  ──────> [Zero-Copy UMEM] ──> [NIC Ring]
       ├──> DPDK PMD Worker ─────> [Hugepages Ring] ───> [Physical Wire]
       ├──> GPU / DOCA Worker ───> [VRAM / GPUNetIO] ──> [PCIe Gen4/5 DPU]
       ├──> L7 Stateful Worker ──> [nghttp2/ngtcp2] ───> [Target App]
       ├──> Scenario Worker ─────> [Stateful Persona] ─> [Target Service]
       └──> Telco Worker ────────> [GTP-U/PFCP/SCTP] ──> [BNG / 5G UPF]
```
</details>

---

## Prerequisites & Compilation

### System Requirements
- **Operating System:** Linux (Ubuntu 22.04+, Debian 12+, RHEL 8+)
- **Compiler:** GCC 9+ or Clang 10+ (C++17 compliant)
- **Build System:** CMake 3.16+ and Make / Ninja
- **Core Libraries:** `libzmq3-dev`, `libssl-dev`, `pkg-config`, `build-essential`
- **Optional Acceleration Drivers:**
  - AF_XDP: `libbpf-dev`, `libelf-dev`
  - HTTP/2, QUIC & `io_uring`: `libnghttp2-dev`, `libngtcp2-dev`, `libngtcp2-crypto-gnutls-dev`, `libnghttp3-dev`, `libgnutls28-dev`, `liburing-dev`
  - DPDK: `libdpdk-dev`
  - CUDA: NVIDIA CUDA Toolkit (12.x+)

### Build Procedure

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y \
  build-essential cmake pkg-config libzmq3-dev libssl-dev \
  libhiredis-dev libpcap-dev libnghttp2-dev libngtcp2-dev \
  libngtcp2-crypto-gnutls-dev libnghttp3-dev libgnutls28-dev liburing-dev

# Configure and build all native targets optimized for this machine's CPU/GPU/NIC hardware
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release -DSAMURAI_NATIVE_ARCH=ON
cmake --build build -j"$(nproc)"
```

The build produces the following native binaries under `build/`:
- `build/cli/samurai` (Primary CLI tool — auto-discovers worker binaries)
- `build/mcp/samurai_mcp` (Native C++17 MCP stdio server)
- `build/control/daemon/samurai_master` (Distributed Master daemon)
- `build/control/daemon/samurai_slave` (Distributed Worker node daemon)
- `build/zmq/samurai_*_worker` (All native dataplane worker engines)
- `build/l4/test_1m_tcp_flows`, `build/zmq/bench_l7_stateful_userspace` (Reproducible L4/L7 benchmark harnesses)
- `build/control/samurai_control_selftest`, `build/mcp/test_samurai_mcp`, `build/l7_emu_native/test_*`, `build/l4/test_*` (Native unit and self-test verification suites)

---

## Usage Guide

### 1) Standalone CLI Execution (`samurai`)

```bash
# List built-in corporate L4, L7, and carrier-telecom profiles
./build/cli/samurai --list-profiles

# High-speed UDP packet test via CPU engine (requires CAP_NET_RAW / sudo)
sudo ./build/cli/samurai \
  --worker cpu \
  --target 127.0.0.1 \
  --port 9999 \
  --protocol udp \
  --count 100000 \
  --rps 50000 \
  --confirm

# Stateful HTTP/2 load test with KPI pass/fail gate and JSON report
./build/cli/samurai \
  --worker l7 \
  --target 127.0.0.1 \
  --port 8080 \
  --l7-protocol http2 \
  --concurrency 4 \
  --keepalive \
  --count 10000 \
  --kpi-max-errors 0 \
  --report-json reports/h2_run.json \
  --confirm

# Carrier 5G telecom simulation (SCTP / Diameter / SIP-SRTP / GTP-U)
./build/cli/samurai \
  --worker telco \
  --profile telco-sctp-flood \
  --target 10.0.0.10 \
  --telco-subscribers 500 \
  --telco-cps 200 \
  --telco-duration-ms 5000 \
  --confirm

# RFC 2544 / 3511 / 8219 compliance suite (live dataplane target)
./build/cli/samurai \
  --run-rfc-suite all \
  --worker l7 \
  --protocol http1 \
  --keepalive \
  --target 127.0.0.1 \
  --port 8080 \
  --rps 1000 \
  --count 200 \
  --confirm \
  --rfc-report-out reports/rfc_report.html
```

### 2) Distributed Multi-Node Cluster Execution

Scale workloads horizontally across multiple baremetal servers:

#### **Master Node (`samurai_master`):**
```bash
./build/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --management-listen 0.0.0.0:8089 \
  --insecure-control \
  --target 10.0.0.50 \
  --port 443 \
  --worker cpu \
  --count 500000 \
  --expect-workers 2
```

#### **Worker Node (`samurai_slave`):**
Run on each agent/generator machine:
```bash
./build/control/daemon/samurai_slave \
  --control-endpoints <MASTER_IP>:5099 \
  --dispatch-mode reverse \
  --worker bundle
```

### 3) Local Host-Native Container Image (Linux, macOS & Windows)

Build the multi-stage container runtime directly on your target host (`SAMURAI_NATIVE_ARCH=ON` by default) so binaries match your local CPU/GPU/DPDK environment:

```bash
# Option 1: Pull the uncompiled GHCR source+toolchain image (compiles natively on YOUR host on first run, cached in samurai-build-cache)
docker run --rm -v samurai-build-cache:/var/cache/samurai ghcr.io/mehmet8-dev/samurai:latest samurai --help

# Option 2: Or bake a standalone image directly from local repo (`SAMURAI_NATIVE_ARCH=ON`)
docker build -t samurai:local .

# Inspect CLI and distributed daemon options
docker run --rm samurai:local samurai --help
docker run --rm samurai:local samurai_master --help

# Linux: run against a local service on 127.0.0.1 via --network host
docker run --rm --network host samurai:local \
  samurai --worker l7 --target 127.0.0.1 --port 8080 --l7-protocol http2 --count 1000 --confirm

# macOS / Windows (Docker Desktop): --network host runs inside the Docker VM;
# target services on your host laptop via host.docker.internal instead of 127.0.0.1:
docker run --rm --add-host host.docker.internal:host-gateway samurai:local \
  samurai --worker l7 --target "$(python3 -c 'import socket; print(socket.gethostbyname("host.docker.internal"))')" --port 8080 --l7-protocol http2 --count 1000 --confirm
```

> **Note:** GitHub Releases publish `ghcr.io/mehmet8-dev/samurai:latest` as an **uncompiled source + toolchain container** (`--target source-runtime`): no C++ binaries are pre-compiled on GitHub Actions runners. On first container launch (or directly via `docker build -t samurai:local .`), CMake compiles `-DSAMURAI_NATIVE_ARCH=ON` specifically for your host hardware (`samurai`, `samurai_mcp`, `samurai_master`, `samurai_slave`, benchmark harnesses, and every worker whose host toolchain is detected), caching binaries in `/var/cache/samurai` (`-v samurai-build-cache:/var/cache/samurai`). On **Windows / macOS (Docker Desktop)**, use `npx -y samurai-net mcp setup --client <id|all> --yes` (or add `--ghcr`) so `%APPDATA%`/`%USERPROFILE%` configs, `host.docker.internal`, the cache volume, and host-local build warm-up are wired automatically. See [`docs/11-docker.md`](docs/11-docker.md) for Docker Desktop networking details.

### 4) Docker Compose Deployment

```bash
# Run the 1M active TCP flow benchmark via Docker Compose
docker compose --profile bench run --rm bench

# Launch a distributed Master + 2 Slaves + Redis HA cluster
docker compose -f docker-compose.distributed.yml up -d
curl -s http://127.0.0.1:8089/healthz
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
# Verify Distributed Control Plane, RPC wire protocol, and Native MCP server
./build/control/samurai_control_selftest
./build/mcp/test_samurai_mcp

# Verify L2/L3/ASTF and Stateful L7 Engines
./build/l7_emu_native/test_l2l3_astf
./build/l7_emu_native/test_kernel_threaded_l7

# Verify L4 Userspace TCP Sliding Window, SACK Recovery, and 100k Shard Scaling
./build/l4/test_tcp_sliding_window
./build/l4/test_100k_tcp_flows
```

---

## Documentation

| Area | Key Guides |
| :--- | :--- |
| **Architecture** | [System Overview](docs/00-overview.md) · [Core Runtime Modules](docs/25-core-runtime-modules.md) · [ZMQ Worker & ABI](docs/36-zmq-worker-architecture.md) · [DPU-GPU CUPS Telecom](docs/49-telecom-gpu-dpu-cups-dataplane-architecture.md) · [GeForce P2P & Doorbell](docs/46-gpu-initiated-doorbell-and-baremetal-pmd.md) |
| **AI Agents & MCP** | [Native C++17 MCP Server Guide](mcp/README.md) · [Portable Agent Skill (`SKILL.md`)](skills/samurai-netbench/SKILL.md) |
| **Installation & Setup** | [Prerequisites & Compilation](#prerequisites--compilation) · [DPDK Environment Setup](docs/34-dpdk-environment-setup-guide.md) · [NUMA & DMA Tuning](docs/21-numa-tx-rx-afxdp-dpdk-dma-guide.md) · [Environment & CLI Reference](docs/20-env-cli-reference.md) |
| **Deployment** | [Docker & Containers](docs/11-docker.md) · [Distributed Control Plane](docs/40-distributed-control-plane-handbook.md) · [Production Operations Runbook](docs/32-production-operations-runbook.md) · [Monitoring & Dashboards](docs/12-dashboard.md) · [Helm Chart](deploy/helm/samurai) |
| **Benchmarking** | [Benchmarks & Comparison Index](docs/benchmarks/README.md) · [Benchmark Profiles](docs/19-benchmark-profiles.md) · [Benchmark Acceptance Handbook](docs/23-benchmark-acceptance-handbook.md) · [RFC Baseline Runbook](docs/39-rfc-benchmark-baseline-runbook.md) · [L4 1M Flows Report](docs/benchmarks/43-tcpdp-1m-flows-benchmark-report.md) · [L7 Stateful Report](docs/benchmarks/44-l7-stateful-userspace-benchmark-report.md) · [Reproduce Script](scripts/reproduce-benchmarks.sh) |
| **Developer Guides** | [CMake Build & Native Testing](docs/09-dev-testing.md) · [Native Worker API](docs/39-native-architecture-and-worker-api.md) · [CLI Deep Map](docs/26-cli-package-deep-map.md) · [Target Safety Policy](docs/07-safety.md) · [Open-Source Launch Playbook](docs/50-open-source-growth-and-launch-playbook.md) · [Full Docs Index](docs/README.md) |

---

## Security & Authorized Use Policy

This software is strictly intended for network administrators, security researchers, and systems engineers conducting authorized resilience, scalability, and stress assessments on infrastructure they own or hold explicit written permission to test. Unauthorized generation of hostile traffic is illegal under international computer misuse statutes. The end user assumes all legal liability.

For coordinated vulnerability disclosure, supported versions, and secure-by-default controls (target allowlists/denylists, ZMQ CURVE, HMAC-SHA256 JWT RBAC, SHA-256 audit log chains), see [`SECURITY.md`](SECURITY.md).

---

## Community

- **GitHub Discussions:** Join architecture discussions, Q&A, RFC reviews, and benchmark sharing at [GitHub Discussions](https://github.com/Mehmet8-Dev/Samurai/discussions).
- **Issues & Benchmarks:** Use the structured templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) for bug reports, feature requests, new PR proposals, and independent hardware [Benchmark Reports](.github/ISSUE_TEMPLATE/benchmark_report.md).

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

### AGPL-3.0 Adoption FAQ
- **Internal Lab, WAF & CI/CD Testing:** Running unmodified Samurai against your own servers, staging environments, WAFs, or CI/CD pipelines does **not** require disclosing your application's source code.
- **Custom Plugins, Forks & Managed SaaS:** If you modify Samurai and either distribute binaries or operate the modified version over a network as a hosted/managed service or SaaS platform, you must disclose the complete corresponding source code of your Samurai derivative under AGPL-3.0.
- **Commercial Licensing & Support:** Organizations needing proprietary integration without AGPL-3.0 obligations, dedicated SLA/SLO agreements, or custom engineering can contact the author directly via GitHub ([@Mehmet8-Dev](https://github.com/Mehmet8-Dev)) or `mehmetokur756@gmail.com`.
