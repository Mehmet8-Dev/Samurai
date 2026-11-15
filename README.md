# Samurai Network Resilience & Line-Rate Stress Platform

Samurai (Release 2.2+, Codename: **Shogun**) is an enterprise-grade, high-performance network resilience and line-rate stress testing platform designed strictly for authorized lab and infrastructure validation environments.

The platform is engineered in modern **C++ (C++17)** with zero runtime Python latency, featuring a **ZeroMQ (ZMQ) binary IPC wire protocol**, **Kernel-Bypass (AF_XDP, DPDK)** drivers, **NVIDIA CUDA & DOCA GPUNetIO packet synthesis**, and a **64-shard Userspace TCP/L7 engine**.

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

# Clone repository and create build directory
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

The build produces the following native binaries under `build/`:
- `build/samurai/cli/samurai` (Primary CLI tool)
- `build/samurai/control/daemon/samurai_master` (Distributed Master daemon)
- `build/samurai/control/daemon/samurai_slave` (Distributed Worker node daemon)
- `build/samurai/zmq/daemon/samurai_*_worker` (All native dataplane worker engines)
- `build/samurai/*_selftest` (Unit test and self-test verification suites)

---

## Usage Guide

### 1) Standalone CLI Execution (`samurai`)

```bash
# High-speed UDP packet test via CPU engine
./build/samurai/cli/samurai \
  --worker cpu \
  --target 192.168.1.100 \
  --port 80 \
  --protocol udp \
  --count 1000000 \
  --confirm

# AF_XDP Kernel-Bypass zero-copy line-rate test
./build/samurai/cli/samurai \
  --worker afxdp \
  --target 10.0.0.1 \
  --interface eth0 \
  --rate 5000000 \
  --duration 30 \
  --confirm

# Stateful HTTP/2 simulation test
./build/samurai/cli/samurai \
  --worker l7 \
  --target 10.0.0.50 \
  --port 443 \
  --l7-protocol h2 \
  --duration 60 \
  --confirm

# Multi-step stateful user scenario execution
./build/samurai/cli/samurai \
  --worker scenario \
  --scenario-file docs/scenario_web_mobile.yaml \
  --confirm
```

### 2) Distributed Multi-Node Cluster Execution

Scale workloads horizontally across multiple baremetal servers:

#### **Master Node (`samurai_master`):**
```bash
./build/samurai/control/daemon/samurai_master \
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
./build/samurai/control/daemon/samurai_slave \
  --control-endpoints tcp://<MASTER_IP>:5099 \
  --worker afxdp \
  --interface eth0
```

### 3) Docker Compose Deployment

```bash
docker-compose -f docker-compose.distributed.yml up -d
```

---

## Dataplane Worker Types

| Worker Name (`--worker`) | Native Binary | Capabilities & Acceleration Path |
| :--- | :--- | :--- |
| `cpu` | `samurai_cpu_worker` | Raw sockets, memory ring buffer, dynamic header spoofing |
| `afxdp` | `samurai_afxdp_worker` | Linux XSK / UMEM zero-copy kernel bypass |
| `dpdk` | `samurai_dpdk_worker` | DPDK PMD hardware ring buffers and hugepages |
| `gpu` | `samurai_gpu_worker` | NVIDIA CUDA warp-parallel packet synthesis |
| `doca` | `samurai_doca_worker` | NVIDIA BlueField DPU & GPUNetIO direct VRAM streaming |
| `l7` | `samurai_l7_worker` | Stateful HTTP/1.1, HTTP/2 (nghttp2), QUIC / HTTP/3 (ngtcp2) |
| `scenario` | `samurai_scenario_worker` | Persona-based multi-step user workflows and SLA tracking |
| `defense` | `samurai_defense_worker` | Variational Autoencoder (VAE) resilience evaluation |

---

## Native Self-Test Verification Suites

Run the built-in C++ validation binaries to verify subsystems in isolated environments:

```bash
# Verify Distributed Control Plane and RPC wire protocol
./build/samurai/control/samurai_control_selftest

# Verify Stateful L7 Engine and Protocol Bridges
./build/samurai/l7_emu_native/samurai_l7_selftest

# Verify Scenario Engine and SLA Verification
./build/samurai/scenario_engine_native/samurai_scenario_engine_selftest
```

---

## Security & Authorized Use Policy

This software is strictly intended for network administrators, security researchers, and systems engineers conducting authorized resilience, scalability, and stress assessments on infrastructure they own or hold explicit written permission to test. Unauthorized generation of hostile traffic is illegal under international computer misuse statutes. The end user assumes all legal liability.

---

## Technical Documentation Index

For exhaustive architectural specifications and subsystem deep-dives, see [`docs/README.md`](docs/README.md).
