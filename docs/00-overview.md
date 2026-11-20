# 00 - System Architecture & Subsystem Map

Samurai is an enterprise-grade, high-performance network resilience and line-rate stress testing platform designed for authorized lab environments. Built in pure C++17 with zero runtime Python latency, it provides modular, hardware-accelerated packet synthesis, stateful protocol simulation, and distributed control planes.

![Samurai End-to-End System Architecture](assets/diagrams/samurai_system_architecture.svg)

---

## 1. Architectural Layers

### A) Native CLI Layer (`samurai/cli/`)
- **Binary:** `samurai`
- **Source Modules:** `main.cpp`, `args.cpp`, `validation.cpp`, `profiles.cpp`, `kpi_gate.cpp`, `reporting.cpp`, `rfc_suite.cpp`
- **Responsibilities:** Command-line argument parsing, security boundaries and allowlists (`TargetSafety`), profile compilation, RFC suite execution, and local job spawning via the ZMQ Supervisor engine.

### B) Distributed Control Plane (`samurai/control/`)
- **Master Daemon:** `samurai_master` (`daemon/master_main.cpp`)
- **Slave Daemon:** `samurai_slave` (`daemon/slave_main.cpp`)
- **Interconnect:** Asynchronous ZMQ ROUTER / DEALER RPC transport (`control_server.cpp`, `control_client.cpp`, `control_wire.hpp`).
- **Subsystem Services:**
  - `servicer.cpp`: Worker registration (`RegisterWorker`), heartbeat watchdog, metrics aggregation, and shard lifecycle tracking.
  - `shard.cpp`: Workload partitioning across worker nodes based on capacity, region, and acceleration capabilities.
  - `ha.cpp`: High-Availability leader election (`StaticLeaderElector`, `FileLeaseLeaderElector`).
  - `management_api.cpp`: Pure POSIX-socket HTTP REST server (`:8089`) with zero external web dependencies.
  - `control_auth.cpp` & `jwt.cpp`: HMAC-SHA256 JWT tokens and Role-Based Access Control (RBAC).
  - `multimaster.cpp`: Inter-region multi-master cluster federation.

### C) Native Orchestrator & Supervisor (`samurai/orchestrator/`)
- **Modules:** `supervisor.cpp`, `worker_registry.hpp`
- **Responsibilities:** Receives `JobOptions` envelopes from Master, Slave, or CLI, creates dedicated Unix IPC channels (`ipc:///tmp/samurai_jobs_*`), launches native worker processes via `fork()` / `execvp()`, collects telemetry snapshots, and ensures clean termination.

### D) Heterogeneous Native Dataplane Workers (`samurai/zmq/daemon/`)
- `samurai_gpu_worker`: NVIDIA CUDA warp-parallel packet generator (`kernels_l4.cuh`).
- `samurai_doca_worker`: NVIDIA BlueField DPU & DOCA GPUNetIO direct memory dataplane.
- `samurai_afxdp_worker`: Linux kernel-bypass AF_XDP zero-copy UMEM socket engine.
- `samurai_dpdk_worker`: DPDK Poll Mode Driver (PMD) ring buffer engine with hugepages.
- `samurai_l7_worker`: Stateful userspace HTTP/1.1, HTTP/2 (nghttp2), and HTTP/3 QUIC (ngtcp2) engine.
- `samurai_scenario_worker`: Multi-step web and mobile persona user emulator with SLA tracking.
- `samurai_defense_worker`: Closed-loop Variational Autoencoder (VAE) resilience validator.
- `samurai_cpu_worker`: Optimized raw socket and packet ring fallback engine.

### E) Hardware & Protocol Acceleration Engines
- `samurai/l4/`: `tcp_dataplane_core.cpp` (64-shard lock-striped userspace TCP stack).
- `samurai/l7_emu_native/`: `engine.cpp`, `bridge.cpp`, `custom_quic_stack/`, `l2l3_stack/`.
- `samurai/scenario_engine_native/`: `compiler.cpp`, `scheduler.cpp`, `sla.cpp`.
- `samurai/cpu_native/`: `engine.cpp`, `packets.cpp`, `spoofing.cpp`, `amp.cpp`.
- `samurai/core/`: `target_safety.cpp`, `logging.hpp`, `json.hpp`.

---

## 2. Operational Execution Modes

### 1. Standalone Local Execution
```bash
./build/cli/samurai \
  --worker <cpu|afxdp|dpdk|gpu|doca|l7|telco|scenario> \
  --target <TARGET_IP> \
  --port 80 \
  --count 1000000 \
  --confirm
```

### 2. Distributed Multi-Node Cluster
- **Master Node:**
  ```bash
  ./build/control/daemon/samurai_master \
    --control-listen tcp://0.0.0.0:5099 \
    --count 100000000 \
    --target 10.0.0.50
  ```
- **Slave Node:**
  ```bash
  ./build/control/daemon/samurai_slave \
    --control-endpoints <MASTER_IP>:5099 \
    --worker afxdp
  ```

### 3. Integrated Self-Test Suites
- `./build/control/samurai_control_selftest`
- `./build/l7_emu_native/test_l2l3_astf`
- `./build/l7_emu_native/test_kernel_threaded_l7`
- `./build/l4/test_tcp_sliding_window`
