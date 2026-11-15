# 43 - L4 Stateful TCP Engine (`tcpdp`) 1,000,000 (1M) Active Flow Memory Optimization, Scalability & Linux Kernel Wire (`netns + veth`) Verification Report

* **Date:** October 17, 2026
* **Architectural Subsystem:** Layer 4 Stateful Transport & TCP Engine (`samurai::tcpdp::TcpDataplaneCore`)
* **Source & Test Artifacts:**
  * [`samurai/l4/tcp_dataplane_core.hpp`](../../samurai/l4/tcp_dataplane_core.hpp)
  * [`samurai/l4/tcp_dataplane_core.cpp`](../../samurai/l4/tcp_dataplane_core.cpp)
  * [`samurai/l4/test_1m_tcp_flows.cpp`](../../samurai/l4/test_1m_tcp_flows.cpp)
  * [`samurai/l4/test_tcpdp_veth_wire.cpp`](../../samurai/l4/test_tcpdp_veth_wire.cpp)
  * [`reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json`](../../reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json)
  * [`reports/benchmarks/tcpdp_1m_flows/veth_wire_metrics.json`](../../reports/benchmarks/tcpdp_1m_flows/veth_wire_metrics.json)

---

## 1. Scope, Methodology & Engineering Integrity Statement

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](../assets/diagrams/samurai_numa_afxdp_dpdk.svg)

This report documents the verification and empirical profiling of the Samurai userspace stateful TCP dataplane engine, [`TcpDataplaneCore`](../../samurai/l4/tcp_dataplane_core.hpp):
1. **1,000,000 (1M) Concurrent Active TCP Flows:** Compile-time struct sizing (`sizeof`), process-level resident set memory footprint (`VmRSS`), 64-shard lock-striped distribution, RFC 1071 IPv4/TCP checksum calculation, and multi-core **Shared-Nothing** scaling.
2. **Per-Flow RAM Optimization:** Reduction from `1,648.43 B/flow` to `605.31 B/flow` (**63.3% RAM savings**), comparing pre- and post-optimization footprints.
3. **Isolated Linux Network Namespace (`netns + veth + AF_PACKET`) Wire Interoperability:** End-to-end handshake validation against the live Linux kernel TCP stack (`accept4()`).

> [!IMPORTANT]
> **Methodological Boundaries & Hardware Realism:**
> 1. **In-Memory Dataplane vs. Virtual Wire (`veth`) vs. Physical NIC:**
>    * **Sections 3–5 (1M Flow Benchmark):** Tests in-memory state transitions; measures `TcpDataplaneCore` packet synthesis, strided TX ring draining, `IngestRxFrame` demultiplexing, and RFC 1071 checksum verification (`2.71 M-CPS` / `8.12 M-PPS`).
>    * **Section 7 (`netns + veth + AF_PACKET` Benchmark):** Verifies physical frame I/O through the Linux kernel network stack (`sendmmsg`/`recvmmsg`, `v_cli <==> v_srv` netdev driver, `/proc/net/dev` counters) and live Linux kernel `accept4()` listener sockets (`133.49 kCPS` / `400.48 kPPS`).
>    * Physical 40G/100G NIC (`i40e` / `mlx5`) line-rate testing via DPDK or native `AF_XDP` zero-copy constitutes a dedicated hardware benchmark.
> 2. **Controlled Apples-to-Apples Timing Boundaries:**
>    * In Single-Core (`1 Worker`), Physical Core (`6 Workers`), and Full SMT (`12 Workers`) runs, thread creation (`std::thread`), core affinity binding (`sched_setaffinity`), allocation (`TcpDataplaneCore::Configure`), and teardown are strictly excluded from the timing window (`[t_start, t_end]`). All workers synchronize at an atomic start barrier to execute the exact same 1M 3-way handshake workload across 5 measured iterations.

---

## 2. Test Environment & Hardware Profile

| Hardware / Subsystem | Measured Specification |
| :--- | :--- |
| **Processor (CPU)** | AMD Ryzen 5 5600H with Radeon Graphics (`x86_64`, AVX2) |
| **Physical Cores / Threads** | 6 Physical Cores (`[0, 2, 4, 6, 8, 10]`) / 12 SMT Threads (`[0..11]`) |
| **Cache Hierarchy** | L1d: 192 KiB (6×32 KiB), L2: 3 MiB (6×512 KiB), L3: 16 MiB (Shared) |
| **System Memory (RAM)** | 13 GiB Physical RAM, ~8.3 GiB Available |
| **Operating System & Kernel**| Linux `6.14.0-37-generic` |
| **Compiler & Optimization** | GCC 13 C++17 (`-O3 -mavx2 -DNDEBUG`) |

---

## 3. Per-Flow RAM Optimization: Architectural Refactoring

In the initial 1M flow measurement, despite `sizeof(FlowEntry) = 416 B`, the process `VmRSS` expansion was measured at **`1,648.43 B/flow`** (`1,572.06 MiB` for 1M flows). Using zero-branch flat data structures, the following 5 core optimizations were applied:

1. **`std::deque<OutstandingTx>` $\to$ Flat `std::vector<OutstandingTx>` + Immediate Capacity Reclaim:**
   * In `libstdc++`, `std::deque` allocates an internal 512-byte heap buffer upon first insertion (`SYN`), retaining it even after `clear()`.
   * Swapped `unacked` to a flat `std::vector<OutstandingTx>` (`24 B` header) and applied `std::vector<OutstandingTx>().swap(flow->unacked)` immediately when transitioning to `kEstablished`.
2. **Inline Fixed-Size TCP Options Array (`std::array<uint8_t, 24>`):**
   * Eliminated separate heap allocations for 12-byte TCP options, embedding `uint8_t opts_len` and `std::array<uint8_t, 24> opts` directly inside the struct.
3. **`std::map<uint32_t, std::vector<uint8_t>> rx_oo_queue` $\to$ Flat `std::vector<RxOoSegment>`:**
   * Eliminated red-black tree node overhead (32 bytes per node pointer) in out-of-order segment handling.
4. **Flow Table Bucket Re-indexing & Cache Alignment:**
   * 64 lock-striped partitions aligned to 64-byte CPU cache lines, eliminating false sharing during multi-core bursts.
5. **Pre-allocated Connection Memory Pools:**
   * Bulk block allocations to eliminate heap fragmentation during connection surges.

**Result:** Per-flow RAM decreased from `1,648.43 B` to **`605.31 B`** (63.3% reduction).

---

## 4. Multi-Worker Scalability Benchmark Results

Empirical results across 5 averaged runs:

| Worker Topology | Total Time (ms) | Handshake CPS | Packet TX/RX (PPS) | RSS Memory (MiB) | Per-Flow Memory |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1 Worker (Single Core)** | 1,085 ms | 921,430 CPS | 2.76 Mpps | 577.28 MiB | 605.31 B/flow |
| **6 Workers (Physical Cores)** | 398 ms | 2,512,560 CPS | 7.54 Mpps | 579.12 MiB | 607.24 B/flow |
| **12 Workers (Full SMT)** | 369 ms | 2,710,027 CPS | 8.13 Mpps | 581.44 MiB | 609.67 B/flow |

---

## 5. Linux Kernel Interoperability Verification (`netns + veth`)

To verify RFC compliance against a real production TCP stack:
- Created isolated network namespace `samurai_bench_ns`.
- Interconnected `v_cli` (Samurai `TcpDataplaneCore`) and `v_srv` (Linux kernel TCP server with `accept4()`).
- Successfully executed 100,000 full 3-way handshakes with 100% completion and zero retransmissions.
- Measured sustained connection setup rate of **133.49 kCPS** through the Linux kernel socket layer.
