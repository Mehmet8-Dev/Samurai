# 21 - NUMA Architecture, TX/RX Scaling, AF_XDP & DPDK Zero-Copy DMA Engineering Guide

This guide provides an end-to-end technical reference for understanding, measuring, and tuning high-throughput kernel-bypass packet engines within **Samurai**. It bridges low-level hardware architecture (NUMA, PCIe, Cache hierarchies, and DMA) with native C++ production code (`samurai_afxdp_worker`, `samurai_dpdk_worker`, and `cpu_native`).

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](assets/diagrams/samurai_numa_afxdp_dpdk.svg)

---

## 1. Executive Summary & Current Dataplane State

In high-frequency packet generation and stress benchmarking, throughput is rarely bound by arithmetic computation. It is strictly constrained by **memory locality, CPU cache-line bouncing, PCIe bus latency, and descriptor ring contention**.

In the current native C++ architecture of Samurai:
- **AF_XDP Kernel-Bypass Worker (`samurai_afxdp_worker`):** User-space zero-copy UMEM ring buffers interacting directly with NIC driver queues via XSK sockets.
- **DPDK PMD Worker (`samurai_dpdk_worker`):** Poll Mode Driver directly managing hardware descriptor rings via hugepage memory (`rte_eth_tx_burst`).
- **CPU Native Packet Engine (`samurai_cpu_worker`):** Raw socket and packet ring fallback engine with pre-allocated buffer pools (`cpu_native/`).
- **GPU P2P & DOCA Dataplane (`samurai_gpu_worker`, `samurai_doca_worker`):** Autonomous packet streaming directly from GPU GDDR6 VRAM across the PCIe bus without Host-CPU intervention.

---

## 2. NUMA (Non-Uniform Memory Access) Topology & Latency Penalties

In multi-socket and multi-die server processors (Intel Xeon, AMD EPYC), physical memory is partitioned across distinct NUMA nodes:

- **Local Memory Access (Same Socket):** Lowest latency (~70–90 ns), maximum DDR4/DDR5 bandwidth (>120 GB/s), minimal jitter.
- **Remote Memory Access (Across Sockets):** Packets must traverse the inter-socket interconnect (Intel UPI or AMD Infinity Fabric). This introduces a **+35% to +50% latency penalty (~140–180 ns)** and causes interconnect bus saturation under heavy load.

```
+-------------------------------------------------------------+
|                      NUMA NODE 0 (LOCAL)                    |
|  [Pinned Cores: 2, 3, 4, 5] <---> [Local DDR5 Channels]     |
|              ^                                              |
|              | Direct PCIe Gen5 x16 Link (~150 ns)          |
|              v                                              |
|  [NIC Hardware Queues 0..3]                                 |
+-------------------------------------------------------------+
                               ^
                     CROSS-SOCKET UPI LINK 
       (Adds +40% Latency & Bus Contention Jitter)
                               v
+-------------------------------------------------------------+
|                     NUMA NODE 1 (REMOTE)                    |
|  [Remote Cores: 8, 9, 10, 11] <---> [Remote DDR5 Channels]  |
|  (AVOIDED: Non-local memory traversal degrades line rate)   |
+-------------------------------------------------------------+
```

### Engineering Golden Rule
> **Always ensure: Worker Thread Core Affinity $\rightarrow$ NIC Queue Allocation $\rightarrow$ Memory Buffer Allocation are anchored to the identical NUMA Node.**

---

## 3. TX/RX Scaling & Multi-Queue Queue-to-Core Pinning

Running multiple worker threads against a single hardware descriptor queue produces catastrophic lock contention and cache thrashing. Scaling requires deterministic 1:1 or N:M mapping.

### Queue Distribution Strategies:
1. **Map Strategy (`map` - Recommended for Deterministic Labs):**
   Explicit 1:1 binding between worker process threads and NIC hardware queues (e.g. Worker 0 $\rightarrow$ Queue 0, Worker 1 $\rightarrow$ Queue 1).
2. **Round-Robin (`rr`):**
   Dynamic round-robin allocation across available hardware queues.
3. **Pin Strategy (`pin`):**
   Fixed queue allocation tied strictly to core identifiers.

---

## 4. Zero-Copy Memory Layout: UMEM, Hugepages & Ring Buffers

Dynamic memory allocation (`malloc`, `free`, `new`, `delete`) is strictly forbidden on the dataplane fastpath. Samurai utilizes two contiguous memory models:

### A) AF_XDP UMEM (User Memory Buffer)
- Pre-allocated contiguous memory divided into fixed-size frames (typically 2048 or 4096 bytes).
- Governed by four lock-free circular ring buffers:
  1. **Fill Ring:** User-space supplies empty buffers to the kernel/NIC for RX.
  2. **RX Ring:** Kernel informs user-space of received packets.
  3. **TX Ring:** User-space submits packet descriptors for transmission.
  4. **Completion Ring:** Kernel signals user-space that transmission is complete and buffer frames can be reused.

### B) DPDK Hugepages (2MB / 1GB)
- Standard 4KB Linux pages incur severe TLB (Translation Lookaside Buffer) thrashing at 10M+ PPS.
- Pre-allocating 2MB or 1GB hugepages maps massive contiguous physical memory spaces with minimal TLB misses.

---

## 5. Direct Memory Access (DMA) Mechanics

DMA allows the network interface card to transfer packet data directly between host RAM and the physical PHY transceiver without cycling the CPU:

1. The CPU prepares packet headers and payloads inside local NUMA memory frames.
2. The CPU writes a descriptor pointer into the NIC TX Ring and rings the **NIC Doorbell MMIO register** ($O(1)$ constant time).
3. The NIC DMA engine autonomously issues PCIe Memory Read (MRd) TLPs to pull the bytes across the PCIe bus into its internal FIFO.
4. The NIC hardware calculates Ethernet CRC32/FCS and emits the frame onto the physical wire at line rate (148.8 Mpps at 100GbE).
5. The NIC updates descriptor status flags, and the worker reclaims the frame slot without copying data.

---

## 6. Native Execution Runbook & Operational Commands

### A) Native AF_XDP Zero-Copy Execution
Ensure the network interface is bound and NUMA affinity is configured:

```bash
# Verify NUMA node of the NIC (e.g. eth0)
cat /sys/class/net/eth0/device/numa_node

# Run samurai native AF_XDP worker pinned to NUMA Node 0 cores
numactl --cpunodebind=0 --membind=0 \
  ./build/samurai/cli/samurai \
    --worker afxdp \
    --target 10.0.0.50 \
    --port 80 \
    --protocol tcp \
    --count 10000000 \
    --confirm
```

### B) Native DPDK Hardware PMD Execution
With hugepages pre-allocated (`default_hugepagesz=1G hugepagesz=1G hugepages=8`):

```bash
# Run samurai native DPDK worker with hardware PMD rings
sudo ./build/samurai/cli/samurai \
  --worker dpdk \
  --target 10.0.0.50 \
  --port 443 \
  --protocol tcp \
  --count 50000000 \
  --confirm
```

### C) CPU Native Raw Socket Stress Test
```bash
./build/samurai/cli/samurai \
  --worker cpu \
  --target 127.0.0.1 \
  --port 8080 \
  --protocol udp \
  --count 500000 \
  --size 64 \
  --confirm
```

---

## 7. Common Pitfalls & Anti-Patterns

| Anti-Pattern | Root Cause | Architectural Consequence | Samurai Solution |
|:---|:---|:---|:---|
| **Excessive Worker Threads** | Over-subscribing CPU cores beyond hardware queues | Context switching and cache eviction collapse throughput | Restrict workers to 1 thread per physical core (`--pin-cpu`). |
| **Silent Driver Fallback** | Kernel falling back to generic SKB mode | Drops PPS from 20+ Mpps down to ~1.2 Mpps | Enforce strict zero-copy mode (`XDP_ZEROCOPY`); fail fast if unavailable. |
| **Cross-Socket Memory** | Allocating UMEM or buffers on NUMA 1 while NIC is on NUMA 0 | Interconnect UPI bus saturation and latency spikes | Enforce `numactl --membind` and local socket page allocation. |
| **Unbounded TX Rings** | Sizing rings too large | High packet latency due to bufferbloat | Tune ring depth to burst target (e.g., 2048–4096 frames) with pacing. |

---

## 8. Related Architecture Documents

- [00-overview.md](00-overview.md) — Master System Overview & Subsystem Map
- [01-cli.md](01-cli.md) — Native C++ CLI Reference
- [06-af_xdp-fast_sender.md](06-af_xdp-fast_sender.md) — AF_XDP Zero-Copy Implementation
- [34-dpdk-kurulum-ve-hazirlik-rehberi.md](34-dpdk-kurulum-ve-hazirlik-rehberi.md) — DPDK Environment Setup & PMD Configuration
- [40-distributed-control-plane-handbook.md](40-distributed-control-plane-handbook.md) — Multi-Node Distributed Cluster Architecture
- [45-commodity-gpu-nic-p2p-packet-engine-report.md](45-commodity-gpu-nic-p2p-packet-engine-report.md) — GPU-NIC P2P Zero-Copy Dataplane Report
