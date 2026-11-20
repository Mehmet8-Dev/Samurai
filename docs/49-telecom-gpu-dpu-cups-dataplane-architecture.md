# 49 - DPU ARM & GPU Telecom User-Plane (CUPS) Dataplane Architecture & Integration Guide

**Project:** Samurai Carrier-Grade Telecom Engine (Samurai Telecom CUPS Dataplane)  
**Author:** Antigravity Systems Research & Core Engineering  
**Date:** November 8, 2026  
**Target Hardware:** DPU ARMv8-A / ARMv9 (`aarch64`) + NVIDIA GPU (GeForce BAR1 P2P / BlueField DOCA)  
**Document Code:** `DOC-SAMURAI-TELECOM-CUPS-49`

---

![Samurai DPU ARM & GPU Telecom CUPS Architecture](assets/diagrams/samurai_telecom_dpu_gpu_cups.svg)

## 1. Executive Summary and Architectural Vision

In mobile core networks (4G LTE EPC and 5G NR Standalone), decoupling the Control Plane from the User Plane is the cornerstone of **3GPP CUPS (Control and User Plane Separation — 3GPP TS 23.501 / TS 29.244)**. On traditional x86 CPU servers, running N4 PFCP state machines for millions of subscribers alongside hundreds of gigabits of GTP-U tunnel encapsulation on the same processor cores causes severe cache thrashing (L1/L2/L3), cross-core lock contention, and unacceptable packet jitter.

Samurai addresses this bottleneck through **Hardware-Assisted CUPS Partitioning**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SAMURAI HARDWARE-BASED CUPS PARTITIONING                 │
├──────────────────────────────────────┬──────────────────────────────────────┤
│       CONTROL PLANE (CP - SLOWPATH)  │        USER PLANE (UP - FASTPATH)    │
│           DPU ARMv8-A CORES          │            NVIDIA GPU CORES          │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ • 3GPP N4 PFCP State Machines        │ • 100 GbE+ Wire-Rate GTP-U           │
│ • Subscriber SessionMgmt (SessionMgr)│ • 5G NR QFI (0x85) PDU Encapsulation │
│ • Hierarchical Timing Wheel          │ • 802.1ad QinQ & 802.1Q VLAN         │
│ • Low Power & SoC Isolation          │ • Dual-Layer Parallel Checksum       │
│ • Seqlock SHM & ZMQ Event Publisher  │ • GeForce BAR1 Zero-Copy P2P TX Ring │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

This architecture completely offloads packet processing from host CPU cores and Host RAM. Energy-efficient ARM cores on the DPU manage subscriber session lifecycles, while thousands of GPU SM cores write encapsulated telecom packets directly into NIC PCIe DMA rings (BAR1 P2P Ring).

---

## 2. End-to-End System Topology and Datapath

Communication between the DPU ARM controller and the GPU user plane operates across two parallel channels:
1. **High-Speed Shared Memory (Zero-Copy Seqlock SHM):** A live tunnel table `mmap`'d on `/dev/shm`, updated by the DPU and pinned into GPU address space via `cudaHostRegister`.
2. **Asynchronous IPC Control Channel (ZeroMQ Protocol):** A reliable messaging channel carrying dynamic tunnel upsert and batch-clear instructions (`TELCO_TUNNEL_UPSERT`).

```
 +-------------------------------------------------------------------------+
 |                  DPU CONTROL PLANE (ARM64 ABSTRACTION)                  |
 |                                                                         |
 |  [3GPP SMF / AMF Peer] <--(N4 PFCP / UDP 8805)--> [PfcpEngine]          |
 |                                                           |             |
 |                                                [SessionManager O(1)]    |
 |                                                           |             |
 |                                            [DpuArmCupsSessionController]|
 +---------------------+-------------------------------------+-------------+
                       |                                     |
    (POSIX Shared Memory / tmpfs)                 (ZeroMQ IPC Transport)
     /dev/shm/samurai_cups_*.bin                   ipc:///tmp/cups_gpu.ipc
                       |                                     |
                       v                                     v
 +-------------------------------------------------------------------------+
 |                    GPU USER PLANE (NVIDIA CUDA SMs)                     |
 |                                                                         |
 |  samurai_gpu_worker                                                     |
 |    ├── samurai_gpu_packet_telco_attach_cups_shm_v1()                     |
 |    └── HandleTelcoTunnelUpsertPayload()                                 |
 |                                                                         |
 |  [CUDA Persistent / Batch Kernel: kernels_telecom.cuh]                  |
 |    ├── Warp-Level Seqlock Tunnel Lookup (DpuCupsSharedTunnelV1)         |
 |    ├── 5G Extension Header Generation (0x85 PDU Session Container)      |
 |    ├── Hardware Dual-Layer Checksum Folding (Inner + Outer IP/L4)       |
 |    └── Direct Store: Vulkan BAR1 GDDR6 / GeforceP2pRingInstance         |
 +-------------------------------------+-----------------------------------+
                                       |
                         (PCIe P2P DMA Memory Read - MRd)
                                       v
 +-------------------------------------------------------------------------+
 |                  NIC HARDWARE (DPDK / CX-NIC / VFIO)                    |
 |                                                                         |
 |  - PCIe TX Ring Descriptors                                             |
 |  - GPU Doorbell Push (fence.proxy.tens MMIO Register)                   |
 |  - 100 GbE QSFP28 Wire Egress                                           |
 +-------------------------------------------------------------------------+
```

---

## 3. DPU ARM Subscriber Session Management & N4 PFCP State Machine

Running on DPU ARM cores, [`DpuArmCupsSessionController`](../samurai/telecom/cups/dpu_arm_cups_bridge.hpp#L35-L95) drives PFCP signaling compliant with 3GPP TS 29.244.

### 3.1 Session Lifecycle

1. **Session Establishment (`EstablishSubscriberSession`):**
   - Parses incoming `Session Establishment Request` messages from the SMF.
   - Allocates a `TelcoSessionContext` in $O(1)$ time from the DPU ARM [`SessionManager`](../samurai/telecom/core/session_manager.hpp#L150) pool.
   - Populates Uplink/Downlink TEID, UE IPv4, and QFI fields in the tunnel slot.
   - Updates the corresponding `DpuCupsSharedTunnelV1` slot inside the Seqlock-protected shared memory region.
   - Emits a `TELCO_TUNNEL_UPSERT` message over ZMQ to notify the GPU immediately.

2. **Session Modification (`ModifySubscriberSession`):**
   - Dynamically updates TEID/QFI during QoS flow transitions (e.g., QFI 9 default bearer to QFI 1 VoNR/IMS bearer) or handovers.
   - Increments the Seqlock sequence counter so the user plane never reads torn or stale state during updates.

3. **Session Deletion (`DeleteSubscriberSession`):**
   - Clears the tunnel active flag (`kTelcoTunnelFlagActive = 0x01`) and returns the slot to the pool when a subscriber session terminates.

---

## 4. Seqlock-Protected Zero-Copy Shared Memory Contract

Lock-free, zero-copy synchronization between DPU and GPU uses [`DpuCupsSharedRegionHeaderV1`](../samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh#L160-L210).

### 4.1 Memory Layout and Alignment

```cpp
struct alignas(64) DpuCupsSharedTunnelV1 {
  uint32_t teid;               // GTP-U Tunnel Endpoint Identifier
  uint32_t peer_ipv4;          // Peer (gNodeB / UPF) IPv4 address
  uint32_t ue_ipv4;            // Subscriber (UE) inner IPv4 address
  uint16_t vlan_outer;         // 802.1ad S-VLAN
  uint16_t vlan_inner;         // 802.1Q C-VLAN
  uint8_t  qfi;                // 5G QoS Flow Identifier (0..63)
  uint8_t  flags;              // 0x01: Active, 0x02: IPv6, 0x04: Drop
  uint16_t pad;
  uint64_t tx_packets;         // Atomically updated by GPU
  uint64_t tx_bytes;           // Atomically updated by GPU
};

struct alignas(4096) DpuCupsSharedRegionHeaderV1 {
  uint32_t magic;              // 0x43555053 ("CUPS")
  uint16_t version;            // 1
  uint16_t header_bytes;       // sizeof(DpuCupsSharedRegionHeaderV1)
  uint32_t max_tunnels;        // Maximum tunnel capacity
  uint32_t active_tunnels;     // Active tunnel count
  uint64_t sequence_number;    // Seqlock sequence counter
  // Followed by: DpuCupsSharedTunnelV1 tunnels[max_tunnels];
};
```

### 4.2 Linux `tmpfs` & `cudaHostRegister` Requirement

> [!IMPORTANT]
> NVIDIA's `cudaHostRegister` API cannot pin `mmap` regions backed by regular ext4/xfs disk files into GPU page tables and returns `cudaErrorInvalidValue`.
> The shared memory backing file MUST reside on a **POSIX RAM-backed `tmpfs` filesystem (`/dev/shm/...`)** and its total size must be aligned to an integer multiple of the system page size (4096 bytes).

### 4.3 Bidirectional Hardware Memory Barriers

- **DPU ARMv8-A Writer Side:**
  ARM64 implements a weakly ordered memory model. Seqlock updates issue an ARM-native store-release fence:
  ```cpp
  #if defined(__aarch64__)
    asm volatile("dmb ishst" ::: "memory");
  #else
    std::atomic_thread_fence(std::memory_order_release);
  #endif
  ```
- **GPU CUDA Reader Side:**
  GPU warp threads perform a double-read loop over `sequence_number`. If `sequence_number` is odd (DPU write in progress) or changes between the start and end reads, the read is retried:
  ```cuda
  uint64_t seq_before = header->sequence_number;
  if ((seq_before & 1ULL) != 0) { /* write in progress, spin/retry */ }
  // Read tunnel fields...
  __threadfence();
  uint64_t seq_after = header->sequence_number;
  if (seq_before == seq_after) { /* Data consistent, proceed */ }
  ```

---

## 5. CUDA Telecom Kernel Micro-Architecture (`kernels_telecom.cuh`)

The GPU packet engine executes SIMT kernels optimized to generate tens of millions of GTP-U packets per second at wire rate.

### 5.1 4G LTE and 5G NR GTP-U Header Anatomy

Telecom packets consist of two encapsulated layers (outer transport and inner subscriber payload):

```
+---------------------------------------------------------------------------+
| L2 Ethernet (14B) | Single VLAN (4B) / QinQ (8B) [Optional]               |
+---------------------------------------------------------------------------+
| Outer IPv4 Header (20B, Proto: 17 UDP)                                    |
+---------------------------------------------------------------------------+
| Outer UDP Header (8B, Destination Port: 2152)                             |
+---------------------------------------------------------------------------+
| GTP-U Mandatory Header (8B: Flags=0x34, Type=0xFF, TEID=32-bit)           |
+---------------------------------------------------------------------------+
| GTP-U Optional Fields (4B: Seq=16-bit, N-PDU=8-bit, NextExt=0x85)         |
+---------------------------------------------------------------------------+
| 5G PDU Session Container (4B: Len=1, PDU Type=DL, QFI=6-bit, NextExt=0x00)|
+---------------------------------------------------------------------------+
| Inner IPv4 Header (20B, Subscriber UE IP -> Target Server)                |
+---------------------------------------------------------------------------+
| Inner L4 Header (UDP: 8B / TCP: 20B / ICMP: 8B)                           |
+---------------------------------------------------------------------------+
| Payload                                                                   |
+---------------------------------------------------------------------------+
```

### 5.2 5G QFI (`0x85`) PDU Session Container Encapsulation

In 5G Standalone networks, every packet maps to a specific QoS class (QoS Flow Identifier — QFI). The GPU kernel writes the tunnel's QFI into the 4-byte extension header per 3GPP TS 38.415:
- `Flags`: `0x34` (`Version=1`, `PT=1`, `E=1` extension header present).
- `Next Extension Header`: `0x85` (PDU Session Container).
- `PDU Type`: `0x00` (Downlink) or `0x10` (Uplink).
- `QFI`: 6-bit QoS flow identifier (`0x00` through `0x3F`, i.e., 0..63).

### 5.3 Parallel Dual-Layer Checksum Folding

GTP-U packets require accurate checksums on both the outer IPv4 header and the inner IPv4 + L4 (TCP/UDP/ICMP) headers. Packets with invalid checksums are dropped in hardware by core routers and UPFs.

The GPU kernel unrolls loops (`#pragma unroll`) into a 32-bit accumulator and folds into a 16-bit one's complement checksum in warp instructions:
```cuda
// Fold 32-bit accumulator into 16-bit one's complement
sum = (sum >> 16) + (sum & 0xFFFF);
sum += (sum >> 16);
return static_cast<uint16_t>(~sum);
```

---

## 6. DPU ARM Portability Engineering

To run the telecom control plane natively on ARM-based DPUs (NVIDIA BlueField-2/BlueField-3 or Marvell OCTEON), x86-specific intrinsics are abstracted behind architecture-neutral wrappers:

| Capability | x86-64 Equivalent | DPU ARMv8-A (`aarch64`) Equivalent | File |
|:---|:---|:---|:---|
| **Time Stamp Counter (TSC)** | `__builtin_ia32_rdtsc()` | `asm volatile("mrs %0, cntvct_el0" : "=r"(val))` | [`samurai_tsc.h`](../samurai/samurai_tsc.h) |
| **System Timer Frequency** | `/proc/cpuinfo` / TSC calib | `asm volatile("mrs %0, cntfrq_el0" : "=r"(freq))` | [`hierarchical_timing_wheel.cpp`](../samurai/telecom/core/hierarchical_timing_wheel.cpp) |
| **Hardware CRC32** | `_mm_crc32_u64()` | `__crc32cd()` (`<arm_acle.h>`) | [`session_context.hpp`](../samurai/telecom/core/session_context.hpp) |
| **Spinlock Yield** | `__builtin_ia32_pause()` | `asm volatile("yield" ::: "memory")` | [`session_manager.hpp`](../samurai/telecom/core/session_manager.hpp) |
| **Compiler Flags** | `-msse4.2` | `-march=armv8-a+crc` | [`samurai/telecom/CMakeLists.txt`](../samurai/telecom/CMakeLists.txt) |

---

## 7. Codebase Directory Map & Responsibilities

```
samurai/
├── gpu_packet_cuda/
│   ├── kernels_telecom.cuh                 # 4G/5G QFI, QinQ, dual-checksum CUDA kernels
│   ├── zero_copy_dataplane_contract.cuh   # CUPS SHM and BAR1 P2P memory layouts
│   ├── geforce_p2p_runtime.cuh            # Vulkan BAR1 P2P ring queue
│   ├── gpu_initiated_doorbell.cuh         # fence.proxy.tens MMIO doorbell mechanism
│   └── host_api.cuh                       # C ABI exported functions
├── telecom/
│   ├── cups/
│   │   ├── dpu_arm_cups_bridge.hpp        # DPU ARM CUPS bridge header
│   │   └── dpu_arm_cups_bridge.cpp        # 3GPP N4 PFCP session management & seqlock SHM
│   ├── core/
│   │   ├── session_context.hpp            # 128-byte cache-aligned subscriber context
│   │   ├── session_manager.hpp            # O(1) index & CRC32 hash lookup table
│   │   └── hierarchical_timing_wheel.cpp  # ARM64-compatible 3-tier timing wheel
│   └── tests/
│       ├── test_dpu_arm_cups_gpu_bridge.cu # DPU CUPS <-> GPU end-to-end lifecycle test
│       ├── test_gpu_telecom_kernels.cu    # CUDA telecom packet validation test
│       ├── test_gpu_worker_telecom_zmq.cpp# ZMQ IPC control-plane regression test
│       └── test_gpu_doorbell_hardening.cu # GPU-PMD hardware invariants test
└── zmq/daemon/
    ├── gpu_worker.cpp                     # GPU worker process (CUPS SHM + BAR1 P2P)
    ├── telco_worker.cpp                   # Telecom worker process (DPU CUPS controller)
    └── wire_protocol.h                    # TelcoGpuJobEnvelopeV1 & upsert wire protocol
```

---

## 8. Operational Runbook

### 8.1 Launching the DPU CUPS Control Plane

Start `samurai_telco_worker` on the DPU with the shared memory path and GPU ZMQ endpoint:

```bash
# 1. Start telecom controller on DPU ARM
./build/zmq/samurai_telco_worker \
  --worker-id 1 \
  --sub-start 1 --sub-count 10000 \
  --cups-shm-path /dev/shm/samurai_cups_tunnels.bin \
  --cups-gpu-endpoint ipc:///tmp/cups_gpu_control.ipc
```

### 8.2 Launching the GPU User-Plane Worker

The GPU worker attaches to the same `/dev/shm` region and activates the BAR1 P2P ring:

```bash
# 2. Start packet engine worker on GPU host
./build/zmq/samurai_gpu_worker \
  --cups-shm-path /dev/shm/samurai_cups_tunnels.bin \
  --p2p-ring-handle 0x1 \
  --enable-p2p \
  --ipc-endpoint ipc:///tmp/cups_gpu_control.ipc
```

### 8.3 Triggering Live 5G GTP-U Traffic via CLI

```bash
./build/samurai_cli \
  --protocol gtpu \
  --target-ip 10.200.1.1 \
  --teid 0x12345678 \
  --qfi 9 \
  --vlan 100 \
  --inner-vlan 200 \
  --pps 5000000 \
  --duration 30
```

---

## 9. Verification and Test Matrix

All layers are verified via automated CTest and standalone test binaries:

```bash
# Build and run the test suite
ctest --test-dir build --output-on-failure
```

### Verified Test Suites

1. **`telecom_dpu_arm_cups_gpu_bridge`:**
   - Creating, modifying QFI/TEID, and deleting 4 subscribers over N4 PFCP on DPU ARM.
   - GPU attaching to the `/dev/shm` tunnel table via `cudaHostRegister` and emitting valid GTP-U packets.
2. **`telecom_gpu_kernels`:**
   - 4G baseline GTP-U headers and CPU decapsulation verification.
   - Byte-level 5G QFI (`0x85`) PDU session container validation.
   - 802.1Q single VLAN and 802.1ad QinQ double VLAN encapsulation tests.
   - Inner TCP and ICMP dual-layer checksum verification.
   - Dynamic Seqlock tunnel table upsert and clear verification.
3. **`telecom_gpu_worker_zmq`:**
   - Safe rejection of malformed or truncated `TELCO_TUNNEL_UPSERT` payloads.
   - Zero-tunnel clear-only command handling.
   - Live ZMQ IPC job execution and telemetry streaming verification.
4. **`telecom_gpu_doorbell_hardening`:**
   - GPU-PMD hardware invariants, BAR1 memory bounds, and `fence.proxy.tens` barrier validation.

**Result:** `17/17 Tests Passed (100% Pass Rate)`.
