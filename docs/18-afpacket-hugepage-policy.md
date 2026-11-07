# 18 - AF_PACKET & HugePage Policy Reference

This document details the memory allocation policies, Transparent HugePages (THP) enforcement, telemetry instrumentation, and KPI gate criteria for the high-speed packet ring engine.

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](assets/diagrams/samurai_numa_afxdp_dpdk.svg)

---

## 1. Scope & Architectural Boundaries

- **Primary Scope:** `AF_PACKET / TX_RING + THP enforcement` (ring allocation, memory locking, telemetry, and gate verification).
- **Kernel Memory Constraints:** Standard AF_PACKET ring memory is allocated inside the Linux kernel. Therefore, direct userspace `MAP_HUGETLB` guarantees are constrained by kernel memory layout.
- **Engineering Principle:** This policy provides rigorous, verifiable hugepage backing. For guaranteed zero-copy and complete hugepage isolation, AF_XDP (`samurai_afxdp_worker`) or DPDK PMD (`samurai_dpdk_worker`) must be utilized.

---

## 2. HugePage Allocation Modes

- `off`: HugePage enforcement disabled; standard 4 KB page allocations.
- `auto`: Best-effort policy. Applies `madvise(MADV_HUGEPAGE)` and optional page prefaulting (`mlock`); allocation failure does not abort execution.
- `required`: Strict enforcement. If `afpacket_hugepage_effective != 1` after TX_RING allocation, the test is aborted with a critical failure.

---

## 3. Dedicated Lab Profile Semantics

When running under `--lab-profile dedicated`:
- `afpacket_hugepage_mode` automatically defaults to `required`.
- The KPI performance gate checks that hugepages are active and backing the packet buffer rings.
- If `--kpi-hard-fail` is enabled, the CLI exits immediately with a non-zero status code if hugepage backing is unavailable.

---

## 4. CLI Configuration Options

| Flag | Default | Description |
| :--- | :---: | :--- |
| `--afpacket-hugepage-mode {off,auto,required}` | `auto` | Enforces HugePage policy for memory ring buffers. |
| `--afpacket-hugepage-size-kb <int>` | `2048` | Target hugepage size (e.g., 2048 KB or 1048576 KB). |
| `--afpacket-ring-target-mb <int>` | `64` | Desired total ring buffer allocation size in megabytes. |
| `--afpacket-block-size-kb <int>` | `0` | Ring block size in KB (0 = autodetect power of 2). |
| `--afpacket-frame-size <int>` | `0` | Per-packet frame size (0 = auto-aligned). |
| `--afpacket-frames-per-block <int>` | `64` | Number of packet frames contained per memory block. |
| `--afpacket-poll-timeout-ms <int>` | `1` | Blocking timeout for kernel transmission drain. |
| `--afpacket-spin-limit <int>` | `2000` | Busy-wait spin iterations before sleeping. |
| `--afpacket-busy-poll-us <int>` | `0` | Low-latency socket polling duration in microseconds. |
| `--afpacket-qdisc-bypass` | Enabled | Directly bypass Linux queueing discipline (`PACKET_QDISC_BYPASS`). |
| `--afpacket-mlock-ring` | Enabled | Lock ring buffers into physical RAM via `mlockall()`. |
| `--afpacket-prefault-ring` | Enabled | Prefault pages into CPU cache before starting traffic. |

---

## 5. Ring Geometry & Tuning Mechanics

- **Ring Geometry Calculation:** `frame_size`, `frames_per_block`, `block_size`, and `block_nr`.
- **Power of Two Alignment:** Memory block sizes must strictly align with hardware page size multiples (2 MB or 4 KB) to avoid kernel memory fragmentation.
- **Qdisc Bypass:** When enabled, the kernel skips packet scheduling qdiscs, injecting packets directly to the NIC driver TX ring for maximum line-rate throughput.

---

## 6. Runtime Telemetry & Observability Fields

The performance report and Prometheus exporter publish the following metrics:

```json
{
  "afpacket_hugepage_mode": "required",
  "afpacket_hugepage_effective": 1,
  "afpacket_hugepage_size_kb": 2048,
  "afpacket_madvise_hugepage_ok": true,
  "afpacket_mlock_ok": true,
  "afpacket_prefault_pages": 32768,
  "afpacket_ring_block_size": 2097152,
  "afpacket_ring_block_nr": 32,
  "afpacket_ring_size_bytes": 67108864
}
```

---

## 7. Execution Examples

### Standard Verification Run
```bash
./build/ddos_samurai/cli/samurai \
  --worker cpu \
  --target 127.0.0.1 \
  --port 80 \
  --protocol tcp \
  --count 100000 \
  --confirm \
  --afpacket-hugepage-mode auto
```

### Dedicated Lab Strict Production Run
```bash
./build/ddos_samurai/cli/samurai \
  --worker cpu \
  --target 192.168.1.50 \
  --port 443 \
  --protocol tcp \
  --count 10000000 \
  --confirm \
  --lab-profile dedicated \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --afpacket-hugepage-mode required
```
