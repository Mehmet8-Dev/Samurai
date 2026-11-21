---
name: samurai-hardware-dataplane
description: Select, validate, and orchestrate all 10 native C++17 Samurai dataplane workers (cpu, afpacket, afxdp, dpdk, gpu CUDA/BAR1 P2P, doca BlueField, l7 io_uring/kTLS/QUIC, scenario, telco 4G/5G CUPS, defense VAE) with accurate prerequisites and hardware boundaries.
---

# Samurai 10-Worker Hardware & Protocol Dataplane Skill

Always call `samurai_list_workers` first to see which native binaries are compiled on the current host before selecting a worker backend.

## Complete Worker Selection Matrix

| Worker (`--worker`) | Binary | Best For | Prerequisites / Notes |
| :--- | :--- | :--- | :--- |
| `cpu` | `samurai_cpu_worker` | Raw UDP/TCP packet synthesis, header spoofing, amplification simulation | Requires `CAP_NET_RAW` / `sudo` for raw sockets |
| `afpacket` | `samurai_afpacket_worker` | High-rate Linux `TPACKET_V3` mmap TX rings on commodity NICs | Requires `CAP_NET_RAW` / `CAP_NET_ADMIN` |
| `afxdp` | `samurai_afxdp_worker` | Linux XSK / UMEM zero-copy kernel-bypass Mpps workloads | Linux XDP-capable NIC driver + `libbpf` |
| `dpdk` | `samurai_dpdk_worker` | Bare-metal PMD hardware rings & hugepage 40G/100G line-rate | Hugepages + DPDK-bound NIC (`libdpdk`) |
| `gpu` | `samurai_gpu_worker` | NVIDIA CUDA persistent kernel, GeForce BAR1 P2P DMA, GPU MMIO doorbell, QUIC RFC 9001 batch crypto | NVIDIA GPU + CUDA 12.x native host build |
| `doca` | `samurai_doca_worker` | NVIDIA BlueField DPU & DOCA GPUNetIO VRAM streaming | BlueField DPU + DOCA SDK native host build |
| `l7` | `samurai_l7_worker` | Stateful HTTP/1.1, HTTP/2 (`nghttp2` + `io_uring`/kTLS), QUIC/HTTP-3 (`ngtcp2`), DNS | Works unprivileged on any Linux host |
| `scenario` | `samurai_scenario_worker` | Multi-step Web/Mobile persona workflows, JWT/cookie sessions, SLA gates | Driven via `samurai_scenario_compile` / `samurai_scenario_run` |
| `telco` | `samurai_telco_worker` | 4G/5G CUPS: GTP-U (5G QFI), PFCP N4, SCTP (S1-AP/NG-AP), Diameter Ro/Gx, SIP/RTP/SRTP, PPPoE, DHCP, BFD | Use profiles `telco-sctp-flood`, `telco-diameter-billing`, `telco-sip-storm`, `telco-full-carrier` + `samurai_cluster_plan_shards` (`mode: "telco"`) |
| `defense` | `samurai_defense_worker` | Variational Autoencoder (VAE) anomaly scoring & defense verification | Evaluates anomaly resilience under load |

## Coordination Rules

- For heterogeneous clusters (e.g., GPU nodes + AF_XDP nodes + CPU/L7 nodes), pass per-node `gpu_available`, `xdp_available`, `capacity_score`, and `region` into `samurai_cluster_plan_shards` before dispatching jobs.
- Never bypass fail-closed target safety: all MCP operations stay strictly inside loopback / RFC 1918 / RFC 6598 / RFC 2544 lab ranges.
