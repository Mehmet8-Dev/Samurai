---
name: samurai-hardware-dataplane
description: Select, validate, and orchestrate all 10 native C++17 Samurai dataplane workers (cpu, afpacket, afxdp, dpdk, gpu CUDA/BAR1 P2P, doca BlueField, l7 io_uring/kTLS/QUIC, scenario, telco 4G/5G CUPS, defense VAE) with AF_XDP/custom_tcp auto-discovery and fallback boundaries.
---

# Samurai 10-Worker Hardware & Protocol Dataplane Skill

Always call `samurai_list_workers` first to verify which worker binaries exist on the host before launching hardware-specific runs.

## Complete 10-Worker Selection Matrix

| Worker (`--worker`) | Binary | Best For | Prerequisites / Notes |
| :--- | :--- | :--- | :--- |
| `cpu` | `samurai_cpu_worker` | Raw UDP/TCP packet synthesis, header spoofing, amplification testing | Requires `CAP_NET_RAW` / `sudo` for raw sockets |
| `afpacket` | `samurai_afpacket_worker` | High-rate Linux `TPACKET_V3` mmap TX rings on commodity NICs | Requires `CAP_NET_RAW` / `CAP_NET_ADMIN` |
| `afxdp` | `samurai_afxdp_worker` | Linux XSK / UMEM zero-copy/SKB-copy Mpps & custom userspace TCP | Needs XDP interface; MCP auto-discovers route/MAC env (`auto_custom_tcp_env`) |
| `dpdk` | `samurai_dpdk_worker` | Bare-metal PMD hardware rings & hugepages for 40G/100G line-rate | Hugepages + DPDK-bound NIC (`libdpdk`) |
| `gpu` | `samurai_gpu_worker` | NVIDIA CUDA persistent kernel (`gpu_persistent`), GeForce BAR1 P2P DMA (`gpu_bar1_p2p`), QUIC batch crypto | NVIDIA GPU + CUDA 12.x host build |
| `doca` | `samurai_doca_worker` | NVIDIA BlueField DPU & DOCA GPUNetIO VRAM streaming | BlueField DPU + DOCA SDK host build |
| `l7` | `samurai_l7_worker` | Stateful HTTP/1.1, HTTP/2 (`nghttp2` + `io_uring`/kTLS), QUIC/HTTP-3 (`ngtcp2`), DNS | Works unprivileged via kernel sockets |
| `scenario` | `samurai_scenario_worker` | Multi-step HTTP/1.1/H2/QUIC persona journeys, JWT/cookie capture, L4 TCP flows, SLA gates | Driven via `samurai_scenario_compile` / `samurai_scenario_run` |
| `telco` | `samurai_telco_worker` | 4G/5G CUPS: GTP-U (5G `qfi`), PFCP, SCTP, Diameter Ro/Gx, SIP/RTP/`enable_srtp`, QinQ | Profiles: `telco-sctp-flood`, `telco-diameter-billing`, `telco-sip-storm`, `telco-full-carrier` |
| `defense` | `samurai_defense_worker` | Variational Autoencoder (VAE) anomaly scoring & defense verification | Evaluates anomaly resilience under load |

## AF_XDP / `custom_tcp` Wire Configuration

When running `worker: "afxdp"` or an L7/Scenario profile with `transport: "custom_tcp"` (or `"dpdk_direct"`):
- MCP defaults `auto_custom_tcp_env: true`, resolving the Linux egress interface, source IP, source MAC, and gateway/destination ARP MAC automatically, defaulting to `custom_tcp_wire: "af_xdp"` with `xdp_mode: "skb"` (copy mode, `XDP_COPY`, compatible with virtual/veth/Docker NICs without native XDP drivers).
- Override explicitly when needed via `custom_tcp_wire` (`af_xdp` | `af_packet` | `dpdk` | `in_memory`), `xdp_mode` (`skb` | `copy` | `native` | `zerocopy` | `offload`), `custom_tcp_iface`, `custom_tcp_src_ip`, `custom_tcp_dst_mac`, `custom_tcp_src_mac`, and `xdp_queue_id`.

## DPDK Fallback & Enterprise Soak Rules

- **Explicit fallback behavior (never silent):** In `scenario_worker`, requesting `dpdk` / `dpdk_direct` on a binary built without DPDK (or when EAL/port init fails) explicitly rewrites transport to `kernel_socket` and reports `scenario_backend` with `kernel_socket(dpdk_not_built)` or `kernel_socket(dpdk_open_failed)`.
- **Target Authorization:** Internal loopback / RFC 1918 / link-local / CGNAT targets work fail-closed out of the box; external enterprise IPv4s, CIDRs, or domains require explicit `allow_target` / `allow_targets` (or `SAMURAI_MCP_ALLOW_TARGETS`), with `SAMURAI_MCP_DENY_TARGETS` always enforced first.
- **Enterprise Soak:** `samurai_run_benchmark` accepts `duration_s` (up to `86400s`) and `async: true` across workers (`telco` maps to `--telco-duration-ms`, `scenario` uses `SAMURAI_SCENARIO_DURATION_S`, and other dataplane workers iterate bounded rounds and aggregate `soak_summary`).

## Telco 4G/5G CUPS Protocol Examples (`worker: "telco"`)

When using `samurai_run_benchmark` with `worker: "telco"`:
- **5G GTP-U User Plane (`protocol: "gtpu"`):** Pass `port: 2152`, `telco_qfi` (`1–63`), `telco_teid_base`, `telco_pool_profile` (`"linear"` | `"regional-bng"` | `"national-cgnat"`), and `duration_s` (maps to `telco_duration_ms`).
- **5G Control / Signalling (`pfcp`, `sctp`, `diameter`):** Use `protocol: "pfcp"` (`port: 8805`), `protocol: "sctp"` (`profile: "telco-sctp-flood"`), or `protocol: "diameter"` (`port: 3868`, `profile: "telco-diameter-billing"`).
- **IMS / VoIP Media (`sip-rtp`):** Use `protocol: "sip-rtp"` (`port: 5060`, `profile: "telco-sip-storm"`) with `enable_srtp: true` for encrypted RTP media testing.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `transport` shows `kernel_socket(dpdk_not_built)` | Binary compiled without `SAMURAI_WITH_DPDK` or EAL init failed | Rebuild with DPDK enabled + configure hugepages, or intentionally run `kernel_socket` / `af_xdp` SKB mode. |
| `custom_tcp_iface` / ARP lookup fails | Route or ARP neighbor not yet resolved | Ping/probe target once first or supply `custom_tcp_iface`, `custom_tcp_src_ip`, `custom_tcp_src_mac`, `custom_tcp_dst_mac`. |
| Telco run rejects `count: 0` on non-telco worker | Only `telco` timed mode (`telco_duration_ms > 0`) permits `count: 0` | Pass `duration_s` (auto-sets valid `count`) or positive `count`. |
| `cpu` / `afpacket` permission denied | Missing raw socket privileges | Grant `CAP_NET_RAW`/`CAP_NET_ADMIN` or use unprivileged `l7` / `scenario` workers. |
