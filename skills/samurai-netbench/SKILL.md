---
name: samurai-netbench
description: Run reproducible, safety-gated network stress tests, 1M-flow userspace TCP benchmarks, HTTP/1.1-HTTP/2-HTTP/3 L7 profiling, RFC 2544/3511/8219 compliance checks, Scenario Engine workflows, Closed-Loop RL Autopilot, and distributed multi-worker orchestration via Samurai's native C++17 MCP server.
---

# Samurai Full-Platform Orchestration & Live Target Testing Skill

Use this master skill as the entry point for Samurai MCP (`samurai_mcp`, **22 native C++17 tools** + **5 skill resources**). Samurai MCP executes **real live traffic against authorized target servers** using all 10 compiled dataplane workers (not mocks) alongside two reproducible internal benchmarks (`samurai_bench_tcp_flows`, `samurai_bench_l7_userspace`).

Read the specialized skill resources via MCP (`resources/read`) when working on specific domains:
- `samurai://skills/samurai-cluster-orchestrator` — Discovery, node provisioning, multi-worker sharding, autoscaling, `samurai_cluster_run_job` distributed execution, and live shard coordination
- `samurai://skills/samurai-autopilot-rl` — Closed-Loop AIMD/BinSearch/Mahoraga RL + SRLP policies + `LeverShield`
- `samurai://skills/samurai-scenario-author` — Multi-step persona JSON scenarios & SLA verification
- `samurai://skills/samurai-hardware-dataplane` — All 10 dataplane workers (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`), TLS/HTTP2/QUIC, 4G/5G CUPS, GPU BAR1 P2P, and IPFIX export

## Core Methodology (Real Targets, Safety & Boundaries)

1. **Discover capabilities first:** Call `samurai_list_workers` (local host) and `samurai_cluster_discover` (distributed cluster) before running tests.
2. **Respect fail-closed target authorization:** Default scope covers loopback (`127.0.0.0/8`), RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), link-local, and CGNAT (`100.64/10`). Additional explicitly authorized lab IPs/CIDRs must be configured via `SAMURAI_MCP_ALLOW_TARGETS`.
3. **Use the full live control surface:**
   - Single-node real target testing: `samurai_run_benchmark` supports all 10 workers plus L7/TLS (`scheme`, `host_header`, `max_connections`, `max_streams`, `verify_tls`), 4G/5G Telco (`telco_subscribers`, `telco_cps`, `teid_start/count`, `qfi`, `sctp_rate`, `diameter_rate`, `sip_rate`, `enable_srtp`), GPU (`gpu_bar1_p2p`, `gpu_persistent`), live IPFIX/NetFlow (`ipfix_enabled`), and KPI gates.
   - Multi-node real target testing: `samurai_cluster_run_job` dispatches distributed workloads across `expect_workers` connected `samurai_slave` nodes (with optional distributed `--closed-loop` AIMD/BinSearch/Mahoraga RL).
4. **State measurement boundaries explicitly:** Always distinguish between:
   - **Real target-server tests** (`samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window`, `samurai_cluster_run_job`, `samurai_run_rfc_suite` with `live_dataplane: true`) — live network traffic against an authorized SUT.
   - **In-memory dataplane self-benchmarks** (`samurai_bench_tcp_flows`, `samurai_bench_l7_userspace`) — isolated C++ state-machine, memory, and shard scaling measurements without NIC limits.
5. **Report verifiable numbers + hardware context:** Include CPU/cores, kernel version, tool/command executed, target/worker used, throughput (CPS/RPS/PPS), P50/P95/P99 latency, RSS memory, and any errors or unverified gaps.
