---
name: samurai-netbench
description: Run reproducible, safety-gated network stress tests, 1M-flow userspace TCP benchmarks, HTTP/1.1-HTTP/2-HTTP/3 L7 profiling, RFC 2544/3511/8219 compliance checks, Scenario Engine workflows, Closed-Loop RL Autopilot, and distributed multi-worker orchestration via Samurai's native C++17 MCP server.
---

# Samurai Network Benchmarking & Orchestration Skill

Use this master skill as the entry point for Samurai MCP (`samurai_mcp`, 21 native C++17 tools + 5 skill resources). Read the specialized skill resources via MCP (`resources/read`) when working on specific domains:
- `samurai://skills/samurai-cluster-orchestrator` — Discovery, node provisioning, multi-worker sharding, autoscaling, live shard coordination
- `samurai://skills/samurai-autopilot-rl` — Closed-Loop AIMD/BinSearch/Mahoraga RL + SRLP policies + `LeverShield`
- `samurai://skills/samurai-scenario-author` — Multi-step persona JSON scenarios & SLA verification
- `samurai://skills/samurai-hardware-dataplane` — All 10 dataplane workers (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`)

## Core Methodology (Evidence & Boundaries First)

1. **Discover capabilities first:** Call `samurai_list_workers` (local host) and `samurai_cluster_discover` (distributed cluster) before running tests.
2. **Respect fail-closed target safety:** Never target public IPs. Stick to `127.0.0.1`, RFC 1918, RFC 6598, or RFC 2544 lab subnets.
3. **State measurement boundaries explicitly:** Always distinguish between:
   - **In-memory dataplane benchmarks** (`samurai_bench_tcp_flows`, `samurai_bench_l7_userspace`) — C++ state machines, memory layout, checksums, and shard scaling without NIC hardware limits.
   - **Kernel wire / localhost tests** (`samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window`) — real Linux sockets and OS scheduler overhead.
   - **Kernel-bypass / hardware NIC & GPU tests** (`afxdp`, `dpdk`, `gpu`, `doca`) — physical hardware configuration.
4. **Report verifiable numbers + hardware context:** Include CPU/cores, kernel version, tool/command executed, throughput (CPS/RPS/PPS), P50/P95/P99 latency, RSS memory, and any errors or unverified gaps.
