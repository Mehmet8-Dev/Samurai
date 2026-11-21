---
name: samurai-netbench
description: Run reproducible, safety-gated network stress tests, 1M-flow userspace TCP benchmarks, HTTP/1.1-HTTP/2-HTTP/3 L7 profiling, and RFC 2544/3511/8219 compliance checks using Samurai's native C++17 engine via MCP or CLI.
---

# Samurai Network Benchmarking & Resilience Skill

Use this skill whenever the user wants to measure, reproduce, or diagnose L4/L7/Telco network performance, memory footprint, tail latency (P99), or RFC compliance on authorized local/lab infrastructure.

## Core Methodology (Evidence & Boundaries First)

1. **Discover capabilities first:** Call `samurai_list_workers` before running tests so you know which native engines (`cpu`, `afxdp`, `dpdk`, `gpu`, `l7`, `telco`) and benchmark binaries exist on the host.
2. **Respect fail-closed target safety:** Never target public IPs. Stick to `127.0.0.1`, RFC 1918, RFC 6598, or RFC 2544 lab subnets.
3. **State measurement boundaries explicitly:** Always distinguish between:
   - **In-memory dataplane benchmarks** (`samurai_bench_tcp_flows`, `samurai_bench_l7_userspace`) — measures C++ state machines, memory layout, checksums, and shard scaling without NIC hardware limits.
   - **Kernel wire / localhost loopback tests** (`samurai_run_benchmark` against a local listener or `netns+veth`) — exercises real kernel sockets and OS scheduler overhead.
   - **Kernel-bypass / hardware NIC tests** (`afxdp`, `dpdk`, `gpu`, `doca`) — requires physical NIC/GPU configuration.
4. **Report verifiable numbers + hardware context:** Always include CPU model/core count, kernel version, command executed, throughput (CPS/RPS/PPS), P50/P95/P99 latency, RSS memory, and any errors or unverified gaps.

## Common Workflows

- **Reproduce 1M TCP Flows (605 B/flow):** Call `samurai_bench_tcp_flows` with `scale="100k"` for a 0.1s sanity check or `scale="1m"` for the full multi-core scaling run.
- **Profile Local Web Service (L7):** Call `samurai_run_benchmark` with `worker="l7"`, `target="127.0.0.1"`, `port=<PORT>`, `l7_protocol="http2"`, `concurrency=4`, `keepalive=true`, `kpi_max_errors=0`.
- **RFC Compliance Gate:** Call `samurai_run_rfc_suite` with `suite="all"` to generate an RFC 2544 / 3511 / 8219 report.
- **Multi-Step Persona Scenario Testing:** Author a Scenario JSON (`personas`, `flows`, `steps`, `load_model`, `sla`), validate/compile it in-process with `samurai_scenario_compile`, execute live against a local/lab target with `samurai_scenario_run`, and verify SLA thresholds with `samurai_scenario_evaluate_sla`.
- **Closed-Loop Autopilot / RL Capacity Search:** Call `samurai_autopilot_create` (`strategy="binsearch"` or `"rl"`, with SLO thresholds and optional SRLP `policy_path`), then iterate `samurai_autopilot_run_window` (live lab SUT) or `samurai_autopilot_step` (external RL agent loop) while the native SLO jump-cap & `LeverShield` enforce safety bounds.
- **Inspect Distributed Cluster:** Call `samurai_cluster_status` against `127.0.0.1:8089`.
