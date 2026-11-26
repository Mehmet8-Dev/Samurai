---
name: samurai-netbench
description: Run reproducible, safety-gated network stress tests, 1M-flow userspace TCP benchmarks, HTTP/1.1-HTTP/2-HTTP/3 L7 profiling, RFC 2544/3511/8219 compliance checks, Scenario Engine workflows, Closed-Loop RL Autopilot, and distributed multi-worker orchestration via Samurai's native C++17 MCP server.
---

# Samurai Full-Platform Orchestration & Live Target Testing Skill

Use this master skill as the entry point for Samurai MCP (`samurai_mcp`, **25 native C++17 tools** + **5 skill resources & prompts**). Samurai MCP executes **real live traffic against authorized target servers** using all 10 compiled dataplane workers alongside reproducible internal benchmarks (`samurai_bench_tcp_flows`, `samurai_bench_l7_userspace`), fail-closed API/Docker discovery (`samurai_discover_apis`), and long-running background soak management (`samurai_job_status`, `samurai_job_stop`).

Read the specialized skill resources via MCP (`resources/read`) when working on specific domains:
- `samurai://skills/samurai-scenario-author` — Multi-step HTTP/L4-TCP scenarios, JWT/cookie binding, `expected_status` assertions, `duration_s` soak, and SLA gates
- `samurai://skills/samurai-autopilot-rl` — Closed-Loop AIMD/BinSearch/Mahoraga RL + SRLP policies + `LeverShield` (`window_s` 0.2–3600s)
- `samurai://skills/samurai-cluster-orchestrator` — Cluster discovery, local mesh, node provisioning, multi-worker sharding, autoscaling, `samurai_cluster_run_job`, and live shard coordination
- `samurai://skills/samurai-hardware-dataplane` — All 10 dataplane workers (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`), `custom_tcp`/AF_XDP auto-env, 4G/5G CUPS, GPU BAR1 P2P, and IPFIX export

## Tool Selection Decision Matrix

1. **Unknown target / Docker network / REST API surface:** Start with `samurai_discover_apis` (scans Docker socket/ports, probes HTTP routes, extracts OpenAPI schemas, synthesizes starter scenarios).
2. **Host capability check:** Call `samurai_list_workers` and `samurai_list_profiles` before selecting specialized hardware/telco backends.
3. **Stateful user journeys, JWT/cookie auth, L4 TCP expect/send, status assertions:** Use `samurai_scenario_compile` -> `samurai_scenario_run` -> `samurai_scenario_evaluate_sla`.
4. **High-rate L4/L7/Telco/GPU dataplane stress tests:** Use `samurai_run_benchmark` (supports `duration_s` and `async: true`).
5. **Sustainable RPS ceiling / adaptive SLO search:** Use `samurai_autopilot_create` -> `samurai_autopilot_run_window` (or `samurai_autopilot_step`).
6. **RFC compliance reports:** Call `samurai_run_rfc_suite` with `live_dataplane: true` (`rfc2544`, `rfc3511`, `rfc8219`, or `all`).
7. **Multi-worker distributed execution:** Call `samurai_cluster_local_mesh` or `samurai_cluster_discover` -> `samurai_cluster_plan_shards` -> `samurai_cluster_run_job`.

## Fail-Closed Target Authorization & Enterprise Controls

- **Default fail-closed scope:** Without explicit authorization, only loopback (`127.0.0.0/8`), RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`), CGNAT (`100.64/10`), and `host.docker.internal` are permitted.
- **Per-call external/enterprise authorization (`allow_target` / `allow_targets`):** Pass `allow_target` (single IPv4, CIDR like `203.0.113.0/24`, or hostname/`*.domain`) or `allow_targets` (array) directly on target-facing tool calls (`samurai_run_benchmark`, `samurai_scenario_run`, `samurai_run_rfc_suite`, `samurai_discover_apis`, `samurai_autopilot_run_window`, `samurai_cluster_*`). Hostnames are DNS-resolved only when matched in the allowlist.
- **Hard security guardrails:** Wildcards (`*`, `*.*`, `all`, `any`, `0.0.0.0/0`) are always rejected. `SAMURAI_MCP_DENY_TARGETS` always overrides per-call `allow_target` and `SAMURAI_MCP_ALLOW_TARGETS` (including post-DNS resolved IPv4s).
- **Enterprise soak limits:** Default limits allow `count` up to `100,000,000` (`SAMURAI_MCP_MAX_COUNT=0` unlocks up to uint32 wire limit `4294967295`) and `timeout_s` up to `86400s` (24h, configurable up to 7 days via `SAMURAI_MCP_MAX_TIMEOUT_S`).

## Enterprise Soak & Async Execution Workflow

For runs lasting more than ~15–30 seconds:
1. Pass `duration_s` (e.g., `duration_s: 600`) and `async: true` on `samurai_scenario_run` or `samurai_run_benchmark` (`timeout_s` auto-sizes above `duration_s` unless overridden).
2. Capture the returned `job_id` immediately (`status: "running"`).
3. Poll progress or retrieve final `report` / `scenario_telemetry` / `soak_summary` via `samurai_job_status` (`job_id` optional to list all jobs).
4. Abort cleanly at any time via `samurai_job_stop` (`job_id` required; sends `SIGTERM`/`SIGKILL` and returns final captured state).

## Measurement Boundaries & Evidence Rules

Always separate:
- **Real target-server tests:** `samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window`, `samurai_cluster_run_job`, `samurai_run_rfc_suite` (`live_dataplane: true`).
- **In-memory dataplane self-benchmarks:** `samurai_bench_tcp_flows` (`100k`/`1m`), `samurai_bench_l7_userspace` (`h1`/`h2`).
- Report exact tool name, target, worker/protocol, HTTP status breakdown (`status_2xx..5xx`), `expectation_failures`, RPS/PPS, P95/P99 latency, elapsed soak duration, and any failures honestly.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Target blocked by fail-closed MCP safety gate` | Public IP/hostname without authorization | Add `allow_target` or `allow_targets` matching target (and ensure it is not in `SAMURAI_MCP_DENY_TARGETS`). |
| `Wildcard allow_target ... is rejected` | Passed `*` or `0.0.0.0/0` | Specify exact IPv4, bounded CIDR (`>= /1`), or exact/subdomain host (`*.example.com`). |
| `errors: 0` despite HTTP `401`/`500` responses | No step expectation configured on HTTP request | Add `expected_status` / `expect_body_contains` and inspect `scenario_telemetry.status_4xx` / `status_5xx` / `status_codes`. |
| Soak call risks RPC timeout | Long `duration_s` run executed synchronously | Pass `async: true` and poll with `samurai_job_status`. |
