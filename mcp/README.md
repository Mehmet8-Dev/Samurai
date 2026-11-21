# Samurai Native C++17 MCP Server (`samurai_mcp`)

A **100% native C++17, zero-Python, modular Model Context Protocol (MCP) server** (`protocolVersion: "2024-11-05"`) built directly into Samurai's CMake tree (`samurai/mcp/`).

Links directly against `samurai_core` (native JSON + `ValidateTargetSafety`) and `samurai_control` (native `ClosedLoopController`, **Mahoraga `RlPolicy`** SRLP MLP & RL² GRU recurrent inference, `LeverShield`, and `RlExploreConfig`), allowing both **AI coding agents** (Claude Code, Cursor, Codex, Antigravity) and **autonomous Autopilot / RL agents** to drive Samurai over stdio JSON-RPC 2.0.

---

## Modular C++17 Architecture (`samurai/mcp/`)

| Module | Responsibility |
| :--- | :--- |
| [`samurai/mcp/protocol.hpp`](../samurai/mcp/protocol.hpp) / `.cpp` | JSON-RPC 2.0 & MCP `2024-11-05` framing, `initialize`, `ping`, `tools/list`, `tools/call`, stdio stream loop |
| [`samurai/mcp/safety.hpp`](../samurai/mcp/safety.hpp) / `.cpp` | Fail-closed target safety gate wrapping `samurai::core::ValidateTargetSafety` (`allow_public` hard-locked to `false`) |
| [`samurai/mcp/runtime_tools.hpp`](../samurai/mcp/runtime_tools.hpp) / `.cpp` | Shell-free POSIX `fork/execv/poll` runner, binary auto-discovery, pure POSIX HTTP client (`:8089`), benchmark & RFC tools |
| [`samurai/mcp/autopilot_tools.hpp`](../samurai/mcp/autopilot_tools.hpp) / `.cpp` | Stateful Closed-Loop Autopilot & Mahoraga RL Agent session manager (`AIMD` / `BinSearch` / `kRl` + `RlPolicy` + `LeverShield` + `RlExploreConfig`) |
| [`samurai/mcp/scenario_tools.hpp`](../samurai/mcp/scenario_tools.hpp) / `.cpp` | Native Scenario Engine compiler, multi-worker session scheduler, SLA evaluator (`samurai_scenario`), and fail-closed live runner (`samurai_scenario_worker`) |
| [`samurai/mcp/tool_registry.hpp`](../samurai/mcp/tool_registry.hpp) / `.cpp` | Tool registration and JSON Schema definitions for all 15 native tools |
| [`samurai/mcp/main.cpp`](../samurai/mcp/main.cpp) | Thin `samurai_mcp` binary entrypoint |
| [`samurai/mcp/test_samurai_mcp.cpp`](../samurai/mcp/test_samurai_mcp.cpp) | Native C++17 verification suite (`test_samurai_mcp`) |

---

## Quick Setup (Zero Python, Zero Dependencies)

### Option A — Local CMake Build
```bash
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)" --target samurai_mcp samurai

# Register in Claude Code:
claude mcp add samurai -- /path/to/Samurai/build/mcp/samurai_mcp
```

### Option B — Pre-Built GHCR Container (Zero Build)
```bash
claude mcp add samurai -- docker run -i --rm --network host ghcr.io/mehmet8-dev/samurai:latest samurai_mcp
```

### Cursor (`.cursor/mcp.json`) / Codex / Antigravity
```json
{
  "mcpServers": {
    "samurai": {
      "command": "/path/to/Samurai/build/mcp/samurai_mcp"
    }
  }
}
```

---

## All 15 Native MCP Tools

### Dataplane, Benchmarks & Cluster Tools
| Tool | Purpose |
| :--- | :--- |
| `samurai_list_workers` | Discovers compiled C++17 workers (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`), daemons, and benchmarks |
| `samurai_list_profiles` | Lists built-in L4, L7, and 4G/5G carrier-telecom profiles |
| `samurai_run_benchmark` | Runs a bounded, fail-closed benchmark via `samurai` and returns parsed JSON telemetry + KPI gate status |
| `samurai_run_rfc_suite` | Runs RFC 2544 / 3511 / 8219 compliance benchmarks and returns a Markdown report |
| `samurai_bench_tcp_flows` | Reproduces the 100k quick check or 1M active TCP flows (`605 B/flow`) scaling benchmark |
| `samurai_bench_l7_userspace` | Runs the Shared-Nothing HTTP/1.1 & HTTP/2 userspace benchmark (`CPS`, `RPS`, `P50/P95/P99`, `VmRSS`) |
| `samurai_cluster_status` | Queries `samurai_master` `:8089` (`/healthz`, `/v1/state`) over pure POSIX sockets |

### Closed-Loop Autopilot & Mahoraga RL Agent Tools
| Tool | Purpose |
| :--- | :--- |
| `samurai_autopilot_create` | Creates a stateful closed-loop session (`aimd`, `binsearch`, or `rl`) with SLO thresholds, optional native SRLP `policy_path` (MLP or RL² GRU), `LeverShield`, and `RlExploreConfig` |
| `samurai_autopilot_step` | Feeds one measured `LoadSample` + Mahoraga defense ratios (or an external RL agent's `rl_action_rps` / `rl_levers`) into `RlPolicy` + `LeverShield` + `ClosedLoopController::Step()` and returns the safety-shielded 7-D action (`rps`, `concurrency`, `request_mix`, `source_rotation`, `pacing_mode`, `auth_mode`, `evasion_tactic`) |
| `samurai_autopilot_run_window` | Executes one live safety-gated dataplane window at the session's current `setpoint_rps`, folds its JSON telemetry into a `LoadSample`, and returns both live metrics and the next shielded decision |
| `samurai_autopilot_status` | Inspects active sessions, setpoints, `best_good_rps`, `ban_pressure` EWMA, and `LeverShield` memory |
| `samurai_autopilot_reset` | Resets episode state (controller, RL² GRU hidden context, `LeverShield`) or deletes a session |

### Multi-Step Persona Scenario Engine Tools
| Tool | Purpose |
| :--- | :--- |
| `samurai_scenario_compile` | Parses, validates, and compiles inline or file-based Scenario JSON specs (personas, flows, steps, token capture, think-time, L4/L7 actions) in-process via `samurai_scenario` |
| `samurai_scenario_run` | Validates in-process and runs a live fail-closed multi-step persona scenario (HTTP/1.1, HTTP/2, QUIC/H3) via `samurai_scenario_worker` against a loopback/RFC1918 lab target |
| `samurai_scenario_evaluate_sla` | Evaluates any Scenario SLA contract (`min_completion_rate`, `max_step_fail_ratio`, `max_latency_p95_ms`, TCP connect/retransmit ratios) in-process via `evaluate_sla_native()` |

---

## Fail-Closed Safety Policy

1. **Private/Loopback Only by Default:** All target IPs pass through native `samurai::core::ValidateTargetSafety(..., allow_public=false)`.
2. **No Shell Execution:** Subprocesses use direct POSIX `fork()` + `execv()` with `poll()` deadlines — zero `/bin/sh` injection surface.
3. **RL Safety Shield Always Enforced:** Even when an SRLP policy or external RL agent proposes an aggressive jump or ignores 429/503 pushback, `ClosedLoopController::StepRl` enforces `rl_max_jump_factor` and forced multiplicative backoff on SLO violations, while `LeverShield` automatically substitutes WAF path-blocked variants.
