# Samurai Native C++17 MCP Server (`samurai_mcp`)

A **100% native C++17, zero-Python, modular Model Context Protocol (MCP) server** (`protocolVersion: "2024-11-05"`) built directly into Samurai's CMake tree (`samurai/mcp/`).

Links directly against `samurai_core` (native JSON + `ValidateTargetSafety`), `samurai_control` (`ClosedLoopController`, **Mahoraga `RlPolicy`** SRLP MLP & RL² GRU, `LeverShield`, `RlExploreConfig`, `SplitJobToShards`, `SplitTelcoSubscribers`, `AutoscaleController`), and `samurai_scenario` (`parse_spec`, `build_worker_session_plans_native`, `evaluate_sla_native`).

Exposes **22 native tools**, **5 MCP Skill Resources (`samurai://skills/...`)**, and **5 MCP Workflow Prompts** over stdio JSON-RPC 2.0 — enabling Claude Code, Cursor, Codex, Antigravity, and autonomous RL agents to execute live tests against authorized target servers across all 10 workers (L4, L7/TLS/H2/QUIC, GPU BAR1 P2P, 4G/5G Telco CUPS, IPFIX), discover/provision/scale cluster nodes, dispatch distributed multi-worker jobs, run Scenario Engine journeys, and drive Closed-Loop Autopilot runs.

---

## Modular C++17 Architecture (`samurai/mcp/`)

| Module | Responsibility |
| :--- | :--- |
| [`samurai/mcp/protocol.hpp`](../samurai/mcp/protocol.hpp) / `.cpp` | MCP `2024-11-05` JSON-RPC 2.0 engine (`tools/*`, `resources/*`, `prompts/*`, `initialize`, `ping`) |
| [`samurai/mcp/safety.hpp`](../samurai/mcp/safety.hpp) / `.cpp` | Fail-closed target safety gate wrapping `samurai::core::ValidateTargetSafety` (`allow_public=false`) |
| [`samurai/mcp/runtime_tools.hpp`](../samurai/mcp/runtime_tools.hpp) / `.cpp` | Shell-free POSIX `fork/execv/poll` runner, binary auto-discovery, benchmark & RFC compliance tools |
| [`samurai/mcp/cluster_tools.hpp`](../samurai/mcp/cluster_tools.hpp) / `.cpp` | Distributed cluster discovery, SSH node provisioning, live shard reconfiguration, abort, in-process sharding/autoscale planning, and loopback local multi-worker mesh manager |
| [`samurai/mcp/autopilot_tools.hpp`](../samurai/mcp/autopilot_tools.hpp) / `.cpp` | Closed-Loop Autopilot & Mahoraga RL session manager (`AIMD` / `BinSearch` / `kRl` + `RlPolicy` + `LeverShield` + `RlExploreConfig`) |
| [`samurai/mcp/scenario_tools.hpp`](../samurai/mcp/scenario_tools.hpp) / `.cpp` | Scenario Engine in-process compiler, weighted worker scheduler, SLA evaluator, and fail-closed live runner |
| [`samurai/mcp/tool_registry.hpp`](../samurai/mcp/tool_registry.hpp) / `.cpp` | Registration of all 22 tools, 5 skill resources, and 5 workflow prompts |
| [`samurai/mcp/setup_tools.hpp`](../samurai/mcp/setup_tools.hpp) / `.cpp` | Automated MCP client diagnostics (`doctor`) & registration (`setup`) across 10+ AI clients |
| [`samurai/mcp/test_samurai_mcp.cpp`](../samurai/mcp/test_samurai_mcp.cpp) | Native C++17 verification suite (`test_samurai_mcp`) |

---

## Quick Setup (1-Command `doctor` & `setup`)

### Automated Registration (`claude_code`, `cursor`, `codex`, `gemini_cli`, `antigravity`, `windsurf`, `vscode`, `opencode`, `copilot_cli`)

```bash
# 1. Inspect local binaries, host hardware acceleration, and MCP client status
npx -y samurai-net mcp doctor
# (or locally compiled: ./build/mcp/samurai_mcp doctor --client codex --json)

# 2. Preview proposed config changes (safe non-mutating dry-run)
npx -y samurai-net mcp setup --client cursor --dry-run

# 3. Apply registration to a single client or every detected IDE/CLI on Windows / macOS / Linux (creates .bak backup)
npx -y samurai-net mcp setup --client all --yes
npx -y samurai-net mcp setup --client antigravity --yes
npx -y samurai-net mcp setup --client vscode --yes
npx -y samurai-net mcp setup --client claude_desktop --yes

# Or register npx (`npx.cmd` on Windows), local Docker build, or GHCR source-runtime (`--ghcr`):
npx -y samurai-net mcp setup --client claude_code --npx --yes
npx -y samurai-net mcp setup --client claude_code --docker --yes
npx -y samurai-net mcp setup --client claude_code --docker --ghcr --yes
```

> **Windows & macOS (Docker Desktop) — Host-Local Compile Inside Docker & Path Resolution:**
> - **Host-local build (`--docker` or `--ghcr`):** Running `npx -y samurai-net mcp setup ... --yes` compiles C++ **for your local host CPU/GPU (`SAMURAI_NATIVE_ARCH=ON`)** — either via local `docker build` (`samurai:local-v3.3.3`) or with `--ghcr` by pulling the uncompiled `ghcr.io/mehmet8-dev/samurai:latest` source+toolchain image and compiling once into `-v samurai-build-cache:/var/cache/samurai` (pass `--no-build` to skip pre-warming). GitHub CI never pre-compiles binaries inside the GHCR image.
> - **Native Windows IDE/CLI paths:** `samurai-net mcp setup` runs directly on your Windows Node.js host so `%APPDATA%\Code\User\mcp.json`, `%APPDATA%\Claude\claude_desktop_config.json`, `%USERPROFILE%\.cursor\mcp.json`, `%USERPROFILE%\.claude.json`, `%USERPROFILE%\.codex\config.toml`, `%USERPROFILE%\.gemini\antigravity\mcp_config.json`, and `%USERPROFILE%\.codeium\windsurf\mcp_config.json` resolve without container path mismatches.
> - **Docker Desktop networking:** On non-Linux hosts, containers run inside a Linux VM so `--network host` cannot reach host `127.0.0.1`. `mcp setup` automatically emits `--add-host host.docker.internal:host-gateway` so MCP tools can target host services via `host.docker.internal` (or sibling containers on a shared Docker network).

### Manual Setup (Claude Code / Local Container)

### Local CMake Build
```bash
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release -DSAMURAI_NATIVE_ARCH=ON
cmake --build build -j"$(nproc)" --target samurai_mcp samurai samurai_master samurai_slave

claude mcp add samurai -- /path/to/Samurai/build/mcp/samurai_mcp
```

### Host-Native `npx` or Local Docker Container
```bash
# Compiles from source for your machine on first run
claude mcp add samurai -- npx -y -p samurai-net samurai-mcp

# Or using a locally built host-native Docker image (`docker build -t samurai:local .`)
claude mcp add samurai -- docker run -i --rm --network host samurai:local samurai_mcp
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

## All 22 Native MCP Tools

### Dataplane, Live Target Testing, Benchmarks & RFC Compliance (6 Tools)
| Tool | Purpose |
| :--- | :--- |
| `samurai_list_workers` | Discovers all 10 compiled C++17 workers (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`), daemons, and benchmarks |
| `samurai_list_profiles` | Lists built-in L4, L7, and 4G/5G carrier-telecom profiles |
| `samurai_run_benchmark` | Executes real live traffic against an authorized target server using any of the 10 workers (full L7/TLS/H2/QUIC, 4G/5G Telco CUPS/GTP-U/SCTP/Diameter/SIP-SRTP, GPU BAR1 P2P, IPFIX, and KPI gate controls) |
| `samurai_run_rfc_suite` | Runs RFC 2544 / 3511 / 8219 compliance benchmarks (analytical dry-run or `live_dataplane: true` against a target) |
| `samurai_bench_tcp_flows` | Reproduces the 100k quick check or 1M active TCP flows (`605 B/flow`) internal dataplane scaling benchmark |
| `samurai_bench_l7_userspace` | Runs the Shared-Nothing HTTP/1.1 & HTTP/2 internal userspace benchmark (`CPS`, `RPS`, `P50/P95/P99`, `VmRSS`) |

### Distributed Cluster Discovery, Provisioning, Multi-Worker Jobs & Coordination (8 Tools)
| Tool | Purpose |
| :--- | :--- |
| `samurai_cluster_discover` | Queries `samurai_master` `:8089` (`/healthz`, `/v1/cluster/summary`, `/v1/cluster/workers`, `/v1/cluster/shards`, `/v1/cluster/events`, `/metrics`) |
| `samurai_cluster_status` | Alias for `samurai_cluster_discover` |
| `samurai_cluster_provision_node` | Adds new private/RFC1918 worker nodes via `POST /v1/cluster/provision` (SSH/zero-install bootstrap) |
| `samurai_cluster_run_job` | Dispatches and executes a real distributed multi-worker test via `samurai_master` across connected `samurai_slave` nodes (all 10 workers, shard strategies, 4G/5G telco pools, IPFIX, and distributed Closed-Loop AIMD/BinSearch/Mahoraga RL) |
| `samurai_cluster_reconfigure` | Coordinates live worker shards mid-flight via `POST /v1/shards/reconfigure` (RPS, concurrency, Mahoraga levers) |
| `samurai_cluster_abort` | Emergency cluster-wide job abort via `POST /v1/jobs/abort` |
| `samurai_cluster_plan_shards` | In-process multi-worker sharding (`equal`/`capability`/`region` + 5G telco `regional-bng`/`national-cgnat`) & `AutoscaleController` replica planning |
| `samurai_cluster_local_mesh` | Spins up, dynamically scales (`add`/`remove` slave nodes), inspects, or stops a loopback-only (`127.0.0.1`) `samurai_master` + N `samurai_slave` lab cluster |

### Closed-Loop Autopilot & Mahoraga RL Agent (5 Tools)
| Tool | Purpose |
| :--- | :--- |
| `samurai_autopilot_create` | Creates an `aimd`, `binsearch`, or `rl` session with SLO thresholds, optional SRLP `policy_path` (MLP/RL² GRU), `LeverShield`, and `RlExploreConfig` |
| `samurai_autopilot_step` | Runs `RlPolicy::ProposeFor()` (or external RL proposal) + `LeverShield::Govern()` + `ClosedLoopController::Step()` and returns the shielded 7-D action |
| `samurai_autopilot_run_window` | Executes one live safety-gated dataplane window at `current_setpoint_rps`, parses JSON telemetry, and advances the controller |
| `samurai_autopilot_status` | Inspects active sessions, setpoints, `best_good_rps`, `ban_pressure`, and `LeverShield` memory |
| `samurai_autopilot_reset` | Resets episode state (`ResetContext` + `LeverShield::Reset`) or deletes a session |

### Multi-Step Persona Scenario Engine (3 Tools)
| Tool | Purpose |
| :--- | :--- |
| `samurai_scenario_compile` | Parses, validates, and compiles Scenario JSON specs in-process via `samurai_scenario` |
| `samurai_scenario_run` | Validates in-process and runs a live multi-step persona scenario via `samurai_scenario_worker` |
| `samurai_scenario_evaluate_sla` | Evaluates Scenario SLA contracts in-process via `evaluate_sla_native()` |

---

## Portable Agent Skills (Exposed via MCP `resources/*` & `prompts/*`)

All 5 skills are served automatically over MCP (`samurai://skills/<name>`) and stored under `skills/`:

| Skill URI | File | Scope |
| :--- | :--- | :--- |
| `samurai://skills/samurai-netbench` | [`skills/samurai-netbench/SKILL.md`](../skills/samurai-netbench/SKILL.md) | Master benchmarking, RFC compliance & evidence boundaries |
| `samurai://skills/samurai-cluster-orchestrator` | [`skills/samurai-cluster-orchestrator/SKILL.md`](../skills/samurai-cluster-orchestrator/SKILL.md) | Service/node discovery, provisioning, sharding, scaling & live shard coordination |
| `samurai://skills/samurai-autopilot-rl` | [`skills/samurai-autopilot-rl/SKILL.md`](../skills/samurai-autopilot-rl/SKILL.md) | Closed-Loop AIMD/BinSearch/Mahoraga RL, SRLP policies & `LeverShield` |
| `samurai://skills/samurai-scenario-author` | [`skills/samurai-scenario-author/SKILL.md`](../skills/samurai-scenario-author/SKILL.md) | Multi-step Web/Mobile persona scenarios, token capture & SLA checks |
| `samurai://skills/samurai-hardware-dataplane` | [`skills/samurai-hardware-dataplane/SKILL.md`](../skills/samurai-hardware-dataplane/SKILL.md) | Complete 10-worker catalog (`cpu`, `afpacket`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `telco`, `defense`) |
