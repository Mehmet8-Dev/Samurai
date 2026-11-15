# 02 - Orchestrator & Native Supervisor Engine

The Native Orchestrator layer (`samurai/orchestrator/`) acts as the high-speed bridge translating job configurations (`JobOptions`) from the Master daemon, Slave daemon, or local CLI into asynchronous ZeroMQ IPC messages, managing the complete lifecycle of native worker daemons (`samurai_*_worker`).

![Samurai CLI Execution & Worker Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

---

## 1. Core Architectural Responsibilities

1. **Worker Registry & Binary Mapping:**
   Using [`worker_registry.hpp`](file://samurai/orchestrator/worker_registry.hpp), incoming worker specifications (`cpu`, `afxdp`, `l7`, `gpu`, `dpdk`, etc.) map deterministically to compiled native executables:
   - `cpu` $\rightarrow$ `samurai_cpu_worker`
   - `afxdp` $\rightarrow$ `samurai_afxdp_worker`
   - `dpdk` $\rightarrow$ `samurai_dpdk_worker`
   - `gpu` $\rightarrow$ `samurai_gpu_worker`
   - `doca` $\rightarrow$ `samurai_doca_worker`
   - `l7` $\rightarrow$ `samurai_l7_worker`
   - `scenario` $\rightarrow$ `samurai_scenario_worker`
   - `defense` $\rightarrow$ `samurai_defense_worker`

2. **ZMQ Supervisor Lifecycle (`supervisor.cpp`):**
   - Creates dedicated Unix domain socket IPC endpoints (`ipc:///tmp/samurai_jobs_*` and `ipc:///tmp/samurai_events_*`) for process isolation.
   - Launches the worker daemon as an independent OS process using `fork()` and `execvp()`.
   - Sends a strict 56-byte binary wire header (`SamuraiWireHeaderV1`) with the `JobEnvelopeV1` payload (`START_JOB`).
   - Collects sub-second periodic `HEARTBEAT` (1s) and binary `METRIC_SNAPSHOT` (2s) telemetry frames.
   - Gracefully shuts down workers upon completion (`JOB_DONE`) or on abort (`STOP_JOB`).

---

## 2. Distributed Shard Coordination

When operating in cluster mode, `samurai_slave` receives `StartShard` RPC invocations from `samurai_master` and triggers the local Supervisor engine via [`SupervisorShardRunner`](file://samurai/control/daemon/supervisor_shard_runner.cpp). This architecture completely isolates cluster communication from the physical dataplane packet generation loops.
