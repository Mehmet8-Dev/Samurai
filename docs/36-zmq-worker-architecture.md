# 36 - ZMQ Worker Architecture & IPC Wire Protocol

This document outlines the ZeroMQ (ZMQ) inter-process communication (IPC) and cluster wire protocol governing all native worker processes in Samurai.

![Samurai ZMQ Worker & IPC Architecture](assets/diagrams/samurai_system_architecture.svg)

---

## 1. Architectural Boundaries

1. **Native Supervisor Layer (`samurai/orchestrator/supervisor.cpp`):**
   - Launched by CLI or Slave daemons.
   - Allocates dedicated Unix IPC sockets (`ipc:///tmp/samurai_jobs_*` and `ipc:///tmp/samurai_events_*`).
   - Dispatches `START_JOB`, `STOP_JOB`, and `SHUTDOWN` control frames.

2. **Heterogeneous Native Dataplane Workers (`samurai/zmq/daemon/`):**
   - `samurai_cpu_worker`
   - `samurai_afxdp_worker`
   - `samurai_dpdk_worker`
   - `samurai_gpu_worker`
   - `samurai_doca_worker`
   - `samurai_l7_worker`
   - `samurai_scenario_worker`
   - `samurai_defense_worker`

3. **Cluster Distributed Control Plane (`samurai/control/`):**
   - Operates between `samurai_master` (ZMQ ROUTER) and `samurai_slave` (ZMQ DEALER) over encrypted TCP channels (`tcp://<MASTER_IP>:5099`).

---

## 2. Common Worker Framework (`worker_common.hpp` & `zmq_worker_base.hpp`)

All native workers inherit standardized lifecycle methods to guarantee protocol uniformity:
- `SendFrame(...)`: Transmits fixed-width headers and variable payloads in atomic multipart frames.
- `BuildSnapshot(...)` / `SerializeSnapshot(...)`: Generates binary `MetricSnapshotV1` telemetry structs.
- `PacingFromEnvelope(...)`: Configures hardware TSC-based nanosecond pacing rate governors.
- `JsonError(...)`: Serializes failure states into structured JSON error payloads.

---

## 3. ZMQ Protocol Message Types (`MessageType`)

| Hex Code | Symbol | Flow Direction | Purpose |
|:---|:---|:---|:---|
| `0x01` | `START_JOB` | Supervisor $\rightarrow$ Worker | Launches test execution with `JobEnvelopeV1`. |
| `0x02` | `STOP_JOB` | Supervisor $\rightarrow$ Worker | Gracefully requests immediate job cessation. |
| `0x03` | `SHUTDOWN` | Supervisor $\rightarrow$ Worker | Terminates the background worker daemon process. |
| `0x10` | `ACK` | Worker $\rightarrow$ Supervisor | Confirms command receipt with correlation ID. |
| `0x20` | `HEARTBEAT` | Worker $\rightarrow$ Supervisor | Periodic 1-second liveness pulse. |
| `0x21` | `METRIC_SNAPSHOT`| Worker $\rightarrow$ Supervisor | Periodic 2-second binary telemetry metrics. |
| `0x30` | `JOB_DONE` | Worker $\rightarrow$ Supervisor | Emitted on completion with serialized JSON metrics summary. |
| `0xFF` | `ERROR` | Worker $\rightarrow$ Supervisor | Critical exception or hardware failure notification. |
