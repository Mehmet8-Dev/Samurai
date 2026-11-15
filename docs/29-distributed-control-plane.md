# 29 - Distributed Control Plane & Shard Orchestration

This document details the architecture, wire protocols, and operational workflows of the native C++ Master/Slave distributed control plane (`samurai/control/`).

![Samurai Distributed Security & Control Plane](assets/diagrams/samurai_distributed_security.svg)

---

## 1. Subsystem Component Map (`samurai/control/`)

- **Master Daemon:** `daemon/master_main.cpp` (`samurai_master`)
- **Slave Daemon:** `daemon/slave_main.cpp` (`samurai_slave`)
- **Transport Server:** `control_server.cpp` (ZMQ ROUTER socket on `:5099`)
- **Transport Client:** `control_client.cpp` (ZMQ DEALER socket with auto-reconnect)
- **Cluster Servicer:** `servicer.cpp` (Worker registration, heartbeat tracking, and shard status)
- **Workload Sharder:** `shard.cpp` (Capacity-aware packet partitioning)
- **Slave Worker Service:** `worker_shard_service.cpp` (Inbound RPC executor)
- **Master Coordinator:** `master_coordinator.cpp` (High-level job orchestration)
- **High-Availability (HA):** `ha.cpp` (`StaticLeaderElector`, `FileLeaseLeaderElector`)
- **HTTP Management REST API:** `management_api.cpp` (Embedded POSIX HTTP server)
- **Authentication & RBAC:** `control_auth.cpp`, `jwt.cpp`, `auth.cpp`
- **Audit Logging:** `audit_log.cpp` (Tamper-evident SHA-256 hash-chained ledger)
- **Multi-Master Federation:** `multimaster.cpp` (Cross-region coordinator)
- **Autoscale Engine:** `autoscale.cpp` (`AutoscaleController` dynamically calculating worker replica targets)

---

## 2. Master Daemon Lifecycle (`samurai_master`)

1. **HA Leadership Acquisition:** Queries cluster leadership lease status (`ha.cpp`). The active leader maintains lease renewals.
2. **RPC Listener Startup:** Binds the `ControlServer` to `0.0.0.0:5099` (CurveZMQ Z85 encrypted).
3. **Management API & Metrics:** Spawns the HTTP server on port `:8089` and Prometheus exporter on `:9100`.
4. **Worker Discovery & Registration:** Discovers registered slaves (`RegisterWorker`), auditing hardware capabilities (CPU cores, AF_XDP interfaces, CUDA GPUs).
5. **Shard Dispatch:** Splits target packet counts into discrete work units and issues asynchronous `StartShard` RPCs to slaves.
6. **Telemetry Aggregation:** Polls shard progress every 2 seconds, maintaining real-time throughput metrics and auditing execution.

---

## 3. Slave Daemon Lifecycle (`samurai_slave`)

1. **RPC Client Connection:** Connects to the master's endpoint via a ZMQ DEALER socket (`tcp://<MASTER_IP>:5099`).
2. **Capability Registration:** Announces local node resources (worker kinds, CPU topologies, acceleration hardware) to the cluster coordinator.
3. **Heartbeat Loop:** Sends periodic 1-second heartbeat frames to maintain cluster membership.
4. **Shard Execution:** Upon receiving `StartShard`, triggers [`SupervisorShardRunner`](file://samurai/control/daemon/supervisor_shard_runner.cpp) to spawn local native worker processes via ZMQ IPC.
5. **Clean Teardown:** Finalizes local jobs upon `StopShard` or `AbortJob` RPC commands, returning serialized execution summaries.
