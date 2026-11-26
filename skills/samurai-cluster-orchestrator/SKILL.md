---
name: samurai-cluster-orchestrator
description: Discover live Samurai distributed clusters, spin up local loopback meshes, provision worker nodes, plan multi-worker sharding (equal/capability/region/5G telco CGNAT), compute autoscale replica counts, and coordinate distributed jobs in real time via native C++17 MCP tools.
---

# Samurai Distributed Cluster Orchestrator Skill

Use this skill when coordinating multiple Samurai worker nodes across a local loopback lab mesh or a distributed bare-metal/container cluster (`samurai_master` ZMQ control on `tcp://127.0.0.1:5099`, HTTP Management API on `:8089`).

## Core Orchestration Workflow

1. **Discover or Bootstrap Cluster:**
   - **Remote/Existing Master:** Call `samurai_cluster_discover` (or alias `samurai_cluster_status`) on `host` (`127.0.0.1` or `allow_target`-permitted host) and `port` (`8089`) with `include_events: true` and `include_metrics: true` to inspect `/healthz`, `/v1/cluster/summary`, `/v1/cluster/workers`, and `/v1/cluster/shards`.
   - **Local Multi-Worker Lab Mesh:** Call `samurai_cluster_local_mesh` with `action: "start"`, `slaves: 2`, `worker_kind: "bundle"` (`control_port: 5099`, `management_port: 8089`) to spin up a loopback-only `samurai_master` + N `samurai_slave` processes.
2. **Plan Sharding & Autoscale Capacity (`samurai_cluster_plan_shards`):**
   - Pass discovered worker metadata (`worker_id`, `region`, `capacity_score`, `gpu_available`, `xdp_available`):
     - `mode: "packets"`, `strategy: "equal"` | `"capability"` | `"region"`.
     - `mode: "telco"`, `pool_profile: "linear"` | `"regional-bng"` | `"national-cgnat"` for non-overlapping subscriber ranges and QinQ VLAN allocations.
   - Review `autoscale_recommendation` (`desired_replicas`, `recommended_next_step`) from native `AutoscaleController`.
3. **Add Nodes & Scale Capacity:**
   - **Local Mesh:** `samurai_cluster_local_mesh` with `action: "scale"`, `slaves: <desired>`.
   - **SSH Provisioning:** `samurai_cluster_provision_node` with `node_hosts: "10.0.0.11,10.0.0.12"`, `worker_kind: "bundle"`, `worker_region: "eu-central"`. Every host/node IP passes `ValidateMcpTarget` (private/loopback by default, or permitted via `allow_target`/`allow_targets`; `SAMURAI_MCP_DENY_TARGETS` always blocks).
4. **Dispatch & Reconfigure Distributed Jobs:**
   - Call `samurai_cluster_run_job` across `expect_workers` connected `samurai_slave` nodes (`control_listen` default `tcp://127.0.0.1:5099`, `timeout_s` 5–86400s, `count` up to `100M` or `SAMURAI_MCP_MAX_COUNT=0`).
   - Supports inline `scenario` / `scenario_file` distribution, 4G/5G `telco_pool_profile`, `ipfix_enabled`, `allow_target` / `allow_targets` for authorized external SUTs, and distributed `--closed-loop` (`aimd` | `binsearch` | `rl`) with `cl_live_reconfigure`, `cl_lever_shield`, `cl_online_adapt`, and `cl_novelty`.
   - Adjust live shards mid-flight via `samurai_cluster_reconfigure` (`target_rps`, `concurrency`, `request_mix`, `source_rotation`, `pacing_mode`).
   - Emergency stop via `samurai_cluster_abort` (`POST /v1/jobs/abort`), then `samurai_cluster_local_mesh` (`action: "stop"`).

## Auth & Safety Notes

- Management API write operations (`provision_node`, `reconfigure`, `abort`) read `auth_token` argument or `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` / `SAMURAI_MANAGEMENT_API_ADMIN_TOKEN`; read-only `discover` also accepts `SAMURAI_MANAGEMENT_API_VIEWER_TOKEN`.
- Wildcard `allow_target` (`*`, `0.0.0.0/0`) is always rejected.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `expect_workers` times out waiting for slaves | Control endpoint mismatch or slaves not started | Start mesh via `samurai_cluster_local_mesh` (`action: "start"`) or verify `--control-listen` matches slave master endpoint. |
| HTTP Management API returns `401`/`403` | Missing operator/viewer Bearer token | Pass `auth_token` or set `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` / `VIEWER_TOKEN`. |
| Provisioning/job rejects external IP | Missing per-call allowlist | Pass `allow_target` / `allow_targets` covering both master/node or target IP/CIDR. |
