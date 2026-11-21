---
name: samurai-cluster-orchestrator
description: Discover live Samurai distributed clusters, add new worker nodes, plan multi-worker sharding (equal/capability/region/5G telco CGNAT), compute autoscale replica counts, and coordinate live worker shards in real time via native C++17 MCP tools.
---

# Samurai Distributed Cluster Orchestrator Skill

Use this skill when coordinating multiple Samurai worker nodes across a local lab mesh or remote bare-metal/container cluster.

## Core Orchestration Workflow

1. **Discover Current Topology:**
   - Call `samurai_cluster_discover` (against `samurai_master` on `:8089`) with `include_events: true` and `include_metrics: true` to inspect `/healthz`, `/v1/cluster/summary`, `/v1/cluster/workers` (registered nodes, heartbeats, regions, capabilities), and `/v1/cluster/shards`.
   - For local multi-worker experiments without an external cluster, call `samurai_cluster_local_mesh` with `action: "start"`, `slaves: 2`, `worker_kind: "bundle"` to launch a loopback-only (`127.0.0.1`) `samurai_master` + N `samurai_slave` mesh.

2. **Plan Sharding & Scaling Before Dispatch:**
   - Call `samurai_cluster_plan_shards` with discovered worker IDs and their `region`, `capacity_score`, `gpu_available`, and `xdp_available` metadata:
     - `mode: "packets"`, `strategy: "capability"` or `"region"` for L4/L7 traffic distribution.
     - `mode: "telco"`, `pool_profile: "regional-bng"` or `"national-cgnat"` for non-overlapping 4G/5G subscriber ranges and QinQ VLAN allocations.
   - Inspect `autoscale_recommendation` (`desired_replicas`, `recommended_next_step`) computed natively by `AutoscaleController`.

3. **Add Nodes & Scale Capacity:**
   - **Local lab mesh:** Call `samurai_cluster_local_mesh` with `action: "scale"`, `slaves: <desired>` to add or remove live `samurai_slave` processes dynamically.
   - **Remote private lab nodes:** Call `samurai_cluster_provision_node` with `node_hosts: "10.0.0.11,10.0.0.12"`, `worker_kind: "bundle"`, `worker_region: "eu-central"`. Every host IP is validated fail-closed (private/RFC1918/loopback only).

4. **Dispatch Distributed Multi-Worker Jobs & Coordinate Mid-Flight:**
   - Call `samurai_cluster_run_job` to execute a real distributed multi-worker test via `samurai_master` across `expect_workers` connected `samurai_slave` nodes (supports all 10 workers, `shard_strategy`, 4G/5G `telco_pool_profile`, live `ipfix_enabled`, and distributed `--closed-loop` AIMD/BinSearch/Mahoraga RL with `cl_live_reconfigure`, `cl_lever_shield`, `cl_online_adapt`, and `cl_novelty`).
   - Call `samurai_cluster_reconfigure` to update `target_rps`, `concurrency`, `request_mix`, `source_rotation`, or `pacing_mode` across active shards without restarting workers.
   - If SLO degradation or unexpected target saturation occurs, immediately call `samurai_cluster_abort` (`POST /v1/jobs/abort`) and tear down any local mesh with `samurai_cluster_local_mesh` (`action: "stop"`).
