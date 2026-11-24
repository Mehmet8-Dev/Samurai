# 11 - Docker & Containerized Distributed Architecture

Samurai can be deployed and scaled across containerized environments using lightweight multi-stage Docker images.

---

## 1. Distributed Multi-Node Cluster via Docker Compose

The [`docker-compose.distributed.yml`](file://docker-compose.distributed.yml) configuration orchestrates the Master daemon, HA Follower, Redis state coordinator, and dynamic Slave workers:

```bash
# Launch cluster with 4 parallel Slave workers
docker compose -f docker-compose.distributed.yml up --build --scale slave=4
```

---

## 2. Building Host-Native Images

```bash
# Defaults to SAMURAI_NATIVE_ARCH=ON (optimizes for this host CPU/GPU/DPDK)
docker build -f Dockerfile -t samurai:local .

# Portable multi-host build (CI / registry distribution)
docker build -f Dockerfile --build-arg SAMURAI_NATIVE_ARCH=OFF -t samurai:portable .
```

---

## 3. Container Security Capabilities for Kernel-Bypass

High-performance networking modules (AF_XDP, raw sockets, DPDK PMD) require specific Linux capabilities within container manifests:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
  - SYS_NICE
```

---

## 4. macOS & Windows (Docker Desktop) Networking Notes

On Linux, `--network host` lets the container talk directly to `127.0.0.1` services on the host. On **Docker Desktop (macOS & Windows)**, containers run inside a lightweight Linux VM, so `127.0.0.1` refers to the VM rather than your laptop host:

- Use `--add-host host.docker.internal:host-gateway` and target `host.docker.internal` (or publish the Management API with `-p 8089:8089`).
- When using `samurai_mcp setup --docker`, non-Linux builds automatically configure `--add-host host.docker.internal:host-gateway` instead of `--network host`.
- **MCP Target Alias (`host.docker.internal`):** All target-facing MCP tools (`samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window`, `samurai_cluster_run_job`, `samurai_cluster_discover`) accept `"host.docker.internal"` directly, resolve it to an IPv4 address via `getaddrinfo`, and validate the resolved IPv4 fail-closed against `ValidateTargetSafety` (`allow_public=false`).
- **Bundled Mahoraga RL Weights & Distributed Scenarios:** The Docker runtime image packages canonical Mahoraga SRLP weights under `/usr/local/share/samurai/rl/` (e.g. `mahoraga-rl2.srlp`, `mahoraga-waf.srlp`), auto-discovered by `samurai_master` and `samurai_mcp` (`--cl-strategy rl` / `policy_path`). Distributed `samurai_cluster_run_job` and `samurai_master` (`--l7-profile-file` / `--l7-profile-json`) also serialize inline Scenario JSON directly across ZMQ master -> slave shards so containerized workers never depend on host-local file mounts.
