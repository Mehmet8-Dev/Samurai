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

## 2. Host-Native Docker Images (Uncompiled GHCR Source Image or Local Build)

GitHub Releases publish `ghcr.io/mehmet8-dev/samurai:latest` as an **uncompiled source + toolchain image** (`--target source-runtime`): no pre-compiled C++ binaries are baked on GitHub Actions runners. On your first `docker run`, `/usr/local/bin/samurai-entrypoint.sh` compiles Samurai inside the container with `SAMURAI_NATIVE_ARCH=ON` for your host CPU/GPU and caches the binaries in `-v samurai-build-cache:/var/cache/samurai`:

```bash
# Option A: Use GHCR source image (compiles once on YOUR host on first run, cached across runs)
docker run --rm -v samurai-build-cache:/var/cache/samurai ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp

# Option B: Automatic 1-command host Docker build via npx (compiles samurai:local-v3.5.0 with SAMURAI_NATIVE_ARCH=ON)
npx -y samurai-net build --docker

# Option C: Build directly with Docker CLI (defaults to SAMURAI_NATIVE_ARCH=ON)
docker build -f Dockerfile -t samurai:local .

# Option D: Portable multi-host build (only if redistributing across heterogeneous CPUs in a private lab)
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
- When using `npx -y samurai-net mcp setup --client <id|all> --yes` (recommended on Windows/macOS), the Node.js host installer resolves Windows `%APPDATA%` / `%USERPROFILE%` config files directly on the host, builds the local `samurai:local-<ver>` image (`SAMURAI_NATIVE_ARCH=ON`), and automatically emits `--add-host host.docker.internal:host-gateway` instead of `--network host` (plus `npx.cmd` when `--npx` mode is chosen).
- Similarly, running the C++ binary directly with `samurai_mcp setup --docker --host-os windows` injects `--add-host host.docker.internal:host-gateway`.
- **MCP Target Alias (`host.docker.internal`):** All target-facing MCP tools (`samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window`, `samurai_cluster_run_job`, `samurai_cluster_discover`) accept `"host.docker.internal"` directly, resolve it to an IPv4 address via `getaddrinfo`, and validate the resolved IPv4 fail-closed against `ValidateTargetSafety` (`allow_public=false`).
- **Bundled Mahoraga RL Weights & Distributed Scenarios:** The Docker runtime image packages canonical Mahoraga SRLP weights under `/usr/local/share/samurai/rl/` (e.g. `mahoraga-rl2.srlp`, `mahoraga-waf.srlp`), auto-discovered by `samurai_master` and `samurai_mcp` (`--cl-strategy rl` / `policy_path`). Distributed `samurai_cluster_run_job` and `samurai_master` (`--l7-profile-file` / `--l7-profile-json`) also serialize inline Scenario JSON directly across ZMQ master -> slave shards so containerized workers never depend on host-local file mounts.
