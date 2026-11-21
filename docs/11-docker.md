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

## 2. Building Production Images

```bash
docker build -f Dockerfile.prod -t samurai-runtime:latest .
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
