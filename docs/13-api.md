# 13 - Native HTTP Management REST API (`:8089`)

When launched with `--management-listen`, `samurai_master` initializes an embedded, zero-dependency C++ HTTP REST server built directly upon POSIX non-blocking sockets (`ddos_samurai/control/management_api.cpp`).

![Samurai Distributed Security & Control Plane](assets/diagrams/samurai_distributed_security.svg)

---

## 1. REST Endpoints Specification

| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/healthz` | Health check endpoint returning `200 OK`. |
| `GET` | `/v1/cluster/summary` | Cluster state overview: active worker counts, running shards, and throughput summary. |
| `GET` | `/v1/cluster/workers` | Detailed list of registered worker nodes and their last heartbeat timestamps. |
| `GET` | `/v1/cluster/shards` | Status of in-flight and completed workload shards. |
| `POST` | `/v1/jobs/abort` | Emergency abort trigger halting active stress test jobs across all workers. |
| `POST` | `/v1/cluster/provision` | Automated remote SSH agent provisioning trigger (`curl \| sh`). |
| `GET` | `/v1/agent/install` | Shell installation script for zero-install ephemeral agents. |
| `GET` | `/v1/agent/manifest` | HMAC-SHA256 signed worker manifest. |
| `GET` | `/v1/agent/blob` | Authenticated binary payload download endpoint. |
| `GET` | `/metrics` | Prometheus-compatible raw text metrics feed. |
| `GET` | `/v1/cluster/live/sse` | Server-Sent Events (SSE) live telemetry stream. |
| `GET` | `/v1/cluster/live/ws` | Real-time bidirectional WebSocket event stream. |

---

## 2. Authentication & Authorization Boundaries

API requests are authorized via three complementary mechanisms:
1. **Role Token Header:** `Authorization: Bearer <ADMIN_OR_OPERATOR_TOKEN>`
2. **HMAC-SHA256 JWT:** Signed tenant, role, and expiration claims verified via OpenSSL.
3. **Trusted Reverse-Proxy Headers:** Enterprise proxy integration reading `X-Forwarded-User` and `X-Forwarded-Roles` over authenticated local networks.
