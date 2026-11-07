# 12 - Telemetry Visibility, Prometheus & Grafana Dashboards

Samurai exposes real-time dataplane metrics through an embedded Prometheus exporter, Server-Sent Events (SSE), WebSockets, and pre-configured Grafana monitoring dashboards.

---

## 1. Observability Subsystem

1. **Prometheus Exporter (`:8089/metrics`):**
   The Management API exposes aggregated telemetry across all active workers, including packet/request throughput (pps / RPS), transmission errors, TCP retransmits, and p50/p95/p99 latency percentiles.

2. **Grafana Monitoring Stack:**
   A complete monitoring stack is available in the `monitoring/` directory:
   ```bash
   cd monitoring && docker compose up -d
   ```
   - **Prometheus UI:** `http://localhost:9090`
   - **Grafana Dashboards:** `http://localhost:3000`

---

## 2. Real-Time Telemetry Streams

High-frequency cluster events can be consumed live via standard protocols:
- **Server-Sent Events (SSE):** `GET /v1/cluster/live/sse`
- **WebSocket Feed:** `WS /v1/cluster/live/ws`
