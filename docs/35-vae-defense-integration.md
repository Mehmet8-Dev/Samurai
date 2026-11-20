# 35 - Variational Autoencoder (VAE) Defense Verification & Defense Worker

This document describes the closed-loop anomaly detection and defense evaluation engine within Samurai, operated via the native `samurai_defense_worker` daemon.

![Samurai Resilience & Gateway Architecture](assets/diagrams/samurai_system_architecture.svg)

---

## 1. Architectural Scope & Objectives

The defense evaluation layer is engineered to:
- Learn nominal system and traffic baseline behavior under non-stressed conditions.
- Compute mathematical anomaly scores during line-rate stress and multi-vector traffic generation.
- Quantify Web Application Firewall (WAF), IPS, and scrubbing center efficacy by measuring detection accuracy, false positive rates, and evasion latency.

---

## 2. Native C++ Defense Worker Architecture (`samurai_defense_worker`)

[`defense_worker.cpp`](../samurai/zmq/daemon/defense_worker.cpp) operates as an autonomous native worker:
- **Supervisor Integration:** Attaches to dedicated Unix IPC channels (`ipc:///tmp/samurai_jobs_defense`) managed by the ZMQ Supervisor.
- **Dynamic Perturbation Testing:** Injects micro-variations into packet sizes, TCP window sizes, header orders, and timing intervals to test the sensitivity boundary of defense classifiers.
- **Metric Telemetry:** Continuously streams anomaly scores, classified drop ratios, and bypass confidence metrics back to the control plane.

---

## 3. Execution Example

```bash
# Execute defense resilience validation
./build/cli/samurai \
  --worker defense \
  --target 10.0.0.50 \
  --port 80 \
  --count 50000 \
  --confirm
```
