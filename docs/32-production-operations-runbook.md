# 32 - Production Operations Runbook

This runbook establishes standard operating procedures, baseline deployment configurations, and incident response runbooks for operating Samurai multi-node clusters in production and dedicated lab environments.

![Samurai Security & Cluster Topology](assets/diagrams/samurai_distributed_security.svg)

---

## 1. Pre-Flight Deployment Checklist

- [ ] Cryptographically signed license key and enterprise tier verified.
- [ ] TLS certificates and mutual TLS (mTLS) keys installed with correct permissions.
- [ ] Cluster shared secret and HMAC-SHA256 tokens configured.
- [ ] Target IP allowlists and safety denylists defined (`target_safety.cpp`).
- [ ] ZMQ Control Plane port configured to standard port `5099`.
- [ ] Monitoring and observability stack active (Prometheus exporter on `:8089/metrics`).

---

## 2. Master Node Baseline Configuration

Start the distributed Master daemon with High Availability (HA) and RBAC enabled:

```bash
./build/samurai/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --api-listen 0.0.0.0:8089 \
  --ha-mode static \
  --ha-node-id master-01 \
  --ha-peers master-01,master-02 \
  --control-rbac-enable \
  --control-rbac-audit-log-path /var/log/samurai/audit.log
```

---

## 3. Worker Node (Slave) Baseline Configuration

Start distributed worker daemons across compute nodes:

```bash
./build/samurai/control/daemon/samurai_slave \
  --control-endpoints tcp://<MASTER_IP>:5099 \
  --worker afxdp \
  --interface eth0 \
  --stats-stream-interval-ms 1000
```

---

## 4. Routine Health Verification

- **HTTP REST Health:** `GET http://<MASTER_IP>:8089/healthz` returns `200 OK`.
- **Cluster Capacity:** `GET http://<MASTER_IP>:8089/v1/cluster/summary` reports expected worker node counts and active shard allocations.
- **Prometheus Telemetry:** `GET http://<MASTER_IP>:8089/metrics` returns non-zero throughput and latency gauges.
- **Audit Hash Chain:** `tools/verify_audit_chain.py` confirms 100% valid SHA-256 blocks.

---

## 5. Incident Classification & Triage

1. **Authentication & Token Expiry:**
   - *Symptom:* HTTP `401 Unauthorized` or `403 Forbidden` on REST management API.
   - *Remediation:* Regenerate HMAC JWT tokens and verify shared secrets match across cluster endpoints.
2. **HA Leader Lease Split-Brain:**
   - *Symptom:* Multiple nodes claiming master status or RPC connection timeouts.
   - *Remediation:* Verify network connectivity between peers, check file lease locks on shared volume, or restart secondary master daemons.
3. **Dataplane Kernel-Bypass Drop / Driver Failover:**
   - *Symptom:* AF_XDP or DPDK worker reporting hardware ring queue overruns or falling back to raw socket mode.
   - *Remediation:* Verify hugepage availability (`grep HugePages /proc/meminfo`), check NIC ring descriptor limits (`ethtool -g`), and restart the local worker.
4. **GPU Initialization Failure:**
   - *Symptom:* `samurai_gpu_worker` failing on CUDA device allocation.
   - *Remediation:* Verify NVIDIA driver status via `nvidia-smi`, confirm BAR1 memory mapping, and verify CUDA toolkit version alignment.

---

## 6. Disaster Recovery & Backup Procedures

- **License and Audit Storage Backup:**
  - Automated backups executed via `tools/backup_license_db.sh`.
  - Monthly recovery drills validated using `tools/restore_drill_smoke.sh`.
- **Orderly Cluster Teardown:**
  - Send SIGTERM to `samurai_master`; supervisor sends `STOP_JOB` to all active shards and drains worker ring buffers.
