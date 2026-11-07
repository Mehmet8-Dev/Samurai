# Distributed Container & Cluster Deployment Guide

This document describes deploying the distributed C++ Master/Slave architecture of Samurai using Docker Compose, Helm/Kubernetes, and High-Availability (HA) failover topologies.

![Samurai Distributed Security & Cluster Topology](assets/diagrams/samurai_distributed_security.svg)

---

## 1. Docker Compose Multi-Node Orchestration

The [`docker-compose.distributed.yml`](../docker-compose.distributed.yml) file orchestrates the Redis coordinator, primary Master node, and horizontally scalable Slave instances:

```bash
docker compose -f docker-compose.distributed.yml up --build --scale slave=4
```

### Cluster Subsystems:
- **`samurai_master`:** Central ZMQ Control Plane listening on `tcp://0.0.0.0:5099` alongside the REST Management API on port `:8089`.
- **`samurai_slave`:** Distributed worker daemons that attach to the master control plane, receive shard jobs, and invoke local ZMQ Supervisors.

---

## 2. Kubernetes & Helm Deployment

Deploying horizontally scalable agent pools on Kubernetes:

```bash
helm upgrade --install samurai deploy/helm/samurai \
  --set image.repository=your-registry/samurai \
  --set image.tag=latest \
  --set master.port=5099 \
  --set slave.replicas=5
```

---

## 3. High Availability (HA) Failover Deployments

Samurai includes native C++ leader election algorithms for multi-master clusters:

### 3.1 File-Lock Lease Mode (Shared Storage / Single Host)
```bash
./build/ddos_samurai/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --ha-mode file-lock \
  --ha-node-id master-1 \
  --ha-lease-path /tmp/samurai_master_lease.json \
  --count 10000000 \
  --target 10.0.0.50
```

### 3.2 Static Peer Consensus Mode (Explicit Master Peers)
```bash
./build/ddos_samurai/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --ha-mode static \
  --ha-node-id master-1 \
  --ha-peers master-1,master-2 \
  --count 10000000 \
  --target 10.0.0.50
```
