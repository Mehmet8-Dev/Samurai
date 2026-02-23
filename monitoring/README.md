# External Monitoring (Prometheus + Grafana)

This folder provides an *application-external* monitoring stack to observe host and NIC health during authorized load/stress tests.

Scope:
- Host metrics (CPU, memory, load average, disk, network throughput, drops/errors)
- Kernel softnet drops (via node-exporter textfile collector)
- SaaS API metrics (`/metrics`, Prometheus format)
- Optional pre/post run snapshots saved under `reports/telemetry/`

It does not require instrumenting the Python application.

## Option A: Docker Compose (Recommended)

Prereqs:
- Docker + Docker Compose

Start:

```bash
cd monitoring
docker compose up -d
```

Endpoints:
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (default: `admin` / `admin`)
- Node Exporter: `http://localhost:9100/metrics` (scraped by Prometheus)

Stop:

```bash
cd monitoring
docker compose down
```

## Softnet Drops (Textfile Collector)

Node exporter is configured with a textfile collector directory mounted from:

- `monitoring/textfile/`

Generate softnet metrics (sum across CPUs) into that directory:

```bash
python3 monitoring/bin/collect_softnet_textfile.py --out monitoring/textfile/samurai_softnet.prom
```

Run it periodically (cron/systemd timer). The values in `/proc/net/softnet_stat` are counters since boot, so this works well.

## Run Snapshots (Pre/Post)

Collect a "customer-friendly" snapshot (no app integration required):

```bash
bash monitoring/bin/run_snapshot.sh my_run_001
```

Outputs:
- `reports/telemetry/my_run_001/` (timestamped files)

If you want NIC driver counters (optional), you can also run:

```bash
sudo bash monitoring/bin/run_snapshot.sh my_run_001 --ethtool <iface>
```

## What To Watch (Customer-Facing)

High-signal host-side indicators:
- CPU saturation, loadavg, iowait
- memory pressure (MemAvailable, swap in/out)
- NIC throughput (TX/RX bps/pps) + errors/drops
- kernel softnet drops/time_squeeze (RX path pressure)
- `node_network_*` per-interface drop/error counters
