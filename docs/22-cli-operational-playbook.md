# 22 - CLI Operational Playbook

![Samurai CLI Execution & Worker Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

## Purpose

This document provides an end-to-end operational playbook for the Samurai Network Resilience Platform (`./build/ddos_samurai/cli/samurai`), presenting structured operational workflows for testing, benchmarking, and resilience verification.

Goals:

- Rapidly onboard operators to productive execution.
- Facilitate precise command-line parameter and profile selection.
- Establish distinct methodologies across preflight checks, application baselines, dataplane benchmarks, soak longevity evaluations, PCAP replays, and artifact generation.
- Supply production-ready, copy-pasteable command templates.

This handbook is strictly intended for authorized, isolated laboratory and staging network environments.

## Target Audience

- Performance Engineers
- Platform and Site Reliability Engineering (SRE) Teams
- Laboratory Benchmark Operators
- Layer 7 and Dataplane Developers performing regression evaluations
- Technical Leads defining benchmark standards and compliance gates

## Operational Principles

Every rigorous performance engagement must proceed through the following phases:

1. Parameter and scope validation
2. Authorization and boundary verification
3. Dry-run execution to clear parser and preflight checks
4. Short baseline verification run
5. Controlled benchmark or longevity soak execution
6. Report and artifact aggregation
7. Statistical reproducibility validation

Key Operational Rules:

- Never launch a live execution without completing a successful `--dry-run`.
- Execute privileged kernel-bypass paths (AF_XDP, TX_RING, DPDK) exclusively on dedicated lab infrastructure.
- Never certify long-running benchmarks without archiving formal run reports via `--run-report`.
- For authoritative benchmark scoring, always enforce `--lab-profile dedicated` coupled with strict KPI gates.

## Workflow Selection Matrix

| Operational Need | Recommended Workflow |
|---|---|
| Verify flags and validate configuration syntax without traffic | Dry-run validation |
| Ensure codebase and local environment dependencies are healthy | Automated self-test |
| Measure baseline application Layer 7 HTTP/HTTPS throughput | Layer 7 baseline |
| Measure raw line-rate packet transmission and driver efficiency | Dataplane benchmark |
| Evaluate memory stability, RSS drift, and packet rate degradation | Soak longevity run |
| Generate synthetic PCAP datasets on hardware accelerators | GPU PCAP generator |
| Replay historical network capture traces with precise timing | PCAP replay engine |
| Validate neural traffic model integration without network output | Traffic-model dry-validate |
| Drive maximum line-rate load using CUDA kernel batching | GPU compute backend workflow |

## Environment Preparation Checklist

The following directory layout is recommended across operational nodes:

```text
artifacts/
├── reports/
├── pcaps/
├── logs/
└── configs/
```

Initialize directory tree:

```bash
mkdir -p artifacts/reports artifacts/pcaps artifacts/logs artifacts/configs
```

Verify binary and dependencies:

```bash
./build/ddos_samurai/cli/samurai --self-test
```

Inspect available profiles and command flags:

```bash
./build/ddos_samurai/cli/samurai --help
./build/ddos_samurai/cli/samurai --list-profiles
```

## Tier 1: Parse and Preflight Validation

Preflight operations transmit zero packets over the wire. This step acts as the primary gate for verifying configuration syntax, flag combinations, and worker thread mapping before engaging network devices.

### Example 1: Basic TCP Dry-Run

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.20.15 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --count 5000 \
  --workers 8 \
  --dry-run \
  --confirm \
  --log artifacts/logs/basic_dry_run.log
```

Validation objectives:

- Validate parameter parsing, profile resolution, and schema validation.
- Review worker process core allocations.
- Confirm target IP, port, and transport protocol bindings are accepted.

### Example 2: HTTP/2 Preflight Check

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.30.25 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --http-path /health /api/status \
  --http-method GET \
  --http2-concurrency 200 \
  --http2-connections 4 \
  --http2-streams-per-conn 50 \
  --tls-profile chrome_120 \
  --h2-profile chrome_120 \
  --h2-transport auto \
  --dry-run \
  --confirm \
  --log artifacts/logs/http2_dry_run.log
```

Validation objectives:

- Validate Layer 7 scenario configuration prior to live execution.
- Validate HTTP/2 transport engine selection and TLS fingerprint compatibility.

## Tier 2: Configuration File Workflows

For reproducible benchmarks and continuous integration pipelines, declarative YAML configuration files are strongly preferred over long command-line invocations.

### Sample Configuration

`artifacts/configs/web_stress_dev.yaml`:

```yaml
target: 10.10.40.12
port: 443
attack_vector: http
http_scheme: https
http_method: GET
http_path:
  - /
  - /health
  - /ready
http_concurrency: 120
http_timeout: 5.0
workers: 8
count: 60000
rps: 2000
profile: web-stress
run_report: true
run_report_format: both
run_report_dir: artifacts/reports
log: artifacts/logs/web_stress_dev.log
```

Execute dry-run from configuration file:

```bash
./build/ddos_samurai/cli/samurai \
  --config artifacts/configs/web_stress_dev.yaml \
  --dry-run \
  --confirm
```

Execute live run from configuration file:

```bash
./build/ddos_samurai/cli/samurai \
  --config artifacts/configs/web_stress_dev.yaml \
  --confirm
```

Operational rule:

- Store permanent workload configurations in declarative YAML.
- Pass one-off overrides via command-line flags.
- Command-line arguments always supersede YAML configuration fields.

## Tier 3: Application-Layer Baseline Workflows

Application-layer baselines evaluate target HTTP/S services under controlled concurrency to establish clean performance benchmarks.

### Flow A: HTTP Service Baseline

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.50.20 \
  --port 8443 \
  --attack-vector http \
  --http-scheme https \
  --http-method GET \
  --http-path / /login /api/health \
  --http-concurrency 80 \
  --http-timeout 3 \
  --workers 6 \
  --count 30000 \
  --rps 1500 \
  --profile web-stress \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/http_baseline.log
```

Key measurements delivered:

- Target application throughput, latency distribution, and timeout characteristics.
- Structured run report capturing clean baseline metrics.
- Reference standard for subsequent stress and soak evaluations.

### Flow B: Web Application Firewall and CDN Resilience Evaluation

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.50.30 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --http-path / /search /api/v1/items \
  --profile web-bypass \
  --tls-profile chrome_120 \
  --h2-profile chrome_120 \
  --h2-transport hyper-h2 \
  --ninja-mode \
  --http2-concurrency 300 \
  --http2-connections 6 \
  --http2-streams-per-conn 60 \
  --workers 8 \
  --count 50000 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/web_bypass_baseline.log
```

Applicable scenarios:

- Evaluating target application behavior behind reverse proxies, CDNs, or WAF appliances.
- Assessing browser-assisted challenge evaluation against standard HTTP/2 client multiplexing.

## Tier 4: Stateful and Specialized Layer 7 Scenarios

Note:
- The `websocket` attack vector is not supported in the Layer 7 V1 strict path and produces a fail-visible preflight error.

### Flow A: HTTP/2 Stateful Profile with Custom TCP Stack

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.60.15 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --l7-template-mode profile \
  --l7-profile-file artifacts/configs/l7_http2_profile.json \
  --stateful-runtime-backend afxdp \
  --custom-tcp-mode required \
  --custom-tcp-backend af_xdp \
  --http2-concurrency 120 \
  --workers 6 \
  --count 15000 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/http2_stateful_profile.log
```

### Flow B: Native QUIC Strict Capability Gate

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.10.70.40 \
  --port 443 \
  --attack-vector quic \
  --http-scheme https \
  --quic-path /api/ping \
  --quic-method GET \
  --quic-concurrency 200 \
  --quic-conn-pool-size 4 \
  --l7-quic-engine c_state \
  --l7-quic-require-native \
  --l7-capability-strict \
  --quic-expect-status-min 200 \
  --quic-expect-status-max 299 \
  --quic-require-response-headers true \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/quic_native_strict.log
```

Benefits of strict capability gating:

- Guarantees fail-fast behavior when Python bridge fallback is prohibited.
- Identifies missing native capabilities during preflight rather than midway through a benchmark.

## Tier 5: Dataplane and Sender Benchmark Workflows

These operations require elevated Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_SYS_NICE`) or root privileges and must be executed in dedicated lab testbeds.

### Flow A: TX_RING Controlled Dataplane Benchmark

```bash
sudo ./build/ddos_samurai/cli/samurai \
  --target 10.20.10.50 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cpu \
  --sender-backend txring \
  --sender-fallback-policy fail \
  --dataplane-core-mode required \
  --afpacket-hugepage-mode required \
  --afpacket-ring-target-mb 256 \
  --afpacket-frames-per-block 128 \
  --afpacket-poll-timeout-ms 1 \
  --lab-profile dedicated \
  --dp-queue-strategy pin \
  --dp-queues 8 \
  --workers 8 \
  --count 5000000 \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/txring_dedicated.log
```

Application context:

- Eliminates unverified sender fallbacks (`--sender-fallback-policy fail`).
- Enforces dedicated dataplane core isolation and hugepage ring allocations.
- Produces rigorous, publishable lab benchmarks.

### Flow B: AF_XDP Zero-Copy Benchmark

```bash
sudo ./build/ddos_samurai/cli/samurai \
  --target 10.20.20.60 \
  --port 53 \
  --protocol udp \
  --attack-vector basic \
  --sender-backend xdp \
  --sender-fallback-policy fail \
  --xdp-enable \
  --xdp-interface eth2 \
  --xdp-queue-id 0 \
  --xdp-mode 1 \
  --xdp-attach-bpf \
  --workers 4 \
  --count 3000000 \
  --lab-profile dedicated \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/afxdp_benchmark.log
```

Operational notes:

- `--xdp-mode 1` engages native driver mode for maximum kernel-bypass throughput.
- Explicitly configure BPF object and section paths if non-default filtering is required.

## Tier 5B: GPU Compute Backend Operational Workflows

Setting `--compute-backend cuda` activates the GPU hardware packet generation pipeline. This workflow monitors the full acceleration pipeline:

- GPU template and packet generation kernels
- Host-ready ring buffer streaming
- CUDA stream concurrency and memory copy overlap
- Pinned host memory management
- Combined throughput behavior across the sender and hardware dataplane

Execution Progression:
Dry-Run -> Short Smoke Run -> Baseline -> Parameter Tuning -> Longevity Soak -> CPU vs GPU A/B Comparison

### Flow A: GPU Readiness Dry-Run

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.10.10 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 4 \
  --count 20000 \
  --gpu-template-pool-size-l4 16 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 65536 \
  --gpu-stream-count 2 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 256 \
  --dry-run \
  --confirm \
  --log artifacts/logs/gpu_readiness_dry_run.log
```

Validation objectives:

- Confirm CUDA runtime libraries and GPU devices initialize correctly.
- Verify GPU allocation and pipeline parameters pass schema validation.
- Validate worker, batch, and stream combinations.

### Flow B: GPU Smoke Run

Verifies end-to-end functionality of the GPU pipeline in a live transmission cycle.

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.10.10 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --sender-backend auto \
  --workers 4 \
  --count 100000 \
  --rps 2000 \
  --gpu-template-pool-size-l4 16 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 65536 \
  --gpu-stream-count 2 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 256 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/gpu_smoke.log
```

Applicable scenarios:

- Post-installation validation of new CUDA drivers or hardware.
- Verification following kernel updates or native bridge compilation.
- Pre-benchmark sanity testing in staging environments.

### Flow C: GPU Baseline Throughput

Establishes initial reference throughput under default GPU tuning.

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.20.20 \
  --port 53 \
  --protocol udp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 6 \
  --count 1500000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 100000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 512 \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/gpu_baseline_udp.log
```

Evaluation objectives:

- Determine initial GPU line-rate throughput figures.
- Verify host system stability under large CUDA batch allocations.
- Detect host pinned memory saturation or DMA transfer bottlenecks.

### Flow D: GPU Tuned Benchmark

High-throughput performance measurement under optimized GPU pipeline settings.

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.30.30 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --sender-backend c_ext_l3 \
  --sender-fallback-policy fail \
  --workers 8 \
  --count 4000000 \
  --gpu-template-pool-size-l4 32 \
  --gpu-ring-capacity 6 \
  --gpu-batch-size 150000 \
  --gpu-stream-count 4 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 1024 \
  --gpu-full-variation \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/gpu_tuned_benchmark.log
```

Methodological safeguards:

- Explicitly fixes the sender backend and prohibits silent fallback.
- Records exact GPU pipeline configuration within the run report artifact.
- Ensures identical tuning parameters can be replayed for verification.

### Flow E: Combined GPU and TX_RING Architecture

Evaluates GPU generation throughput coupled with kernel-bypass TX_RING transmission.

```bash
sudo ./build/ddos_samurai/cli/samurai \
  --target 10.21.40.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --sender-backend txring \
  --sender-fallback-policy fail \
  --dataplane-core-mode required \
  --afpacket-hugepage-mode required \
  --afpacket-ring-target-mb 256 \
  --lab-profile dedicated \
  --dp-queue-strategy pin \
  --dp-queues 8 \
  --workers 8 \
  --count 5000000 \
  --gpu-template-pool-size-l4 32 \
  --gpu-ring-capacity 6 \
  --gpu-batch-size 150000 \
  --gpu-stream-count 4 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 1024 \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/gpu_txring_dedicated.log
```

Diagnostic insights:

- Isolates whether throughput limits stem from GPU generation or TX transmission rings.
- Evaluates impact of hardware queue pinning on line-rate packet dispatch.
- Measures pipeline stability under strict laboratory profiles.

### Flow F: GPU Longevity Soak Test

Monitors memory footprint and packet rate stability under extended GPU generation.

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.50.50 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 8 \
  --count 100000000 \
  --rps 4000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 5 \
  --gpu-batch-size 120000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 1024 \
  --soak-profile 1h \
  --soak-warmup-s 180 \
  --soak-snapshot-interval 15 \
  --soak-max-error-rate-pct 0.5 \
  --soak-max-pps-drop-pct 10 \
  --soak-max-vram-growth-mb 256 \
  --soak-max-pinned-growth-mb 256 \
  --soak-max-backlog 12000 \
  --run-report \
  --run-report-dir artifacts/reports \
  --loss-telemetry auto \
  --confirm \
  --log artifacts/logs/gpu_soak_1h.log
```

Critical telemetry metrics:

- GPU VRAM consumption over time
- Host pinned memory expansion
- Ring buffer backlog depth
- PPS drift over prolonged duration

### Flow G: GPU Fault-Injection Longevity Soak

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.60.60 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 8 \
  --count 100000000 \
  --rps 3500 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 5 \
  --gpu-batch-size 120000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 1024 \
  --soak-profile 6h \
  --fault-inject gpu-stream-error \
  --fault-after-s 1200 \
  --fault-duration-s 5 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/gpu_fault_soak.log
```

Purpose:

- Observe recovery and error containment during simulated CUDA stream failures.
- Validate resilience of GPU worker threads under infrastructure anomalies.

### Flow H: CPU vs GPU A/B Comparison

To guarantee statistical validity, keep target IP, worker counts, packet totals, and reporting configurations strictly identical across runs.

CPU Baseline Reference:

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.70.70 \
  --port 53 \
  --protocol udp \
  --attack-vector basic \
  --compute-backend cpu \
  --workers 8 \
  --count 2000000 \
  --run-report \
  --run-report-out artifacts/reports/cpu_udp_ab \
  --confirm \
  --log artifacts/logs/cpu_udp_ab.log
```

GPU Accelerated Counterpart:

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.21.70.70 \
  --port 53 \
  --protocol udp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 8 \
  --count 2000000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 100000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 512 \
  --run-report \
  --run-report-out artifacts/reports/gpu_udp_ab \
  --confirm \
  --log artifacts/logs/gpu_udp_ab.log
```

### GPU Operational Troubleshooting Guide

If GPU throughput falls below theoretical line-rate:

1. Verify whether the sender backend or network interface is the bottleneck.
2. Check if `--gpu-batch-size` is excessively large, introducing pipeline latency.
3. Evaluate whether `--gpu-stream-count` is insufficient for effective DMA overlap.
4. Check if host memory contention exists via `--gpu-pinned-max-mb`.
5. Measure if `--gpu-full-variation` increases per-packet computation overhead.

Recommended tuning steps:

1. Increment `--gpu-stream-count`: 2 -> 3 -> 4.
2. Increment `--gpu-pipeline-depth`: 2 -> 3.
3. Test graduated batch sizes for `--gpu-batch-size`.
4. Capture separate run reports for every tuning iteration.

## Tier 6: Soak and Longevity Stability Workflows

Soak runs evaluate system stability, memory leaks, and performance drift over extended time windows.

### Flow A: 1-Hour Application Layer Soak

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.30.10.70 \
  --port 443 \
  --attack-vector http \
  --http-scheme https \
  --http-path /api/health \
  --http-method GET \
  --http-concurrency 100 \
  --workers 8 \
  --rps 1200 \
  --count 100000000 \
  --profile web-stress \
  --soak-profile 1h \
  --soak-warmup-s 120 \
  --soak-snapshot-interval 15 \
  --soak-max-error-rate-pct 0.5 \
  --soak-max-pps-drop-pct 8 \
  --soak-max-rss-growth-mb 256 \
  --soak-max-backlog 10000 \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --loss-telemetry auto \
  --loss-fail-pct 3 \
  --confirm \
  --log artifacts/logs/http_soak_1h.log
```

### Flow B: Soak with Fault-Injection

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.30.20.80 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --profile web-stress \
  --h2-transport auto \
  --http2-concurrency 250 \
  --workers 8 \
  --rps 1800 \
  --count 100000000 \
  --soak-profile 6h \
  --fault-inject sender-restart gpu-stream-error \
  --fault-after-s 900 \
  --fault-duration-s 5 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/http2_fault_soak.log
```

Benefits:

- Assesses recovery behavior under transient hardware or process failure.
- Aggregates error rate, backlog growth, and memory degradation into a single report.

## Tier 7: GPU PCAP Synthetic Artifact Generation

This workflow does not transmit packets over physical interfaces; it synthesizes deterministic, high-realism PCAP traces on GPU hardware for testing and ML pipelines.

### Flow A: Short Synthetic PCAP Generation

```bash
./build/ddos_samurai/cli/samurai \
  --gpu-pcap \
  --gpu-pcap-duration 10 \
  --gpu-pcap-pps 50000 \
  --gpu-pcap-mode mix \
  --gpu-pcap-src-ip 10.40.1.10 \
  --gpu-pcap-dst-ip 10.40.2.20 \
  --gpu-pcap-tcp-port 443 \
  --gpu-pcap-udp-port 53 \
  --gpu-pcap-out artifacts/pcaps/gpu_mix_10s_50k.pcap
```

### Flow B: Realistic Dataset Artifact with Realism Scoring

```bash
./build/ddos_samurai/cli/samurai \
  --gpu-pcap \
  --gpu-pcap-duration 30 \
  --gpu-pcap-pps 75000 \
  --gpu-pcap-mode mix \
  --gpu-pcap-realistic \
  --gpu-pcap-variable-size \
  --gpu-pcap-size-profile mixed \
  --gpu-pcap-flow-count 4096 \
  --gpu-pcap-realism-report \
  --gpu-pcap-realism-sample 25000 \
  --gpu-pcap-realism-out artifacts/pcaps/gpu_realistic_mix.realism.json \
  --gpu-pcap-run-report \
  --gpu-pcap-run-report-format both \
  --gpu-pcap-run-report-out artifacts/reports/gpu_realistic_mix \
  --gpu-pcap-out artifacts/pcaps/gpu_realistic_mix.pcap
```

Target use cases:

- Trace replay validation in staging labs.
- Parser and deep packet inspection (DPI) stress testing.
- Synthetic dataset generation for traffic classification models.
- Realism regression validation.

## Tier 8: PCAP Replay Workflows

### Flow A: Inspect Capture Metadata

```bash
./build/ddos_samurai/cli/samurai \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-info
```

### Flow B: Timing-Aware Replay

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.50.10.90 \
  --port 443 \
  --attack-vector pcap-replay \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-timing multiplier \
  --pcap-speed 1.5 \
  --pcap-loops 3 \
  --pcap-filter-proto tcp udp \
  --pcap-filter-dst-port 443 \
  --pcap-batch-size 1024 \
  --workers 4 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/pcap_replay_multiplier.log
```

### Flow C: Layer 2 Replay via TX_RING

```bash
sudo ./build/ddos_samurai/cli/samurai \
  --target 10.50.20.91 \
  --port 443 \
  --attack-vector pcap-replay \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-use-l2 \
  --pcap-timing topspeed \
  --sender-backend txring \
  --sender-fallback-policy fail \
  --lab-profile dedicated \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/pcap_l2_txring.log
```

## Tier 9: Traffic Model and Dataset Workflows

Because runtime traffic model integration is constrained, initial validation should always execute via `--traffic-model-dry-validate`.

### Flow A: Traffic Planner Model Validation

```bash
./build/ddos_samurai/cli/samurai \
  --traffic-model mamba2 \
  --traffic-model-checkpoint artifacts/models/mamba2_lab.ckpt \
  --traffic-model-config artifacts/models/mamba2_lab.yaml \
  --traffic-model-device cpu \
  --traffic-model-seed 42 \
  --traffic-model-label-mix benign=0.5,evasive=0.3,aggressive=0.2 \
  --traffic-model-session-len 32 \
  --traffic-model-planner-batch 64 \
  --traffic-model-timeout-ms 1500 \
  --traffic-model-fallback fail \
  --traffic-model-export-events artifacts/reports/mamba2_events.jsonl \
  --traffic-model-dry-validate
```

### Flow B: Controlled Live Run with Dataset Capture

```bash
./build/ddos_samurai/cli/samurai \
  --target 10.60.10.100 \
  --port 443 \
  --attack-vector http \
  --http-scheme https \
  --http-path /api/check \
  --workers 4 \
  --count 20000 \
  --rps 800 \
  --traffic-model-dataset-capture artifacts/reports/runtime_events.jsonl \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/runtime_dataset_capture.log
```

## Tier 10: Professional Operational Patterns

### Pattern 1: Prior to Introducing New Workload Scenarios

1. Review `--help` and `--list-profiles`.
2. Execute `--dry-run` to validate schema and arguments.
3. Execute a short baseline run.
4. Inspect the resulting run report.
5. Proceed to formal benchmark or soak runs.

### Pattern 2: Prior to Publishing Benchmark Results

1. Enforce strict fallback policies: `--sender-fallback-policy fail`.
2. Persist comprehensive metrics using `--run-report`.
3. Document kernel capability and privilege requirements.
4. Include queue, worker, and backend identifiers in artifact filenames.

### Pattern 3: Accepting Soak Longevity Runs

1. Configure an adequate warmup duration.
2. Fix telemetry snapshot intervals.
3. Explicitly define error rate and PPS degradation criteria.
4. Incorporate interface packet loss telemetry in the final report.

## Common Operational Pitfalls

### Skipping Dry-Run Validation

Consequences:
- Configuration and syntax errors surface mid-run during live execution.
- Benchmark validity is compromised, wasting test windows.

### Benchmarking with Permissive Fallback (`allow`)

Consequences:
- The engine may silently degrade to a slower or non-deterministic sender backend, falsifying benchmark throughput.

Remedy:
- For authoritative benchmarks, always specify:
  - `--sender-fallback-policy fail`
  - `--l7-fallback-policy fail`

### Running Privileged Dataplane Paths as Non-Root

Privileged paths requiring elevated Linux capabilities:
- `txring`
- `xdp`
- Raw socket transmission

## Artifact Naming Conventions

Structured artifact naming ensures long-term traceability across automated pipelines:

```text
artifacts/reports/2026-04-06_http2_webstress_10k_rps_dev
artifacts/reports/2026-04-06_txring_dedicated_8q_failfast
artifacts/pcaps/2026-04-06_gpu_mix_30s_75k_realistic.pcap
```

Recommended filename elements:

- Date stamp (YYYY-MM-DD)
- Vector / Protocol
- Profile name
- Target throughput or duration
- Sender backend / lab environment classification

## Summary and References

The Samurai Network Resilience Platform delivers optimal, reproducible results when operators select workflows matching their operational tier:

1. Always execute `--dry-run` first.
2. Establish a short reference baseline.
3. Perform controlled benchmark or longevity soak runs.
4. Archive artifacts via `--run-report`.

Related Architecture Documentation:

- `docs/01-cli.md`
- `docs/08-config.md`
- `docs/18-afpacket-hugepage-policy.md`
- `docs/19-benchmark-profiles.md`
- `docs/20-env-cli-reference.md`
- `docs/23-benchmark-acceptance-handbook.md`
