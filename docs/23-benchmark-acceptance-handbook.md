# 23 - Benchmark and Acceptance Handbook

![Samurai CLI Execution & Benchmark Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

## Purpose

This handbook defines the formal evaluation framework for runs executed via the Samurai Network Resilience Platform (`./build/cli/samurai`) and its benchmark pipeline. It elevates performance evaluation beyond simple execution ("Did it run?") to rigorous technical certification ("Is the result valid, statistically comparable, and publishable?").

This document answers core operational questions:

- Is this run technically valid and acceptable?
- Can these performance figures be certified and published?
- Is this execution merely observational, or does it provide decisive acceptance evidence?
- Should the next operational phase focus on debugging, tuning, or parity certification?

This handbook is strictly designed for authorized, isolated laboratory and staging network environments.

## Target Audience

- Benchmark Operators
- Performance Engineers
- Platform and Site Reliability Engineering (SRE) Teams
- Technical Leads evaluating parity and KPI validation gates
- Systems Developers comparing CPU, TX_RING, AF_XDP, DPDK, and GPU pipelines

## Scope and Boundaries

This handbook:

- Is not an exhaustive CLI flag reference.
- Does not serve as a primary command-line cheat sheet.
- Does not replace standard debugging runbooks.

Recommended companion documentation:

- `docs/22-cli-operational-playbook.md`
- `docs/19-benchmark-profiles.md`
- `docs/10-troubleshooting.md`
- `docs/20-env-cli-reference.md`

## Core Decision Model

Every benchmark run must be evaluated across the following sequential criteria:

1. Did the run terminate cleanly and achieve technical completion?
2. Is the recorded run quality status marked as `valid`?
3. Did the execution satisfy all KPI validation gate thresholds (`pass`)?
4. Did the sender and dataplane backend remain strictly on the designated path?
5. Does the test environment classification (`dev`, `ci_safe`, `dedicated_lab`) match the claimed performance tier?
6. Is the archived artifact package complete, reviewable, and reproducible?
7. Should the result be classified as an authoritative benchmark, a reference baseline, an observational soak, or a debug artifact?

Core Operational Rules:

- If `run_quality != valid`, never claim benchmark validity.
- If the KPI validation gate fails, never publish parity or acceptance claims.
- If fallback or mixed transmission paths occurred, never present the run as a deterministic backend benchmark.
- Without an archived, complete artifact bundle, never treat long-running executions as official results.

## Run Classifications and Confidence Levels

| Run Type | Operational Purpose | Evaluative Authority |
|---|---|---|
| Dry-run | Configuration, argument parsing, and preflight validation | Operational readiness |
| Smoke run | Quick health check and end-to-end functionality verification | Low |
| Baseline | Reference performance characterization | Medium |
| Benchmark | Rigorous, KPI-governed performance measurement | High |
| Soak | Longevity stability, memory leak, and throughput drift tracking | High |
| Fault-injection soak | Resilience and degradation tolerance under simulated failure | High |
| Debug run | Deep root-cause isolation and diagnostic tracing | Diagnostic only (not a benchmark) |

Fundamental distinction:

- Every benchmark is a run.
- Not every run qualifies as a benchmark.

## Minimum Criteria for a Valid Run

An execution is classified as technically valid only when all following criteria are satisfied:

- `workers_total > 0`
- `attempted_total > 0`
- Execution completed without premature manual cancellation or unhandled system interruption.
- Run report telemetry generated statistically grounded metric data.
- Core telemetry fields corresponding to the target backend and run profile are fully populated.

Primary telemetry fields inspected in the run report:

- `results.run_quality`
- `results.warnings`
- `results.sender_path` or `results.sender_paths_used`
- `results.sender_fallback_reason`
- `parity.normalized_results.kpi_gate_status`
- `parity.normalized_results.score_eligible`

## Invalid or Suspicious Run Indicators

A run must be rejected from official benchmark certification if any of the following conditions exist:

- `run_quality == interrupted`
- `run_quality == invalid_metrics`
- `attempted_total == 0`
- `workers_total == 0`
- `sender_fallback_reason != none` when targeting a deterministic backend.
- `sender_paths_used` contains multiple disparate active transmission paths (mixed path).
- The run claimed `dedicated_lab` status but degraded to non-privileged kernel paths.
- The archived artifact bundle is missing or incomplete.

In such cases, the execution is not useless, but its classification is downgraded:

- Downgraded from an authoritative benchmark to a diagnostic debug artifact.
- Downgraded from a parity certification to an observational baseline.
- Downgraded from a publishable finding to preliminary tuning input.

## Distinctions: Baseline, Benchmark, and Soak

### Baseline

A baseline captures expected system behavior at a specific point in time under standard conditions.

Applicable use cases:

- Rapid regression checks across Git branches.
- Reference checkpoints prior to architectural tuning.
- Detecting major performance regressions early.

Insufficient for:

- Claiming profile-based parity certification.
- Publishing formal line-rate performance specifications.
- Proving multi-hour longevity stability.

### Benchmark

A benchmark is a rigorously controlled performance measurement evaluated against predefined profiles and strict KPI validation gates.

Mandatory requirements:

- Explicitly declared profile.
- Unambiguous environment classification.
- Strictly deterministic sender and dataplane backend execution.
- Comprehensive, reproducible artifact package.

### Soak

Soak evaluations prioritize temporal stability and endurance over peak instantaneous burst rates:

- Does resident memory (RSS) or GPU VRAM expand over time (memory leaks)?
- Does packet transmission rate (PPS/RPS) drift or degrade over hours?
- Do hidden sender fallbacks or buffer degradations emerge late in the test?
- Does the engine maintain acceptable quality under periodic fault injection?

A successful soak run provides strong evidence of architectural stability, but does not substitute for high-intensity peak throughput benchmarks.

## KPI Gate Interpretation Guide

Profile-based acceptance is governed by the `kpi_gate_status` and `score_eligible` report fields:

- `kpi_gate_status == pass`: The run satisfied all minimum performance and error rate thresholds defined by the profile.
- `kpi_gate_status == fail`: The run failed profile criteria and cannot be accepted for parity certification.
- `score_eligible == 1`: The run meets all architectural prerequisites for formal scoring.
- `score_eligible == 0`: Even if metrics are generated, the run cannot be accepted as publishable parity data.

Example Certification Outcomes:

- `run_quality=valid`, `kpi_gate_status=pass`, `score_eligible=1`:
  Authoritative benchmark candidate suitable for official publication.
- `run_quality=valid`, `kpi_gate_status=fail`:
  Technically valid execution that failed acceptance thresholds; tuning required.
- `run_quality=invalid_metrics`, `kpi_gate_status=fail`:
  Invalid run; telemetry or environment failure must be resolved before re-testing.

## Extracting Tuning Decisions from Run Reports

Tuning should not rely on superficial, isolated numbers. Follow this structured methodology:

1. Determine whether the run is technically valid.
2. Identify the root problem classification.
3. Adjust only the specific parameter group governing that domain.
4. Modify a minimal set of variables per iteration.

Operational guidelines:

- If packet loss is elevated, inspect queue geometry, transmission rings, and buffer allocations first.
- If rate accuracy degrades, inspect pacing configurations, CPU pinning, and worker core distribution first.
- If fallback occurs, resolve backend dependencies and environment privileges before tuning throughput.
- If mixed transmission paths appear, lock down explicit backend bindings prior to performance optimization.

### Telemetry Field Diagnostic Reference

| Run Report Field | Diagnostic Meaning | Primary Tuning Target |
|---|---|---|
| `wire_loss_est_pct` | Packet loss pressure on egress queues or driver interfaces | Queue count, ring target MB, backend mode |
| `rate_accuracy_pct` | Variance from target pacing and timing intervals | Worker count, RPS rate, pacing engine |
| `sender_fallback_reason` | Inability to maintain requested high-speed path | Driver capabilities, kernel privileges, backend policy |
| `sender_paths_used` | Datapath drift or mixed transmitter routing during run | Explicit backend fixation (`--sender-backend`) |
| `txring_flush_error_count` | Kernel-level transmission errors during TX_RING flush | Ring geometry, poll timeout, spin limits |
| `txring_flush_eagain_count` | Transient buffer exhaustion and kernel backpressure | Ring capacity, frames per block, queue depth |
| `txring_tp_drops` | Packet drops recorded by Linux kernel packet socket ring | Ring buffer allocation, NIC queue alignment |
| `gpu_ring_depth_peak` | Peak queue pressure in GPU producer-consumer ring | GPU worker queues, pipeline overlap depth |
| `gpu_ring_block_wait_ns` | GPU producer stalled waiting for host buffer space | GPU batch size, stream count, pipeline depth |
| `workers_failed` / `workers_interrupted` | Worker crash or signal abort | Core stability, memory allocation, permissions |
| `dp_queue_id` / `strategy` / `affinity` | Alignment across NUMA nodes, queues, and CPU cores | NUMA mapping, explicit queue map (`--dp-queue-map`) |
| `afpacket_hugepage_effective` | Efficiency of TX_RING hugepage memory allocations | Hugepages configuration, mlock, prefaulting |

### Systematic Tuning Matrix

| Symptom | Probable Root Cause | Parameter to Increase | Parameter to Decrease | Feature to Disable |
|---|---|---|---|---|
| High `wire_loss_est_pct`, acceptable `rate_accuracy_pct` | Egress transmission ring saturated | `--afpacket-ring-target-mb`, `--dp-queues` | `--workers` | Unnecessary `--gpu-full-variation` |
| Low `rate_accuracy_pct`, low/moderate loss | Pacing thread jitter or core contention | `--afpacket-spin-limit`, `--dp-queues` | `--workers`, `--gpu-batch-size` | Aggressive `--afpacket-busy-poll-us` |
| High `txring_flush_eagain_count` | Transmission ring emptying slower than ingress fill | `--afpacket-ring-target-mb`, `--afpacket-frames-per-block` | `--workers`, `--rps` | - |
| High `txring_flush_error_count` | Ring geometry mismatch or driver backpressure | Moderate `--afpacket-poll-timeout-ms` | `--afpacket-spin-limit`, `--rps` | Experimental `--afpacket-busy-poll-us` |
| Elevated `gpu_ring_block_wait_ns` | GPU kernel generates faster than host DMA drains | `--gpu-stream-count`, `--gpu-pipeline-depth` | `--gpu-batch-size` | `--gpu-full-variation` |
| GPU active, but throughput stalls while latency increases | GPU kernel batch size excessively large | `--gpu-stream-count` | `--gpu-batch-size` | `--gpu-full-variation` |
| Sender fallback observed | Host lacks required privileges or device mapping | Compatible queue and interface configuration | Excess workers or unpinned queues | Replace `--sender-backend auto` with explicit backend |
| Mixed transmission paths recorded | Non-deterministic worker dispatch routing | `--dp-queue-strategy map` or `pin` | `--workers` (match topology) | Permissive fallback policies |

## Profile-Based Acceptance Logic

### `dev` Profile

- Designed for rapid local development and sanity testing.
- Suitable for local regression detection and quick feedback loops.
- Insufficient for formal product or enterprise marketing claims.

Permissible claim:
"The proposed change introduced no immediate regression against local dev baselines."

Impermissible claim:
"Lab-grade parity and maximum throughput certified."

### `ci_safe` Profile

- Tailored for deterministic, automated continuous integration pipelines.
- Provides standard quality and regression gates prior to code merges.

Permissible claim:
"Passed automated CI benchmark acceptance gates under controlled virtual test harness."

### `dedicated_lab` Profile

- Required for authoritative, line-rate performance and parity claims.
- Demands bare-metal hardware, elevated capabilities/root, and deterministic backends.
- Zero tolerance for fallback or path degradation.

Mandatory gate rules:
- `sender_fallback_reason == none`
- `sender_paths_used` must report exactly one uniform, active transmission backend.

## Sender Path and Fallback Interpretation

Never evaluate throughput figures without first validating transmission path integrity.

Inspect these fields:

- `sender_path`
- `sender_paths_used`
- `sender_fallback_reason`
- Target `--sender-backend`

Evaluation rules:

- If the actual path matches the requested target path, the benchmark is statistically valid.
- If fallback occurred, the run may have diagnostic value, but cannot represent the performance of the target backend.
- A `MIXED` path state invalidates official benchmark claims, as contribution across paths is indeterminate.

Operational rules:

- To claim a "TX_RING benchmark", the entire run must have executed exclusively via TX_RING.
- To claim an "AF_XDP benchmark", execution must have completed via XDP with zero driver fallback.
- To claim a "GPU baseline", GPU kernel generation must be verified via hardware telemetry.

### Corrective Action Upon Detecting Fallback

When `sender_fallback_reason` is present, do not tune throughput parameters; fix path stability first:

1. Declare `--sender-backend` explicitly (e.g., `xdp` or `txring`).
2. Enforce strict failure: `--sender-fallback-policy fail`.
3. Verify `sender_paths_used` reports a single, uniform backend.
4. Reduce worker and queue counts to align with physical interface capabilities.
5. Re-run and verify zero fallbacks before resuming throughput optimization.

## Tuning Strategy Based on Loss and Rate Accuracy

Always evaluate `wire_loss_est_pct` and `rate_accuracy_pct` together:

- High Loss + High Accuracy: Transmission pipeline is keeping target pace, but physical queues or buffers are overflowing.
- High Loss + Low Accuracy: Both scheduling and transmission layers are overwhelmed.
- Low Loss + Low Accuracy: No packets are being dropped, but timing pacing is unstable.

### Scenario 1: High Loss, High Accuracy

Diagnosis: The engine sustains the target pacing rhythm, but the transmission rings or interface queues cannot drain the volume.

Corrective actions:
- Increase `--afpacket-ring-target-mb`.
- Gradually increment `--afpacket-frames-per-block`.
- Increase `--dp-queues` up to hardware NIC queue capacity.
- Reduce `--workers` if CPU core oversubscription is occurring.
- Disable heavy variation calculations like `--gpu-full-variation`.

### Scenario 2: High Loss, Low Accuracy

Diagnosis: Severe resource contention affecting both timing scheduling and packet transmission.

Corrective actions:
- Reduce `--workers`.
- Temporarily lower `--rps` or overall count to locate system capacity threshold.
- Reduce `--gpu-batch-size` if using CUDA backend.
- Transition from round-robin (`--dp-queue-strategy rr`) to deterministic queue mapping (`map` or `pin`).

### Scenario 3: Low Loss, Low Accuracy

Diagnosis: Packets are successfully delivered without drops, but inter-packet gap timing and pacing variance fail to meet benchmark standards.

Corrective actions:
- Increment `--afpacket-spin-limit`.
- Tune `--afpacket-poll-timeout-ms` for workload characteristics.
- Align worker processes and dataplane queues symmetrically.
- Enforce pacing thread affinity via `--pin-cpu`.

### Scenario 4: Kernel TX_RING Drops and Flush Contention

Examine: `txring_tp_drops`, `txring_flush_error_count`, `txring_flush_eagain_count`, and `txring_hold_block_pressure_pct`.

Corrective actions:
- Increase `--afpacket-ring-target-mb`.
- Increase `--afpacket-frames-per-block`.
- Apply moderate `--afpacket-spin-limit` thresholds.
- Avoid modifying ring parameters by large increments simultaneously; excessively large rings increase memory latency.

## Interpreting GPU Performance Telemetry

GPU-accelerated pipelines must not be evaluated solely on peak packets-per-second:

- Did the GPU readiness dry-run pass cleanly?
- Did the initial smoke run maintain stability?
- Did throughput gains coincide with increased error rates or silent fallbacks?
- Are tuning parameters (pipeline depth, stream count, batch size) documented in the report?
- Was CPU vs GPU comparison conducted under identical constraints?

Negative indicators in GPU evaluations:
- Passing readiness in dry-run, but falling back to CPU during live execution.
- Rapid performance collapse under simulated fault injection.
- High throughput accompanied by `invalid_metrics` or failed KPI gates.

Positive indicators in GPU evaluations:
- Cohesive progression from smoke run to baseline to tuned benchmark.
- Minimal drift in memory and PPS across extended soak runs.
- Complete artifact archive enabling exact replication.

### GPU Tuning Guidelines

Elevated `gpu_ring_depth_peak` and `gpu_ring_block_wait_ns`:
- Producer is outrunning host DMA transfer capabilities.
- Action: Decrease `--gpu-batch-size`, increase `--gpu-stream-count`, increase `--gpu-pipeline-depth` (e.g., 2 -> 3).

GPU Enabled but Throughput Stalls:
- Bottleneck is typically located on the network sender, not the GPU kernel.
- Action: Inspect `sender_path`, fix `--sender-backend`, and verify NIC queue distribution.

Throughput Increases but Timing Accuracy Degrades:
- Large batch sizes or pipeline buffering are disrupting pacing intervals.
- Action: Reduce `--gpu-batch-size`, reduce worker counts, and stabilize CUDA stream counts.

## NUMA Topology and Queue Placement Guide

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](assets/diagrams/samurai_numa_afxdp_dpdk.svg)

Optimal performance requires aligning worker CPU cores, packet queues, network interface TX rings, and physical memory on the identical NUMA node.

### Impact of NUMA Cross-Talk

When worker threads run on NUMA Node 0 while the network interface is bound to PCIe lanes on NUMA Node 1:

- Inter-socket UPI/QPI traffic introduces latency and timing jitter.
- `rate_accuracy_pct` degrades significantly.
- Memory bus contention increases queue pressure.
- Effective line-rate throughput drops compared to theoretical capacity.

### Inspecting Host Topology

Execute the following commands on dedicated lab nodes:

```bash
lscpu
numactl --hardware
ethtool -l <iface>
cat /sys/class/net/<iface>/device/numa_node
```

Operational goals:
- Identify total NUMA nodes and CPU core layout.
- Determine which NUMA node physically hosts the target NIC.
- Confirm hardware TX queue capacity.
- Align worker processes and thread affinities to matching cores.

### Operational NUMA Rules

1. Size `--workers` according to physical core counts on the local NUMA node.
2. Ensure `--dp-queues` does not exceed hardware NIC TX queue capacity.
3. For rigorous benchmarks, always use `--dp-queue-strategy map` or `pin`.
4. Define explicit 1-to-1 worker-to-queue bindings via `--dp-queue-map`.
5. Pin pacing threads to dedicated isolated cores using `--pin-cpu`.

| Strategy | Recommended Context | Architectural Characteristics |
|---|---|---|
| `rr` | Initial baseline and exploratory runs | Non-deterministic queue assignment across workers |
| `pin` | Standard lab testing on fixed topology | Stable worker-to-queue binding |
| `map` | Authoritative line-rate certification | Explicit, deterministic worker-to-queue layout |

## CPU vs GPU A/B Comparison Invariants

To publish valid A/B comparative performance evaluations between CPU and GPU pipelines, maintain strict identity across all baseline variables:

- Identical destination target, port, and network topology.
- Identical run profile and duration/count targets.
- Identical acceptance criteria and KPI gate definitions.
- Identical reporting formats and telemetry tracking.

A comparison is invalid if:
- One run is a short baseline while the other is an extended soak.
- One run used `dev` criteria while the other used `dedicated_lab`.
- One run experienced backend fallback while the other executed natively.
- One run operated across mixed transmission paths.

## Artifact Inspection Checklist

Every certified benchmark must archive the following complete artifact set:

1. Formal execution report (`run_report.json` and `run_report.md`).
2. Complete profile and environment metadata embedded within the report.
3. Telemetry fields (`sender_path`, fallback reason, KPI gates) clearly populated.
4. Raw execution log file preserved in the artifact repository.
5. Interface packet loss telemetry or realism evaluation files attached where applicable.
6. Artifact filenames adhering to standard chronological naming conventions.

If artifacts are incomplete:
- Reject the execution as an authoritative benchmark record.
- Re-execute the test with mandatory artifact capture enabled.

## Result Publishing Standards

When communicating benchmark results internally or externally, use this structured reporting summary:

```text
Run Type: Dedicated Benchmark
Profile: dedicated_lab
Sender Path: txring
Run Quality: valid
KPI Gate Status: pass
Fallback: none
Eligibility: score_eligible=1
Artifact Package: Complete
Key Metrics: 14.88 Mpps line-rate, 0.02% wire loss, 99.4% rate accuracy
Archive Location: artifacts/reports/2026-04-06_txring_dedicated_8q_failfast.json
```

## Next Step Selection Guide

### Case 1: Run Completed but KPI Gate Failed

Action:
- Perform gap analysis against the failed threshold.
- Identify whether failure was driven by packet loss, latency, or error rate.
- Compare against historical `dev` baselines.
- Apply targeted queue or pacing tuning and re-test.

### Case 2: Run Quality Marked as Invalid

Action:
- Cease benchmark interpretation immediately.
- Transition to system troubleshooting.
- Inspect worker crashes, signal interruptions, kernel errors, and telemetry collection pipelines.

### Case 3: Run Valid and Gate Passed, but Fallback Detected

Action:
- Archive run as an observational operational baseline.
- Do not publish as a certified backend benchmark.
- Fix backend dependencies and re-run with `--sender-fallback-policy fail`.

### Case 4: Run Valid, Gate Passed, Zero Fallback

Action:
- Lock and archive the artifact bundle.
- Execute a confirmation run to demonstrate reproducibility.
- Publish formal benchmark certification.

## Common Misinterpretations

- High Throughput Equates to a Good Run:
  False. If elevated throughput coincides with silent backend fallback or distorted metrics, the benchmark is invalid.
- `valid` Quality Automatically Qualifies as an Accepted Benchmark:
  False. `valid` merely confirms technical completion and metric integrity; it must also satisfy KPI gate thresholds.
- `dev` Results Substitute for Dedicated Lab Testing:
  False. Development profiles provide fast feedback for engineers, but lack the rigorous controls required for formal line-rate certification.
- Mixed Transmission Paths Are Acceptable:
  False. Mixed path execution obscures the contribution of individual drivers and invalidates architectural claims.

## Summary

A sound benchmarking culture relies on disciplined operational rigor: classifying every run correctly, rejecting invalid results without compromise, and guaranteeing complete statistical reproducibility across every published figure.

Core Evaluation Hierarchy:
1. Technical Validity First
2. KPI Acceptance Second
3. Performance and Line-Rate Claims Third
