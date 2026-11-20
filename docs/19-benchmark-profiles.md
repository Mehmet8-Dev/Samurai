# 19 - Productized Benchmark Profiles & KPI Gates

This document standardizes execution profiles for benchmarking, Continuous Integration (CI), and baremetal lab validation across three immutable tiers:

- `dev` (Local rapid iteration and developer workstation)
- `ci_safe` (Hermetic CI pipeline environments)
- `dedicated_lab` (High-density baremetal line-rate verification)

![Samurai CLI Execution & Benchmark Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

---

## 1. Profile Definitions & KPI Thresholds

### 1.1 Developer Profile (`dev`)
Designed for non-root local debugging and functional verification.

```bash
./build/cli/samurai --profile dev --target 127.0.0.1 --confirm
```

**KPI Acceptance Gates:**
- `run_quality == valid`
- `send_success_ratio_pct >= 90.0%`
- `wire_loss_est_pct <= 10.0%`
- `rate_accuracy_pct >= 85.0%`

**Generated Artifacts:**
- `artifacts/benchmarks/dev/benchmark_summary.json`
- `artifacts/benchmarks/dev/benchmark_meta.json`

---

### 1.2 CI Pipeline Safe Profile (`ci_safe`)
Designed for automated pull request validation in virtualized runners with limited raw socket privileges.

```bash
./build/cli/samurai --profile ci_safe --target 127.0.0.1 --confirm
```

**KPI Acceptance Gates:**
- `run_quality == valid`
- `send_success_ratio_pct >= 95.0%`
- `wire_loss_est_pct <= 5.0%`
- `rate_accuracy_pct >= 90.0%`

**Generated Artifacts:**
- `artifacts/benchmarks/ci_safe/benchmark_summary.json`
- `artifacts/benchmarks/ci_safe/benchmark_meta.json`

---

### 1.3 Dedicated Baremetal Lab Profile (`dedicated_lab`)
Requires root / `CAP_NET_RAW` / `CAP_NET_ADMIN` privileges, hugepages, and dedicated physical NIC interfaces.

```bash
sudo ./build/cli/samurai \
  --profile dedicated_lab \
  --worker afxdp \
  --interface eth0 \
  --target 10.0.0.50 \
  --confirm
```

**KPI Acceptance Gates:**
- `run_quality == valid`
- `send_success_ratio_pct >= 99.0%`
- `wire_loss_est_pct <= 1.0%`
- `rate_accuracy_pct >= 98.0%`
- `sender_fallback_reason == none` (Zero fallback drift permitted)
- `afpacket_hugepage_effective == 1` (When using ring buffers)

**Generated Artifacts:**
- `artifacts/benchmarks/dedicated_lab/benchmark_summary.json`
- `artifacts/benchmarks/dedicated_lab/loss_telemetry_full.json`
- `artifacts/benchmarks/dedicated_lab/benchmark_meta.json`

---

## 2. Pipeline Enforcement & Quality Gates

The benchmark engine enforces strict mathematical validation before marking any run as passing:
1. `parity.normalized_results.kpi_gate_status == pass`
2. `parity.normalized_results.score_eligible == 1`
3. Single active execution path: Multi-path drift or hidden driver fallback causes immediate run failure.

If any threshold is violated, the CLI returns a non-zero exit code (`1`), blocking CI/CD pipelines from merging degraded code.
