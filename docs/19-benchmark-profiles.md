# 19 - Benchmark Profiles (Productized)

Bu dokuman benchmark akislarini 3 sabit profile indirger:

- `dev`
- `ci_safe`
- `dedicated_lab`

Hepsi icin tek giris komutu:

```bash
python -m ddos_samurai.benchmark_profiles --profile <dev|ci_safe|dedicated_lab> --run
```

Not: `dedicated_lab` root/privileged ortami gerektirir.

## Profiller

### dev

Komut:

```bash
python -m ddos_samurai.benchmark_profiles --profile dev --run
```

Beklenen KPI esikleri (parity profile: `dev`):

- `run_quality == valid`
- `send_success_ratio_pct >= 90.0`
- `wire_loss_est_pct <= 10.0`
- `rate_accuracy_pct >= 85.0`

Artifact standardi:

- `artifacts/benchmarks/dev/benchmark_summary.json`
- `artifacts/benchmarks/dev/benchmark_meta.json`

### ci_safe

Komut:

```bash
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run
```

Beklenen KPI esikleri (parity profile: `ci_safe`):

- `run_quality == valid`
- `send_success_ratio_pct >= 95.0`
- `wire_loss_est_pct <= 5.0`
- `rate_accuracy_pct >= 90.0`

Artifact standardi:

- `artifacts/benchmarks/ci_safe/benchmark_summary.json`
- `artifacts/benchmarks/ci_safe/benchmark_meta.json`

### dedicated_lab

Komut:

```bash
sudo python -m ddos_samurai.benchmark_profiles --profile dedicated_lab --run
```

Beklenen KPI esikleri (parity profile: `dedicated_lab`):

- `run_quality == valid`
- `send_success_ratio_pct >= 99.0`
- `wire_loss_est_pct <= 1.0`
- `rate_accuracy_pct >= 98.0`
- `quic_stack_mode == h3_stateful` (QUIC scope aktifse)

Artifact standardi:

- `artifacts/benchmarks/dedicated_lab/benchmark_summary.json`
- `artifacts/benchmarks/dedicated_lab/loss_telemetry_full.json`
- `artifacts/benchmarks/dedicated_lab/benchmark_meta.json`

## Referans Dosyalar

- Profil tanimlari: `benchmarks/benchmark_profiles.json`
- KPI/gate esikleri: `benchmarks/parity_matrix.json`
- Runner: `ddos_samurai/benchmark_profiles.py`
