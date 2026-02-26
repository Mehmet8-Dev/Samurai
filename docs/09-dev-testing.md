# 09 - Gelistirme ve Test

## Test Profilleri

Bu repo test orchestrasyonu icin `pytest` kullanir ve iki profile ayrilir:

- `ci_safe` (default): non-privileged, GPU olmayan hizli katman
- `full`: privileged/root + opsiyonel GPU + genis benchmark katmani

Profil secimi:

```bash
SAMURAI_TEST_PROFILE=ci_safe python3 -m pytest tests -q -rs
SAMURAI_TEST_PROFILE=full python3 -m pytest tests -q -rs
```

Komut standardi: testler `python3 -m pytest ...` formatiyla calistirilir.

## Marker Sozlesmesi

Asagidaki marker seti kullanilir:

- `ci_safe`
- `privileged`
- `gpu`
- `benchmark`
- `rfc_positive`
- `rfc_negative`

`SAMURAI_TEST_PROFILE=ci_safe` iken `privileged` ve `gpu` testler otomatik skip edilir.

## RFC Suite Ayrimi

- Pozitif RFC suite: `tests/test_rfc_compliance.py` (`rfc_positive`)
- Negatif RFC/anomaly suite: `tests/test_rfc_negative.py` (`rfc_negative`)

Calistirma:

```bash
python3 -m pytest tests/test_rfc_compliance.py tests/test_rfc_negative.py -q -rs
```

Rapor cikti dizini/dosyasi:

- `SAMURAI_RFC_REPORT_OUT`

Uretilen dosyalar:

- `rfc_positive_report.json`
- `rfc_negative_report.json`

## Benchmark Suite

CI-safe benchmark:

```bash
python3 -m pytest tests/test_benchmark_ci.py -q -rs
```

Full benchmark:

```bash
SAMURAI_TEST_PROFILE=full python3 -m pytest tests/test_benchmark_full.py tests/test_pacing_root.py tests/test_loss_telemetry_full.py -q -rs
```

Benchmark environment degiskenleri:

- `SAMURAI_BENCH_REPORT_OUT`
- `SAMURAI_BENCH_BASELINE`
- `SAMURAI_BENCH_UPDATE_BASELINE`
- `SAMURAI_LOSS_TELEMETRY` (`auto|0|1`, default: `auto`)
- `SAMURAI_LOSS_IFACE` (opsiyonel iface override)
- `SAMURAI_LOSS_FAIL_PCT` (default: `5`)
- `SAMURAI_LOSS_REPORT_OUT` (opsiyonel loss JSON output)
- `SAMURAI_GPU_CACHE_MAX_ENTRIES` (default: `8`)
- `SAMURAI_GPU_RNG_POOL_MAX_ENTRIES` (default: `8`)

Repo baseline dosyasi:

- `benchmarks/benchmark_baseline_ci.json`

Ornek:

```bash
SAMURAI_BENCH_BASELINE=benchmarks/benchmark_baseline_ci.json \
SAMURAI_BENCH_REPORT_OUT=artifacts/benchmark_summary.json \
python3 -m pytest tests/test_benchmark_ci.py -q -rs
```

`SAMURAI_BENCH_UPDATE_BASELINE=1` verildiginde mevcut benchmark raporu baseline dosyasina yazilir.

Baseline yenileme (lokal):

```bash
mkdir -p benchmarks artifacts
SAMURAI_BENCH_BASELINE=benchmarks/benchmark_baseline_ci.json \
SAMURAI_BENCH_UPDATE_BASELINE=1 \
SAMURAI_BENCH_REPORT_OUT=artifacts/benchmark_summary_ci_local.json \
python3 -m pytest tests/test_benchmark_ci.py -q -rs
```

Full + loss telemetry tek komut:

```bash
sudo SAMURAI_TEST_PROFILE=full \
SAMURAI_LOSS_TELEMETRY=1 \
SAMURAI_LOSS_FAIL_PCT=5 \
SAMURAI_BENCH_REPORT_OUT=artifacts/benchmark_summary_full.json \
SAMURAI_LOSS_REPORT_OUT=artifacts/loss_telemetry_full.json \
./ven311/bin/python -m pytest -q \
tests/test_benchmark_full.py \
tests/test_pacing_root.py \
tests/test_loss_telemetry_full.py -rs
```

## CI Is Akislari

- `.github/workflows/ci.yml`: `ci_safe` profile + relatif benchmark regresyon kapisi (`SAMURAI_BENCH_BASELINE=benchmarks/benchmark_baseline_ci.json`)
- `.github/workflows/full-bench.yml`: manuel full RFC + benchmark kosusu
- `runner_strategy=github-hosted|self-hosted`
- `use_sudo=true|false`
- `update_baseline=true` secilirse guncellenmis baseline `artifacts/benchmark_baseline_ci.updated.json` olarak artifact'e yuklenir
- `promote_baseline=true` + `update_baseline=true` secilirse baseline dosyasi branch'e otomatik commit/push edilir

Onerilen CI-uyumlu baseline yenileme:

1. `full-bench` workflow'unu `runner_strategy=github-hosted`, `update_baseline=true`, `promote_baseline=true` ile calistir.
2. Workflow commit'i branch'e push eder ve `benchmarks/benchmark_baseline_ci.json` GH runner metrikleriyle guncellenir.
3. Sonraki `ci.yml` kosularinda relatif regresyon kapisi bu dosyaya gore calisir.

## Sandbox/CI Ortami Notu (Scapy PermissionError)

Bazi kilitli ortamlarda Scapy importu netlink socket erisimine takilabilir.
Repo bu riski azaltmak icin lazy import kullanir:

- `ddos_samurai/scapy_support.py`

Bu sayede non-root/sandbox ortamlarda test collection daha stabil calisir.
