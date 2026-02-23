# 09 - Gelistirme ve Test

## Test Profilleri

Bu repo test orchestrasyonu icin `pytest` kullanir ve iki profile ayrilir:

- `ci_safe` (default): non-privileged, GPU olmayan hizli katman
- `full`: privileged/root + opsiyonel GPU + genis benchmark katmani

Profil secimi:

```bash
SAMURAI_TEST_PROFILE=ci_safe pytest tests -q -rs
SAMURAI_TEST_PROFILE=full pytest tests -q -rs
```

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
pytest tests/test_rfc_compliance.py tests/test_rfc_negative.py -q -rs
```

Rapor cikti dizini/dosyasi:

- `SAMURAI_RFC_REPORT_OUT`

Uretilen dosyalar:

- `rfc_positive_report.json`
- `rfc_negative_report.json`

## Benchmark Suite

CI-safe benchmark:

```bash
pytest tests/test_benchmark_ci.py -q -rs
```

Full benchmark:

```bash
SAMURAI_TEST_PROFILE=full pytest tests/test_benchmark_full.py tests/test_pacing_root.py -q -rs
```

Benchmark environment degiskenleri:

- `SAMURAI_BENCH_REPORT_OUT`
- `SAMURAI_BENCH_BASELINE`
- `SAMURAI_BENCH_UPDATE_BASELINE`

Ornek:

```bash
SAMURAI_BENCH_BASELINE=artifacts/benchmark_baseline.json \
SAMURAI_BENCH_REPORT_OUT=artifacts/benchmark_summary.json \
pytest tests/test_benchmark_ci.py -q -rs
```

`SAMURAI_BENCH_UPDATE_BASELINE=1` verildiginde mevcut benchmark raporu baseline dosyasina yazilir.

## CI Is Akislari

- `.github/workflows/ci.yml`: `ci_safe` profile
- `.github/workflows/full-bench.yml`: manuel full RFC + benchmark kosusu

## Sandbox/CI Ortami Notu (Scapy PermissionError)

Bazi kilitli ortamlarda Scapy importu netlink socket erisimine takilabilir.
Repo bu riski azaltmak icin lazy import kullanir:

- `ddos_samurai/scapy_support.py`

Bu sayede non-root/sandbox ortamlarda test collection daha stabil calisir.
