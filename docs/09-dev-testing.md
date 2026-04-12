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

## Faz 2/3 Regresyon Seti (onerilen hizli dogrulama)

Asagidaki set, HTTP stateful + HTTP/2 transport + WS scenario + PCAP flow-aware/L2 degisikliklerini hedefli dogrular:

```bash
PYTHONPATH=. python3 -m pytest -q \
  tests/test_l7_stateful.py \
  tests/test_senders_http2.py \
  tests/test_orchestrator_cpu.py \
  tests/test_pcap_replay.py
```

CLI parser degisiklikleri (yeni flag'ler) icin:

```bash
PYTHONPATH=. python3 -m pytest -q \
  tests/test_cli_parser.py::TestCliParser::test_parser_has_expected_flags \
  tests/test_cli_parser.py::TestCliParser::test_attack_vector_choices_are_aligned_with_orchestrator
```

Not:

- `tests/test_sender_comprehensive.py` bazi ortamlarda `SAMURAI_TEST_PROFILE=ci_safe` ile skip olabilir.
- Bu beklenen davranistir; privileged path testleri full profile ile kosulmalidir.

## RFC Suite Ayrimi

- Pozitif RFC suite: `tests/test_rfc_compliance.py` (`rfc_positive`)
- Negatif RFC/anomaly suite: `tests/test_rfc_negative.py` (`rfc_negative`)

Calistirma:

```bash
python3 -m pytest tests/test_rfc_compliance.py tests/test_rfc_negative.py -q -rs
```

Rapor cikti dizini/dosyasi:

- `SAMURAI_RFC_REPORT_OUT`

## RFC Gate (CI Fail Kapisi)

RFC negatif raporu artik pipeline'da gate edilir:

```bash
python tests/test_rfc_gate_ci.py --report artifacts/rfc_negative_report.json --min-score 100
```

Gate kurallari:

- Rapor dosyasi bulunmali ve JSON parse edilebilmeli.
- `score >= min-score` (varsayilan: `100`).
- `passed == total` (default strict).
- Kritik check isimleri `passed=true` olmali:
  - `checksum_invalid_detected`
  - `tcp_data_offset_invalid_detected`
  - `total_length_mismatch_detected`
  - `ttl_zero_detected`
  - `udp_length_mismatch_detected`

Bu kosullardan biri saglanmazsa script non-zero exit dondurur ve CI fail olur.

Uretilen dosyalar:

- `rfc_positive_report.json`
- `rfc_negative_report.json`

## Benchmark Suite

Urunlesmis benchmark profilleri icin tek komut runner:

```bash
python -m ddos_samurai.benchmark_profiles --profile dev --run
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run
sudo python -m ddos_samurai.benchmark_profiles --profile dedicated_lab --run
```

Runner; profil bazli `pytest` komutunu cagirir, artifact standardini dogrular ve
`benchmark_meta.json` yazar.

Benchmark profile alias notlari:

- `developer_fallback` -> `ci_safe`
- `full` -> `dedicated_lab`

Runner yardimci bayraklari:

```bash
python -m ddos_samurai.benchmark_profiles --list
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run --artifact-root artifacts/benchmarks
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run --python-bin "$(which python3)"
```

Legacy dogrudan benchmark komutlari:

```bash
python3 -m pytest tests/test_benchmark_ci.py -q -rs
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
- `benchmarks/parity_matrix.json` (Samurai + TRex ortak benchmark sozlesmesi)

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

Parite profili secimi:

```bash
SAMURAI_PARITY_PROFILE=ci_safe python3 -m pytest tests/test_benchmark_ci.py -q -rs
SAMURAI_PARITY_PROFILE=dedicated_lab SAMURAI_TEST_PROFILE=full python3 -m pytest tests/test_benchmark_full.py -q -rs
```

Notlar:

- Benchmark raporlari `parity` bolumu altinda normalize edilmis `normalized_results` ve `rows` uretir.
- `parity.required_result_fields` listesi, run-report tarafinda zorunlu takip edilen alanlarin aynisidir.
- `run_quality != valid` kosular parity skorlamasinda kullanilmamalidir.

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

## Self-Test Yardimcisi (Programatik)

`ddos_samurai/selftest.py` icindeki `run_unittest_discover(...)` fonksiyonu,
CLI disinda da self-diagnostic ihtiyaclari icin structured ozet doner:

- `tests_run`
- `failures`
- `errors`
- `skipped`
- `successful`
- `output`

Bu ozellik, CI diagnostic script'lerinde veya lokal "tek komutla saglik kontrolu"
akislari icin dogrudan yeniden kullanilabilir.
