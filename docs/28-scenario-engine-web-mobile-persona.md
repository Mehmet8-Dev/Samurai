# Scenario Engine (Web/Mobile Persona)

Scenario Engine, kullanıcı davranışını persona + flow + step modeliyle üreten L7 senaryo yürütme katmanıdır.

## Kapsam

- Odak: **L7**
- Desteklenen transport/backend: **HTTP/1.1 (`http`)**, **HTTP/2 (`http2`)**, **L4 TCP (`l4_tcp`)**
- Not: `l4_tcp` backend'i L4 Session Driver + custom TCP dataplane yolunu kullanır.

## Senaryo Dosyası

Örnek dosya:
- [scenario_web_mobile.yaml](./scenario_web_mobile.yaml)

Temel alanlar:
- `schema_version`
- `personas`
- `flows`
- `load_model`
- `sla`

## CLI Kullanımı

Scenario çalıştırmak için:

```bash
python -m ddos_samurai.cli \
  --scenario-file docs/scenario_web_mobile.yaml \
  --scenario-mode enforce \
  --scenario-vus 100000 \
  --scenario-ramp-seconds 120 \
  --scenario-max-session-seconds 60 \
  --confirm
```

Önemli flagler:
- `--scenario-file <yaml>`
- `--scenario-mode {off,shadow,enforce}`
- `--scenario-vus <int>`
- `--scenario-ramp-seconds <int>`
- `--scenario-max-session-seconds <int>`
- `--scenario-sla-profile <name|inline>`

## Çalışma Modları

- `off`: legacy akış
- `shadow`: scenario metrikleri + legacy metrikler birlikte
- `enforce`: SLA fail olursa run fail

## Step Tipleri

Desteklenen tipler:
- `request`
- `pause`
- `branch`
- `loop`
- `assert`
- `end_session`

Ek davranışlar:
- `on_failure: retry|skip|abort`
- `think_time.distribution: uniform|gaussian`
- `body_template` request body olarak runtime’da enjekte edilir
- `session_timeout_ms` persona timeout policy içinde desteklenir

## Metrikler

Scenario summary/per-flow seviyesinde:
- `sessions_started`, `sessions_completed`
- `step_attempted`, `step_failed`
- `session_completion_rate`, `step_fail_ratio`
- `ramp_target_vus`, `ramp_actual_vus`, `ramp_accuracy_pct`
- `sla_status`
- per-flow `latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms`

## CI ve Benchmark Notu

- Scenario benchmark smoke + memory profile CI job’u aktiftir.
- 1M resmi benchmark koşusu env-gated olarak ayrıca tetiklenir.
