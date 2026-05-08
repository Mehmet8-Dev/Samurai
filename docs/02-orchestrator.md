# Orchestrator

Orchestrator, worker process'lerinin yasam dongusunu, sender cagrilarini ve istatistik birlesimini yoneten merkez katmandir.
Ana dosya: `ddos_samurai/orchestrator.py`.

## Temel Sorumluluklar

1. Worker process davranisi
- Her worker icin runtime args alir
- Sender secimi ve cagrisi yapar
- Paylasimli progress/sent/errors sayaçlarini gunceller

2. L4/L7 stateful akislar
- L7 emulation/runtime cagrilarini yonetir
- Stateful runtime backend preflight alanlarini rapora yazar

3. Telemetry birlestirme
- Worker event listelerini normalize eder
- `stats_core` ile ortak metrik semasina map eder

4. Resource/health monitor
- Worker icinde periodic kaynak verisi toplar
- Parent monitor tarafinda soak alarm mantigina veri saglar

## Worker Calisma Modeli

- Parent process CLI runtime tarafinda workerlari spawn eder
- Worker `orchestrator.start_worker` ile baslar
- Her worker sender facade (`senders.py`) üzerinden trafik uretir
- Cikis kodu + stats JSON event olarak geri doner

## Onemli Integrasyon Noktalari

- CLI runtime: `ddos_samurai/cli/runtime.py`
- Sender facade: `ddos_samurai/senders.py`
- Reporting: `ddos_samurai/reporting.py`
- Loss telemetry: `ddos_samurai/loss_telemetry.py`

## Hata/Fallback Davranisi

- Sender path hazir degilse fail-visible stats uretir
- Belirli feature/path yoksa fallback reason alanlarini doldurur
- KPI gate veya strict policy aktifse hard fail davranisi tetiklenebilir

## Gelistirme Icın Kural

Orchestrator degisikliginde su test gruplari oncelikli kosulmalidir:

- `tests/test_orchestrator*.py`
- `tests/test_senders_*.py`
- `tests/test_reporting.py`
- `tests/test_cli_dry_run_reporting.py`
