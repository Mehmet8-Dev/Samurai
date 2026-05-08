# Genel Bakis

Samurai, yetkili/lab ortamlarinda kullanilmak uzere tasarlanmis, moduler bir ag stres ve dayaniklilik test platformudur.
Bu belge, projeyi hizli ama teknik olarak dogru sekilde anlamak icin "harita" dokumanidir.

## Neyi Cozer?

- L2/L3/L4/L7 seviyelerinde yuk uretimi
- CPU ve opsiyonel GPU hizlandirmali paket/payload uretimi
- Dagitik (master/slave) calisma modeli
- Benchmark, KPI gate, soak ve run raporlama
- Tenant ve role bazli control-plane yonetimi

## Ust Seviye Mimari

1. CLI katmani
- Giris noktasi: `python -m ddos_samurai.cli`
- Moduller: `ddos_samurai/cli/*`
- Gorev: arguman/cofiguration parse, lisans gate, preflight, mode dispatch

2. Runtime/orkestrasyon katmani
- Moduller: `ddos_samurai/cli/runtime.py`, `ddos_samurai/orchestrator.py`
- Gorev: worker lifecycle, process yonetimi, progress/telemetry toplama

3. Sender facade ve transport katmani
- Facade: `ddos_samurai/senders.py`
- Uygulamalar: `ddos_samurai/_senders/*`
- Aktif politika: sender backend tarafinda XDP odakli, fallback politikasi fail

4. Packet/payload uretim katmani
- CPU packet engine: `ddos_samurai/cpu_packet_engine.py`, `ddos_samurai/packet.py`
- GPU packet/payload: `ddos_samurai/gpu_packet.py`, `ddos_samurai/_gpu_packet_cuda_backend.py`, `ddos_samurai/gpu_cuda_payload/*`

5. Dagitik control-plane
- Master: `ddos_samurai/control/master.py`
- Slave: `ddos_samurai/control/slave.py`
- gRPC server/interceptor: `ddos_samurai/control/server.py`
- Management API: `ddos_samurai/control/management_api.py`
- HA, discovery, autoscale, multi-master: `ddos_samurai/control/*`

6. Lisans ve urunlestirme katmani
- Client-side lisans: `ddos_samurai/licensing/*`
- (Ayrik) lisans sunucusu: `license_server/*`
- Tier/feature gate: `ddos_samurai/licensing/features.py`, `ddos_samurai/licensing/gates.py`

## Calisma Modlari

- Offline modlar:
  - `--self-test`
  - `--dry-run`
  - `--gpu-pcap`
  - `--pcap-info`
- Live standalone mod:
  - `--role standalone` (default)
- Distributed mod:
  - `--role master`
  - `--role slave`

## Kritik Guvenlik ve Kalite Noktalari

- Hedef guvenligi:
  - `utils.validate_target_safety()`
  - default: public hedef blok
  - allowlist + global denylist destekli
- Runtime guvenlik davranisi:
  - soak alarminda auto-abort opsiyonu
- Lisans gate:
  - live run oncesi zorunlu dogrulama
- KPI/benchmark gate:
  - CI acceptance ve run-quality kontrolu

## Dokuman Seti Icinde Nereye Bakmali?

- CLI akisi: `docs/01-cli.md`
- Orkestrasyon ve sender zinciri: `docs/02-orchestrator.md`, `docs/03-senders.md`
- GPU ve AF_XDP: `docs/05-gpu.md`, `docs/06-af_xdp-fast_sender.md`
- Safety ve config: `docs/07-safety.md`, `docs/08-config.md`
- Dagitik deployment: `docs/distributed-container-native.md`, `docs/29-distributed-control-plane.md`
- Lisans ve urun paketleme: `docs/30-licensing-and-commercialization.md`, `docs/31-security-release-gates.md`
