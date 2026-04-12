# 00 - Genel Bakis

Release modeli: `Samurai (Kenjaku)`
Eski release modeli: `Samurai (Ronin)`

## Hedef

Samurai, farkli trafik vektorleri (L3/L4/L7) icin ortak bir calistirma modeli sunar:

- Tek CLI arayuzu (`ddos_samurai/cli/` paketi)
- Worker/process modeli (`ddos_samurai/orchestrator.py`)
- Birden fazla sender ve paket/payload engine

Bu dokuman, kod tabaninda degisiklik yapacak kisi icin "nereden baslamali" sorusuna cevap verir.

## Yuksek Seviyede Veri Akisi

1. Giris noktasi: `advv2.py`
2. CLI parse + config merge: `ddos_samurai/cli/app.py`
3. Guvenlik kapilari: `ddos_samurai/utils.py`
4. Worker spawn: `multiprocessing.Process(... orchestrator.start_worker ...)`
5. Worker async dispatch: `ddos_samurai/orchestrator.py:worker_process()`
6. Vektore gore yol secimi:
   - CPU L4/L3: `ddos_samurai/senders.py` + `ddos_samurai/packet.py`
   - GPU L4/L3: `ddos_samurai/gpu_packet.py` + native CUDA backend + sender
   - L7: `ddos_samurai/senders.py` ve `ddos_samurai/l7_emu/*` + `ddos_samurai/l7_emu_native/*`
   - AF_XDP/TX_RING: `ddos_samurai/af_xdp_sender.py`, `fast_sender.c`, `dataplane_core.c`

## Katmanlar ve Sorumluluklar

### CLI (`ddos_samurai/cli/`)

- Arg parse (argparse)
- Config/default birlestirme
- Dry-run / self-test / benchmark-run girisleri
- Safety gate ve profile preflight
- Runtime env bridge (`SAMURAI_*` export)

Paket ici ayrim:

- `app.py`: ince orchestration katmani
- `__main__.py`: `python -m ddos_samurai.cli` bootstrap
- `args.py`: `build_parser()`
- `config.py`: YAML config merge + soak config
- `profile_resolver.py`: profil uygulama ve alias normalization
- `validation.py`: parser/preflight guard'lari
- `offline_modes.py`: self-test, dry-run, gpu-pcap, pcap-info
- `runtime.py`: live run, worker spawn, monitor, final report

### Orkestrator (`ddos_samurai/orchestrator.py`)

- Worker process entrypoint + affinity denemesi
- Backend/vektor dispatch
- L4/L7 sender akislari arasinda route

### Sender katmani (`ddos_samurai/senders.py` + `ddos_samurai/_senders/*`)

- `senders.py`: public facade + uyumluluk noktasi
- `_senders/*`: L2/L3, L7, stats, runtime/context implementasyonlari

### Paket/Payload Uretimi

- CPU (Scapy): `ddos_samurai/packet.py`
- GPU (Numba/CuPy + native CUDA bridge): `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_payload.py`, `ddos_samurai/anomaly_packet.py`

### Runtime Governance, Telemetry ve Profil Katmani

- Benchmark runner: `ddos_samurai/benchmark_profiles.py`
- KPI gate karar katmani: `ddos_samurai/kpi_gate.py`
- Stateful runtime session/hot-path sozlesmesi: `ddos_samurai/stateful_runtime.py`
- In-process metrics store: `ddos_samurai/metrics.py`
- Live textfile exporter: `ddos_samurai/live_metrics.py`
- Workload profile registry: `ddos_samurai/workload_profiles.py`
- TLS/H2 profile adlari: `ddos_samurai/profile_names.py`

Geriye donuk facade/adapter notlari:

- `ddos_samurai/custom_tcp_dataplane.py` -> `l4.state_engine` additive API facade
- `ddos_samurai/l4_state_engine.py` -> backward-compat import facade
- `ddos_samurai/topology_native.py` -> native topology compile/preview bridge
- `ddos_samurai/gpu_cuda_payload/` -> GPU vector plan + stateful request-plan bridge

Bu katmanlarin detayli dokumu: `docs/25-core-runtime-modules.md`.

## GPU-CPU Is Bolumu (pratik)

- GPU: header/payload varyasyon, checksum/mutasyon, paralel random/template coguletme
- CPU: stateful takip, timer/timeout, TX path (socket/TX_RING/AF_XDP), raporlama

Stateful TCP/L7 session tarafi agirlikli olarak CPU/C state engine uzerindedir.

## Repo Gercegi Notu (2026-04-06)

Bu checkout'ta:
- `dashboard/` dizini yok
- `ddos_samurai/api.py` yok
- `ddos_samurai/cli.py` yok; CLI artik `ddos_samurai/cli/` paketi olarak tutuluyor

Bu nedenle UI/API odakli belgeler tarihsel/legacy baglam olarak okunmalidir.

## Calisma Ortami Notlari

- Raw socket, AF_XDP, TX_RING gibi yollar root/capability isteyebilir.
- CUDA yolu driver/runtime uyumuna baglidir.
- CI/sandbox ortamlarinda Scapy/GPU/root gereksinimleri nedeniyle skip veya permission hatalari gorulebilir.
