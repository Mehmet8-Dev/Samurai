# Samurai (Kenjaku)

Samurai, **yalnizca yetkili ortamlarda** kullanilmak uzere tasarlanmis moduler bir ag stres ve guvenlik test platformudur.

## Surum Isimleri

- Teknik surum (SemVer): `2.1.0`
- Mevcut kod adi: `Kenjaku`
- Eski kod adi: `Ronin`

Odak alanlari:

- L3/L4/L7 trafik ve davranis testleri
- CPU + C extension + opsiyonel CUDA hizlandirma
- Profil tabanli benchmark, run-report ve telemetry

## Durum (2026-04-12)

- Aktif cekirdek: `advv2.py` + `ddos_samurai/cli/` + `orchestrator/senders`
- Aktif hizli yollar: `fast_sender.c`, `pacing_engine.c`, `xdp_sender.c`, `dataplane_core.c`
- Aktif GPU yolu: Python bridge + native CUDA (`ddos_samurai/libgpu_packet_cuda.so`)
- Aktif stateful L7 yolu: `ddos_samurai/l7_emu/`* + `ddos_samurai/l7_emu_native/*`
- Aktif GPU vector planner yolu: `ddos_samurai/gpu_cuda_payload/*` + `_gpu_cuda_payload_native`
- Repo kokunde `dashboard/` dizini yok.
- Repo icinde `ddos_samurai/api.py` yok.

Not: `docker-compose.yml` icinde `api`/`dashboard` servis tanimlari var; bu checkout'ta ilgili kaynaklar bulunmadigi icin dogrudan calismaz.

## Yasal ve Etik Sinir

Bu proje sadece izinli hedeflerde kullanilmalidir.
Yetkisiz sistemlere trafik gondermek yasa disi olabilir ve tum sorumluluk kullanicidadir.

## Ana Bilesenler

- CLI giris: `advv2.py`, `ddos_samurai/cli/`
- CLI paket yapisi: `app.py`, `args.py`, `config.py`, `profile_resolver.py`, `validation.py`, `offline_modes.py`, `runtime.py`
- Worker/dispatch: `ddos_samurai/orchestrator.py`
- Sender facade + ic moduller: `ddos_samurai/senders.py`, `ddos_samurai/_senders/*`
- Stateful runtime + topology: `ddos_samurai/stateful_runtime.py`, `ddos_samurai/topology_native.py`, `ddos_samurai/custom_tcp_dataplane.py`
- CPU paket yolu: `ddos_samurai/packet.py`, `ddos_samurai/cpu_packet_engine.py`
- GPU paket/payload: `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_payload.py`, `ddos_samurai/anomaly_packet.py`
- GPU CUDA payload planner: `ddos_samurai/gpu_cuda_payload/`
- Native CUDA ABI: `ddos_samurai/gpu_packet_cuda.hpp`, `ddos_samurai/gpu_packet_cuda/*`, `ddos_samurai/libgpu_packet_cuda.so`
- C hizlandirma: `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c`, `ddos_samurai/xdp_sender.c`, `ddos_samurai/dataplane_core.c`
- Monitoring stack: `monitoring/`

## Desteklenen Yol ve Vektorler (aktif kod)

- Compute backend: `cpu`, `cuda`
- L3/L4: TCP, UDP, ICMP, spoofing, fragment, pcap replay
- L7: HTTP/HTTP2/QUIC (`python` / `c_state` secimli, stateful runtime V1)
- Diger: anomaly/fuzz benzeri malformed paket varyasyonlari, amplification senaryolari

Not:

- `websocket` attack-vector mevcut checkout'ta L7 emu V1 strict yolunda fail-visible kapatilidir.

## Kurulum

### 1) Python bagimliliklari

```bash
pip install -r requirements.txt
```

### 2) C extension build

```bash
python setup.py build_ext --inplace
```

### 3) Opsiyonel CUDA

```bash
pip install cupy-cuda12x numba-cuda[cu13]
python setup.py build_ext --inplace
```

## GPU Native Path Knob'lari

- `--gpu-template-pool-size-l4` (`SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4`)
- `--gpu-template-pool-size-l7` (`SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7`)
- `--gpu-ring-capacity` (`SAMURAI_GPU_RING_CAPACITY`)
- `--gpu-stream-count` (`SAMURAI_GPU_STREAMS`)
- `--gpu-pipeline-depth` (`SAMURAI_GPU_PIPELINE_DEPTH`)
- `--gpu-pinned-max-mb` (`SAMURAI_GPU_PINNED_MAX_MB`)
- `--gpu-packet-zerocopy-output` (`SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT`)

`--gpu-packet-zerocopy-output` acikken native CUDA output buffer mapped host memory'e alinabilir; bu mod her topolojide daha hizli olmak zorunda degildir, benchmark ile dogrulanmalidir.

Native CUDA bridge akisi:

- `device mem -> (async D2H veya mapped host) -> host-ready buffer`
- `--gpu-stream-count` + `--gpu-pipeline-depth` ile double-buffer/queue overlap
- Host-ready olmayan native cagrilarda `samurai_gpu_packet_wait()` bariyeri uygulanir

## Hizli Baslangic

### Self-test (trafik gondermez)

```bash
python -m ddos_samurai.cli --self-test
```

### Dry-run (gonderim yapmaz)

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 8080 \
  --protocol tcp --attack-vector basic \
  --count 100 --dry-run --confirm
```

### Profil listesi

```bash
python -m ddos_samurai.cli --list-profiles
```

## Monitoring (opsiyonel)

```bash
cd monitoring
docker compose up -d
```

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

## Test

```bash
pytest tests -q -rs
```

Ornek hedefli testler:

```bash
PYTHONPATH=. pytest -q tests/test_cli_parser.py
PYTHONPATH=. pytest -q tests/native_gpu/test_cuda_backend_bridge.py
PYTHONPATH=. pytest -q tests/test_l7_emu_v1.py tests/test_stateful_topology_contract.py
PYTHONPATH=. pytest -q tests/test_gpu_cuda_payload_facade.py
```

## Benchmark Profilleri

```bash
python -m ddos_samurai.benchmark_profiles --profile dev --run
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run
sudo python -m ddos_samurai.benchmark_profiles --profile dedicated_lab --run
```

## Dokumantasyon

- `docs/README.md`
- `docs/00-overview.md`
- `docs/01-cli.md`
- `docs/03-senders.md`
- `docs/05-gpu.md`
- `docs/16-l7-stateful-phase2-phase3-update.md`
- `docs/18-afpacket-hugepage-policy.md`
- `docs/20-env-cli-reference.md`
- `docs/26-cli-package-deep-map.md`
- `docs/27-gpu-cuda-payload.md`

## Proje Dizini (kisa)

```text
.
├── advv2.py
├── ddos_samurai/
├── tests/
├── docs/
├── monitoring/
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Lisans

`setup.py` siniflandirmasinda MIT lisansi belirtilmistir.