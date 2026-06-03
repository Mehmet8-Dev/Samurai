# 33 - DOCA GPUNetIO Mimari ve Operasyon Notlari

- Tarih: 2026-05-13
- Guncelleme: 2026-06-03
- Kapsam: CUDA persistent/stream runtime, DOCA GPUNetIO, DPU/GPU flow-state contract
- Durum: Kod entegrasyonu mevcut; donanim lab KPI kapanisi ayri kosudur

## 1) Mevcut Mimari

DOCA GPUNetIO artik GPU TX backend ailesinin bir uyesidir. Local process
boundary ZMQ worker runtime ile, dataplane state contract ise `gpu_packet_cuda`
altinda tutulur.

Ana bilesenler:

- ZMQ DOCA worker: `ddos_samurai/zmq/daemon/doca_gpunetio_worker.cpp`
- DPU authoritative state runtime: `ddos_samurai/gpu_packet_cuda/dpu_state_runtime.hpp`
- DOCA GPUNetIO ABI: `ddos_samurai/gpu_packet_cuda/tx_backend_doca_gpunetio.cuh`
- DOCA backend bridge: `ddos_samurai/gpu_packet_cuda/doca_gpunetio_backend.cpp`
- GPU worker hot-flow receiver: `ddos_samurai/zmq/daemon/gpu_worker.cpp`

## 2) Runtime Akisi

1. CLI/orchestrator DOCA worker'a ZMQ `START_JOB` gonderir.
2. DOCA worker native DOCA backend'i yukler.
3. TXQ/RXQ ve opsiyonel contract writer acilir.
4. `FlowStateTable` flow state'i olusturur.
5. DPU state, GPU worker'a `FLOW_STREAM_UPSERT` ve `FLOW_UPDATE` yollar.
6. TX batch'ler `send_vector` ile gonderilir.
7. RX feedback aciksa ACK/SYN/FIN/RST paketleri `receive_burst` ile state'e islenir.
8. Retransmit, zero-window, pause ve quota kararlari GPU stream policy'ye yansitilir.

## 3) Strict/Fallback Politikasi

`persistent + stream` modunda backend kontrati:

- `SAMURAI_GPU_TX_BACKEND` yalnizca `af_xdp|af_packet|doca_gpunetio`
- `SAMURAI_GPU_TX_BACKEND_STRICT=1` zorlanir (preflight)
- `doca_gpunetio` seciminde:
  - `SAMURAI_GPU_DOCA_ENABLE=1` zorunlu
  - `SAMURAI_GPU_DOCA_DEVICE` zorunlu (orn: `mlx5_0`)
  - `--xdp-interface` zorunlu

Bu davranis fallback yerine fail-fast stratejisini korur.

## 4) DPU/GPU Contract Basliklari

- `dpu_state_runtime.hpp` ZMQ dizininde degil, `gpu_packet_cuda` altindadir.
- DPU state event'leri version/epoch tasir.
- GPU'ya iki ana event akar: `FLOW_UPDATE` ve `FLOW_STREAM_UPSERT`.
- Policy template bitleri pause, retransmit ve zero-window-probe bilgisini tasir.
- DOCA worker, DPU state'i GPU worker job endpoint'ine non-blocking ZMQ publish eder.

## 5) Donanim Olmadan Dogrulama

Donanim yokken kosulabilen dogrulama:

```bash
PYTHONPATH=. pytest tests/test_zmq_wire_contract.py -q
PYTHONPATH=. pytest tests/test_zmq_m3_workers.py -q
PYTHONPATH=. pytest tests/native_gpu/test_backend_facade.py -q
```

Beklenti:

- ZMQ wire ABI ve DPU state header smoke testleri dogrulanir
- Worker source/layout kontratlari dogrulanir
- Backend facade kontratlari dogrulanir
- Gercek line-rate/perf metrikleri dogrulanmaz (lab gerekir)

## 6) Donanimli Lab Kapanisi

- E2E TX latency ve Mpps
- RX feedback latency
- DPU->GPU update latency
- Queue scaling ve jitter dagilimi
- GPU/NIC ayni PCIe switch topoloji etkisi

## 7) Ilgili Belgeler

- [05 - GPU](./05-gpu.md)
- [20 - Env + CLI Tam Referans](./20-env-cli-reference.md)
- [36 - ZMQ Worker Architecture](./36-zmq-worker-architecture.md)
- [37 - DPU/GPU Dataplane Architecture](./37-dpu-gpu-dataplane-architecture.md)
- [ADR: DOCA Hybrid + Strict](./adr/2026-05-13-doca-gpunetio-hybrid-strict.md)
- [Perf: DOCA GPUNetIO Progress Report](./perf/doca-gpunetio-progress-report.md)
