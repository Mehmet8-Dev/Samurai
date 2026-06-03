# GPU

Bu belge GPU packet/payload, classifier ve DPU/GPU contract katmaninin mevcut
uygulamasini aciklar.

## Bilesenler

1. Packet generation backend
- Native lib: `ddos_samurai/libgpu_packet_cuda.so`
- Python facade: `ddos_samurai/gpu_packet.py`
- Native kaynaklar: `ddos_samurai/gpu_packet_cuda/*`

2. Defense/classifier backend
- Native lib: `ddos_samurai/libgpu_packet_cuda_defense.so`
- Kernel glue: `ddos_samurai/gpu_packet_cuda/kernels_defense_*.cuh`

3. GPU payload planner
- `ddos_samurai/gpu_cuda_payload/*`
- CUDA kernels + pybind bridge + Python facade

4. DPU/GPU state contract
- Authoritative DPU state runtime: `ddos_samurai/gpu_packet_cuda/dpu_state_runtime.hpp`
- DOCA GPUNetIO ABI: `ddos_samurai/gpu_packet_cuda/tx_backend_doca_gpunetio.cuh`
- DOCA backend bridge: `ddos_samurai/gpu_packet_cuda/doca_gpunetio_backend.cpp`

## Runtime Parametreleri (Ozet)

- `--gpu-defense-mode on|off`
- `--gpu-classifier-runtime tensorrt`
- `--gpu-classifier-engine-path <engine>`
- `--gpu-rdma-mode auto|direct|host_staging|doca_gpunetio`
- `--gpu-rdma-strict`
- `--gpu-batch-max`
- `--gpu-batch-flush-timeout-ms`

Detayli env/cli mapping icin: `docs/20-env-cli-reference.md`

## ZMQ Worker Runtime Iliskisi

GPU ve DOCA yollarinda ZMQ bir dataplane degildir. ZMQ, CLI/orchestrator ile
local native worker daemon'lari arasindaki job/event IPC katmanidir.

- GPU worker: `ddos_samurai/zmq/daemon/gpu_worker.cpp`
- DOCA worker: `ddos_samurai/zmq/daemon/doca_gpunetio_worker.cpp`
- Wire contract: `ddos_samurai/zmq/wire.py`, `ddos_samurai/zmq/daemon/wire_protocol.h`

Detay: `docs/36-zmq-worker-architecture.md`

## DPU/GPU Dataplane Contract

DOCA worker, DPU authoritative state'i `gpu_packet_cuda/dpu_state_runtime.hpp`
uzerinden yurutur. Bu runtime TCP state, retransmit, zero-window, passive-open
ve GPU stream policy kararlarini uretir. GPU worker'a `FLOW_UPDATE` ve
`FLOW_STREAM_UPSERT` mesajlari publish edilir.

Detay: `docs/37-dpu-gpu-dataplane-architecture.md`

## DOCA GPUNetIO Modu

`doca_gpunetio`, GPU TX backend seceneklerinden biridir. Strict modda ortam
uygun degilse fallback yerine fail-visible hata beklenir.

Pratik notlar:

- Persistent + stream modunda backend strict preflight ile dogrulanir.
- `doca_gpunetio` seciminde zorunlu env/parametreler:
  - `SAMURAI_GPU_DOCA_ENABLE=1`
  - `SAMURAI_GPU_DOCA_DEVICE` (orn: `mlx5_0`)
  - `--xdp-interface`
- Uygun olmayan ortamda fallback yerine fail-visible davranis beklenir.

Detayli gecis durumu:
- `docs/33-doca-gpunetio-migration-status.md`

## Send-Path Classifier Akisi

1. Sender path paket buffer olusturur
2. `gpu_defense.classify_packets_if_enabled` devreye girer
3. Hard fail policy tetiklenirse sender early-exit yapar
4. Classifier stats run raporuna eklenir

## Native RX -> GPU Pipeline

Ana akis `af_xdp_sender.run_gpu_rx_pipeline()`:

- AF_XDP RX capture
- Batch classify (TensorRT runtime)
- Suspicious toplam/pps metrikleri

CLI tetikleme:

```bash
python -m ddos_samurai.cli \
  --gpu-rx-pipeline on \
  --gpu-rx-iface eth0 \
  --gpu-rx-duration-s 10
```

## Sinirlar ve Dikkat Noktalari

- GPU yolu opsiyoneldir; CPU fallback/alternatif yollar ayri tutulur
- RDMA strict mod ortam uyumsuzlugunda fail-visible davranir
- Benchmark sonuclarinda GPU classifier acik/kapali durumlar ayri raporlanmalidir
