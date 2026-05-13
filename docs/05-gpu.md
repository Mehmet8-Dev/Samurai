# GPU

Bu belge GPU packet/payload ve classifier katmaninin mevcut uygulamasini aciklar.

## Bilesenler

1. Packet generation backend
- Native lib: `ddos_samurai/libgpu_packet_cuda.so`
- Python facade: `ddos_samurai/gpu_packet.py`
- Duzey bridge: `ddos_samurai/_gpu_packet_cuda_backend.py`

2. Defense/classifier backend
- Native lib: `ddos_samurai/libgpu_packet_cuda_defense.so`
- Kernel glue: `ddos_samurai/gpu_packet_cuda/kernels_defense_*.cuh`

3. GPU payload planner
- `ddos_samurai/gpu_cuda_payload/*`
- CUDA kernels + pybind bridge + Python facade

## Runtime Parametreleri (Ozet)

- `--gpu-defense-mode on|off`
- `--gpu-classifier-runtime tensorrt`
- `--gpu-classifier-engine-path <engine>`
- `--gpu-rdma-mode auto|direct|host_staging|doca_gpunetio`
- `--gpu-rdma-strict`
- `--gpu-batch-max`
- `--gpu-batch-flush-timeout-ms`

Detayli env/cli mapping icin: `docs/20-env-cli-reference.md`

## DOCA GPUNetIO Modu (Hybrid + Strict)

`doca_gpunetio`, mevcut yapiyi kaldirmadan eklenen yeni backend hattidir.

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
