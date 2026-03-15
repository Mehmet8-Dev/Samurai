# 05 - GPU Engine (gpu_packet.py + native CUDA backend)

## Rol

GPU yolu iki ana hedefe hizmet eder:

- Paket/payload uretimini paralellestirmek
- Uretilen batch'i CPU TX hattina verimli sekilde beslemek

Kod tabaninda hem Python tarafi (Numba/CuPy) hem native CUDA C++ ABI yolu vardir.

## Guncel Durum (2026-03-15)

1. L3/L4 paket uretim hot-path:
   - GPU generate (header/checksum/random/template mutate)
   - Cikti CPU TX hattina verilir
2. L7 planner/payload path:
   - GPU varyasyon/planning hizlandiricisi
   - Gercek state + socket I/O CPU/C state engine tarafinda

Yani L7 icin tam bir GPU network stack yok; GPU burada generator/planner rolu oynar.

## D2H ve Zero-Copy Output

Varsayilan davranis:
- Native CUDA cikti device memory'de olusur
- Export asamasinda host tarafa D2H copy yapilir
- Stream verildiginde D2H `cudaMemcpyAsync` ile queue'lanir (hemen stream sync yok)
- Senkronizasyon bariyeri:
  - `return_host_ready=True`: orchestrator `ready_event` ile bekler
  - `return_host_ready=False`: Python bridge `samurai_gpu_packet_wait()` ile bekler

Opsiyonel davranis:
- `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT=1`
- veya CLI: `--gpu-packet-zerocopy-output`
- Native output buffer `cudaHostAllocMapped` ile acilir
- Kernel mapped host alana yazar; export'ta ekstra D2H adimi atlanir
- Hazirlik senkronu yine stream event/wait bariyerleri ile yapilir

Notlar:
- Bu knob native CUDA path icindir.
- Her GPU/PCIe topolojisinde performans kazanci garanti degildir.
- A/B benchmark ile karar verilmelidir.
- AF_PACKET TX_RING kullaniminda son adimda ring frame'e `memcpy` halen vardir (UMEM/XDP degilse tam wire-level zero-copy olmaz).

## Pipeline Knob'lari

- `--gpu-template-pool-size-l4`
- `--gpu-template-pool-size-l7`
- `--gpu-ring-capacity`
- `--gpu-stream-count`
- `--gpu-pipeline-depth`
- `--gpu-full-variation`
- `--gpu-pinned-max-mb`
- `--gpu-packet-zerocopy-output`

## Backpressure ve Ring

Producer-consumer ring kullanilir:
- bounded queue (`SAMURAI_GPU_RING_CAPACITY`, default `3`)
- queue doldugunda producer bekler (drop yerine backpressure)
- telemetry: `gpu_ring_depth_peak`, `gpu_ring_block_wait_ns`

## Pinned Host Pool Limiti

Pinned host buffer pool limit-aware calisir:
- limit: `SAMURAI_GPU_PINNED_MAX_MB` (default `512`)
- LRU eviction + oversize bypass
- telemetry: `pool_evictions`, `oversize_bypass`, `high_watermark_bytes`

## Cekirdek Fonksiyonlar

`ddos_samurai/gpu_packet.py` tarafinda orchestrator'in kullandigi baslica API'ler:
- `generate_packets_from_template_pool(...)`
- `generate_amplification_packets(...)`
- `generate_stateful_packets(...)`
- `generate_fragmented_packets(...)`
- `copy_gpu_to_host_pinned(...)` (D2H/pinned copy yolu)

Native CUDA export yolunda zero-copy aciksa ek D2H atlanabilir; bu, `gpu_packet.py` tarafindaki genel pinned-copy API'sini tamamen ortadan kaldirmaz.
