# 05 - GPU Yolları

## Kapsam

Projede GPU kullanımı iki ana hatta ayrılır:

1. `gpu_packet.py`: L3/L4 paket üretim hızlandırması
2. `gpu_cuda_payload/`: L7 payload/vector planlama hızlandırması

## Operasyonel Gerçek

- GPU, çoğu senaryoda üretim/planner hızlandırıcısıdır
- Ağ I/O ve stateful kontrol akışının önemli kısmı CPU/C katmanında kalır

## Kritik Knob'lar

- `--gpu-template-pool-size-l4`
- `--gpu-template-pool-size-l7`
- `--gpu-ring-capacity`
- `--gpu-batch-size`
- `--gpu-stream-count`
- `--gpu-pipeline-depth`
- `--gpu-packet-zerocopy-output`
- `--gpu-kernel-mode {batch,persistent}`
- `--gpu-stream-api {compat,stream}`

## Persistent Mod Notu

`gpu-kernel-mode=persistent` + `gpu-stream-api=stream` kombinasyonu env tarafında daha katı TX backend davranışı tetikler (`SAMURAI_GPU_TX_BACKEND_STRICT=1`).

## Doğrulama

Performans iddiaları sistemden sisteme değişir; özellikle `zerocopy-output` için benchmark karşılaştırması şarttır.
