# GPU

## Bileşenler

- Packet üretim backend: `libgpu_packet_cuda.so`
- Defense/classifier backend: `libgpu_packet_cuda_defense.so`
- Python bridge: `ddos_samurai/_gpu_packet_cuda_backend.py`

## Classifier Akışı

- Init: runtime/engine/rdma policy ile backend açılır.
- Classify: batch `classify_batch()` çağrılır.
- Stats: classifier telemetrisi `read_classifier_stats()` ile okunur.

## Native RX->GPU

- AF_XDP RX API: `xdp_sender.c` (`xdp_recv_ctx`)
- Runtime bridge: `af_xdp_sender.run_gpu_rx_pipeline()`
- Çıktı: `gpu_rx_packets_total`, `gpu_rx_suspicious_total`, `gpu_rx_pps`, `gpu_classifier_*`
