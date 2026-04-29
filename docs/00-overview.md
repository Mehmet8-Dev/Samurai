# Genel Bakış

Samurai, izinli/lab kullanım için ağ stres ve güvenlik doğrulama platformudur.

## Katmanlar

- CLI: `ddos_samurai/cli/*`
- Orkestrasyon: `ddos_samurai/orchestrator.py`
- Sender facade: `ddos_samurai/senders.py`
- Sender modülleri: `ddos_samurai/_senders/*`
- AF_XDP native: `ddos_samurai/xdp_sender.c`, `ddos_samurai/af_xdp_sender.py`
- GPU packet/classifier: `ddos_samurai/gpu_packet.py`, `ddos_samurai/_gpu_packet_cuda_backend.py`

## Aktif Yol

- L2/L3 gönderim için XDP backend zorunlu/policy fail.
- GPU defense/classifier, send-path içinde opsiyonel (`gpu_defense_mode=on`).
- Native RX->GPU classify pipeline, `af_xdp_sender.run_gpu_rx_pipeline()` üzerinden çalışır.
