# L7 Native Custom QUIC/H3 Full Parity Yol Haritası

## Neden minimalden başlandı?
- İlk teslim, eski Python QUIC tabanının kaldırılmasını güvenli tamamlamak için **transport + minimal H3** kapsamıyla sınırlandı.
- Amaç, orchestrator sözleşmesini kırmadan tek native kaynakta çalışır bir QUIC tabanı oluşturmaktı.
- Bu aşama artık tamamlandı; sonraki hedef tam H3 parity.

## Hedef Fazlar
- Faz 1 (tamam): minimal H3 request/response, fail-visible QUIC metrik sözleşmesi, native-core tek kaynak.
- Faz 2 (tamam — runtime event): H3 control-plane parity (`GOAWAY`, graceful drain, replacement kararları). Gerçek GOAWAY frame / `shutdown` cb / client shutdown notice → `h3_goaway_events` + `h3_drain_cycles`; sahte hard-failure GOAWAY kaldırıldı.
- Faz 3 (tamam — runtime event): QPACK dynamic table parity — encoder/decoder stream insert sayacı + capacity eviction approx → `quic_h3_qpack_*` + `quic_h3_qpack_dynamic_ready`.
- Faz 4 (tamam — runtime event): `PRIORITY_UPDATE` (stream priority apply + ack) ve `EXTENDED_CONNECT` event bağları.
- Faz 5 (hot-path + full parity iskeleti tamam): `DATAGRAM` TX/RX, server-push / cancel-on-promise politikası; AF_PACKET/AF_XDP UDP datapath; regresyon matrisi KPI’ları mevcut şemada.

## UDP I/O backend kodları
`quic_runtime_udp_io_backend` / `quic_runtime_backend_requested`:
- `0` = kernel_socket (`quic_runtime_native_hot_path_ready=0`)
- `1` = af_xdp (ready=1)
- `2` = dpdk (ready=1; native path şu an no-op → fallback veya strict fail)
- `3` = af_packet (ready=1; `udp_io.cpp` L2 IPv4/UDP frame + `AF_PACKET` SOCK_RAW)

Seçim: profile `stateful_runtime_backend` veya `SAMURAI_STATEFUL_RUNTIME_BACKEND`
(`af_packet` / `afpacket` / `packet` / `raw`, `afxdp`, `dpdk`, aksi kernel).

AF_PACKET için: `SAMURAI_XDP_INTERFACE` veya `SAMURAI_AF_PACKET_IFACE`, dst MAC
(`SAMURAI_AF_PACKET_DST_MAC` / `SAMURAI_QUIC_AF_XDP_DST_MAC` / ARP lookup).

## Faz 2–5 Kabul Kriterleri (metrik anahtarları)
- `custom_quic_stack` içinde parity-state modeli bulunmalı ve metrik olarak dışarı verilmeli.
- `custom_quic_stack` içinde H3 control-plane (`GOAWAY/drain/replacement`) için ayrı modül ve metrik üretimi olmalı.
- QUIC sonuçlarında aşağıdaki anahtarlar stabil olmalı:
  - `quic_h3_parity_phase`
  - `quic_h3_parity_target_phase`
  - `quic_h3_parity_progress_ratio`
  - `quic_h3_parity_gap`
  - `quic_h3_control_stream_ready`
  - `quic_h3_qpack_dynamic_ready`
  - `quic_h3_goaway_ready`
  - `quic_h3_priority_update_ready`
  - `quic_h3_extended_connect_ready`
  - `quic_h3_datagram_ready`
  - `quic_h3_server_push_ready`
  - `quic_h3_goaway_events`
  - `quic_h3_drain_cycles`
  - `quic_h3_replace_now`
  - `quic_h3_replace_after_idle`
  - `quic_h3_control_plane_failures`
  - `quic_h3_graceful_close_ratio`
  - `quic_h3_qpack_encoder_inserts` / `quic_h3_qpack_decoder_inserts` / `quic_h3_qpack_evictions`
  - `quic_runtime_native_hot_path_ready`
- `h3_real_client` bilinçli shim: `run_h3_ngtcp2_client` delegasyonu (ayrı stack yok).

## Not
- Parity hedefi **incremental full H3**: opcode’lar (`H3_GOAWAY`, `H3_QPACK_DYNAMIC`, `H3_PRIORITY_UPDATE`, `H3_EXTENDED_CONNECT`, `H3_DATAGRAM`, `H3_SERVER_PUSH`) profile `ops` üzerinden istenir; ready bayrakları gerçek event sayaçlarına bağlıdır.
- Sonraki iş: Faz 6 concurrency ölçek, Faz 7 L2 emu, Faz 8 CI `test_l7_*` suite (Faz 0 `test_l7_dispatch` iskeleti mevcut).
