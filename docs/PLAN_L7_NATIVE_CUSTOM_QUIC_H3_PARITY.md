# L7 Native Custom QUIC/H3 Full Parity Yol Haritası

## Neden minimalden başlandı?
- İlk teslim, eski Python QUIC tabanının kaldırılmasını güvenli tamamlamak için **transport + minimal H3** kapsamıyla sınırlandı.
- Amaç, orchestrator sözleşmesini kırmadan tek native kaynakta çalışır bir QUIC tabanı oluşturmaktı.
- Bu aşama artık tamamlandı; sonraki hedef tam H3 parity.

## Hedef Fazlar
- Faz 1 (tamam): minimal H3 request/response, fail-visible QUIC metrik sözleşmesi, native-core tek kaynak.
- Faz 2 (aktif): H3 control-plane parity (`GOAWAY`, graceful drain, replacement kararları).
- Faz 3: QPACK dynamic table parity (encoder/decoder state, eviction, header compression doğruluğu).
- Faz 4: advanced stream semantics (`PRIORITY_UPDATE`, `EXTENDED_CONNECT`, backpressure davranışı).
- Faz 5: full parity (`DATAGRAM`, server-push politikaları, regresyon matrisi ve KPI stabilization).

## Faz 2 Kabul Kriterleri
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
- `_senders` adapter katmanı aynı anahtarları capability yokken de default/fail-visible üretebilmeli.

## Not
- Faz 2 ile birlikte hedef artık “minimal client” değil, **parity roadmap’e bağlı incremental full H3** yaklaşımıdır.
