# 03 - Senders (Facade + Internal Modules)

## Rol

`ddos_samurai/senders.py`, dış API yüzeyini sabit tutan facade katmanıdır. Gerçek implementasyonlar `ddos_samurai/_senders/*` altında bulunur.

## Neden Bu Yapı

- Dış uyumluluğu korur
- Büyük tek dosya riskini azaltır
- L2/L3, L7, stats, runtime sorumluluklarını ayırır

## İç Modül Haritası

- `_senders/runtime.py`: backend/policy çözümleme
- `_senders/stats_core.py`: stats, pacing, loss hesapları
- `_senders/buffer_norm.py`: buffer normalize/pinned kopya yardımcıları
- `_senders/context.py`: sender context yaşam döngüsü
- `_senders/l2l3_entry.py`, `_senders/l2l3_raw.py`: raw gönderim yolları
- `_senders/l7_quic.py` ve diğer `l7_*` modülleri: L7 yolları
- `_senders/legacy_attacks.py`: legacy slow/amplification yolları

## Güncel Politikalar

CLI tarafında seçim daraltıldığı için sender route’u pratikte daha katıdır:

- backend: `xdp`
- fallback policy: `fail`

Bu, eski belgelerdeki esnek fallback zincirlerini operasyonel olarak sınırlar.

## Dış API Örneği

- `packet_sender`
- `paced_raw_socket_sender`
- `http_app_sender`, `http2_sender`, `quic_sender`
- `close_sender_context`
