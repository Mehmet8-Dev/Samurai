# 03 - Senders (Strict Facade + Internal Modules)

## Rol

`ddos_samurai/senders.py` artik bir "strict facade" katmanidir.
Dis API'yi sabit tutar, asil implementasyon ise `ddos_samurai/_senders/*` modullerine dagitilmistir.

Amac:

- dis bagimliliklari ve test monkey-patch noktalarini korumak
- buyuk/monolith dosya riskini azaltmak
- L2/L3, L7, stats, runtime import ve context sorumluluklarini ayirmak

## Public API (Degismeyen Yuzey)

Facade'de korunmus fonksiyonlar:

- `send_packet_async`, `packet_sender`
- `get_gateway_info`, `xdp_sender`, `raw_socket_sender`, `paced_raw_socket_sender`
- `http_app_sender`, `http_stateful_sender`, `http2_sender`
- `websocket_sender`, `websocket_scenario_sender`
- `quic_sender`
- `slow_attack_sender`, `amplification_sender`
- `close_sender_context`

Korunan patch/test noktalarindan ornekler:

- `FAST_SENDER_AVAILABLE`, `HTTPX_AVAILABLE`, `WEBSOCKETS_AVAILABLE`, `HYPER_H2_AVAILABLE`
- `_estimate_paced_packets`, `_apply_pacing_stats`, `_scapy`

## Icerik Haritasi (`_senders/*`)

| Modul | Sorumluluk |
|---|---|
| `_senders/runtime.py` | Lazy import, backend/fallback policy resolve, opsiyonel bagimlilik yukleme |
| `_senders/stats_core.py` | `_stats`, pacing/loss metrikleri, normalize/merge yardimcilari |
| `_senders/buffer_norm.py` | GPU/CPU buffer normalize ve pinned-copy yardimcilari |
| `_senders/context.py` | sender context lifecycle (`close_sender_context`) |
| `_senders/l2l3_entry.py` | `get_gateway_info`, `xdp_sender` giris noktalari |
| `_senders/l2l3_raw.py` | `raw_socket_sender`, `paced_raw_socket_sender` ve L2/L3 fallback zinciri |
| `_senders/l7_http1_simple.py` | HTTP/1.1 legacy/simple sender |
| `_senders/l7_http1_stateful.py` | HTTP stateful sender (VU/workflow) |
| `_senders/l7_http2.py` | HTTP/2 sender (c_state route + python/hyper-h2) |
| `_senders/l7_ws_simple.py` | Basit websocket sender |
| `_senders/l7_ws_scenario.py` | Stateful websocket scenario sender |
| `_senders/l7_quic.py` | QUIC sender (native/bridge/legacy route semantigi) |
| `_senders/legacy_packet.py` | Scapy tabanli packet sender yollari |
| `_senders/legacy_attacks.py` | slow-* ve amplification legacy akislari |

Not: `senders.py` facade bu modulleri cagirirken log/stats/runtime bagimliliklarini parametre olarak enjekte eder.

## L2/L3 Akis Ozeti

`raw_socket_sender` ve `paced_raw_socket_sender`:

1. policy (`sender_backend`, `sender_fallback_policy`) normalize edilir
2. varsa dataplane session yolu denenir
3. L2/L3 hizli yollar sirayla denenir (TX_RING, C_EXT_L3, Python)
4. sonuc `_stats` semasi ile normalize edilip doner

Temel gozlemlenebilirlik alanlari:

- `sender_path`, `sender_fallback_reason`, `fallback_count`
- `permission_error_count`
- pacing aktifse `actual_rps`, `rate_accuracy_pct`, `jitter_p99_ns`
- TX_RING/PACKET istatistik alanlari (flush counters, tp_packets/tp_drops, vb.)

## L7 Akis Ozeti

L7 sender fonksiyonlari facade'de kalir, fakat uygulama `_senders/l7_*` dosyalarinda:

- `http_stateful_sender`, `http2_sender`, `websocket_scenario_sender`, `quic_sender`
  once `l7.dispatch` + `l7.c_adapter` ile route edilir
- profile/capability kurali fallback'i kisitlayabilir (`l7_capability_strict`, dedicated profile)
- QUIC icin `l7_quic_require_native=true` oldugunda native disi yollar fail-visible olur

## AF_XDP ve Raw Backend Iliskisi

- `xdp_sender` giris noktasi `_senders/l2l3_entry.py` icindedir
- AF_XDP uygun degilse policy'ye gore raw sender'a geri doner
- runtime bagimliliklar (`XDP_AVAILABLE`, `XDPSender`, `check_xdp_available`) facade'den enjekte edilir

## Context ve Kaynak Yonetimi

- Public kapanis fonksiyonu: `senders.close_sender_context(...)`
- implementasyon: `_senders/context.py`
- amac: persistent sender/dataplane kaynaklarini worker kapanisinda deterministik temizlemek

## Katki Kurallari (Yeni Yapi)

- disaridan cagri semasi degistirilmemeli; degisiklik once facade uyumlulugu uzerinden degerlendirilmeli
- yeni helper/sorumluluk eklenirse once `_senders/*` icine alinmali
- `senders.py` icinde is kurali yazmak yerine delege eden ince wrapper tercih edilmeli
- regresyonlarda oncelikli testler:
  - `tests/test_senders_import_fallback.py`
  - `tests/test_senders_facade_runtime_forwarding.py`
  - `tests/test_senders_http2.py`
  - `tests/test_senders_pacing_progress.py`
  - `tests/test_afpacket_hugepage_policy.py`
