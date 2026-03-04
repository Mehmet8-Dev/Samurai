# 03 - Senders (ddos_samurai/senders.py)

## Rol

Sender katmani, "uretilmis bir seyi hedefe iletme" sorumlulugunu tasir.
Bu, iki ana gruba ayrilir:

- Paket tabanli (L3/L2): Scapy / raw socket / C extension / AF_XDP
- Uygulama tabanli (L7): httpx, websockets, aioquic

## CPU Paket Sender (Scapy)

- `packet_sender(packet_config, count, delay, rps, jitter, ramp, verbose)`
  - Her iterasyonda `packet_utils.create_packet(cfg)` cagrilir.
  - Fragmentation aciksa `scapy.fragment()` ile paket listeye genisler.
  - `send_packet_async` ile thread executor uzerinden gonderilir.

Not: Fragmentation karari builder'da degil sender'da uygulanir (builder tek paket dondurur).

## Raw Socket Sender (L3/L2 Fast Path)

- `raw_socket_sender(packets_buffer, target_ip, target_port, count, verbose, ..., force_l2=False)`
  - `socket.SOCK_RAW` uzerinden L3 gonderim (genelde root ister).
  - Varsa `fast_sender` C eklentisi ile hizli gonderim:
    - `send_ring_optimized`: L2 TX_RING (Ether header gerekir)
    - `send_optimized`: L3 sendmmsg benzeri hizlandirma
  - Yoksa Python `sendmmsg` veya `sendto` fallback.

`force_l2=True` davranisi:

- L2 yolu kullanilamazsa sessiz L3 fallback yapmaz.
- `sender_path=L2_UNAVAILABLE` ile fail-visible sonuc doner.

`packets_buffer` beklenen format:

- Birden fazla paketin ardarda dizildigi "contiguous bytes buffer"
- `packet_size = len(buffer) // count` varsayimi ile dilimlenir.

Bu sebeple GPU tarafinda paketlerin sabit boyda uretilmesi kritik.

## AF_XDP Sender

- `xdp_sender(...)` fonksiyonu AF_XDP uygun degilse `raw_socket_sender`'a geri duser.
- Asil AF_XDP implementasyonu `ddos_samurai/af_xdp_sender.py` icindedir.

## L7 Sender'lar

- HTTP/1.1: `http_app_sender` (httpx)
- HTTP/1.1 Stateful: `http_stateful_sender` (VirtualUser pool)
- HTTP/2: `http2_sender` (`httpx` veya `hyper-h2`)
- WebSocket: `websocket_sender` (websockets)
- WebSocket Stateful Scenario: `websocket_scenario_sender` (auth -> subscribe -> ping/pong)
- QUIC/HTTP3: `quic_sender` (aioquic)
- Slow-* akislari: `slow_attack_sender` (baglanti/soket davranisi)

Bu akislarda profil semantigi aciktir:

- TLS profili: `tls_profile` -> orchestrator tarafinda `stealth.create_ja3_context(...)`
- HTTP/2 profili: `h2_profile` -> `h2_mimic.apply_h2_profile(...)`

`h2_profile=none` ise profil uygulanmaz ve sender istatistiklerinde gorunur:

- `h2_profile_disabled`
- `h2_profile_applied`
- `h2_profile_apply_failed`

Ek HTTP/2 transport metri gi:

- `h2_transport=httpx|hyper-h2`

### HTTP/2 Transport Secimi (Faz 3)

`http2_sender` icinde iki yol vardir:

1. `hyper-h2` yolu
   - Profil ayarlari gercek transport seviyesinde uygulanir.
   - `h2_profile_applied=1` ve `h2_transport=hyper-h2` doner.
   - Hata durumunda:
     - `h2_transport=hyper-h2` zorlandiysa fail-visible cikis
     - `auto` modda `httpx` fallback

2. `httpx` yolu (geri uyum)
   - Mevcut request-plan / status counter davranisi korunur.
   - `h2_transport=httpx` olarak raporlanir.

Not: `hyper-h2` implementation detaylari `ddos_samurai/h2_transport.py` icindedir.

### HTTP Stateful Sender (Faz 2)

`http_stateful_sender`:

- Per-VU workflow zinciri calistirir.
- Varsayilan chain: `bootstrap -> prefetch -> action`.
- `run_vu_pool(...)` ile cookie/token/redirect izolasyonu saglar.
- L7 metrikleri (`session_success_rate`, `cookie_set_apply_rate`, `redirect_follow_ratio`, `retry_success_rate`) stats icinde doner.

### WebSocket Scenario Sender (Faz 3)

`websocket_scenario_sender` adimlari:

1. connect
2. optional auth message
3. 0..N subscribe message
4. ping adimi (`ws_ping_count`)
5. optional recv/ack (`ws_await_response`)

Ek stats:

- `ws_sessions_ok`
- `ws_auth_sent`
- `ws_subscribe_sent`
- `ws_ping_sent`
- `ws_pong_received`
- `ws_scenario_enabled`

## Sender Path Secimi ve Fallback Karar Agaci (trex_path)

`raw_socket_sender` ve `paced_raw_socket_sender` su oncelik sirasini izler:

```
1. TX_RING_L2 (en hizli)
   |-- Kosul: fast_sender C extension yuklu + send_ring_optimized mevcut
   |          + gateway MAC bulundu + MAC uzunlugu 6 byte
   |-- Not: C extension TX_RING kurulumunda once TPACKET_V3 dener, gerekirse TPACKET_V2'ye otomatik duser
   |-- Basarisiz olursa -> fallback_count++
   |
2. C_EXT_L3 (sendmmsg via C)
   |-- Kosul: fast_sender C extension yuklu + send_optimized mevcut
   |-- Basarisiz olursa -> fallback_count++
   |
3. PYTHON_SENDMMSG (Python sendmmsg wrapper)
   |-- Kosul: socket nesnesi sendmmsg destekliyor (Linux)
   |-- PermissionError -> permission_error_count++
   |
4. PYTHON_SENDTO (en yavas fallback)
   |-- Her paket icin sendto() cagrisi
   |-- PermissionError -> permission_error_count++
```

Ek gozlemlenebilirlik:

- `fast_sender.get_ring_info()` ile aktif TX_RING versiyonu (`TPACKET_V3` / `TPACKET_V2`) ve ring boyutlari okunabilir.
- Bu introspection API sender path ismini degistirmez; `sender_path=TX_RING_L2` semantigi ayni kalir.

### Stats Dict Yeni Alanlari

Her sender donusunde su ek alanlar bulunur:

| Alan | Tip | Aciklama |
|---|---|---|
| `sender_path` | string | Kullanilan TX yolu (`TX_RING_L2`, `C_EXT_L3`, `PYTHON_SENDMMSG`, `PYTHON_SENDTO`, `NONE`) |
| `fallback_count` | int | Kac kez daha yavas bir yola geri donuldugu |
| `permission_error_count` | int | PermissionError kaynakli hata sayisi |

`sender_path=NONE` durumu: raw socket olusturma asamasinda hata (ornegin PermissionError) olustu, hicbir yol denenmedi.

### Raporlama

Bu alanlar `orchestrator.py` -> `reporting.py` -> run report JSON/MD/Prom zinciri ile disari aktarilir.
Run report seviyesinde toplanir:

- `sender_paths_used`: `{"TX_RING_L2": 4, "C_EXT_L3": 2}` seklinde worker bazli dagilim
- `fallback_count`: Toplam fallback sayisi
- `permission_error_count`: Toplam yetki hatasi
- `send_success_ratio_pct`: `sent / attempted * 100`

## Pacing V2 Alanlari

`paced_raw_socket_sender` L2/L3 yollarinda ayni semayi dondurur (additive/backward-compatible).
Ek olarak `force_l2=True` ile L2 zorlamasi desteklenir.

- `actual_rps`
- `rate_accuracy_pct`
- `jitter_p99_ns`
- `ipg_mean_ns`
- `sleep_calls`
- `busywait_cycles`
- `so_txtime_active`
- `txtime_errors`
- `txring_flush_enobufs_count`
- `txring_flush_ebusy_count`
- `txring_flush_other_errno_count`
- `txring_flush_last_errno`
- `txring_flush_last_errno_name`
- `txring_frame_wait_ns`
- `txring_poll_count`
