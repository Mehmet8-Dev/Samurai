# 16 - L7 Stateful / Faz 2-3 Degisiklik Ozeti

Bu dokuman, son refactor turunda eklenen Faz 2 ve Faz 3 degisikliklerini tek yerde toplar.

## Kapsam

- HTTP stateful workflow motoru
- HTTP/2 transport secimi (`httpx` + `hyper-h2`)
- WebSocket senaryo motoru (state machine)
- PCAP replay flow-aware rewrite (TCP seq/ack delta)
- PCAP replay L2 (`use_l2`) aktif yol
- Ilgili test ve CLI/orchestrator entegrasyonu

## 1) Yeni Modul: VirtualUser Engine

Dosya: `ddos_samurai/virtual_user.py`

Eklenenler:

- `WorkflowStep`, `ExtractRule`, `WorkflowResult`, `L7Metrics`
- `VirtualUser`:
  - Per-user cookie jar
  - Token extraction/injection
  - Redirect takibi
  - Retry/backoff
- `run_vu_pool(...)`:
  - Concurrency-limitli VU havuzu
  - Aggregate L7 metric toplama

## 2) HTTP Stateful Sender

Dosya: `ddos_samurai/senders.py`

Eklenen fonksiyon:

- `http_stateful_sender(...)`
  - Varsayilan workflow: `bootstrap -> prefetch -> action`
  - `run_vu_pool(...)` entegrasyonu
  - L7 metriclerini sender stats'a ekler

Ek iyilestirme:

- `http_app_sender(...)` icine retry/backoff sayaclari eklendi:
  - `retry_attempt_total`
  - `retry_success_count`

## 3) HTTP/2 Transport (Faz 3.1)

Yeni dosya:

- `ddos_samurai/h2_transport.py`
  - `hyper-h2` tabanli minimal H2 transport
  - Profile settings + window update uygulama
  - status kodu sayaclari

Guncellenen sender:

- `http2_sender(..., h2_transport_name="auto")`
  - `auto|httpx|hyper-h2` secimi
  - `hyper-h2` hata verirse:
    - `hyper-h2` zorlamada fail-visible
    - `auto` modda `httpx` fallback

Yeni stats alani:

- `h2_transport`

## 4) WebSocket Scenario Motoru (Faz 3.2)

Dosya: `ddos_samurai/senders.py`

Yeni fonksiyon:

- `websocket_scenario_sender(...)`
  - Akis: connect -> auth -> subscribe -> ping/pong
  - `await_response` ile adim bazli recv opsiyonu

Yeni stats alanlari:

- `ws_sessions_ok`
- `ws_auth_sent`
- `ws_subscribe_sent`
- `ws_ping_sent`
- `ws_pong_received`
- `ws_scenario_enabled`

## 5) PCAP Replay Flow-aware Rewrite (Faz 3.3)

Dosya: `ddos_samurai/pcap_replay.py`

Eklenenler:

- `PcapReplayConfig.flow_aware_rewrite` (default `True`)
- TCP flow collision algilama
- 5-tuple yon bazli deterministic seq delta
- Reverse akista ACK duzeltme

Yeni prep metrikleri:

- `flow_aware_rewrite`
- `flow_rewrite_direction_count`
- `flow_collision_count`
- `tcp_seq_adjusted`
- `tcp_ack_adjusted`

## 6) PCAP Replay L2 Yolunun Aktif Edilmesi (Faz 3.4)

Dosyalar:

- `ddos_samurai/pcap_replay.py`
- `ddos_samurai/senders.py`

Degisiklik:

- `use_l2=True` artik yalnizca "informational" degil.
- Replay path sender'a `force_l2=True` geciriyor.
- L2 kullanilamazsa fail-visible `sender_path=L2_UNAVAILABLE`.

Konfig guard:

- `use_l2=True` ve `strip_ethernet=True` birlikte verilirse config hatasi.

## 7) CLI ve Orchestrator Entegrasyonu

### CLI (`ddos_samurai/cli/`)

Yeni flagler:

- `--h2-transport {auto,httpx,hyper-h2}`
- `--ws-scenario`
- `--ws-auth-message`
- `--ws-subscribe-message`
- `--ws-ping-count`
- `--ws-await-response`
- `--pcap-use-l2`
- `--pcap-no-flow-aware`

### Orchestrator (`ddos_samurai/orchestrator.py`)

Yeni dispatch davranislari:

- `http + stateful=true` -> `http_stateful_sender`
- `websocket + ws_scenario=true` -> `websocket_scenario_sender`
- `http2` -> `h2_transport_name` passthrough
- `pcap-replay` -> `use_l2` + `flow_aware_rewrite` passthrough

## 8) Test Guncellemeleri (Faz 3.5)

Guncellenen test dosyalari:

- `tests/test_l7_stateful.py`
  - WS scenario testleri
- `tests/test_senders_http2.py`
  - `hyper-h2` path testi
- `tests/test_pcap_replay.py`
  - flow-aware seq rewrite testi
  - `use_l2` replay forwarding testi
  - `use_l2 + strip_eth` conflict testi
- `tests/test_orchestrator_cpu.py`
  - websocket scenario dispatch testi
  - stateful http dispatch testi

Onerilen hedefli komut:

```bash
PYTHONPATH=. python3 -m pytest -q \
  tests/test_l7_stateful.py \
  tests/test_senders_http2.py \
  tests/test_orchestrator_cpu.py \
  tests/test_pcap_replay.py
```
