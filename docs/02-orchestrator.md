# 02 - Orchestrator (ddos_samurai/orchestrator.py)

## Rol

Orchestrator, worker basina "hangi yol calisacak" kararini tek yerde toplar.
CLI sadece processleri baslatir; is mantigi worker tarafinda dispatch edilir.

## Giris Noktalari

- `start_worker(worker_id, args, progress, progress_lock, tls_profile)`
  - CPU affinity ayarlamayi dener (Linux).
  - `asyncio.run(worker_process(...))` ile async akisi baslatir.

- `worker_process(worker_id, args, ...)`
  - `args` bir dict (CLI `vars(namespace)` cikisi).
  - `compute_backend` ve `attack_vector` kombinasyonuna gore ilgili sender/engine'i cagirir.

## Backend Secimi

### CPU yolu

`attack_vector`:

- L7: `senders.http_app_sender`, `senders.http_stateful_sender`, `senders.http2_sender`, `senders.websocket_sender`, `senders.websocket_scenario_sender`, `senders.quic_sender`, `senders.slow_attack_sender`
- Amplification: `senders.amplification_sender`
- Diger L4/L3: `senders.packet_sender` + `packet.PacketConfig`

Profil akisi:

- `tls_profile` yalnizca TLS context olusturma hattinda kullanilir.
- `h2_profile` yalnizca HTTP/2 sender hattina gider.
- `h2_profile=none` oldugunda orchestrator explicit olarak "uygulama yok" semantigini korur.
- `h2_transport` HTTP/2 sender'a dogrudan aktarilir (`auto|httpx|hyper-h2`).

HTTP stateful dispatch:

- `attack_vector=http` ve `stateful=true` ise `http_stateful_sender(...)` cagrilir.
- `stateful=false` ise `http_app_sender(...)` kullanilir.

WebSocket scenario dispatch:

- `attack_vector=websocket` ve `ws_scenario=true` ise `websocket_scenario_sender(...)` cagrilir.
- `ws_scenario=false` ise klasik `websocket_sender(...)` yolu korunur.

### CUDA yolu

CUDA akisi, GPU tarafinda paket/payload uretir; gonderim genelde `senders.raw_socket_sender` ile yapilir.

GPU modulu importu "lazy" tutulur:

- `from . import gpu_packet, gpu_payload, anomaly_packet` gibi importlar sadece CUDA yolunda calisir.

## Template Pool Yaklasimi (GPU)

GPU genel L4 paket uretiminde:

- CPU uzerinde bir "template_pool" olusturulur (farkli header varyasyonlari icin).
- Template'ler normalize edilerek ayni byte uzunluguna getirilir (GPU kernel hizalamasi icin).
- Sonra `gpu_packet.generate_packets_from_template_pool()` ile kopyalanip per-packet randomizasyon/spoof uygulanir.

Bu tasarim, "Scapy ile paket formatini tanimla, GPU ile hizli cogalt" modelidir.

## Hybrid Ring + Backpressure (CUDA Raw)

CUDA raw/template-pool ve stateful hatlarinda worker su akisi kullanir:

- producer: GPU kernel launch + async D2H pinned copy
- consumer: `senders.paced_raw_socket_sender` ile NIC aktarimi
- queue: bounded ring (`--gpu-ring-capacity`, env: `SAMURAI_GPU_RING_CAPACITY`)
- politika: queue dolunca producer block olur (drop yok)

Run metrikleri:

- `gpu_ring_depth_peak`
- `gpu_ring_block_wait_ns`

## State Engine Konfigurasyonu

CUDA worker baslangicinda C extension state engine runtime olarak konfigure edilir:

- `--state-table-size` (`SAMURAI_STATE_TABLE_SIZE`)
- `--state-lock-count` (`SAMURAI_STATE_LOCK_COUNT`)
- `--state-timeout-sec` (`SAMURAI_STATE_TIMEOUT_SEC`)
- `--state-sweep-interval-ms` (`SAMURAI_STATE_SWEEP_INTERVAL_MS`)

Gonderim sonrasi `ingest_tx_packets(...)` ile paket bazli state update yapilir.
Periyodik `sweep_state_table(...)` cagrisi timeout olan kayitlari temizler.

## Progress Guncellemesi

`finally` blogunda `progress.value += args['count']` yapilir.
Bu, "gonderildi" degil "worker gorev tamamlandi" semantigine daha yakindir (tek tek paket sayimi degil).

## PCAP Replay Dispatch Guncellemesi (Faz 3)

Orchestrator, `pcap_replay.PcapReplayConfig` olustururken yeni alanlari da doldurur:

- `use_l2` <- `--pcap-use-l2`
- `flow_aware_rewrite` <- `not --pcap-no-flow-aware`

Boylece replay hattinda L2 zorlama ve TCP flow-aware rewrite davranisi worker katmanindan aktif edilir.

## Worker Status Semantigi (v2 - trex_path)

Worker status degeri artik gercek gonderim sonucuna gore turetilir:

| Status | Kosul | Anlam |
|---|---|---|
| `ok` | `sent > 0` ve `errors <= sent` | Basarili gonderim |
| `degraded` | `sent > 0` ama `errors > sent` | Yuksek hata orani |
| `failed` | `attempted > 0` ama `sent = 0` | Hicbir paket gonderilemedi |
| `interrupted` | `KeyboardInterrupt` | Kullanici iptal etti |

Onceden worker status sadece exception varsa "failed", yoksa "ok" oluyordu.
Bu yanlis metrik uretiyordu: 10M attempted / 0 sent durumunda bile "ok" rapor ediliyordu.

## Worker Event Semasi

Her worker tamamlandiginda `run_events` listesine su alanlarla eklenir:

```json
{
    "worker_id": 1,
    "attack_vector": "basic",
    "compute_backend": "cpu",
    "protocol": "tcp",
    "target": "192.168.1.1",
    "count_cfg": 100000,
    "status": "ok | degraded | failed | interrupted",
    "error": "",
    "duration_s": 2.45,
    "stats": {
        "attempted": 100000,
        "sent": 99800,
        "errors": 200,
        "bytes_sent_est": 5990000,
        "sender_path": "TX_RING_L2",
        "fallback_count": 0,
        "permission_error_count": 0
    },
    "sender_path": "TX_RING_L2",
    "fallback_count": 0,
    "permission_error_count": 0,
    "queue_backlog_peak": 512
}
```

### Yeni Alanlar

- **sender_path**: Hangi gonderim yolunun kullanildigini gosterir (`TX_RING_L2`, `C_EXT_L3`, `PYTHON_SENDMMSG`, `PYTHON_SENDTO`, `NONE`).
- **fallback_count**: Kac kez daha yavas bir yola geri donuldugunu sayar.
- **permission_error_count**: Yetki hatasi kaynakli basarisiz islem sayisi.
- **queue_backlog_peak**: Worker'in en yuksek kuyruk derinligi (resource_stats'tan).

### Pacing V2 Event Alanlari (additive)

Worker event ve `stats` icinde su alanlar da toplanir:

- `actual_rps`
- `rate_accuracy_pct`
- `jitter_p99_ns`
- `ipg_mean_ns`
- `sleep_calls`
- `busywait_cycles`
- `so_txtime_active`
- `txtime_errors`

Bu alanlar `resource_stats` icine de aktarilir ve live textfile exporter tarafinda gauge olarak yayinlanir:

- `pacing_actual_rps`
- `pacing_rate_accuracy_pct`
- `pacing_jitter_p99_ns`
- `pacing_ipg_mean_ns`
- `pacing_sleep_calls`
- `pacing_busywait_cycles`
- `pacing_so_txtime_active`
- `pacing_txtime_errors`
