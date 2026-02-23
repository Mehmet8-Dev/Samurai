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

- L7: `senders.http_app_sender`, `senders.http2_sender`, `senders.websocket_sender`, `senders.quic_sender`, `senders.slow_attack_sender`
- Amplification: `senders.amplification_sender`
- Diger L4/L3: `senders.packet_sender` + `packet.PacketConfig`

Profil akisi:

- `tls_profile` yalnizca TLS context olusturma hattinda kullanilir.
- `h2_profile` yalnizca HTTP/2 sender hattina gider.
- `h2_profile=none` oldugunda orchestrator explicit olarak "uygulama yok" semantigini korur.

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

## Progress Guncellemesi

`finally` blogunda `progress.value += args['count']` yapilir.
Bu, "gonderildi" degil "worker gorev tamamlandi" semantigine daha yakindir (tek tek paket sayimi degil).

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

