# 00 - Genel Bakis

## Hedef

DDoSamurai, farkli "attack vector" (L4 ve L7) akislari icin ortak bir calistirma modeli sunar:

- Tek bir CLI arayuzu (`ddos_samurai/cli.py`)
- Bir worker/process modeli (`ddos_samurai/orchestrator.py`)
- Birden fazla gonderim motoru ("sender") ve paket/payload ureti mi ("builder/engine")

Bu dokuman, kod tabaninda degisiklik yapacak kisi icin "nereden baslamali" ve "hangi katman ne is yapar" sorularini cevaplar.

## Yuksek Seviyede Veri Akisi

1. Giris noktasi: `advv2.py`
2. CLI parse + config merge: `ddos_samurai/cli.py`
3. Guvenlik kapilari (target allowlist/public block): `ddos_samurai/utils.py`
4. Worker spawn: `multiprocessing.Process(... orchestrator.start_worker ...)`
5. Worker icinde async dispatch: `ddos_samurai/orchestrator.py:worker_process()`
6. Vektore gore:
   - CPU L4: `ddos_samurai/senders.py:packet_sender()` + `ddos_samurai/packet.py:create_packet()`
   - GPU L4: `ddos_samurai/gpu_packet.py` + `ddos_samurai/senders.py:raw_socket_sender()`
   - L7: `ddos_samurai/senders.py:http_app_sender/http2_sender/websocket_sender/quic_sender/...`
   - AF_XDP (opsiyonel): `ddos_samurai/af_xdp_sender.py` uzerinden

## Dashboard + API (Opsiyonel Kontrol Yuzeyi)

Bu repoda "UI ile kontrol" icin opsiyonel iki katman vardir:

- API: `ddos_samurai/api.py` (FastAPI)
- UI: `dashboard/` (React)

UI, API'yi poll ederek log/stats goruntuler ve start/stop komutlarini gonderir.
Detay:

- `docs/12-dashboard.md`
- `docs/13-api.md`

## Katmanlar ve Sorumluluklar

### CLI katmani (`ddos_samurai/cli.py`)

- Arg parse (argparse)
- YAML config'ten default set etme
- "dry-run" (packet builder dogrulama) gibi calistirma modlari
- Safety gate'leri calistirma
- Worker/process sayisi ve is bolumu

### Orkestrator (`ddos_samurai/orchestrator.py`)

- Worker process entrypoint + CPU affinity denemesi
- Tek bir "args dict" uzerinden backend/vektor secimi
- Backend'e gore uygun sender/engine cagrisi

### Sender katmani (`ddos_samurai/senders.py`)

- CPU tabanli Scapy gonderimi
- Raw socket gonderimi (Linux'ta hizli yol: sendmmsg / C extension)
- L7 istek gonderimleri (httpx/websockets/aioquic)
- AF_XDP entegrasyon noktasi

### Paket/payload ureti mi

- CPU (Scapy): `ddos_samurai/packet.py`
- GPU (Numba/CuPy): `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_payload.py`, anomaly icin `ddos_samurai/anomaly_packet.py`

## Calisma Ortami Notlari

- Raw socket, AF_XDP, TX_RING gibi yollar genelde root/uygun capability ister.
- Baz ortamlarda Scapy, interface listesi icin netlink soketi acmaya calisir. Bu, sandbox/CI ortamina gore PermissionError uretebilir.
- Bu repo, "lazy import" kullanarak GPU init'ini geciktirmeye calisir (ornek: CLI'da orchestrator importu parse sonrasina atilmis).
