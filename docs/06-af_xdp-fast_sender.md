# 06 - AF_XDP ve fast_sender (C Eklentileri)

Bu dokuman CPU paketlerinin "nasil daha hizli gonderildigini" anlatir.
Samurai'de iki temel hizlandirma yolu vardir:

- `fast_sender`: raw socket / sendmmsg / TX_RING odakli C eklentisi
- `xdp_sender` + `af_xdp_sender.py`: Linux AF_XDP odakli yol

## Ne Zaman Hangi Yol?

1. XDP backend aktif ve ortam uyumluysa:
- Oncelik AF_XDP yoluna verilir

2. XDP acilamiyorsa:
- Politika ve ortam ayarlarina gore raw socket yoluna gecilir

3. C eklenti yok veya uyumsuzsa:
- Sistem fail-visible davranabilir ya da fallback edebilir (sender policy'ye bagli)

Detay fallback kurallari icin bkz: `docs/03-senders.md`

## fast_sender

Entegrasyon noktasi: `ddos_samurai/senders.py:raw_socket_sender()`

Temel C API:

- L3 hizli yol:
  - `send_optimized(fd, packets_buffer, target_ip, target_port, packet_size, count)`
- L2 hizli yol:
  - `send_ring_optimized(iface, packets_buffer, packet_size, count, gateway_mac)`
- Introspection:
  - `get_ring_info()`

### TX_RING Davranisi

- `send_ring_optimized` AF_PACKET TX_RING kurulumunda once `TPACKET_V3` dener.
- Kernel/ortam desteklemiyorsa otomatik `TPACKET_V2` fallback uygular.
- Public Python fonksiyon imzasi degismez; fallback C extension icinde cozulur.

`get_ring_info()` ornek donus:

```python
{
  "is_setup": 1,
  "packet_version": 2,
  "packet_version_name": "TPACKET_V3",
  "iface": "eth0",
  "tp_block_size": 4096,
  "tp_frame_size": 4096,
  "tp_block_nr": 4096,
  "tp_frame_nr": 4096,
  "ring_size": 16777216,
  "frame_header_size": 48
}
```

### fast_sender Icin Operasyonel Gereksinimler

- CAP_NET_RAW / root izinleri
- Dogru interface secimi
- L2 modunda Ether header ve gateway MAC tutarliligi
- packet_size ile buffer offset hesaplarinin uyumu

## AF_XDP

Entegrasyon noktasi: `ddos_samurai/senders.py:xdp_sender()`

`ddos_samurai/af_xdp_sender.py` sorumluluklari:

- C extension lazy-load
- Kernel/NIC uyumluluk kontrolu
- Socket/queue setup
- Uygun degilse kontrollu fallback

### AF_XDP Icin Kritik Gereksinimler

- Uyumlu Linux kernel ve driver
- NIC'in XDP/zero-copy kabiliyeti
- Queue/CPU affinity ve NUMA planlamasi
- Yeterli yetki ve sistem limitleri

Bu gereksinimlerden biri eksikse AF_XDP yolu devreye girmeyebilir.

## En Sık Hata Modlari

1. Extension import hatasi
- Belirti: module load error
- Cozum: build artefaktlarini ve ABI uyumunu kontrol et

2. TX_RING setup hatasi
- Belirti: ring kurulumu fail veya kisa surede packet drop
- Cozum: iface, MTU, packet_size ve TPACKET surumunu dogrula

3. AF_XDP init hatasi
- Belirti: queue bind/socket create fail
- Cozum: kernel config, driver, queue map ve izinleri kontrol et

4. Beklenmeyen fallback
- Belirti: performans ani dusus, sender backend degisimi
- Cozum: runtime log + sender policy + preflight raporunu birlikte incele

## Dogrulama ve Benchmark Onerisi

Hizli teknik dogrulama:

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_sender_comprehensive.py
PYTHONPATH=. python3 -m pytest -q tests/test_senders_import_fallback.py
PYTHONPATH=. python3 -m pytest -q tests/test_af_xdp_zero_copy.py
```

Profil bazli benchmark:

```bash
python -m ddos_samurai.benchmark_profiles --profile ci_safe --run
sudo python -m ddos_samurai.benchmark_profiles --profile dedicated_lab --run
```

Parite ve kapasite yorumlarken `run_quality`, loss telemetry ve SLO gate sonuclari
birlikte degerlendirilmelidir.
