# 06 - AF_XDP ve fast_sender (C Eklentileri)

Bu dokuman, iki farkli hizlandirma yolunu mimari seviyede aciklar:

- `fast_sender`: Raw socket / sendmmsg / TX_RING hizlandirmalari icin C eklentisi
- `xdp_sender` + `af_xdp_sender.py`: Linux AF_XDP tabanli high-performance gonderim

## fast_sender

Entegrasyon noktasi: `ddos_samurai/senders.py:raw_socket_sender()`

Beklenenler:

- L3 hizli yol: `send_optimized(fd, packets_buffer, target_ip, target_port, packet_size, count)`
- L2 hizli yol: `send_ring_optimized(iface, packets_buffer, packet_size, count, gateway_mac)`
- Introspection: `get_ring_info()`

TX_RING davranisi:

- `send_ring_optimized` AF_PACKET TX_RING kurulumunda once `TPACKET_V3` dener.
- Kernel/ortam V3'u desteklemiyorsa otomatik `TPACKET_V2` fallback uygular.
- Public fonksiyon imzasi degismez; fallback tamamen C extension icindedir.

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

Riskler:

- Buffer formatinin bozulmasi (packet_size hesaplari)
- Ether header zorunlulugu (TX_RING icin)
- C eklentisinin mevcut olmamasi halinde fallback davranisi

## AF_XDP

Entegrasyon noktasi: `ddos_samurai/senders.py:xdp_sender()`

`ddos_samurai/af_xdp_sender.py`:

- C extension'i lazy load eder.
- Sistemin AF_XDP destek durumunu kontrol eder.
- Uygun degilse raw socket sender'a geri duser.

Not: AF_XDP tipik olarak kernel/driver/NIC uyumu ve yetkiler ister. Bu sebeple bu yol her ortamda acilmayabilir.
