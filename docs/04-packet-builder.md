# 04 - Packet Builder (ddos_samurai/packet.py)

## Rol

CPU yolunda paket uretimi Scapy ile yapilir.
Bu modul:

- Spoofing kaynak IP secimi
- L4 (TCP/UDP/ICMP) paket uretimi
- DNS paket uretimi
- HTTP icin "polymorphic payload" olusturma

## Temel Veri Yapilari

- `PacketConfig` (dataclass)
  - target_ip, target_port, protocol
  - spoof + spoof_opts
  - tcp_flags, ttl, tos, window
  - fragment_enabled/fragment_size (fragmentation sender'da uygulanir)
  - pad_size
  - attack_vector, dns_* ayarlari

- `SpoofingOptions` (dataclass)
  - mode: random/realistic/subnet/list
  - subnet, list_file

## Spoofing

`get_spoofed_ip()` secilen moda gore:

- subnet: CIDR icinden rastgele
- list: dosyadan (cache'lenir) rastgele
- diger: random/realistic (su an basitlestirilmis)

Dosya bazli list modunda `_CACHED_IP_LIST` kullanilir; bu global cache davranisi testlerde/worker'larda gozetilmeli.

## Payload ve Padding

- SYN-only paketlerde payload/padding eklenmemesi icin guard var.
- Non-SYN akislarda payload yoksa "dynamic random payload" eklenebiliyor.

Bu mantik, stealth davranislarini korumak icin kritiktir; degistirirken `tests/test_packet_builder.py` gibi testleri hizalayin.

