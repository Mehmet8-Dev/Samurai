# 04 - Packet Builder (ddos_samurai/packet.py)

## Rol

CPU dataplane'de paketin "ham iskeleti" bu modulde kurulur.
Sender katmani paketleri sadece iletir; IP/TCP/UDP/ICMP/DNS seviyesindeki
alan kombinasyonlari esasen burada olusur.

Bu modulun birincil sorumluluklari:

- Spoofing kaynak IP secimi
- L3/L4 paket olusturma (TCP/UDP/ICMP)
- DNS paket olusturma
- HTTP icin polymorphic payload olusturma
- Padding/payload guard kurallari

## Kod Haritasi

- Konfig dataclass'lari:
  - `PacketConfig`
  - `SpoofingOptions`
- Yardimci ureticiler:
  - `build_packet(...)`
  - `build_dns_packet(...)`
  - `build_http_payload(...)`
  - `get_spoofed_ip(...)`

Not: CPU paket jenerasyonu Scapy'ye dayalidir; runtime tarafinda lazy import
deseni (`ddos_samurai/scapy_support.py`) ile sandbox ortamlari korunur.

## Temel Veri Yapilari

### `PacketConfig`

Alan gruplari:

- Hedef: `target_ip`, `target_port`, `protocol`
- Spoofing: `spoof`, `spoof_opts`
- TCP tuning: `tcp_flags`, `ttl`, `tos`, `window`
- Fragment niyeti: `fragment_enabled`, `fragment_size`
- Boyut/payload: `pad_size`, `attack_vector`
- DNS secenekleri: `dns_*`

Onemli not:

- `fragment_enabled` ve `fragment_size` niyeti burada tasinir; gercek fragment
  davranisi sender/runtime tarafinda uygulanir.

### `SpoofingOptions`

- `mode`: `random | realistic | subnet | list`
- `subnet`: CIDR kaynagi
- `list_file`: satir bazli IP listesi

## Paket Uretim Akisi

1. Girdi normalizasyonu (`PacketConfig`)
2. Kaynak IP karari (`get_spoofed_ip`)
3. Protokole gore temel katman olusturma
4. Payload/padding guard kurallari
5. Paket boyutu ve alan tutarliligi
6. Sender'a byte stream olarak gecis

## Spoofing Detayi

`get_spoofed_ip()` moda gore:

- `subnet`: CIDR icinden rastgele secim
- `list`: dosyadan okunan IP havuzundan secim
- `random/realistic`: runtime tarafinda tanimli basitlestirilmis secim

Performans notu:

- `list` modunda `_CACHED_IP_LIST` ile dosya tekrar okunmaz.
- Uzun sureli worker'larda liste degistiyse cache invalidation stratejisi
  operasyonel olarak planlanmalidir (restart veya acik cache reset akisi).

## Payload ve Padding Kurallari

- SYN-only paketlerde payload/padding eklenmez.
- Non-SYN akislar icin payload yoksa dinamik random payload uretilir.
- HTTP attack vector senaryolarinda polymorphic payload jenerasyonu devreye girer.

Bu kurallar:

- TCP semantigini bozmayi engeller
- Basit IDS/heuristic yakalanma desenlerini azaltir
- Benchmark kosularinda daha tutarli paket davranisi uretir

## En Sık Hata Modlari

1. Scapy import/permission sorunlari
- Belirti: test collection veya runtime'da import error
- Cozum: lazy import yolunu koru, ortam profile'ini (`ci_safe/full`) dogru sec

2. Spoof list dosyasi bozuk
- Belirti: invalid IP parse veya bos havuz
- Cozum: listeyi pre-validate et, invalid satirlari fail-fast raporla

3. Protokol/flag uyumsuzlugu
- Belirti: beklenmeyen paket formati veya hedefte no-op
- Cozum: parser katmaninda stricter validation + unit test

## Test ve Dogrulama

Dokunus sonrasi minimum set:

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_packet.py
PYTHONPATH=. python3 -m pytest -q tests/test_packet_extra.py
```

Ilgili senaryolarda ek dogrulama:

- `tests/test_cpu_packet_engine.py`
- `tests/test_orchestrator_cpu.py`
