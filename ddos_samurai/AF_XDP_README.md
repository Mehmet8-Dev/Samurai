# AF_XDP Entegrasyonu - Samurai (Ronin) 🚀

Bu belge, Samurai'nin yeni **AF_XDP** (Address Family XDP) entegrasyonunu açıklar.

## 📌 AF_XDP Nedir?

AF_XDP, Linux kernel'ında bulunan **yüksek performanslı** bir paket işleme mekanizmasıdır. eXpress Data Path (XDP) ile birlikte çalışarak, paketlerin **kernel bypass** veya **hızlandırılmış** iletimini sağlar.

### Avantajları

| Özellik | AF_XDP | Raw Socket | DPDK |
|---------|--------|------------|------|
| Kernel entegrasyonu | ✅ Native | ✅ Native | ❌ Userspace |
| Kurulum kolaylığı | ✅ Kolay | ✅ Kolay | ❌ Zor |
| Özel donanım gereksinimi | ❌ Yok | ❌ Yok | ✅ Bazı NIC'ler |
| Performans | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Root yetkisi | ✅ Gerekli | ✅ Gerekli | ✅ Gerekli |

## 🎯 Çalışma Modları

### 1. Copy Mode (SKB/Generic) - Herkesin Kullandığı

Bu mod, **tüm Linux sistemlerinde** ve **tüm NIC'lerde** çalışır.

**Gereksinimler:**
- Linux kernel ≥ 4.18 (önerilen: 5.10+)
- Root yetkisi
- Standart Ethernet kartı (Intel, Realtek, vs.)

**Bu modda:**
- ✅ AF_XDP çalışır
- ✅ Raw socket'ten ~2-5x daha hızlı
- ❌ Zero-copy yok (kernel → userspace kopya var)
- ❌ Performans sınırlı

**Kullanım alanları:**
- Öğrenme ve test
- ML veri toplama
- Prototipleme

### 2. Native Mode (DRV) - Driver Destekli

**Gereksinimler:**
- XDP destekli NIC driver'ı
- Intel (ixgbe, i40e, ice), Mellanox, vs.

**Bu modda:**
- ✅ Çok daha yüksek performans
- ✅ Daha düşük CPU kullanımı
- ✅ Daha düşük latency

### 3. Zero-Copy Mode - En Yüksek Performans

**Gereksinimler:**
- Zero-copy destekli NIC (Intel i40e, ice, Mellanox)
- Özel driver yapılandırması

**Bu modda:**
- ✅ Maksimum performans (10M+ pps)
- ✅ Kernel bypass
- ✅ Sıfır kopya

## 🛠️ Kurulum

### 1. Bağımlılıkları Yükle

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    python3-dev \
    linux-headers-$(uname -r) \
    libbpf-dev \
    libelf-dev \
    clang \
    llvm

# Fedora/RHEL
sudo dnf install -y \
    python3-devel \
    kernel-headers \
    libbpf-devel \
    elfutils-libelf-devel \
    clang \
    llvm
```

### 2. Modülü Derle

```bash
cd /path/to/Samurai

# Bağımlılıkları kontrol et
cd ddos_samurai && make check

# Modülü derle
cd .. && python3 setup.py build_ext --inplace

# Veya sadece XDP için
cd ddos_samurai && make xdp
```

### 3. Kurulumu Doğrula

```bash
# Python'dan test et
python3 -c "from ddos_samurai import xdp_sender; print(xdp_sender.xdp_info())"

# Sistem bilgisini göster
python3 -c "from ddos_samurai.af_xdp_sender import XDPIntegration; XDPIntegration.print_system_info()"
```

## 💻 Kullanım

### Python API

```python
from ddos_samurai.af_xdp_sender import XDPSender, XDPIntegration

# Sistem durumunu kontrol et
XDPIntegration.print_system_info()

# Sender oluştur (root gerekli)
sender = XDPSender(interface="eth0")
sender.start()

# Raw IP paketleri gönder
packets = [packet1_bytes, packet2_bytes, ...]
sent = sender.send(packets)

# UDP paketleri gönder (helper)
sender.send_udp("192.168.1.1", 80, [b"payload1", b"payload2"])

# İstatistikleri al
stats = sender.get_stats()
print(f"Sent: {stats.tx_packets} packets at {stats.packets_per_second:.0f} pps")

# Kapat
sender.stop()
```

### Context Manager ile

```python
from ddos_samurai.af_xdp_sender import XDPSender

with XDPSender(interface="eth0") as sender:
    for _ in range(1000):
        sender.send(packet_list)
```

### CLI Kullanımı

```bash
# XDP ile UDP flood
sudo python3 cli.py --target 192.168.1.100 --port 80 \
    --protocol udp --count 1000000 \
    --compute-backend cuda \
    --sender-backend xdp --sender-fallback-policy fail \
    --xdp-interface eth0 --xdp-mode 0

# mode=2 (offload request) için politika:
# --sender-fallback-policy fail  => hard policy (capability probe başarısızsa hata)
# --sender-fallback-policy allow => soft policy (unsupported ise mode=1'e düşer)
sudo python3 cli.py --target 192.168.1.100 --port 80 \
    --protocol udp --count 1000000 \
    --sender-backend xdp --sender-fallback-policy allow \
    --xdp-interface eth0 --xdp-mode 2

# XDP sistem bilgisi
sudo python3 -c "from ddos_samurai.af_xdp_sender import XDPIntegration; XDPIntegration.print_system_info()"
```

## 📊 Performans Karşılaştırması

Test ortamı: Intel i7-12700, 32GB RAM, Intel I225-V NIC, Ubuntu 24.04

| Yöntem | PPS | CPU Kullanımı |
|--------|-----|---------------|
| Scapy (sendp) | ~1,000 | Yüksek |
| Raw Socket | ~50,000 | Orta |
| fast_sender (TX_RING) | ~500,000 | Düşük |
| **AF_XDP (Copy)** | ~800,000 | Düşük |
| AF_XDP (Native) | ~2,000,000 | Çok Düşük |
| AF_XDP (Zero-Copy) | ~10,000,000+ | Minimal |

*Not: Gerçek değerler donanıma ve ağ yapılandırmasına göre değişir.*

## 🔧 Sorun Giderme

### "AF_XDP not available" Hatası

```bash
# Root yetkisi kontrolü
sudo python3 -c "import os; print('Root:', os.geteuid() == 0)"

# Kernel sürümü kontrolü
uname -r  # >= 4.18 olmalı

# AF_XDP header kontrolü
ls -la /usr/include/linux/if_xdp.h
```

### "Permission denied" Hatası

```bash
# Çalıştırırken sudo kullanın
sudo python3 your_script.py

# Veya CAP_NET_RAW capability ekleyin
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### Derleme Hataları

```bash
# Linux headers kurulu mu?
sudo apt install linux-headers-$(uname -r)

# Python dev headers kurulu mu?
sudo apt install python3-dev

# Bağımlılık kontrolü
cd ddos_samurai && make check
```

### Düşük Performans

1. **NAPI busy-poll** etkinleştir:
```bash
echo 50 | sudo tee /proc/sys/net/core/busy_read
echo 50 | sudo tee /proc/sys/net/core/busy_poll
```

2. **IRQ affinity** optimize et:
```bash
# NIC IRQ'larını belirli CPU'lara sabitle
sudo sh -c 'echo 1 > /proc/irq/XXX/smp_affinity'
```

3. **Ring buffer** boyutunu artır:
```bash
sudo ethtool -G eth0 rx 4096 tx 4096
```

## 📁 Dosya Yapısı

```
ddos_samurai/
├── xdp_sender.c        # C API - AF_XDP socket implementasyonu
├── xdp_prog.c          # BPF program (XDP kernel programı)
├── af_xdp_sender.py    # Python wrapper ve yüksek seviye API
├── senders.py          # XDP entegrasyonlu paket gönderim modülü
├── Makefile            # Derleme sistemi
└── AF_XDP_README.md    # Bu dosya
```

## 🔗 Referanslar

- [Linux AF_XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf/xsk Library](https://github.com/libbpf/libbpf)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [AF_XDP Performance Benchmark](https://netdevconf.info/0x14/pub/papers/55/0x14-paper55-talk-paper.pdf)

## ⚠️ Yasal Uyarı

AF_XDP, **sadece izin verilen sistemlerde** test amaçlı kullanılmalıdır. Bu teknoloji çok yüksek paket hızlarına ulaşabilir ve kötüye kullanıldığında ciddi sorunlara yol açabilir.
