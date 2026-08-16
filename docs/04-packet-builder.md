# 04 - CPU Packet Builder ve Spoofing Engine

CPU Dataplane motorunda paketlerin sentezlenmesi, başlık alanlarının yapılandırılması ve spoofing (kaynak IP sahteciliği) işlemleri tamamen yerel C++ modülü olan [`ddos_samurai/cpu_native/`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/cpu_native/) altında yürütülür.

---

## 1. Modül Bileşenleri

- **`engine.cpp` / `engine.hpp`:** CPU tabanlı paket üretim motoru ve tampon halkası yöneticisi.
- **`packets.cpp`:** TCP (SYN, ACK, FIN, RST, XMAS), UDP, ICMP, DNS ve HTTP paketlerinin bayt seviyesinde C++ ile üretimi.
- **`spoofing.cpp`:** Kaynak IP seçim algoritmaları (Rastgele, CIDR alt ağ, IP listesi, Gerçekçi internet dağılımı).
- **`amp.cpp`:** Amplifikasyon (Yükseltme) saldırı paket şablonları (DNS, NTP, SSDP, SNMP, Memcached).
- **`pool.cpp`:** Bellek ayırma (allocation) gecikmesini sıfırlayan önceden ayrılmış paket havuzları.

---

## 2. Desteklenen Protokoller ve Vektörler

### L4 Protokolleri:
- **TCP:** SYN Flood, ACK Flood, RST Flood, SYN-ACK Flood, Custom TCP Flags.
- **UDP:** UDP Flood, Generic UDP Payload, DNS Query Flood.
- **ICMP:** Echo Request (Ping Flood), Unreachable, Redirect.

### L7 & Amplifikasyon Vektörleri:
- **DNS Amplification:** ANY / TXT sorgu paketleri.
- **NTP Monlist:** UDP port 123 istekleri.
- **SSDP M-SEARCH:** UDP port 1900 UPnP keşif istekleri.
- **Memcached:** UDP port 11211 get/stats istekleri.

---

## 3. Spoofing Modları

1. **Random (`random`):** Tamamen rastgele 0.0.0.0 - 255.255.255.255 aralığında kaynak IP üretimi (özel ayrılmış bloklar hariç).
2. **Subnet (`subnet`):** Belirtilen CIDR bloğu (örneğin `192.168.1.0/24`) içinden rastgele kaynak IP seçimi.
3. **List (`list`):** Harici bir dosyadan okunan IP listesi üzerinden döngüsel veya rastgele seçim.
4. **Realistic (`realistic`):** Gerçek internet AS (Autonomous System) dağılımlarına uygun kaynak IP seçimi.
