# 07 - Hedef Güvenliği (Target Safety) ve RFC Kontrolleri

DDoSamurai, testlerin yanlışlıkla yetkisiz hedeflere yönlendirilmesini ve kontrolsüz trafik üretimini engellemek için yerleşik güvenlik mekanizmalarına (`ddos_samurai/core/target_safety.cpp` ve `ddos_samurai/cli/validation.cpp`) sahiptir.

---

## 1. Hedef Güvenlik Kuralları

- **Özel / Yerel Ağ Koruması (Default Private):**
  Varsayılan olarak yalnızca loopback (`127.0.0.0/8`), özel yerel ağlar (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) ve lab IP bloklarına izin verilir.
- **Genel (Public) IP Koruması:**
  İnternete açık genel IP adreslerine test yapılabilmesi için `--allow-public-target` bayrağının açıkça belirtilmesi zorunludur.
- **Genel Yasaklı Bloklar (Global Denylist):**
  Kritik internet altyapıları (örneğin DNS root sunucuları, acil durum ağları vb.) ve `--safety-global-deny-target` ile girilen CIDR blokları asla hedeflenemez; bu kurallar allowlist kurallarını ezer.

---

## 2. Güvenlik Bayrakları

```bash
# Sadece belirli bir alt ağa izin verme
./build/ddos_samurai/cli/samurai --allow-target 192.168.10.0/24 ...

# Belirli bir alt ağı tamamen yasaklama
./build/ddos_samurai/cli/samurai --safety-global-deny-target 10.0.0.0/24 ...

# Kamu/İnternet hedefine bilinçli onay
./build/ddos_samurai/cli/samurai --allow-public-target --target 203.0.113.10 ...
```

---

## 3. RFC Uyumluluk Testleri (`rfc_suite.cpp`)

Paket sentezleme motorlarının doğruluğunu ve anomali filtrelerini test etmek için RFC uygunluk paketleri çalıştırılabilir:

```bash
./build/ddos_samurai/cli/samurai --rfc-suite positive
./build/ddos_samurai/cli/samurai --rfc-suite negative
```
