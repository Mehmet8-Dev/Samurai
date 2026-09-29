# 35 - VAE Savunma Entegrasyonu ve Defense Worker

Bu doküman, DDoSamurai içindeki savunma odaklı VAE (Variational Autoencoder) anomali analiz motorunu ve native `samurai_defense_worker` ikilisini açıklar.

---

## 1. Amaç ve Kapsam

Savunma katmanının temel amacı:
- Trafik ve sistem metriklerindeki normal çalışma davranışını öğrenmek.
- Üretilen test yükü altındaki sistem anomali skorlarını hesaplamak.
- Savunma / WAF / IPS bypass tekniklerinin etkinlik seviyesini ölçmek.

---

## 2. Native C++ Defense Worker (`samurai_defense_worker`)

[`defense_worker.cpp`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/defense_worker.cpp) bağımsız bir native ZMQ işçisi olarak çalışır:

- **ZMQ Supervisor Entegrasyonu:** `ipc:///tmp/samurai_jobs_defense` üzerinden emri alır.
- **Anomali ve Savunma Testleri:** Farklı paket boyutları, bayrak manipülasyonları ve gecikme örüntüleriyle hedef savunma duvarlarının tepkilerini ölçer.
- **Metrik Yayını:** Anomali skorlarını ve savunma bypass oranlarını anlık olarak raporlar.

---

## 3. Çalıştırma

```bash
# Defense worker ile analiz testi
./build/ddos_samurai/cli/samurai \
  --worker defense \
  --target 10.0.0.50 \
  --port 80 \
  --count 50000 \
  --confirm
```
