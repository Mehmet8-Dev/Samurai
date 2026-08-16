# 10 - Sorun Giderme (Troubleshooting)

Bu belge, native C++ çalışma zamanında en sık karşılaşılan hata durumlarını ve çözüm adımlarını içerir.

---

## 1. ZMQ IPC Soket Erişim Hataları (`/tmp/samurai_jobs_*`)

- **Belirti:** `jobs socket init failed` veya `Permission denied`.
- **Neden:** `/tmp` altındaki soket dosyalarının önceki bir çalışmadan kalan farklı kullanıcı izinlerine sahip olması.
- **Çözüm:** Eski soket dosyalarını temizleyin:
  ```bash
  rm -f /tmp/samurai_jobs_* /tmp/samurai_events_*
  ```

---

## 2. AF_XDP / Raw Socket Yetki Hataları (`Operation not permitted`)

- **Belirti:** `samurai_afxdp_worker` veya raw socket başlatılamıyor.
- **Neden:** Linux kernel raw paket ve XSK soketleri için `CAP_NET_RAW` / `CAP_NET_ADMIN` veya root yetkisi gerektirir.
- **Çözüm:** Komutu `sudo` ile çalıştırın veya ilgili ikiliye capability atayın:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./build/ddos_samurai/zmq/daemon/samurai_afxdp_worker
  ```

---

## 3. Dağıtık Slave Master'a Bağlanamıyor

- **Belirti:** `registration with master failed (endpoints=...)`.
- **Kontrol:**
  1. Master çalışıyor ve portu (`:5099`) dinliyor mu? (`ss -tulpn | grep 5099`)
  2. `--cluster-secret` değerleri Master ve Slave üzerinde birebir aynı mı?
  3. Güvenlik duvarı (UFW / iptables) port erişimini engelliyor mu?

---

## 4. CMake / Derleme Bağımlılık Eksikleri

- **Belirti:** `libzmq not found` veya `OpenSSL not found`.
- **Çözüm:**
  ```bash
  sudo apt-get install -y libzmq3-dev libssl-dev pkg-config build-essential cmake
  ```
