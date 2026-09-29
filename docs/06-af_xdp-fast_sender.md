# 06 - AF_XDP Kernel-Bypass ve Zero-Copy

AF_XDP (XSK - eXpress Data Path Sockets), Linux çekirdeğinin ağ yığınını atlayarak doğrudan ağ kartı halkalarına erişen modern kernel-bypass teknolojisidir.

---

## 1. Çalışma Prensibi

1. **UMEM Tahsisi:** Kullanıcı alanında (User-Space) büyük bellek blokları (Hugepages / Paged Memory) ayrılır ve UMEM olarak XSK soketine bağlanır.
2. **Fill & Completion Rings:** Bellek çerçeveleri kernel'a iletilir ve işlenen paketler serbest bırakılır.
3. **TX Ring:** Hazırlanan paket verisi hiçbir `send()` sistem çağrısı ve kernel kopyalaması olmaksızın doğrudan NIC TX donanım halkasına fırlatılır.

---

## 2. DDoSamurai AF_XDP Worker (`samurai_afxdp_worker`)

[`afxdp_worker.cpp`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/afxdp_worker.cpp) bağımsız bir native daemon olarak çalışır:

- **ZMQ Kontrolü:** Master veya CLI'dan gelen `START_JOB` emirlerini alır.
- **Sıfır Kopyalama:** `libbpf` ve `libxdp` API'leri üzerinden sıfır kopyalı modda (`XDP_ZEROCOPY`) soket bağlar.
- **CPU & NUMA Pinning:** Ağ kartının bağlı olduğu NUMA düğümündeki izole CPU çekirdeklerine kilitlenir.

---

## 3. Çalıştırma

```bash
# Gerekli sistem izinleri ve root ile çalıştırma
sudo ./build/ddos_samurai/cli/samurai \
  --worker afxdp \
  --target 10.0.0.50 \
  --port 80 \
  --protocol tcp \
  --count 10000000 \
  --confirm
```
