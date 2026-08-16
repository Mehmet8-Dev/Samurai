# 16 - L7 Stateful Native Runtime (Güncel Mimari)

Bu doküman, DDoSamurai'nin C++ ile çalışan yerel (native) L7 Stateful motorunu, User-Space TCP entegrasyonunu ve Kernel-Bypass bağlantılarını açıklar.

---

## 1. Mimari Kapsam

- **L7 Motor Çekirdeği:** [`ddos_samurai/l7_emu_native/`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/)
  - `engine.cpp` / `engine.hpp`: Epoll/Reactor tabanlı HTTP/1.1, HTTP/2 (nghttp2), QUIC/H3 (ngtcp2) ve DNS akış yöneticisi.
  - `bridge.cpp` / `bridge.hpp`: Dataplane ve User-Space TCP TX/RX tampon köprüsü (`peek_custom_tcp_tx_packets_raw`, `ingest_custom_tcp_rx_frame_raw`).
  - `custom_quic_stack/`: AF_XDP ve User-Space UDP soketleri üzerinden doğrudan QUIC bağlantısı (`h3_ngtcp2_client.cpp`).
  - `l2l3_stack/`: ARP, DHCP, IGMP ve IPv6 Neighbor Discovery (ND) motorları.
- **User-Space TCP Dataplane:** [`ddos_samurai/l4/tcp_dataplane_core.cpp`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp)
  - 64-shard kilit şeritli (lock-striped) TCP akış tablosu.
  - Donanım hızında 3-way handshake, sequence/ACK takibi, out-of-order paket işleme, timer-wheel retransmission.
- **ZMQ Worker Dağıtımı:** [`samurai_l7_worker`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/l7_worker.cpp)

---

## 2. Desteklenen Protokol Seti

| Protokol | Native Motor | Transport Modları |
| :--- | :--- | :--- |
| **HTTP/1.1** | `l7_emu_native` / `engine.cpp` | `kernel_socket`, `custom_tcp` (AF_XDP / DPDK) |
| **HTTP/2** | `nghttp2` + `engine.cpp` | `kernel_socket`, `custom_tcp` (AF_XDP / DPDK) |
| **QUIC / HTTP/3**| `custom_quic_stack` (`ngtcp2`) | `kernel_socket`, `custom_quic` (AF_XDP UMEM) |
| **DNS** | `dns_client_engine.cpp` | UDP / Raw Socket / AF_XDP |

---

## 3. Çalışma Yolları (Transport Backends)

1. **Kernel Socket Modu (`kernel_socket`):**
   Standart POSIX epoll event loop kullanır. Root yetkisi gerekmez; test ve geliştirme için uygundur.
2. **Strict Custom Dataplane Modu (`custom_tcp` / `custom_quic`):**
   Linux çekirdeği tamamen devre dışı bırakılır. L7 istekleri doğrudan DDoSamurai'nin kendi User-Space TCP/UDP stack'inde paketlenir ve `AF_XDP` ya da `DPDK` donanım halkalarına zero-copy olarak fırlatılır.

---

## 4. Doğrulama ve Self-Test

```bash
./build/ddos_samurai/l7_emu_native/samurai_l7_selftest
```
