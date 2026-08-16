# 03 - Senders ve Native Dataplane Motorları

Senders katmanı, orkestratörden gelen iş zarflarını (`JobEnvelopeV1`) doğrudan işletim sistemi çekirdeğine, ağ kartına (NIC) veya GPU donanımına aktaran yüksek performanslı C++ motorlarından oluşur.

---

## 1. Dataplane Motorları Matrisi

| Motor / Worker | Katman | Teknoloji | Açıklama |
| :--- | :--- | :--- | :--- |
| **`samurai_cpu_worker`** | L3/L4 | Raw Socket, TPACKET_V3, Packet Ring | Klasik Linux raw socket ve halka tamponları üzerinden optimize edilmiş TCP/UDP/ICMP iletimi. |
| **`samurai_afxdp_worker`** | L3/L4 | Linux AF_XDP (XSK), Zero-Copy UMEM | Linux çekirdeğini atlayarak doğrudan NIC donanım halkalarına yazar/okur. |
| **`samurai_dpdk_worker`** | L3/L4 | DPDK PMD, Hugepages, Polled-Mode | Donanım kuyruklarına doğrudan zero-copy erişim sağlayarak Mpps seviyesinde paket üretir. |
| **`samurai_gpu_worker`** | L3/L4 | NVIDIA CUDA, GPU Parallel Synthesis | Milyonlarca paketin başlık ve yüklerini GPU çekirdeklerinde paralel sentezler. |
| **`samurai_doca_worker`** | L3/L4 | NVIDIA BlueField DPU, GPUNetIO | DPU üzerinden doğrudan GPUDirect RDMA ile paket iletimi ve akış takibi. |
| **`samurai_l7_worker`** | L7 | Epoll Reactor, User-Space TCP, nghttp2, ngtcp2 | HTTP/1.1, HTTP/2, QUIC/H3 ve DNS protokollerini hem Kernel socket hem de Kernel-Bypass ile yönetir. |
| **`samurai_scenario_worker`** | L7 | Scenario DSL Compiler, Scheduler, SLA Engine | Gerçek kullanıcı davranışlarını (Web/Mobile Persona) simüle eden çok adımlı senaryolar. |
| **`samurai_defense_worker`** | Savunma | VAE (Variational Autoencoder), Bypass Tests | Savunma sistemlerinin anomali tespit eşiklerini test eden akıllı analiz motoru. |

---

## 2. ZMQ Binary Wire Başlığı (`SamuraiWireHeaderV1`)

Tüm worker'lar standartlaştırılmış 56 baytlık ikili başlık üzerinden haberleşir:

```cpp
#pragma pack(push, 1)
struct SamuraiWireHeaderV1 {
  uint32_t magic;           // 0x534D5249 ("SMRI")
  uint8_t  version;         // 0x01
  uint8_t  msg_type;        // START_JOB, STOP_JOB, ACK, HEARTBEAT vb.
  uint8_t  worker_kind;     // CPU, GPU, DPDK, AF_XDP, L7 vb.
  uint8_t  reserved;        // Hizalama dolgusu
  uint64_t correlation_id;  // İstek/Yanıt eşleme kimliği
  char     job_id[32];      // İş kimliği
  uint32_t payload_len;     // Ek veri uzunluğu
};
#pragma pack(pop)
```

---

## 3. Pacing ve Hız Denetimi (`pacing_engine.c`)

Tüm sender motorları, mikrosaniye seviyesinde hassas zamanlama ve TSC (Time Stamp Counter) tabanlı donanım sayaçları kullanan `pacing_engine` ile hedef RPS / pps değerine birebir uyum sağlar.
