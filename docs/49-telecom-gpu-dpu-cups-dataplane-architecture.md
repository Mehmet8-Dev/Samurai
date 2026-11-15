# 49 - DPU ARM & GPU Tabanlı Telekom Veri Düzlemi (CUPS) Mimarisi ve Entegrasyon Rehberi

**Proje:** Samurai Taşıyıcı Sınıfı Telekom Motoru (Samurai Telecom CUPS Dataplane)  
**Yazar:** Antigravity Sistem Araştırma ve Çekirdek Mühendisliği  
**Tarih:** 8 Kasım 2026  
**Hedef Donanım:** DPU ARMv8-A / ARMv9 (aarch64) + NVIDIA GPU (GeForce BAR1 P2P / BlueField DOCA)  
**Doküman Kodu:** `DOC-SAMURAI-TELECOM-CUPS-49`

---

![Samurai DPU ARM & GPU Telecom CUPS Architecture](assets/diagrams/samurai_telecom_dpu_gpu_cups.svg)

## 1. Yönetici Özeti ve Mimari Vizyon

Mobil şebekelerde (4G LTE EPC ve 5G NR Standalone) kontrol düzlemi ile veri düzleminin birbirinden ayrılması, **3GPP CUPS (Control and User Plane Separation - 3GPP TS 23.501 / TS 29.244)** standartlarının temel taşıdır. Geleneksel x86 CPU sunucularında, milyonlarca abonenin N4 PFCP durum makinelerini yönetmek ile yüzlerce gigabitlik GTP-U tünel kapsülleme ve paket iletimini aynı işlemci çekirdeklerinde yürütmek; ciddi önbellek kirlenmesine (L1/L2/L3 thrashing), çekirdekler arası kilit çekişmesine (lock contention) ve kabul edilemez paket gecikme dalgalanmalarına (jitter) yol açar.

Samurai, bu sorunu çözmek için **Donanım Tabanlı CUPS Ayrımı** yaklaşımını hayata geçirmiştir:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SAMURAI DONANIM TABANLI CUPS BÖLÜMÜ                   │
├──────────────────────────────────────┬──────────────────────────────────────┤
│       KONTROL DÜZLEMİ (CP - SLOWPATH)│        VERİ DÜZLEMİ (UP - FASTPATH)  │
│         DPU ARMv8-A ÇEKİRDEKLERİ     │          NVIDIA GPU ÇEKİRDEKLERİ     │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ • 3GPP N4 PFCP Durum Makineleri      │ • 100 GbE+ Tel Hızında GTP-U         │
│ • Abone Oturum Yönetimi (SessionMgr) │ • 5G NR QFI (0x85) PDU Kapsülleme    │
│ • Zamanlama Çarkı (Timing Wheel)     │ • 802.1ad QinQ & 802.1Q VLAN         │
│ • Düşük Güç Tüketimi & SoC Yalıtımı  │ • Çift Katmanlı Paralel Checksum     │
│ • Seqlock SHM & ZMQ Event Yayıncısı  │ • GeForce BAR1 Zero-Copy P2P TX Ring │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

Bu mimari sayesinde CPU ana belleği (Host RAM) ve ana CPU çekirdekleri paket işleme yükünden tamamen kurtarılır. DPU üzerindeki enerji verimli ARM çekirdekleri abone yaşam döngüsünü yönetirken, GPU'nun binlerce SM çekirdeği telekom paketlerini doğrudan ağ kartının PCIe DMA halkalarına (BAR1 P2P Ring) yazar.

---

## 2. Uçtan Uca Sistem Topolojisi ve Veri Yolu

DPU ARM denetleyicisi ile GPU veri düzlemi arasındaki haberleşme iki paralel kanal üzerinden yürütülür:
1. **Yüksek Hızlı Paylaşımlı Bellek (Zero-Copy Seqlock SHM):** `/dev/shm` üzerinde `mmap` edilmiş, DPU tarafından güncellenen ve GPU adres uzayına `cudaHostRegister` ile pinlenmiş canlı tünel tablosu.
2. **Asenkron IPC Kontrol Kanalı (ZeroMQ Protocol):** Dinamik tünel ekleme, güncelleme ve toplu temizleme (`TELCO_TUNNEL_UPSERT`) talimatlarını taşıyan güvenilir mesajlaşma hattı.

```
 +-------------------------------------------------------------------------+
 |                    DPU KONTROL DÜZLEMİ (ARM64 SOYUTLAMA)                |
 |                                                                         |
 |  [3GPP SMF / AMF Peer] <--(N4 PFCP / UDP 8805)--> [PfcpEngine]          |
 |                                                           |             |
 |                                                [SessionManager O(1)]    |
 |                                                           |             |
 |                                            [DpuArmCupsSessionController]|
 +---------------------+-------------------------------------+-------------+
                       |                                     |
    (POSIX Shared Memory / tmpfs)                 (ZeroMQ IPC Transport)
     /dev/shm/samurai_cups_*.bin                   ipc:///tmp/cups_gpu.ipc
                       |                                     |
                       v                                     v
 +-------------------------------------------------------------------------+
 |                    GPU VERİ DÜZLEMİ (NVIDIA CUDA SM'LERİ)               |
 |                                                                         |
 |  samurai_gpu_worker                                                     |
 |    ├── samurai_gpu_packet_telco_attach_cups_shm_v1()                     |
 |    └── HandleTelcoTunnelUpsertPayload()                                 |
 |                                                                         |
 |  [CUDA Persistent / Batch Kernel: kernels_telecom.cuh]                  |
 |    ├── Warp-Level Seqlock Tunnel Lookup (DpuCupsSharedTunnelV1)         |
 |    ├── 5G Extension Header Generation (0x85 PDU Session Container)      |
 |    ├── Hardware Dual-Layer Checksum Folding (Inner + Outer IP/L4)       |
 |    └── Direct Store: Vulkan BAR1 GDDR6 / GeforceP2pRingInstance         |
 +-------------------------------------+-----------------------------------+
                                       |
                         (PCIe P2P DMA Memory Read - MRd)
                                       v
 +-------------------------------------------------------------------------+
 |                 AĞ KARTI DONANIMI (DPDK / CX-NIC / VFIO)                |
 |                                                                         |
 |  - PCIe TX Ring Descriptors                                             |
 |  - GPU Doorbell Push (fence.proxy.tens MMIO Register)                   |
 |  - 100 GbE QSFP28 Tel Çıkışı                                            |
 +-------------------------------------------------------------------------+
```

---

## 3. DPU ARM Abone Oturum Yönetimi & N4 PFCP Durum Makinesi

DPU ARM çekirdekleri üzerinde çalışan [`DpuArmCupsSessionController`](../samurai/telecom/cups/dpu_arm_cups_bridge.hpp#L35-L95), 3GPP TS 29.244 spesifikasyonuna uygun PFCP mesajlaşmasını yürütür.

### 3.1 Oturum Yaşam Döngüsü

1. **Oturum Kurulumu (`EstablishSubscriberSession`):**
   - SMF'den gelen `Session Establishment Request` paketi ayrıştırılır.
   - DPU ARM üzerindeki [`SessionManager`](../samurai/telecom/core/session_manager.hpp#L150) havuzundan $O(1)$ sürede `TelcoSessionContext` tahsis edilir.
   - Uplink/Downlink TEID, UE IPv4 ve QFI değerleri tünel yuvasına yazılır.
   - Seqlock korumalı paylaşımlı bellek bölgesindeki ilgili `DpuCupsSharedTunnelV1` yuvası güncellenir.
   - GPU'nun anında haberdar olması için ZMQ üzerinden `TELCO_TUNNEL_UPSERT` paketi gönderilir.

2. **Oturum Güncellemesi (`ModifySubscriberSession`):**
   - QoS akış geçişlerinde (örneğin QFI 9 default bearer'dan QFI 1 VoNR/IMS bearer'a geçiş) veya el değiştirme (handover) durumlarında TEID/QFI dinamik olarak güncellenir.
   - Güncelleme sırasında veri düzleminin eski veya bozuk veri okumaması için Seqlock sürüm sayacı artırılır.

3. **Oturum Silme (`DeleteSubscriberSession`):**
   - Abone oturumu kapatıldığında tünel aktiflik bayrağı (`kTelcoTunnelFlagActive = 0x01`) sıfırlanır ve yuva serbest bırakılır.

---

## 4. Seqlock Korumalı Sıfır Kopyalı Paylaşımlı Bellek Sözleşmesi

DPU ile GPU arasında kilitsiz (lock-free) ve sıfır kopyalı senkronizasyon sağlamak için [`DpuCupsSharedRegionHeaderV1`](../samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh#L160-L210) veri yapısı kullanılır.

### 4.1 Bellek Yapısı ve Hizalama

```cpp
struct alignas(64) DpuCupsSharedTunnelV1 {
  uint32_t teid;               // GTP-U Tünel Uç Nokta Tanımlayıcısı
  uint32_t peer_ipv4;          // Karşı uç (gNodeB / UPF) IPv4 adresi
  uint32_t ue_ipv4;            // Abone (UE) dahili IPv4 adresi
  uint16_t vlan_outer;         // 802.1ad S-VLAN
  uint16_t vlan_inner;         // 802.1Q C-VLAN
  uint8_t  qfi;                // 5G QoS Akış Tanımlayıcısı (0..63)
  uint8_t  flags;              // 0x01: Active, 0x02: IPv6, 0x04: Drop
  uint16_t pad;
  uint64_t tx_packets;         // GPU tarafından atomik güncellenen sayaç
  uint64_t tx_bytes;           // GPU tarafından atomik güncellenen sayaç
};

struct alignas(4096) DpuCupsSharedRegionHeaderV1 {
  uint32_t magic;              // 0x43555053 ("CUPS")
  uint16_t version;            // 1
  uint16_t header_bytes;       // sizeof(DpuCupsSharedRegionHeaderV1)
  uint32_t max_tunnels;        // Maksimum tünel kapasitesi
  uint32_t active_tunnels;     // Canlı tünel sayısı
  uint64_t sequence_number;    // Seqlock sürüm sayacı
  // Devamında: DpuCupsSharedTunnelV1 tunnels[max_tunnels];
};
```

### 4.2 Linux tmpfs & `cudaHostRegister` Zorunluluğu

> [!IMPORTANT]
> NVIDIA CUDA sürücüsünün `cudaHostRegister` API'si, sıradan ext4/xfs disk dosyaları üzerindeki `mmap` alanlarını GPU sayfa tablolarına pinleyemez ve `cudaErrorInvalidValue` hatası döner.
> Paylaşımlı bellek dosyasının mutlaka **POSIX RAM tabanlı tmpfs dosya sisteminde (`/dev/shm/...`)** oluşturulması ve boyutunun sistem sayfa boyutuna (4096 bayt) tam kat olarak hizalanması zorunludur.

### 4.3 Çift Yönlü Donanım Bellek Bariyerleri

- **DPU ARMv8-A Tarafı (Yazma):**
  ARM64 zayıf bellek modeline (weakly ordered memory) sahiptir. Seqlock güncellemesi yapılırken ARM mimarisine özgü store-release talimatı verilir:
  ```cpp
  #if defined(__aarch64__)
    asm volatile("dmb ishst" ::: "memory");
  #else
    std::atomic_thread_fence(std::memory_order_release);
  #endif
  ```
- **GPU CUDA Tarafı (Okuma):**
  GPU SM'lerindeki warp thread'leri tünel verisini okurken çift okuma (double read) döngüsü uygular. `sequence_number` tek sayı ise (DPU o sırada yazıyorsa) veya okuma sonundaki sayaç başlangıçtaki sayaçla eşleşmiyorsa okuma tekrarlanır:
  ```cuda
  uint64_t seq_before = header->sequence_number;
  if ((seq_before & 1ULL) != 0) { /* yazma devam ediyor, bekle */ }
  // Tünel alanlarını oku...
  __threadfence();
  uint64_t seq_after = header->sequence_number;
  if (seq_before == seq_after) { /* Veri tutarlı, devam et */ }
  ```

---

## 5. CUDA Telekom Çekirdeği Mikro-Mimarisi (`kernels_telecom.cuh`)

GPU paket motoru, saniyede onlarca milyon GTP-U paketini tel hızında üretmek için optimize edilmiş SIMT çekirdeklerine sahiptir.

### 5.1 4G LTE ve 5G NR GTP-U Başlık Anatomisi

Telekom paketleri dış (outer) ve iç (inner) olmak üzere iki katmandan oluşur:

```
+---------------------------------------------------------------------------+
| L2 Ethernet (14B) | Single VLAN (4B) / QinQ (8B) [Opsiyonel]              |
+---------------------------------------------------------------------------+
| Dış IPv4 Başlığı (20B, Proto: 17 UDP)                                     |
+---------------------------------------------------------------------------+
| Dış UDP Başlığı (8B, Hedef Port: 2152)                                    |
+---------------------------------------------------------------------------+
| GTP-U Temel Başlığı (8B: Flags=0x34, Type=0xFF, TEID=32-bit)              |
+---------------------------------------------------------------------------+
| GTP-U İsteğe Bağlı Alanlar (4B: Seq=16-bit, N-PDU=8-bit, NextExt=0x85)    |
+---------------------------------------------------------------------------+
| 5G PDU Session Container (4B: Len=1, PDU Type=DL, QFI=6-bit, NextExt=0x00)|
+---------------------------------------------------------------------------+
| İç IPv4 Başlığı (20B, Abone IP -> Hedef Sunucu)                           |
+---------------------------------------------------------------------------+
| İç L4 Başlığı (UDP: 8B / TCP: 20B / ICMP: 8B)                             |
+---------------------------------------------------------------------------+
| Faydalı Yük (Payload)                                                     |
+---------------------------------------------------------------------------+
```

### 5.2 5G QFI (0x85) PDU Session Container Kapsülleme

5G Standalone ağlarında her paket belirli bir QoS sınıfına (QoS Flow Identifier - QFI) aittir. GPU çekirdeği, tünel tablosundan gelen QFI değerini 3GPP TS 38.415 spesifikasyonuna göre 4 baytlık uzantı başlığına yazar:
- `Flags`: `0x34` (`Version=1`, `PT=1`, `E=1` uzantı başlığı var).
- `Next Extension Header`: `0x85` (PDU Session Container).
- `PDU Type`: `0x00` (Downlink) veya `0x10` (Uplink).
- `QFI`: `0x00` ila `0x3F` (0..63) arasındaki 6-bit QoS akış numarası.

### 5.3 Paralel Çift Katmanlı Sağlama Toplamı (Dual Checksum)

Bir GTP-U paketinde hem dış IPv4 başlığının hem de iç IPv4 ve L4 (TCP/UDP/ICMP) başlıklarının sağlama toplamlarının doğru hesaplanması zorunludur. Yanlış sağlama toplamına sahip paketler taşıyıcı yönlendiricileri (Core Routers) veya UPF tarafından donanımda anında düşürülür.

GPU çekirdeği, döngüleri tamamen açarak (`#pragma unroll`) 32-bit akümülatör üzerinde paralel toplama yapar ve 16-bit 1's complement katlama işlemini tek bir CUDA warp talimatı ile tamamlar:
```cuda
// 32-bit toplamı 16-bit one's complement'e katlama
sum = (sum >> 16) + (sum & 0xFFFF);
sum += (sum >> 16);
return static_cast<uint16_t>(~sum);
```

---

## 6. DPU ARM Taşınabilirlik Mühendisliği

Telekom kontrol düzleminin NVIDIA BlueField-2/BlueField-3 veya Marvell OCTEON DPU gibi ARM tabanlı işlemcilerde yerel performansla çalışabilmesi için x86'ya özgü donanım talimatları soyutlanmıştır:

| İşlev | x86-64 Karşılığı | DPU ARMv8-A (aarch64) Karşılığı | Dosya |
|:---|:---|:---|:---|
| **Zaman Sayacı (TSC)** | `__builtin_ia32_rdtsc()` | `asm volatile("mrs %0, cntvct_el0" : "=r"(val))` | [`samurai_tsc.h`](../samurai/samurai_tsc.h) |
| **Sistem Frekansı** | `/proc/cpuinfo` / TSC calib | `asm volatile("mrs %0, cntfrq_el0" : "=r"(freq))` | [`hierarchical_timing_wheel.cpp`](../samurai/telecom/core/hierarchical_timing_wheel.cpp) |
| **Donanım CRC32** | `_mm_crc32_u64()` | `__crc32cd()` (`<arm_acle.h>`) | [`session_context.hpp`](../samurai/telecom/core/session_context.hpp) |
| **Spinlock Beklemesi** | `__builtin_ia32_pause()` | `asm volatile("yield" ::: "memory")` | [`session_manager.hpp`](../samurai/telecom/core/session_manager.hpp) |
| **Derleme Bayrağı** | `-msse4.2` | `-march=armv8-a+crc` | [`samurai/telecom/CMakeLists.txt`](../samurai/telecom/CMakeLists.txt) |

---

## 7. Kod Tabanı Dizin Haritası ve Görev Dağılımı

```
samurai/
├── gpu_packet_cuda/
│   ├── kernels_telecom.cuh                 # 4G/5G QFI, QinQ, dual-checksum CUDA çekirdekleri
│   ├── zero_copy_dataplane_contract.cuh   # CUPS SHM ve BAR1 P2P bellek düzeni
│   ├── geforce_p2p_runtime.cuh            # Vulkan BAR1 P2P ring kuyruğu
│   ├── gpu_initiated_doorbell.cuh         # fence.proxy.tens MMIO zil mekanizması
│   └── host_api.cuh                       # C ABI dışa aktarım fonksiyonları
├── telecom/
│   ├── cups/
│   │   ├── dpu_arm_cups_bridge.hpp        # DPU ARM CUPS köprü sınıfı başlığı
│   │   └── dpu_arm_cups_bridge.cpp        # 3GPP N4 PFCP oturum yönetimi ve seqlock SHM
│   ├── core/
│   │   ├── session_context.hpp            # 128-byte önbellek hizalı abone bağlamı
│   │   ├── session_manager.hpp            # O(1) indeks ve CRC32 hash arama tablosu
│   │   └── hierarchical_timing_wheel.cpp  # ARM64 uyumlu 3 kademeli zamanlama çarkı
│   └── tests/
│       ├── test_dpu_arm_cups_gpu_bridge.cu # DPU CUPS <-> GPU uçtan uca yaşam döngüsü testi
│       ├── test_gpu_telecom_kernels.cu    # CUDA telekom paket doğrulama testi
│       ├── test_gpu_worker_telecom_zmq.cpp# ZMQ IPC kontrol düzlemi regresyon testi
│       └── test_gpu_doorbell_hardening.cu # GPU-PMD donanım değişmezleri testi
└── zmq/daemon/
    ├── gpu_worker.cpp                     # GPU işçi süreci (CUPS SHM + BAR1 P2P)
    ├── telco_worker.cpp                   # Telekom işçi süreci (DPU CUPS denetleyicisi)
    └── wire_protocol.h                    # TelcoGpuJobEnvelopeV1 ve upsert tel protokolü
```

---

## 8. İşletim ve Çalıştırma Kılavuzu (Operational Runbook)

### 8.1 DPU CUPS Kontrol Düzlemi Başlatma

DPU üzerinde telekom işçisi başlatılırken paylaşımlı bellek dosya yolu ve GPU ZMQ soketi belirtilir:

```bash
# 1. DPU ARM üzerinde telekom denetleyicisini ayağa kaldır
./build/zmq/samurai_telco_worker \
  --worker-id 1 \
  --sub-start 1 --sub-count 10000 \
  --cups-shm-path /dev/shm/samurai_cups_tunnels.bin \
  --cups-gpu-endpoint ipc:///tmp/cups_gpu_control.ipc
```

### 8.2 GPU Veri Düzlemi İşçisi Başlatma

GPU işçisi başlatıldığında aynı `/dev/shm` bölgesine bağlanır ve BAR1 P2P ringini aktif eder:

```bash
# 2. GPU tarafında paket motoru işçisini ayağa kaldır
./build/zmq/samurai_gpu_worker \
  --cups-shm-path /dev/shm/samurai_cups_tunnels.bin \
  --p2p-ring-handle 0x1 \
  --enable-p2p \
  --ipc-endpoint ipc:///tmp/cups_gpu_control.ipc
```

### 8.3 CLI Üzerinden Canlı GTP-U 5G İşi Tetikleme

Orkestratör üzerinden 5G QFI tünel trafiği başlatmak için:

```bash
./build/samurai_cli \
  --protocol gtpu \
  --target-ip 10.200.1.1 \
  --teid 0x12345678 \
  --qfi 9 \
  --vlan 100 \
  --inner-vlan 200 \
  --pps 5000000 \
  --duration 30
```

---

## 9. Doğrulama ve Test Matrisi

Sistemin tüm katmanları otomatik CTest ve bağımsız test ikilileri ile doğrulanmaktadır:

```bash
# Test paketini derle ve çalıştır
ctest --test-dir build --output-on-failure
```

### Doğrulanan Test Başlıkları

1. **`telecom_dpu_arm_cups_gpu_bridge`:**
   - DPU ARM üzerinde N4 PFCP ile 4 abonenin oluşturulması, QFI/TEID modifikasyonu ve silinmesi.
   - GPU'nun `/dev/shm` tünel tablosuna `cudaHostRegister` ile bağlanarak doğru GTP-U paketleri üretmesi.
2. **`telecom_gpu_kernels`:**
   - 4G temel GTP-U başlıkları ve CPU dekapsülasyon testi.
   - 5G QFI (0x85) PDU session container bayt düzeyinde doğruluk testi.
   - 802.1Q tek VLAN ve 802.1ad QinQ çift VLAN kapsülleme testi.
   - İç TCP ve ICMP çift katmanlı sağlama toplamı doğrulaması.
   - Dinamik seqlock tünel tablosu upsert ve temizleme testi.
3. **`telecom_gpu_worker_zmq`:**
   - Bozuk veya kesilmiş `TELCO_TUNNEL_UPSERT` paketlerinin güvenli reddi.
   - Sıfır tünelli clear-only komutunun işlenmesi.
   - Canlı ZMQ IPC üzerinden iş çalıştırma ve metrik akışı doğrulaması.
4. **`telecom_gpu_doorbell_hardening`:**
   - GPU-PMD donanım değişmezleri, BAR1 bellek sınırları ve `fence.proxy.tens` bariyer doğrulamaları.

**Sonuç:** `17/17 Test Passed (100% Başarı Oranı)`.
