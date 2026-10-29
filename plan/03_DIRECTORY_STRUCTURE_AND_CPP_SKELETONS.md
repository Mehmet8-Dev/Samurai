# Dizin Yapısı, Saf C++ İskeletleri ve Uygulama Haritası
## Doküman No: 03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md

> **Yazar:** Samurai Core Architecture Team  
> **Tarih:** 29 Ekim 2026  
> **Konum:** `ddos_samurai/plan/03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md`  
> **Bağlantılı Dokümanlar:**  
> - [`README.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/README.md)  
> - [`01_TELCO_ENGINE_ARCHITECTURE.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/01_TELCO_ENGINE_ARCHITECTURE.md)  
> - [`02_STATEFUL_AND_STATELESS_PROTOCOLS.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/02_STATEFUL_AND_STATELESS_PROTOCOLS.md)  

---

## 1. Dizin ve Dosya Hiyerarşisi

Samurai projesinin mevcut mimarisinde (`ddos_samurai/`):
- **Tek Native DPDK Katmanı:** [`ddos_samurai/dpdk/`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/dpdk/) altında (`dpdk_core.hpp`, `dpdk_core.cpp`) konsolide edilmiştir. Dolayısıyla telekom motorunun içinde mükerrer/ikinci bir `dpdk/` dizini **açılmaz**; mevcut `dpdk_core` kullanılır.
- **Telekom Motoru Kütüphanesi:** Mevcut [`ddos_samurai/telecom/`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/telecom/) dizini altında toplanır.
- **Worker Daemon:** Diğer tüm worker'lar gibi projenin ana ZMQ dizini olan [`ddos_samurai/zmq/daemon/`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/) altında yer alır.

```
ddos_samurai/
├── dpdk/                                 # MEVCUT: DDoSamurai'nin TEK Native DPDK Çekirdeği
│   ├── dpdk_core.hpp                     # Port yapılandırması, mempool, RSS ve RX/TX burst soyutlaması
│   └── dpdk_core.cpp                     # rte_eth_rx_burst / rte_eth_tx_burst hat hızı I/O
│
├── telecom/                              # MEVCUT: Taşıyıcı Sınıfı Telekom Motoru (samurai_telecom)
│   ├── CMakeLists.txt                    # samurai_telecom_static kütüphanesi
│   ├── lockfree_l2l3_cache.hpp           # Mevcut: 64-bayt hizalı ARP/ND kilitli olmayan tablolar
│   ├── l2l3_fastpath_wiring.hpp          # Mevcut: Hızlı yol çerçeve sınıflandırma ve yönlendirme
│   ├── l2l3_fastpath_wiring.cpp
│   ├── core/
│   │   ├── telco_protocol_if.hpp         # ITelcoProtocol taban soyutlaması ve metadatalar
│   │   ├── session_context.hpp           # 128-bayt hizalı TelcoSessionContext struct
│   │   ├── session_manager.hpp           # 1M+ abone için lock-free bellek ve arama tablosu
│   │   ├── session_manager.cpp
│   │   ├── hierarchical_timing_wheel.hpp # BNG Blaster esinli 3 kademeli (1ms/100ms/1s) O(1) çark
│   │   ├── hierarchical_timing_wheel.cpp
│   │   ├── fastpath_classifier.hpp       # Donanım mbuf ayrıştırıcı ve FSM/Fastpath demux
│   │   ├── fastpath_classifier.cpp
│   │   └── ring_buffer_shuttle.hpp       # Fastpath ile Slowpath FSM arası SPSC halka kuyruğu
│   └── protocols/
│       ├── stateful/
│       │   ├── pppoe/
│       │   │   ├── pppoe_types.hpp       # RFC 2516 / RFC 1661 ikili başlıklar (packed)
│       │   │   ├── pppoe_fsm.hpp         # LCP, PAP/CHAP, IPCP durum makinesi
│       │   │   ├── pppoe_engine.hpp      # ITelcoProtocol PPPoE uygulaması
│       │   │   └── pppoe_engine.cpp
│       │   ├── dhcp/
│       │   │   ├── dhcpv4_engine.hpp     # IPoE DHCPv4 DORA & kira yöneticisi
│       │   │   └── dhcpv4_engine.cpp
│       │   └── mobile/
│       │       ├── gtpu_types.hpp        # 3GPP TS 29.281 GTPv1-U başlıkları
│       │       ├── gtpu_engine.hpp       # GTP-U tünel ve echo canlılık motoru
│       │       ├── gtpu_engine.cpp
│       │       ├── pfcp_types.hpp        # 3GPP TS 29.244 PFCP N4 ikili başlıkları
│       │       ├── pfcp_engine.hpp       # PFCP Association & PDR/FAR oturum motoru
│       │       └── pfcp_engine.cpp
│       └── stateless/
│           ├── stateless_gtpu_flooder.hpp # Yüksek hızlı hat hızında GTP-U basıcı
│           ├── stateless_gtpu_flooder.cpp
│           ├── qinq_sweep_engine.hpp      # Çift katmanlı VLAN (802.1ad) tarama motoru
│           └── qinq_sweep_engine.cpp
│
└── zmq/                                  # MEVCUT: Samurai ZMQ Dağıtık Düzlemi
    ├── CMakeLists.txt                    # add_samurai_worker(samurai_telco_worker daemon/telco_worker.cpp)
    └── daemon/
        ├── telco_worker.cpp              # YENİ: MasterCoordinator'a bağlanan Telco Worker Daemon
        ├── wire_protocol.h               # WorkerKind::TELCO = 10, TelcoMsgType uzantıları
        ├── worker_common.hpp             # Ortak socket ve sinyal yakalayıcılar
        ├── zmq_worker_base.hpp           # Taban worker sınıfı
        └── (mevcut: dpdk_worker.cpp, l7_worker.cpp, cpu_worker.cpp, afxdp_worker.cpp...)
```

---

## 2. Saf C++ Çekirdek Sınıf İskeletleri

### 2.1 Protokol Taban Arayüzü: `telco_protocol_if.hpp`

```cpp
#pragma once

#include <cstdint>
#include <string_view>

struct rte_mbuf;
struct rte_mempool;

namespace ddos_samurai::telecom {

struct TelcoSessionContext;

enum class TelcoProtocolId : uint8_t {
    NONE = 0,
    PPPOE = 1,
    DHCPV4 = 2,
    DHCPV6 = 3,
    GTPU = 4,
    PFCP = 5,
    BFD = 6,
    DOT1X = 7,
    STATELESS_GTPU = 10,
    QINQ_SWEEP = 11
};

struct PacketMetadata {
    uint16_t outer_vlan;
    uint16_t inner_vlan;
    uint16_t ether_type;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    const uint8_t* payload_ptr;
    uint16_t payload_len;
};

struct ProtocolConfig {
    uint32_t max_sessions{100000};
    uint32_t rate_cps{1000};        // Kurulum Hızı (Calls Per Second)
    uint32_t retransmit_timeout_ms{500};
    uint32_t max_retries{3};
    bool     enable_vlan_tagging{false};
};

class ITelcoProtocol {
public:
    virtual ~ITelcoProtocol() = default;

    virtual bool Init(const ProtocolConfig& cfg) = 0;
    virtual void Shutdown() = 0;

    // Gelen veri veya kontrol paketini işle
    virtual void OnRxPacket(rte_mbuf* mbuf, 
                            const PacketMetadata& meta, 
                            TelcoSessionContext* session) = 0;

    // Zamanlayıcı tikinde retransmission veya periyodik işleri yürüt
    virtual uint32_t OnTimerTick(uint64_t current_tsc) = 0;

    // Belirli bir oturum ve olay için paket üret
    virtual rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                                    TelcoSessionContext* session, 
                                    uint16_t event_type) = 0;

    virtual bool IsStateful() const noexcept = 0;
    virtual TelcoProtocolId GetProtocolId() const noexcept = 0;
    virtual std::string_view GetProtocolName() const noexcept = 0;
};

} // namespace ddos_samurai::telecom
```

---

### 2.2 128-Bayt Önbellek Hizalı Oturum Bağlamı: `session_context.hpp`

```cpp
#pragma once

#include <cstdint>

namespace ddos_samurai::telecom {

enum class SessionState : uint8_t {
    IDLE = 0,
    DISCOVERING,     // PPPoE PADI / DHCP DISCOVER / PFCP Assoc Req
    AUTHENTICATING,  // PPP PAP/CHAP / 802.1X EAP
    ESTABLISHED,     // Aktif tünel / Abone hatta / Veri akışı serbest
    TERMINATING,     // PADT / DHCP RELEASE / PFCP Deletion
    FAILED,          // Timeout veya auth rejection
    TEARDOWN         // Bellek temizleme aşaması
};

struct alignas(16) Flow5Tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[7];
};

struct alignas(64) TelcoSessionContext {
    // =========================================================================
    // --- 1. CACHE LINE (64 Bayt): FASTPATH 5-TUPLE, L2/L3 & TÜNEL TANIMLAYICILARI ---
    // =========================================================================
    // Durumlu L4 5-Tuple (IPv4/Port/Protokol - 13 bayt)
    uint32_t client_ip;        // Abone IPv4 adresi (4 bayt)
    uint32_t peer_ip;          // Ağ geçidi / Hedef Sunucu IPv4 adresi (4 bayt)
    uint16_t client_port;      // İstemci kaynak portu (2 bayt)
    uint16_t peer_port;        // Sunucu hedef portu (2 bayt)
    uint8_t  ip_proto;         // IP Protokol numarası (TCP:6, UDP:17, ICMP:1) (1 bayt)

    // Telekom Kimlikleri ve Tüneller (16 bayt)
    uint32_t session_id;       // PPPoE Session ID veya Abone İndeksi (4 bayt)
    uint32_t teid_uplink;      // 5G/4G GTP-U Uplink TEID (4 bayt)
    uint32_t teid_downlink;    // 5G/4G GTP-U Downlink TEID (4 bayt)
    uint16_t s_vlan;           // Outer Service VLAN (802.1ad QinQ) (2 bayt)
    uint16_t c_vlan;           // Inner Customer VLAN (802.1q) (2 bayt)

    // L2 MAC Adresleri (12 bayt)
    uint8_t  client_mac[6];    // Abone MAC adresi (6 bayt)
    uint8_t  peer_mac[6];      // BRAS / Ağ Geçidi MAC adresi (6 bayt)

    // Durum ve Hızlı Eşleme Doğrulaması (13 bayt)
    SessionState state;        // FSM Oturum Durumu (1 bayt)
    uint8_t  protocol_id;      // PPPOE, DHCP, GTP, vb. (1 bayt)
    uint32_t flow_hash;        // Donanım RSS / SSE4.2 CRC32 5-Tuple Hash Özeti (4 bayt)
    uint8_t  pad1[6];          // 64 Bayta Tamamlama Dolgusu (6 bayt)
    // -------------------------------------------------------------------------
    // 1. Cache Line Toplamı: 13 + 16 + 12 + 1 + 1 + 4 + 7 = 64 bayt.

    // =========================================================================
    // --- 2. CACHE LINE (64 Bayt): ZAMANLAYICI ÇARKI, FSM VE TELEMETRİ SAYAÇLARI ---
    // =========================================================================
    // Hiyerarşik Zamanlayıcı Çarkı Bağlantıları (O(1) İki Yönlü Liste - 24 bayt)
    TelcoSessionContext* wheel_prev; // Zamanlayıcı çarkı önceki düğüm (8 bayt)
    TelcoSessionContext* wheel_next; // Zamanlayıcı çarkı sonraki düğüm (8 bayt)
    uint64_t timer_expire_tsc;       // Zaman aşımı süresi dolma TSC zamanı (8 bayt)
    uint64_t last_activity_tsc;      // Son gelen/giden paket TSC zamanı (8 bayt)

    // Telemetri ve Performans Sayaçları (24 bayt)
    uint64_t tx_packets;             // İletilen toplam paket (8 bayt)
    uint64_t rx_packets;             // Alınan toplam paket (8 bayt)
    uint64_t tx_bytes;               // İletilen toplam bayt (8 bayt)
    uint64_t rx_bytes;               // Alınan toplam bayt (8 bayt)

    // PPP / Tünel Protokol FSM Parametreleri (8 bayt)
    uint16_t ppp_lcp_identifier;     // PPP transaction identifier (2 bayt)
    uint16_t retry_count;            // Yeniden deneme sayacı (2 bayt)
    uint32_t ppp_magic_number;       // PPP loop detection magic number (4 bayt)
    // -------------------------------------------------------------------------
    // 2. Cache Line Toplamı: 32 + 24 + 8 = 64 bayt.
};
static_assert(sizeof(TelcoSessionContext) == 128, "TelcoSessionContext tam 2 cache line (128 bayt) olmalidir!");

} // namespace ddos_samurai::telecom
```

---

### 2.3 Oturum Yöneticisi: `session_manager.hpp`

```cpp
#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"
#include <cstdint>
#include <memory>
#include <atomic>
#include <vector>

namespace ddos_samurai::telecom {

class SessionManager {
public:
    explicit SessionManager(uint32_t max_sessions, int socket_id = 0);
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    // Yeni oturum tahsis et (O(1) Lock-Free ID havuzundan)
    TelcoSessionContext* AcquireSession();

    // Oturumu havuza iade et
    void ReleaseSession(TelcoSessionContext* ctx);

    // Birincil indeksle hızlı erişim (O(1))
    inline TelcoSessionContext* GetSessionByIndex(uint32_t index) noexcept {
        if (__builtin_expect(index >= max_sessions_, 0)) return nullptr;
        return &sessions_pool_[index];
    }

    // PPPoE için MAC + SessionID ile arama
    TelcoSessionContext* FindPppoeSession(const uint8_t mac[6], uint16_t session_id) noexcept;

    // 4G/5G için TEID ile arama
    TelcoSessionContext* FindGtpuSession(uint32_t teid) noexcept;

    // Durumlu L4 5-Tuple ile donanım hızlandırmalı O(1) arama
    TelcoSessionContext* FindSessionBy5Tuple(const Flow5Tuple& tuple) noexcept;
    TelcoSessionContext* FindSessionBy5Tuple(uint32_t src_ip, uint32_t dst_ip, 
                                            uint16_t src_port, uint16_t dst_port, 
                                            uint8_t proto) noexcept;

    uint32_t GetActiveSessionCount() const noexcept {
        return active_sessions_.load(std::memory_order_relaxed);
    }

    uint32_t GetCapacity() const noexcept { return max_sessions_; }

private:
    uint32_t max_sessions_;
    int socket_id_;
    TelcoSessionContext* sessions_pool_{nullptr}; // Hugepages üzerinde ayrılır
    std::atomic<uint32_t> active_sessions_{0};

    // Boş oturum indekslerini tutan kilitli olmayan (lock-free) yığın
    std::unique_ptr<uint32_t[]> free_indices_;
    std::atomic<uint32_t> free_head_{0};

    // 5-Tuple O(1) arama hash tablosu (Donanım CRC32 intrinsics)
    static constexpr uint32_t HASH_TABLE_SIZE = 1048576; // 1M yuva
    static constexpr uint32_t HASH_TABLE_MASK = HASH_TABLE_SIZE - 1;
    TelcoSessionContext** hash_buckets_{nullptr};
};

} // namespace ddos_samurai::telecom
```

---

### 2.3 Hiyerarşik Zamanlayıcı Çarkı: `hierarchical_timing_wheel.hpp`

```cpp
#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"
#include <cstdint>
#include <functional>

namespace ddos_samurai::telecom {

class HierarchicalTimingWheel {
public:
    static constexpr size_t TIER0_SLOTS = 1024; // 1ms çözünürlük (0 - 1023 ms)
    static constexpr size_t TIER1_SLOTS = 64;   // 100ms çözünürlük (0 - 6.4 s)
    static constexpr size_t TIER2_SLOTS = 3600; // 1s çözünürlük (0 - 3600 s)

    using ExpireCallback = std::function<void(TelcoSessionContext*)>;

    HierarchicalTimingWheel(uint64_t tsc_hz);
    ~HierarchicalTimingWheel() = default;

    // Oturumu belirli bir gecikmeyle (milisaniye) çarka bağla (O(1))
    void Schedule(TelcoSessionContext* session, uint32_t delay_ms);

    // Oturumu çarktan çıkar (O(1))
    void Cancel(TelcoSessionContext* session);

    // Her çalışma döngüsünde TSC ile çağrılır; süresi dolanları tetikler
    uint32_t Advance(uint64_t current_tsc, ExpireCallback cb);

private:
    uint64_t tsc_hz_;
    uint64_t tsc_per_ms_;
    uint64_t last_tsc_{0};

    uint32_t wheel0_idx_{0};
    uint32_t wheel1_idx_{0};
    uint32_t wheel2_idx_{0};

    TelcoSessionContext* tier0_[TIER0_SLOTS]{nullptr};
    TelcoSessionContext* tier1_[TIER1_SLOTS]{nullptr};
    TelcoSessionContext* tier2_[TIER2_SLOTS]{nullptr};

    void InsertIntoTier0(TelcoSessionContext* session, uint32_t slot);
    void RemoveFromList(TelcoSessionContext** head, TelcoSessionContext* session);
};

} // namespace ddos_samurai::telecom
```

---

### 2.4 ZMQ Wire Protocol Uzantısı: `wire_protocol.h`

Mevcut `ddos_samurai/zmq/daemon/wire_protocol.h` dosyasına eklenecek telekom modülleri:

```cpp
// ddos_samurai/zmq/daemon/wire_protocol.h içerisine eklenecek:

enum class WorkerKind : std::uint8_t {
  CPU = 1,
  GPU = 2,
  DPDK = 3,
  AF_XDP = 4,
  DOCA = 5,
  L7 = 6,
  DEFENSE = 7,
  SCENARIO = 8,
  AF_PACKET = 9,
  TELCO = 10, // YENİ: Taşıyıcı Sınıfı Telekom Motoru Worker Daemon
};

enum class TelcoMsgType : uint16_t {
    START_PPPOE_EMULATION = 0x0501,
    STOP_PPPOE_EMULATION  = 0x0502,
    START_GTPU_EMULATION  = 0x0503,
    STOP_GTPU_EMULATION   = 0x0504,
    TELCO_STATS_REQUEST   = 0x0505,
    TELCO_STATS_REPORT    = 0x0506
};

#pragma pack(push, 1)
struct TelcoJobPayload {
    uint32_t subscriber_count;
    uint32_t rate_cps;
    uint16_t base_vlan_s;
    uint16_t base_vlan_c;
    uint8_t  base_mac[6];
    uint32_t base_client_ip;
    uint32_t gateway_ip;
    char     auth_username[32];
    char     auth_password[32];
};

struct TelcoStatsPayload {
    uint32_t active_sessions;
    uint32_t established_sessions;
    uint32_t failed_sessions;
    uint32_t current_cps;
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint32_t avg_setup_latency_us;
};
#pragma pack(pop)
```

---

### 2.5 ZMQ Worker Daemon İskeleti ve CMake Bağlantısı: `telco_worker.cpp`

Tüm Samurai worker daemon'ları gibi (`cpu_worker.cpp`, `dpdk_worker.cpp`, `l7_worker.cpp`), yeni `telco_worker.cpp` de doğrudan `ddos_samurai/zmq/daemon/` altında yer alır ve `ddos_samurai/zmq/CMakeLists.txt` içerisine `add_samurai_worker` makrosuyla eklenir:

```cmake
# ddos_samurai/zmq/CMakeLists.txt içine eklenecek yapılandırma:
add_samurai_worker(samurai_telco_worker daemon/telco_worker.cpp)
target_include_directories(samurai_telco_worker PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../telecom
    ${CMAKE_CURRENT_SOURCE_DIR}/../telecom/core 
    ${CMAKE_CURRENT_SOURCE_DIR}/../telecom/protocols
    ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk)
target_link_libraries(samurai_telco_worker PRIVATE 
    samurai_telecom_static 
    samurai_core 
    pacing_engine_static 
    pthread 
    dl)

if(DPDK_FOUND)
  target_compile_definitions(samurai_telco_worker PRIVATE SAMURAI_WITH_DPDK=1)
  target_include_directories(samurai_telco_worker PRIVATE ${DPDK_INCLUDE_DIRS})
  target_link_directories(samurai_telco_worker PRIVATE ${DPDK_LIBRARY_DIRS})
  target_link_libraries(samurai_telco_worker PRIVATE ${DPDK_LIBRARIES})
  target_compile_options(samurai_telco_worker PRIVATE ${DPDK_CFLAGS_OTHER})
  target_link_options(samurai_telco_worker PRIVATE ${DPDK_LDFLAGS_OTHER})
endif()
```

#### 2.5.1 Orkestratör Kaydı: `ddos_samurai/orchestrator/worker_registry.hpp`

Samurai'nin Supervisor ve Shard yöneticisi tarafından worker'ın otomatik tanınması için tabloya eklenir:

```cpp
// ddos_samurai/orchestrator/worker_registry.hpp içine eklenecek:
inline constexpr WorkerEntry kWorkerTable[] = {
    {samurai::wire::WorkerKind::CPU, "cpu", "samurai_cpu_worker"},
    {samurai::wire::WorkerKind::GPU, "gpu", "samurai_gpu_worker"},
    {samurai::wire::WorkerKind::DPDK, "dpdk", "samurai_dpdk_worker"},
    {samurai::wire::WorkerKind::AF_XDP, "afxdp", "samurai_afxdp_worker"},
    {samurai::wire::WorkerKind::DOCA, "doca", "samurai_doca_worker"},
    {samurai::wire::WorkerKind::L7, "l7", "samurai_l7_worker"},
    {samurai::wire::WorkerKind::DEFENSE, "defense", "samurai_defense_worker"},
    {samurai::wire::WorkerKind::SCENARIO, "scenario", "samurai_scenario_worker"},
    {samurai::wire::WorkerKind::AF_PACKET, "afpacket", "samurai_afpacket_worker"},
    {samurai::wire::WorkerKind::TELCO, "telco", "samurai_telco_worker"}, // YENİ
};
```

#### 2.5.2 `ddos_samurai/zmq/daemon/telco_worker.cpp` İskeleti:

```cpp
#include "wire_protocol.h"
#include "worker_common.hpp"
#include "zmq_worker_base.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/dpdk/dpdk_core.hpp"
#include <zmq.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>

using namespace samurai::wire;
using namespace samurai::daemon;
using namespace ddos_samurai::telecom;

int main(int argc, char** argv) {
    std::string jobs_endpoint = "ipc:///tmp/samurai_jobs_telco";
    std::string events_endpoint = "ipc:///tmp/samurai_events_telco";

    // Supervisor argümanlarını ayrıştır (SupervisorConfig::SpawnWorker standardı)
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--job-endpoint" && i + 1 < argc) {
            jobs_endpoint = argv[++i];
        } else if (std::string(argv[i]) == "--event-endpoint" && i + 1 < argc) {
            events_endpoint = argv[++i];
        }
    }

    std::cout << "[TELCO_WORKER] Samurai Carrier-Grade Telco Daemon baslatiliyor..." << std::endl;
    std::cout << "[TELCO_WORKER] Jobs (PULL): " << jobs_endpoint << ", Events (PUSH): " << events_endpoint << std::endl;

    void* zmq_ctx = zmq_ctx_new();
    void* jobs_sock = zmq_socket(zmq_ctx, ZMQ_PULL);
    void* events_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);

    // Supervisor soket bağlama protokolü (Worker jobs'ı bağlar, events'e bağlanır)
    if (zmq_bind(jobs_sock, jobs_endpoint.c_str()) != 0) {
        // Zaten bağlıysa bağlanmayı dene
        zmq_connect(jobs_sock, jobs_endpoint.c_str());
    }
    zmq_connect(events_sock, events_endpoint.c_str());

    // 1.000.000 abone kapasiteli SessionManager başlat (Hugepages)
    SessionManager session_mgr(1000000);

    // 1ms çözünürlüklü Timing Wheel (2.4 GHz TSC kalibrasyonu)
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel timing_wheel(tsc_hz);

    std::atomic<bool> running{true};
    uint64_t last_metric_tsc = __builtin_ia32_rdtsc();
    uint64_t tsc_per_sec = tsc_hz;

    // Ana olay döngüsü
    while (running.load(std::memory_order_relaxed)) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        
        // ZMQ komutlarını non-blocking yokla
        int rc = zmq_msg_recv(&msg, jobs_sock, ZMQ_DONTWAIT);
        if (rc > 0) {
            auto* hdr = reinterpret_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
            if (IsHeaderV1Compatible(*hdr)) {
                if (hdr->msg_type == static_cast<uint8_t>(MessageType::START_JOB)) {
                    // Telco emülasyonunu başlat (Abone havuzlarını ve zamanlayıcı çarkını kur)
                } else if (hdr->msg_type == static_cast<uint8_t>(MessageType::STOP_JOB)) {
                    // Oturum sonlandırma / Teardown
                } else if (hdr->msg_type == static_cast<uint8_t>(MessageType::SHUTDOWN)) {
                    running.store(false);
                }
            }
            zmq_msg_close(&msg);
        }

        uint64_t now_tsc = __builtin_ia32_rdtsc();

        // 1. Zamanlayıcı çarkını ilerlet (Retransmit / Keepalive)
        timing_wheel.Advance(now_tsc, [](TelcoSessionContext* ctx) {
            // Süresi dolan FSM olayını işle
        });

        // 2. Periyodik MetricSnapshotV1 gönder (Her saniye)
        if (now_tsc - last_metric_tsc >= tsc_per_sec) {
            MetricSnapshotV1 snap{};
            snap.packets_sent = session_mgr.GetActiveSessionCount(); // Örnek telemetri
            snap.actual_rps = session_mgr.GetActiveSessionCount();
            snap.rate_accuracy_pct = 100.0;

            SendFrame(events_sock, MessageType::METRIC_SNAPSHOT, 0, WorkerKind::TELCO, "", &snap, sizeof(snap));
            last_metric_tsc = now_tsc;
        }
    }

    zmq_close(jobs_sock);
    zmq_close(events_sock);
    zmq_ctx_term(zmq_ctx);
    return 0;
}
```

---

## 3. 5 Aşamalı Test ve Doğrulama Yol Haritası (5-Stage Verification Roadmap)

Yüz binlerce aboneye geçmeden önce, tek protokolde (PPPoE) uçtan uca doğrulanabilir 5 aşamalı test planı uygulanır:

| Aşama | Test Kapsamı | Test Dosyası / Senaryosu | Başarı ve Doğrulama Ölçütü (Pass Criteria) |
|---|---|---|---|
| **Aşama 1** | Tek worker, düşük sayıda PPPoE oturumu (1 - 100) | `tests/test_pppoe_fsm.cpp` | PADI -> PADO -> PADR -> PADS -> LCP (MRU/Auth) -> CHAP (MD5) -> IPCP (IP/DNS) durum akışı ve veri akışı başarı oranı %100. |
| **Aşama 2** | Tek worker, artan abone sayısı (1.000 -> 100.000) | `tests/test_telco_session_mgr.cpp` & `tests/test_timing_wheel.cpp` | 128-bayt önbellek hizalaması korunur; 100.000 abonede bellek tüketimi <= 16 MB; O(1) HTW tik süresi < 500 ns. |
| **Aşama 3** | Çoklu worker (Multi-Worker Core Affinity) | `tests/test_multi_worker_telco.cpp` | Her CPU çekirdeğine bir worker sharding; kilitli olmayan halka (SPSC) üzerinden sıfır yarış durumu (zero race condition). |
| **Aşama 4** | Çoklu düğüm kümesi (Master + 2 Slave) | `tests/test_telco_cluster_sharding.cpp` | `MasterCoordinator` ve `WorkerShardService` üzerinden 500.000 abonenin eşit ve dengeli dağıtılması; hedef CPS doğrulaması. |
| **Aşama 5** | Uzun süreli stres ve hata enjeksiyonu | `tests/test_telco_chaos_recovery.cpp` | PADT fırtınası (teardown storm), sunucu çökmesi, hat kopması (link flap) ve yeniden deneme fırtınası (retry storm) altında toparlanma. |

### Standart Telemetri ve Denetim Log Formatı (Audit Output)
Tüm aşamalarda ölçümler şu ortak şemayla kaydedilir:

```
test_id,protocol,subscriber_count,active_sessions,session_setup_rate_cps,session_failure_rate_pct,packets_per_second,rx_drops,tx_errors,cpu_utilization_pct,memory_usage_mb,test_duration_s,hardware_spec
```

*Örnek Log Kaydı:*
```
TELCO-STG1-001,PPPOE,100,100,250.0,0.0,500,0,0,1.2,0.01,5.0,"Local Veth, DPDK 22.11, Core i7"
TELCO-STG2-001,PPPOE,100000,99850,12500.0,0.15,200000,0,0,18.4,12.8,30.0,"Local Veth, DPDK 22.11, Core i7"
```
