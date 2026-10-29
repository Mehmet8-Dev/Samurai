# Samurai Modüler Telekom Motoru (Telecom Engine) - Mimari Tasarım Dokümanı
## Doküman No: 01_TELCO_ENGINE_ARCHITECTURE.md

> **Yazar:** Samurai Core Architecture Team  
> **Tarih:** 29 Ekim 2026  
> **Aktif Git Dalı:** `feat/telecom-engine-integration`  
> **Konum:** `ddos_samurai/plan/01_TELCO_ENGINE_ARCHITECTURE.md`  
> **Bağlantılı Dokümanlar:**  
> - [`README.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/README.md)  
> - [`02_STATEFUL_AND_STATELESS_PROTOCOLS.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/02_STATEFUL_AND_STATELESS_PROTOCOLS.md)  
> - [`03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/plan/03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md)  

---

## 1. Giriş ve Temel Tasarım İlkeleri

Samurai Telecom Engine, telekom operatörlerinin omurga ve kenar sistemlerini (BNG/BRAS, CGNAT, 4G/5G UPF, Taşıyıcı Ethernet Ağ Geçitleri) hat hızında ve milyonlarca eşzamanlı abone/tünel ölçeğinde test etmek için tasarlanmış saf C++ bir motor mimarisidir.

### 1.1 Çekirdek İlkeler (Core Axioms)

1. **Zero-Copy ve Sıfır Dinamik Bellek Tahsisi (Zero Dynamic Allocation on Fastpath):**
   - Çalışma anında (runtime loop) `malloc`, `new`, `std::vector::push_back` veya `std::string` kesinlikle kullanılmaz.
   - Tüm mbuf'lar önceden tahsis edilmiş DPDK `rte_mempool` bellek havuzlarından sağlanır.
   - Tüm oturum durumları başlatma anında (init-time) NUMA-farkındalıklı (NUMA-aware) devasa bellek bloklarına (Hugepages) yerleştirilir.

2. **Veri Düzlemi (Fastpath) ve Kontrol Düzlemi (Slowpath/FSM) Kesin Ayrımı:**
   - **Fastpath Worker Çekirdekleri:** Yalnızca donanım kuyruklarından gelen veri paketlerini (GTP-U kullanıcı verisi, PPPoE data, IPoE data) ayrıştırır, oturum tablosundan O(1) hızında TEID/SessionID eşleştirir ve iletir.
   - **Slowpath / FSM Worker Çekirdekleri:** Protokol müzakerelerini (LCP, PAP/CHAP, IPCP, DHCP DORA, PFCP Association, 802.1X EAP) yürütür. Bu paketler hızlı yoldan lock-free SPSC halkalar (`rte_ring`) ile kontrol çekirdeğine iletilir.
   - **ZMQ Kontrol Düzlemi Sınırı:** ZMQ IPC (`ipc:///tmp/samurai_jobs_*` ve `ipc:///tmp/samurai_events_*`) yalnızca testin başlatılması, yapılandırılması ve saniyede bir telemetri snapshot'ı için kullanılır. **Paket başına ZMQ mesajlaşması KESİNLİKLE YAPILMAZ.**

3. **Önbellek Çizgisi ve Sahte Paylaşım (False Sharing) Koruması:**
   - Her oturum veri yapısı (`TelcoSessionContext`) L1 veri önbelleği çizgisiyle (`alignas(64)`) tam hizalıdır (toplam 128 bayt, tam 2 önbellek çizgisi).
   - Birden fazla worker çekirdeğinin aynı önbellek çizgisine yazmasını engellemek için oturum tabloları CPU çekirdekleri arasında sharding (parçalama) yöntemiyle bölünür (Core-affinity shared-nothing sharding).

4. **Taşıyıcı Sınıfı Esinlenmeler:**
   - **RtBrick BNG Blaster:** Abone durum makineleri, zamanlayıcı çarkı (Hierarchical Timing Wheel) ve O(1) abone FSM geçişleri.
   - **Open5GS:** 3GPP TS 29.281 (GTPv1-U) ve TS 29.244 (PFCP) ikili başlık ayrıştırması ve durum modelleri.

---

## 2. Mevcut L2/L3 ve Telekom Bileşenlerinin Olgunluk Sınıflandırması

Bir protokol paketini tanımak veya sınıflandırabilmek, o protokolün tüm durum yaşam döngüsünün uygulandığı anlamına gelmez. Samurai kod tabanındaki mevcut bileşenler telekom yükü açısından 3 seviyede sınıflandırılır:

| Bileşen | Konum | Durum | Açıklama ve Yol Haritası |
|---|---|---|---|
| **`LockfreeArpTable`** | [`ddos_samurai/telecom/lockfree_l2l3_cache.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/telecom/lockfree_l2l3_cache.hpp) | **HAZIR** | 64-bayt hizalı, kilitli olmayan (atomic sequence/epoch), hat hızında O(1) MAC çözümleme tablosu. Telekom motorunda doğrudan kullanılır. |
| **`LockfreeNdTable`** | [`ddos_samurai/telecom/lockfree_l2l3_cache.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/telecom/lockfree_l2l3_cache.hpp) | **HAZIR** | IPv6 Neighbor Discovery için wait-free önbellek tablosu. |
| **`BfdEngine`** | [`ddos_samurai/l7_emu_native/l2l3_stack/bfd_engine.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/l2l3_stack/bfd_engine.hpp) | **HAZIR** | RFC 5880/5881 durum makinesi, asenkron keepalive ve failover tespiti. Telekom BFD oturumlarında kullanılır. |
| **`L2L3FastpathWiring`** | [`ddos_samurai/telecom/l2l3_fastpath_wiring.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/telecom/l2l3_fastpath_wiring.hpp) | **GENİŞLETİLEBİLİR** | Çerçeve sınıflandırması (`ControlFrameType::Pppoe`, `Dhcp`, `Bfd`, vb.) hazır; ancak GTP-U ve PFCP tünel başlık ayrıştırması eklenecektir. |
| **`DhcpStateMachine`** | [`ddos_samurai/l7_emu_native/l2l3_stack/dhcp_state_machine.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/l2l3_stack/dhcp_state_machine.hpp) | **GENİŞLETİLEBİLİR** | Tekil DORA durumları uygulanmış; 1M+ abone eşzamanlı kira yenileme çarkı (`HierarchicalTimingWheel`) entegrasyonu eklenecektir. |
| **`PppoeEngine`** | Planlanan: `ddos_samurai/telecom/protocols/stateful/pppoe/` | **EKSİK (Faz 1)** | Discovery (PADI/PADO/PADR/PADS/PADT) ve Session (LCP/PAP/CHAP/IPCP) FSM'leri uçtan uca uygulanacaktır. |
| **`GtpuEngine` / `PfcpEngine`** | Planlanan: `ddos_samurai/telecom/protocols/stateful/mobile/` | **EKSİK (Faz 2)** | 3GPP TS 29.281 / 29.244 tünel yönetimi ve TEID eşleme motoru uygulanacaktır. |

---

## 3. Modüler Protokol Arayüzü (`ITelcoProtocol`)

Tüm telekom protokolleri standart bir C++ soyutlamasına dayanır:

```cpp
namespace ddos_samurai::telecom {

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

## 4. Abone Oturum Yöneticisi (`SessionManager`)

Milyonlarca abonenin eşzamanlı simülasyonu için her abone oturumu tam **128 bayt (2 önbellek çizgisi)** olarak paketlenir:

```cpp
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

struct alignas(64) TelcoSessionContext {
    // --- 1. Cache Line (64 bytes): Sıcak Arama ve Tanımlayıcılar ---
    uint32_t session_id;       // PPPoE Session ID veya Abone İndeksi (4 byte)
    uint32_t teid_uplink;      // 5G/4G GTP-U Uplink TEID (4 byte)
    uint32_t teid_downlink;    // 5G/4G GTP-U Downlink TEID (4 byte)
    uint32_t client_ip;        // Tahsis edilen IPv4 adresi (4 byte)
    uint8_t  client_mac[6];    // Abone MAC adresi (6 byte)
    uint8_t  peer_mac[6];      // BRAS/UPF Ağ Geçidi MAC adresi (6 byte)
    uint16_t s_vlan;           // Outer/Service VLAN (QinQ 802.1ad) (2 byte)
    uint16_t c_vlan;           // Inner/Customer VLAN (802.1q) (2 byte)
    SessionState state;        // Oturum FSM Durumu (1 byte)
    uint8_t  protocol_id;      // PPPoE, IPoE, GTP, vb. (1 byte)
    uint16_t ppp_lcp_identifier;// PPP LCP/IPCP transaction id (2 byte)
    uint32_t ppp_magic_number; // PPP loop detection magic number (4 byte)
    uint64_t last_activity_tsc;// Son gelen/giden paket TSC zamanı (8 byte)
    uint64_t timer_expire_tsc; // Zamanlayıcı süresi dolma TSC zamanı (8 byte)
    uint32_t retry_count;      // Yeniden deneme sayacı (4 byte)
    uint8_t  pad1[4];          // 64 byte tamamlama (4 byte)

    // --- 2. Cache Line (64 bytes): Sayaçlar, Tünel Parametreleri ve Zamanlayıcı Bağları ---
    uint64_t tx_packets;       // İletilen toplam paket (8 byte)
    uint64_t rx_packets;       // Alınan toplam paket (8 byte)
    uint64_t tx_bytes;         // İletilen toplam bayt (8 byte)
    uint64_t rx_bytes;         // Alınan toplam bayt (8 byte)
    TelcoSessionContext* wheel_prev; // Zamanlayıcı çarkı çift yönlü bağlı liste (8 byte)
    TelcoSessionContext* wheel_next; // Zamanlayıcı çarkı çift yönlü bağlı liste (8 byte)
    void*    user_data;        // Protokole özel ek veri göstericisi (8 byte)
    uint64_t seid;             // PFCP Session Endpoint Identifier (8 byte)
};
static_assert(sizeof(TelcoSessionContext) == 128, "TelcoSessionContext tam 2 cache line (128 bayt) olmalidir!");

} // namespace ddos_samurai::telecom
```

---

## 5. BNG Blaster Esinlenmesi: Hiyerarşik Zamanlayıcı Çarkı (`HierarchicalTimingWheel`)

Geleneksel Min-Heap tabanlı zamanlayıcılar ($O(\log N)$) 1 milyon abone ölçeğinde CPU'yu kilitler. BNG Blaster mimarisi referans alınarak 3 kademeli $O(1)$ zamanlayıcı çarkı kullanılır:

- **Tier 0 (1ms Çözünürlük, 1024 Yuva):** BFD (10ms/30ms keepalive), PPPoE LCP Echo, hızlı yeniden iletimler.
- **Tier 1 (100ms Çözünürlük, 64 Yuva):** PPPoE PADI/PADR zaman aşımları, DHCP Kira T1/T2 durumları.
- **Tier 2 (1s Çözünürlük, 3600 Yuva):** Oturum genel ömrü, periyodik telemetri aralıkları.

`TelcoSessionContext` yapısı içerisindeki `wheel_prev` ve `wheel_next` işaretçileri sayesinde zamanlayıcı ekleme/çıkarma işlemleri **sıfır bellek tahsisi (zero allocation)** ile yalnızca 4 işaretçi güncellemesinden ibarettir.

---

## 6. DPDK Veri Düzlemi ve Donanım İzolasyonu

Ağ kartı donanım erişimi için Samurai'nin merkezi DPDK çekirdeği ([`ddos_samurai/dpdk/dpdk_core.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/dpdk/dpdk_core.hpp)) kullanılır.

### 6.1 Donanım Optimizasyon Kuralları
1. **Kuyruk Sahipliği (Queue Ownership):** Her worker çekirdeğine özel donanım TX ve RX kuyruğu atanır. Çekirdekler arası kilit (spinlock/mutex) KESİNLİKLE KULLANILMAZ.
2. **NUMA Yerleşimi:** NIC'in bağlı olduğu PCIe kök kompleksinin NUMA düğümündeki Hugepages üzerinden `rte_pktmbuf_pool_create` çağrılır. Çapraz NUMA (QPI/UPI veri yolu geçişi) önlenir.
3. **Burst Boyutu:** Hat hızı için optimum 64 mbuf burst işleme boyutu kullanılır.

```
[ Ağ Kartı (NIC) - 10G/40G/100G ] 
       |
       v  samurai::dpdk::ReceiveBurst (64 rte_mbuf)
+---------------------------------------------------------------------------------+
|               L2L3FastpathWiring::ClassifyFrame (ddos_samurai/telecom/)          |
+---------------------------------------------------------------------------------+
| 1. VLAN / QinQ Başlıklarını Çöz (802.1Q / 802.1ad)                              |
| 2. ControlFrameType Tespiti:                                                    |
|    - ControlFrameType::Pppoe -> PPPoE Discovery (0x8863) veya LCP (0x8864)      |
|    - ControlFrameType::Dhcp  -> DHCPv4 / DHCPv6 DORA mesajları                  |
|    - ControlFrameType::Bfd   -> BFD keepalive kontrolleri                       |
|    - ControlFrameType::Arp / Icmpv6Nd -> Lockfree L2/L3 önbellek çözümlemesi    |
|    - GTP-U / PFCP UDP Kontrolü (Port 2152 / 8805)                               |
+---------------------------------------------------------------------------------+
          |                                                       |
          | (Kontrol / FSM Paketleri)                             | (Veri Paketleri)
          v                                                       v
+-------------------------------+              +----------------------------------+
| RingBufferShuttle (SPSC Ring) |              | In-Place Fastpath Forward / Decap|
+-------------------------------+              +----------------------------------+
          |                                                       |
          v                                                       v
[ Telco Slowpath Core (FSM/HTW) ]              [ samurai::dpdk::SendBurst (NIC)   ]
```

---

## 7. ZMQ Dağıtık ve Yerel Kontrol Düzlemi (Gelişmiş Sharding Mimarisi)

### 7.1 Yerel Süreç Orkestrasyonu (Supervisor IPC)
- **Yönetici:** [`ddos_samurai/orchestrator/supervisor.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/orchestrator/supervisor.cpp)
- **Kayıt:** [`ddos_samurai/orchestrator/worker_registry.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/orchestrator/worker_registry.hpp) tablosuna `{WorkerKind::TELCO, "telco", "samurai_telco_worker"}` eklenir.
- **Soketler:** Supervisor süreci `fork/exec` ile başlatırken parametre olarak verir:
  - `--job-endpoint ipc:///tmp/samurai_jobs_telco` (ZMQ PULL)
  - `--event-endpoint ipc:///tmp/samurai_events_telco` (ZMQ PUSH)

### 7.2 Gelişmiş Sharding Mimarisi (`MasterCoordinator` & `WorkerShardService`)
500.000 abonenin iki düğüme 250.000'er dağıtılması yalnızca aralık bölmek değildir; 3 temel prensip uygulanır:

1. **Abone Kimliği ve Sahiplik (Identity Ownership):**  
   Her abonenin hangi worker'a ait olduğu MAC, VLAN ve Subscriber ID üzerinden deterministiktir. İki worker aynı aboneyi asla eşzamanlı yönetemez.
2. **Durum Sahipliği (State Ownership - Shared-Nothing):**  
   Bir abonenin FSM durumu ve zamanlayıcıları yalnızca atanmış çekirdeğin yerel belleğinde yaşar. Çekirdekler arası durum kilidi yoktur.
3. **İş Yükü Dengesi ve Retry Fırtınası Koruması:**  
   Bir shard'da BRAS yanıt vermediğinde ve binlerce abone aynı anda yeniden deneme (retry storm) döngüsüne girdiğinde, FSM CPU yükü telemetri ile izlenir; Master yeni oturum kurulum hızını (CPS pacing) dinamik olarak düşürür.
4. **Toparlanma (Failover):**  
   Bir slave düğüm çökerse, MasterCoordinator ilgili shard'ı diğer canlı slave düğüme atar. Durumlar temizlenip oturum kurulumu baştan başlatılır.

---

## 8. Performans ve Güvenilirlik Taahhütleri

- **Ölçeklenebilirlik:** Tek bir NUMA düğümünde 1.000.000+ aktif abone oturumu.
- **Kurulum Hızı (CPS):** DPDK ve Timing Wheel optimizasyonu ile en az 50.000 oturum/saniye (PPPoE Discovery + IPCP).
- **Hafıza Ayak İzi:** Abone başına tam 128 bayt (`sizeof(TelcoSessionContext)`). 1 milyon abone için sadece 128 MB RAM gereksinimi (önbellek dostu).
- **Dürüstlük ve Doğrulama Kuralı:** Donanım testleri yapılmadan teorik hat hızı "üretim onaylı" olarak iddia edilmeyecek; tüm metrikler donanım NIC sayaçları ve standart format ile doğrulanacaktır.
