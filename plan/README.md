# Samurai Modüler Telekom Motoru (Telecom Engine) Mimari Ana Planı
## Taşıyıcı Sınıfı (Carrier-Grade) Durumlu (Stateful) ve Durumsuz (Stateless) Protokol Yığını

> **Tarih:** 29 Ekim 2026  
> **Aktif Git Dalı:** `feat/telecom-engine-integration`  
> **Konum:** `samurai/plan/`  
> **Mimari Hedef:** Saf Modern C++ (C++17/C++20), DPDK Hat Hızı (Wire-Speed Zero-Copy), Samurai Dağıtık ZMQ Kontrol Düzlemi, Modüler Eklenti Mimarisi (`ITelcoProtocol`), RtBrick BNG Blaster (Abone/Erişim FSM & O(1) Timing Wheel) ve Open5GS (GTP/PFCP Mobil Tünelleri) Entegrasyon Modeli.

---

## 1. Yönetici Özeti ve Mimari Vizyon

Samurai; donanım düzeyinde DPDK, AF_XDP ve DOCA GPUNetIO, kullanıcı uzayında RFC 6675 SACK destekli durum bilgili TCP motoru (`TcpDataplaneCore`), L7 ve telemetri altyapısına sahiptir. 

Geliştirilecek olan **Samurai Telecom Engine (`samurai/telecom/`)**, projeyi yalnızca bir siber güvenlik ve stres testi aracı olmaktan çıkarıp, telekom operatörlerinin omurga ve kenar ağlarında (BNG/BRAS, CGNAT, 4G/5G UPF, ISP Peering ve Taşıyıcı Ethernet) **milyonlarca gerçek aboneyi ve mobil tüneli hat hızında emüle eden, doğrulayan ve test eden endüstri standardı bir telekom doğrulama platformuna** dönüştürür.

### 1.1 Temel Mimari İlkeler (Core Axioms)

1. **Mevcut DPDK Katmanının Konsolidasyonu (Tek Sorumluluk):**  
   Telekom motoru içinde fazladan/iç bir `dpdk/` dizini açılmaz. Tüm donanım I/O işlemleri projenin tek native DPDK çekirdeği olan [`samurai/dpdk/dpdk_core.hpp`](../samurai/dpdk/dpdk_core.hpp) üzerinden yürütülür. Ortak API kullanılsa dahi kuyruk sahipliği (queue ownership), NUMA yerleşimi, mbuf bellek havuzları ve burst boyutları telekom iş yükü özelinde izole edilir.
2. **Kontrol Düzlemi ile Veri Düzleminin Kesin Ayrımı:**  
   - **Kontrol Düzlemi (Control Plane):** Test senaryolarının başlatılması, iş dağıtımı ve periyodik telemetri toplama işlemleri ZMQ IPC (`ipc:///tmp/samurai_jobs_*` ve `ipc:///tmp/samurai_events_*`) ile yürütülür. **Paket başına ZMQ mesajlaşması KESİNLİKLE YAPILMAZ.**
   - **Veri Düzlemi (Data Plane):** Paket ayrıştırma, oturum tablosu aramaları, FSM güncellemeleri ve TX enjeksiyonu doğrudan CPU/DPDK halkaları (`rte_ring`) ve paylaşılan bellek üzerinde döner.
3. **Mevcut L2/L3 Altyapısının Olgunluk Seviyesine Göre Sınıflandırılması:**  
   Bir paketi sınıflandırmak, o protokolün tüm oturum yaşam döngüsünü yönetebilmek demek değildir. Mevcut bileşenler net sınıflandırılır:
   - **Hazır:** [`LockfreeArpTable`](../samurai/telecom/lockfree_l2l3_cache.hpp), [`LockfreeNdTable`](../samurai/telecom/lockfree_l2l3_cache.hpp), [`BfdEngine`](../samurai/l7_emu_native/l2l3_stack/bfd_engine.hpp) (FSM & keepalive negotiation).
   - **Genişletilebilir:** [`L2L3FastpathWiring`](../samurai/telecom/l2l3_fastpath_wiring.hpp) (temel çerçeve ayrımı var, telekom tünel demux eklenecek), [`DhcpStateMachine`](../samurai/l7_emu_native/l2l3_stack/dhcp_state_machine.hpp) (tekil DORA var, 1M+ abone kira çarkı eklenecek).
   - **Eksik:** PPPoE Discovery + Session (LCP/PAP/CHAP/IPCP) uçtan uca FSM, GTP-U/PFCP mobil tünelleri.
4. **Tek Protokol Odaklı Aşamalı Geliştirme (Single Protocol First):**  
   Tüm protokolleri (PPPoE, DHCP, GTP-U, PFCP, 802.1X) aynı anda bitirmeye çalışmak yerine, önce **PPPoE (Discovery + LCP/PAP/CHAP/IPCP)** baştan sona çalışan, ölçülebilen ve dağıtık çalıştırılabilen bir referans olarak tamamlanacak; ardından ortak mimari diğer protokollere yaygınlaştırılacaktır.
5. **Gelişmiş Sharding (Yalnızca Aralık Bölmek Değildir):**  
   MasterCoordinator ve WorkerShardService entegrasyonunda abone kimlik sahipliği (ownership), durum sahipliği (state ownership - shared-nothing) ve iş yükü dengesi (aktif oturum vs yeniden deneme fırtınası) ayrı ayrı yönetilir.

---

## 2. Doküman İndeksi

Bu dizindeki plan dokümanları, telekom motorunun her katmanını derinlemesine açıklar:

| Doküman | Başlık | Kapsam |
|---|---|---|
| [`01_TELCO_ENGINE_ARCHITECTURE.md`](01_TELCO_ENGINE_ARCHITECTURE.md) | **Telecom Engine Çekirdek Mimarisi** | `ITelcoProtocol` modüler arayüzü, 128-bayt hizalı abone oturum yöneticisi (`SessionManager`), BNG Blaster esinli zamanlayıcı çarkı (`HierarchicalTimingWheel`), DPDK Ring veri akışı, Supervisor IPC ve `samurai/zmq/daemon/telco_worker.cpp` daemon tasarımı. |
| [`02_STATEFUL_AND_STATELESS_PROTOCOLS.md`](02_STATEFUL_AND_STATELESS_PROTOCOLS.md) | **Durumlu ve Durumsuz Protokoller** | **Durumlu:** PPPoE (LCP/PAP/CHAP/IPCP), DHCPv4/v6, BFD, 802.1X EAP, GTP-U tünelleri ve PFCP oturumları. **Durumsuz:** Hat hızında stateless GTP-U payload basıcı, QinQ (802.1ad) taraması, ARP/ND CoPP stres üreteçleri. |
| [`03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md`](03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md) | **Dizin Düzeni ve Saf C++ İskeletleri** | `samurai/telecom/` modüler motoru, `worker_registry.hpp` kaydı, `telco_worker.cpp` IPC döngüsü, CMake yapılandırması ve 5 aşamalı doğrulama planı. |

---

## 3. Sistem Mimari Şeması

```
+--------------------------------------------------------------------------------------------------+
|                          SAMURAI CLUSTER MASTER (ZMQ COORDINATOR - Port 5099)                    |
|  - Test Planı Oluşturma, Abone Aralıklarının Bölünmesi (Sharding), İş Dağıtımı                  |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 | ZMQ ROUTER/DEALER (Wire Protocol V2/V3)
                                                 v
+--------------------------------------------------------------------------------------------------+
|                    SAMURAI SLAVE NODE & SUPERVISOR (slave_main.cpp / supervisor.cpp)             |
|--------------------------------------------------------------------------------------------------|
|  - WorkerShardService::StartShard(SubscriberRange: 1..250.000, VLANs: 100-149)                  |
|  - fork/exec ile Worker Başlatma:                                                                |
|    samurai_telco_worker --job-endpoint ipc:///tmp/jobs_telco --event-endpoint ipc:///tmp/ev_telco    |
+--------------------------------------------------------------------------------------------------+
                                                 |
                     +---------------------------+---------------------------+
                     | Unix IPC (ZMQ PULL)                                   | Unix IPC (ZMQ PUSH)
                     | Sadece START/STOP/CONFIG                              | Sadece Periyodik Telemetri
                     v                                                       ^ (1 saniyede bir Snapshot)
+--------------------------------------------------------------------------------------------------+
|              SAMURAI TELCO WORKER DAEMON (samurai/zmq/daemon/telco_worker.cpp)              |
|--------------------------------------------------------------------------------------------------|
|  [ KONTROL VE FSM İŞ PARÇACIĞI (Slowpath Core) ]                                                 |
|  - Hierarchical Timing Wheel (1ms hassasiyet, O(1) BFD/LCP/DHCP zamanlayıcı çarkı)               |
|  - PPPoE Discovery, LCP, PAP/CHAP, IPCP FSM Yönetimi                                            |
|  - 128-Bayt Önbellek Hizalı TelcoSessionContext (1.000.000 Abone Havuzu - Hugepages)             |
|  - Shared-Nothing Abone Sahipliği (Kilit Yok)                                                    |
+--------------------------------------------------------------------------------------------------+
          ^                                                                          |
          | SPSC Lock-Free Ring (Rx Kontrol Paketleri)                               | SPSC Lock-Free Ring
          | (PPPoE Disc, LCP, DHCP DORA)                                             | (Tx Kontrol Paketleri)
          |                                                                          v
+--------------------------------------------------------------------------------------------------+
|               SAMURAI DPDK VERİ DÜZLEMİ (samurai/dpdk/dpdk_core.hpp / .cpp)                 |
|--------------------------------------------------------------------------------------------------|
|  - samurai::dpdk::ReceiveBurst (32-64 mbuf hat hızı alım)                                       |
|  - L2L3FastpathWiring::ClassifyFrame (Donanım mbuf ayrıştırma & Fastpath/Slowpath demux)         |
|  - Doğrudan Fastpath İletimi (GTP-U Encap/Decap, Established PPPoE Data, LockfreeArpTable)       |
|  - samurai::dpdk::SendBurst (NIC Kuyruklarına Toplu Gönderim)                                    |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                                 v
+--------------------------------------------------------------------------------------------------+
|                     FİZİKSEL TELEKOM AĞ ARAYÜZÜ (10G/25G/40G/100G NIC Donanımı)                  |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. 5 Aşamalı Doğrulama Metodolojisi ve Standart Ölçüm Formatı

Sistem, yüz binlerce aboneye geçmeden önce aşamalı olarak doğrulanacaktır:

| Aşama | Test Kapsamı | Doğrulanacak / Kanıtlanacak Şey |
|---|---|---|
| **Aşama 1** | Tek worker, düşük sayıda PPPoE oturumu (1 - 100) | Protokol doğruluğu ve FSM geçişleri (PADI -> PADO -> PADR -> PADS -> LCP -> CHAP -> IPCP). |
| **Aşama 2** | Tek worker, artan abone sayısı (1.000 -> 100.000) | Bellek ayak izi (abone başına tam 128 bayt) ve $O(1)$ Timing Wheel CPU ölçeklenmesi. |
| **Aşama 3** | Çoklu worker (Multi-Worker Core Affinity) | Worker izolasyonu, CPU çekirdeklerine sharding ve paylaşılan bellek/ring performansı. |
| **Aşama 4** | Çoklu düğüm kümesi (MasterCoordinator + 2 Slave) | `WorkerShardService` üzerinden abone aralıklarının dağıtımı ve küme seviyesi CPS ölçümü. |
| **Aşama 5** | Uzun süreli stres ve hata enjeksiyonu | PADT fırtınası, ağ kesintisi toparlanması, yeniden deneme (retry storm) yönetimi. |

### Standart Ölçüm Formatı (Audit Output)
Tüm testler şu standart çıktı formatı ile loglanır ve raporlanır:
```
test_id,protocol,subscriber_count,active_sessions,session_setup_rate_cps,session_failure_rate_pct,
packets_per_second,rx_drops,tx_errors,cpu_utilization_pct,memory_usage_mb,test_duration_s,hardware_spec
```

---

## 5. Mühendislik ve Donanım Dürüstlüğü İlkesi

- **Mevcut Donanım Sınırları:** Geliştirme ortamındaki donanım (GTX 1650, 1 GbE NIC, PCIe Gen3) üzerinde yazılım mimarisi, bellek düzeni ve FSM doğruluğu test edilir.
- **Dürüst Raporlama:** 1 GbE yerel ortamda elde edilen test sonuçları asla "100 GbE taşıyıcı sınıfı donanım performansı" olarak abartılmaz. Gerçek hat doyumu ve hat hızı iddiaları yalnızca i40e/mlx5 gibi 25/40/100 GbE fiziksel NIC'ler ve RFC test suite'leri ile doğrulanacaktır.
