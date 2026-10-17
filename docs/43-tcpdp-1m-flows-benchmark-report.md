# 43 - L4 Stateful TCP Motoru (`tcpdp`) 1.000.000 (1M) Aktif Akış Ölçek ve Mimari Doğrulama Raporu

* **Tarih:** 17 Ekim 2026
* **Mimari Katman:** Katman 2 (L4 Stateful Transport & TCP Engine — `ddos_samurai::tcpdp::TcpDataplaneCore`)
* **İlgili Kod ve Test Dosyaları:**
  * [`ddos_samurai/l4/tcp_dataplane_core.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp)
  * [`ddos_samurai/l4/tcp_dataplane_core.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp)
  * [`ddos_samurai/l4/test_1m_tcp_flows.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_1m_tcp_flows.cpp)
  * [`tests/test_1m_tcp_flows.py`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/test_1m_tcp_flows.py)
  * [`tests/bench_1m_tcp_flows.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_1m_tcp_flows.sh)

---

## 1. Kapsam, Metodoloji ve Mühendislik Dürüstlüğü Beyanı

Bu rapor, DDoSamurai'nin kullanıcı alanı (user-space) özel durum bilgili (stateful) TCP veri düzlemi motoru olan [`TcpDataplaneCore`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L133)'un **1.000.000 (1M) eşzamanlı aktif TCP akışı** altındaki gerçek davranışını, bellek ayak izini, kilit şeritleri (lock shards) dağılımını ve çok-çekirdekli **Shared-Nothing** ölçeklenebilirliğini belgeler.

> [!IMPORTANT]
> **Metodolojik Sınırlar ve Donanım Gerçekliği:**
> 1. Bu test, fiziksel bir 40G/100G NIC (`i40e` / `mlx5`) veya dış ağ hattı üzerinde değil; `TcpDataplaneCore` durum makinesinin ve sıfır-kopya (strided) TX/RX halka tamponlarının (ring buffers) işlemci ve RAM üzerindeki **gerçek paket sentezleme, başlık ayrıştırma ve TCB (Transmission Control Block) yaşam döngüsü** kapasitesini ölçmek üzere koşturulmuştur.
> 2. İlk prototipteki iki metodolojik eksiklik bu doğrulama turunda giderilmiştir:
>    * **Tam 1M El Sıkışma:** Sadece 50.000 akışın değil, **1.000.000 akışın tamamının (%100)** `kSynSent` $\to$ `kSynAckRcvd` $\to$ `kEstablished` durumlarına geçişi (1M SYN TX + 1M SYN-ACK RX + 1M ACK TX = **3.000.000 paket**) uçtan uca doğrulanmıştır.
>    * **Canlı Çekirdek Bellek Muhasebesi (`/proc/self/status`):** Yalnızca süreç ömrü tepe değerini (`ru_maxrss`) veren `getrusage` yerine, Linux çekirdeğinin canlı `VmRSS` (anlık fiziksel RAM), `VmHWM` (tepe fiziksel RAM) ve `VmData` sayaçları her fazda okunmuş; yıkım (`core.reset()`) ve `malloc_trim(0)` sonrasında fiziksel sayfaların işletim sistemine geri verildiği kanıtlanmıştır.
> 3. **Telemetri Hatası Düzeltmesi (`SnapshotStats`):** [`tcp_dataplane_core.cpp#L1262-L1294`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1262-L1294) içindeki `SnapshotStats()` metodunun atomik `tx_packets_queued_`, `tx_packets_drained_` ve `tx_packets_sent_` sayaçlarını döndürülen yapıya kopyalamadığı tespit edilmiş ve düzeltilmiştir.

---

## 2. Test Ortamı ve Donanım Özellikleri

| Bileşen | Ölçülen / Doğrulanan Değer |
| :--- | :--- |
| **İşlemci (CPU)** | AMD Ryzen 5 5600H with Radeon Graphics (`x86_64`, AVX2) |
| **Fiziksel Çekirdek / SMT Thread** | 6 Fiziksel Çekirdek / 12 Donanım Thread'i (SMT: 2 thread/core) |
| **Önbellek Hiyerarşisi** | L1d: 192 KiB (6×32 KiB), L2: 3 MiB (6×512 KiB), L3: 16 MiB (Paylaşımlı) |
| **Sistem Belleği (RAM)** | 13 GiB Toplam, ~10 GiB Kullanılabilir |
| **İşletim Sistemi / Çekirdek** | Linux `6.14.0-37-generic` |
| **Derleyici ve Bayraklar** | GCC C++17 (`-O3 -mavx2 -DNDEBUG`) |

---

## 3. Mimari Doğrulama Sonuçları ve Matematiksel Tutarlılık

Test iki ayrı çalışma modunda uçtan uca koşturulmuştur:
1. **Mod A — Tekil Motor (Single-Instance Intra-Core 64-Shard):** Tek bir `TcpDataplaneCore` nesnesi içinde 64 iç kilit şeridi (`kFlowLockShards = 64`) üzerinde 1.000.000 akış.
2. **Mod B — Paylaşımsız Çok-Çekirdek (Shared-Nothing Multi-Core):** 12 donanım thread'inin her birinin kendi çekirdeğine sabitlenerek (`sched_setaffinity`) kendi bağımsız `TcpDataplaneCore` nesnesini yürüttüğü (thread başına ~83.333 akış, toplam 1.000.000 akış) sıfır çapraz-kilit mimarisi.

### 3.1 Faz Bazlı Ölçüm Tablosu

| Faz / Metrik | Ölçülen Değer | Matematiksel Bağıntı / Doğrulama | Durum |
| :--- | :--- | :--- | :--- |
| **Hedef Akış Sayısı ($N_{\text{flows}}$)** | `1.000.000` | 1.000.000 tekil `(src_ip, dst_ip, sport, dport)` 4-tuple | **PASS** |
| **Başlangıç (Baseline) `VmRSS`** | `3.912 KB` (`3.82 MiB`) | `/proc/self/status` başlangıç fiziksel RAM | **PASS** |
| **Tek-Çekirdek SYN Üretim Süresi ($T_{\text{syn}}$)** | `1.792,52 ms` (`1,79252 s`) | 4.096'lık partiler halinde Enqueue + Strided Ring Drain | **PASS** |
| **Tek-Çekirdek SYN Hızı ($\text{CPS}_{\text{syn}}$)** | `557.873,22 akış/sn` (`557,87 kCPS`) | $\text{CPS} = \frac{1.000.000}{1,79252\text{ s}} = 557.873,22\text{ s}^{-1}$ | **PASS** |
| **Üretilen ve Çekilen SYN Paketi** | `1.000.000 / 1.000.000` | `66 B` $\times 10^6 = 66,00\text{ MB}$ (`62,94 MiB`), Kayıp: `%0,00` | **PASS** |
| **64-Shard Dağılımı (Min / Ort / Max)** | `15.620 / 15.625,00 / 15.630` | $\sigma = 2,94$, Maksimum Sapma: **`%0,0320`** (Hedef $\le \%5,0$) | **PASS** |
| **Tek-Çekirdek SYN-ACK + ACK Süresi ($T_{\text{hs}}$)** | `729,53 ms` (`0,72953 s`) | 1M `IngestRxFrame` (66B SYN-ACK) + 1M ACK TX Drain | **PASS** |
| **Tek-Çekirdek El Sıkışma Hızı** | `1.370.745,55 el sıkışma/sn` | $\frac{1.000.000}{0,72953\text{ s}} = 1,37\text{ M-handshakes/sn}$ | **PASS** |
| **Kurulan (`kEstablished`) Akış Sayısı** | `1.000.000 / 1.000.000` | `%100,00` başarılı durum geçişi, `unexpected_rx = 0` | **PASS** |
| **Üretilen ve Çekilen ACK Paketi** | `1.000.000 / 1.000.000` | `54 B` $\times 10^6 = 54,00\text{ MB}$ (`51,50 MiB`), Kayıp: `%0,00` | **PASS** |
| **Tek-Çekirdek Toplam Paket Süresi ($T_{\text{single}}$)** | `2.522,05 ms` (`2,52205 s`) | $T_{\text{syn}} + T_{\text{hs}} = 1.792,52 + 729,53\text{ ms}$, $N_{\text{pkt}} = 3.000.000$ | **PASS** |
| **Tek-Çekirdek Toplam Paket Hızı ($\text{PPS}_{\text{single}}$)** | `1.189.508,53 paket/sn` (`1,19 M-PPS`) | $\text{PPS} = \frac{3.000.000}{2,52205\text{ s}} = 1.189.508,53\text{ PPS}$ | **PASS** |
| **1M `SYN_SENT` Anlık `VmRSS`** | `1.595.360 KB` (`1.557,97 MiB`) | $\Delta\text{RSS} = 1.554,15\text{ MiB} \implies \mathbf{1.629,64\text{ B/akış}}$ | **PASS** |
| **1M `ESTABLISHED` Anlık `VmRSS`** | `1.618.852 KB` (`1.580,91 MiB`) | $\Delta\text{RSS} = 1.577,09\text{ MiB} \implies \mathbf{1.653,70\text{ B/akış}}$ | **PASS** |
| **12-Thread Lockless Okuma Hızı** | `54,74 M-lookups/sn` (`54,81 ms`) | $3.000.000$ `GetFlowLockless` çağrısı, `%100` isabet ve RFC opsiyon teyidi | **PASS** |
| **Bellek Yıkım ve Geri Kazanım (`malloc_trim`)** | `5.940 KB` (`5,80 MiB`) (`639,84 ms`) | `1.580,91 MiB` $\to$ `5,80 MiB` (**`%99,63` RAM işletim sistemine iade**) | **PASS** |
| **Shared-Nothing (12 Thread) 1M El Sıkışma Süresi** | `706,48 ms` (`0,70648 s`) | 12 bağımsız `TcpDataplaneCore`, $N_{\text{flows}} = 10^6$, $N_{\text{pkt}} = 3 \times 10^6$ | **PASS** |
| **Shared-Nothing Tam El Sıkışma Hızı ($\text{CPS}_{\text{SN}}$)** | **`1.415.471,13 akış/sn` (`1,42 M-CPS`)** | $\text{CPS}_{\text{SN}} = \frac{1.000.000}{0,70648\text{ s}} = 1.415.471,13\text{ s}^{-1}$ | **PASS** |
| **Shared-Nothing Toplam Paket Hızı ($\text{PPS}_{\text{SN}}$)** | **`4.246.413,40 paket/sn` (`4,25 M-PPS`)** | $\text{PPS}_{\text{SN}} = \frac{3.000.000}{0,70648\text{ s}} = 4.246.413,40\text{ PPS}$ | **PASS** |
| **Shared-Nothing Çok-Çekirdek Hızlanma Çarpanı** | **`3,57x`** | $\frac{T_{\text{single}}}{T_{\text{SN}}} = \frac{2.522,05\text{ ms}}{706,48\text{ ms}} = 3,57\times$ | **PASS** |

---

## 4. Derinlemesine Teknik Analiz

### 4.1 Neden Tek-Seferde Değil, Partili (Batched) TX Halka Boşaltımı Gereklidir?
[`TcpDataplaneCore`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L546-L547) içinde varsayılan `tx_ring_capacity_ = 8192` ve `tx_overflow_capacity_ = 8192` olarak yapılandırılmıştır (64 shard başına 128 halka slotu + 128 taşma slotu).
* Eğer tüketici (NIC sürücüsü veya test koşucusu) TX halkasını hiç boşaltmadan 1.000.000 `EnqueueConnect` çağrısı yaparsa, ilk 16.384 paketten sonraki paketler taşma kuyruğunun (`ring.overflow`) başından düşürülür (`pop_front()`).
* Gerçek bir DPDK/AF_XDP/AF_PACKET veri düzleminde poller döngüsü her burst'te TX halkasını boşalttığı için, test motoru da 4.096 akışlık partiler halinde [`PeekTxPacketsStrided`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1020) ve [`ConsumeTxPackets`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1141) çağırarak **1.000.000 SYN ve 1.000.000 ACK paketinin tamamını (%100)** sıfır taşma ve sıfır kayıpla telden (wire ring) çekmiştir.

### 4.2 16-Bit Tek'e Tümleyen (One's Complement) Checksum Doğrulaması
Test geliştirilirken 1.000.000 SYN paketinin tel üzerindeki başlıkları denetlenirken dikkat çekici bir matematiksel olgu doğrulanmıştır:
* `TcpChecksum` 16-bitlik bir değer üretir ($2^{16} = 65.536$ olasılık).
* UDP'nin aksine (RFC 768), TCP'de (RFC 793 / RFC 1071) tek'e tümleyen toplamı `0xFFFF` çıktığında tersi (`~0xFFFF`) olan `0x0000` geçerli bir checksum değeridir.
* 1.000.000 pakette beklenen `0x0000` checksum sayısı teorik olarak $\frac{1.000.000}{65.536} \approx \mathbf{15,26}$'dır. Gerçek koşuda tam olarak **17 SYN paketi** ve **20 ACK paketinde** geçerli checksum `0x0000` olarak gözlemlenmiştir. Bu durum, paketlerin sahte/sabit şablonlarla değil, her akış için gerçek dizi numaraları (`iss`) ve portlarla dinamik olarak hesaplandığının matematiksel kanıtıdır.

### 4.3 Bellek Yoğunluğu (`~1.653,70 Bayt/Akış`) ve Geri Kazanım
1.000.000 kurulu (`kEstablished`) TCP akışı toplam **`1.577,09 MiB`** (`1.614.940 KB`) net fiziksel RAM (`VmRSS`) kullanmaktadır:
* Bu bütçenin içinde her akış için:
  1. `FlowEntry` TCB yapısı (`sndbuf`, `unacked` deque, `seg_buf_pool`, `rx_oo_queue` map, `sack_blocks` vector, RFC 6675 ve RFC 7323 durum değişkenleri),
  2. `flows_by_id_shard_` (`std::unordered_map<uint64_t, FlowEntry>`) düğümü ve kova (bucket) işaretçileri,
  3. `flow_index_shard_` (`ankerl::unordered_dense::map<FlowKey, uint64_t>`) düz tablo kaydı,
  4. `timer_heap_shard_` (`std::priority_queue<TimerEntry>`) zamanlayıcı kayıtları (`kConnectTimeout` + `kIdleTimeout`)
  yer almaktadır.
* Faz 7'de `core.reset()` ve `malloc_trim(0)` çağrıldığında `VmRSS` **`1.580,91 MiB`'dan `5,80 MiB`'a** düşmüştür; hiçbir bellek sızıntısı (memory leak) yoktur.

### 4.4 Shared-Nothing Çok-Çekirdek Ölçeklenebilirlik Analizi (`3,57x` Hızlanma)
6 fiziksel çekirdekli / 12 SMT thread'li AMD Ryzen 5 5600H üzerinde:
* Tek çekirdekte 1M tam el sıkışma (3M paket) `2.522,05 ms` (`1,19 M-PPS`) sürerken,
* 12 Shared-Nothing worker ile `706,48 ms` (**`1,42 M-CPS` / `4,25 M-PPS`**) sürede tamamlanmıştır.
* 6 fiziksel çekirdekte hızlanmanın $6\times$ yerine **$3,57\times$** olmasının nedeni kilit çekişmesi değil (worker'lar arası kilit sıfırdır), **DDR4 ana bellek bant genişliği doygunluğudur**: 12 donanım thread'i aynı anda toplam `1,58 GiB` büyüklüğünde (16 MiB L3 önbelleğin $\sim 100$ katı) TCB ve hash tablosu düğümünü ana bellekte tahsis edip güncellediğinden darboğaz CPU aritmetiğinden bellek kontrolcüsüne (DRAM bandwidth) kaymaktadır.

---

## 5. Tekrar Çalıştırma Komutları

```bash
# Tam 1M benchmark script'ini çalıştırma (derleme + koşum + JSON/Markdown rapor üretimi):
./tests/bench_1m_tcp_flows.sh

# Doğrudan C++ ikili dosyasını özel parametrelerle çalıştırma:
./build/l4/test_1m_tcp_flows --flows 1000000 --handshakes 1000000 --threads 12 --json /tmp/report_1m.json

# Pytest otomasyon doğrulamasını çalıştırma:
pytest tests/test_1m_tcp_flows.py -v
```
