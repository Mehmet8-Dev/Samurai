# 43 - L4 Stateful TCP Motoru (`tcpdp`) 1.000.000 (1M) Aktif Akış Bellek Optimizasyonu, Ölçeklenebilirlik ve Gerçek Tel (`netns + veth`) Doğrulama Raporu

* **Tarih:** 17 Ekim 2026
* **Mimari Katman:** Katman 2 (L4 Stateful Transport & TCP Engine — `ddos_samurai::tcpdp::TcpDataplaneCore`)
* **İlgili Kod ve Test Dosyaları:**
  * [`ddos_samurai/l4/tcp_dataplane_core.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp)
  * [`ddos_samurai/l4/tcp_dataplane_core.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp)
  * [`ddos_samurai/l4/test_1m_tcp_flows.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_1m_tcp_flows.cpp)
  * [`ddos_samurai/l4/test_tcpdp_veth_wire.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_tcpdp_veth_wire.cpp)
  * [`tests/test_1m_tcp_flows.py`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/test_1m_tcp_flows.py)
  * [`tests/bench_1m_tcp_flows.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_1m_tcp_flows.sh)
  * [`tests/bench_tcpdp_veth_wire.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_tcpdp_veth_wire.sh)
  * [`reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json)
  * [`reports/benchmarks/tcpdp_1m_flows/veth_wire_metrics.json`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/reports/benchmarks/tcpdp_1m_flows/veth_wire_metrics.json)

---

## 1. Kapsam, Metodoloji ve Mühendislik Dürüstlüğü Beyanı

Bu rapor, DDoSamurai'nin kullanıcı alanı (user-space) özel durum bilgili (stateful) TCP veri düzlemi motoru olan [`TcpDataplaneCore`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L144-L281)'un:
1. **1.000.000 (1M) eşzamanlı aktif TCP akışı** altındaki derleme zamanı yapı boyutlarını (`sizeof`), süreç bazlı çekirdek bellek ayak izini (`VmRSS`), 64-şeritli kilit dağılımını, RFC 1071 IPv4/TCP checksum doğrulamasını ve çok-çekirdekli **Shared-Nothing** ölçeklenebilirliğini,
2. **Akış Başına RAM Optimizasyonu (`1.648,43 B/akış` $\to$ `605,31 B/akış`, `%63,3` RAM tasarrufu)** öncesi ve sonrası karşılaştırmasını,
3. **İzole Linux Network Namespace (`netns + veth + AF_PACKET`) Gerçek Tel ve Canlı Linux Kernel TCP Yığını (`accept4()`)** birlikte çalışabilirlik (interoperability) doğrulamasını belgeler.

> [!IMPORTANT]
> **Metodolojik Sınırlar ve Donanım Gerçekliği:**
> 1. **Bellek-İçi Veri Düzlemi vs. Sanal Tel (`veth`) vs. Fiziksel NIC Ayrımı:**
>    * **Bölüm 3–5'teki 1M Akış Testi:** Bellek-içi (in-memory) veri düzlemi ve durum makinesi testidir; `TcpDataplaneCore`'un gerçek Ethernet/IPv4/TCP çerçevelerini sentezleme, strided TX halkasından boşaltma, `IngestRxFrame` ile ayrıştırma ve RFC 1071 checksum doğrulama hızını (`2,71 M-CPS` / `8,12 M-PPS`) ölçer.
>    * **Bölüm 7'deki `netns + veth + AF_PACKET` Testi:** Çerçevelerin gerçek Linux çekirdeği ağ yığınından (`sendmmsg`/`recvmmsg`, `v_cli <==> v_srv` netdev sürücüsü ve `/proc/net/dev` sayaçları) ve canlı Linux kernel TCP `accept4()` dinleyicisinden geçtiği gerçek paket G/Ç doğrulamasıdır (`133,49 kCPS` / `400,48 kPPS`).
>    * Fiziksel 40G/100G NIC (`i40e` / `mlx5`) üzerinde DPDK / native `AF_XDP` zero-copy hat hızı doğrulaması ayrı bir donanım test konusudur.
> 2. **Kontrollü Elma-Elma (Apples-to-Apples) Zamanlama Sınırları (P0):**
>    * Tek-Çekirdek (`1 Worker`), Fiziksel Çekirdek (`6 Worker`) ve Tam SMT (`12 Worker`) karşılaştırmalarında iş parçacığı oluşturma (`std::thread`), çekirdek sabitleme (`sched_setaffinity`), `TcpDataplaneCore::Configure` tahsisleri ve yıkım (`wcore.reset()`) işlemleri zamanlama penceresinin (`[t_start, t_end]`) **dışına** çıkarılmış; tüm worker'lar atomik başlangıç bariyerinde senkronize edilerek **birebir aynı 2.048'lik partili 1M 3-yollu el sıkışma iş yükü** 5'er kez ölçülmüştür.

---

## 2. Test Ortamı ve Donanım Özellikleri

| Bileşen | Ölçülen / Doğrulanan Değer |
| :--- | :--- |
| **İşlemci (CPU)** | AMD Ryzen 5 5600H with Radeon Graphics (`x86_64`, AVX2) |
| **Fiziksel Çekirdek / SMT Thread** | 6 Fiziksel Çekirdek (`[0, 2, 4, 6, 8, 10]`) / 12 Mantıksal Thread (`[0..11]`) |
| **Önbellek Hiyerarşisi** | L1d: 192 KiB (6×32 KiB), L2: 3 MiB (6×512 KiB), L3: 16 MiB (Paylaşımlı) |
| **Sistem Belleği (RAM)** | 13 GiB Toplam, ~8,3 GiB Kullanılabilir |
| **İşletim Sistemi / Çekirdek** | Linux `6.14.0-37-generic` (`perf_event_paranoid = 4`) |
| **Derleyici ve Bayraklar** | GCC 13 C++17 (`-O3 -mavx2 -DNDEBUG`) |

---

## 3. Akış Başına RAM Optimizasyonu: Mimari Değişiklikler ve Öncesi/Sonrası Karşılaştırması

İlk 1M akış ölçümünde `sizeof(FlowEntry) = 416 B` olmasına rağmen süreç `VmRSS` artışı akış başına **`1.648,43 B`** (`1.572,06 MiB` / 1M akış) olarak ölçülmüştü. Hiçbir yerde ekstra pointer `if` dalı eklenmeden, sıfır-ek-dal (branch-free) düz veri yapılarıyla aşağıdaki 5 temel optimizasyon uygulanmıştır:

1. **`std::deque<OutstandingTx>` $\to$ Düz `std::vector<OutstandingTx>` + `kEstablished` Anında Kapasite İadesi:**
   * `libstdc++` içindeki `std::deque` (`80 B` başlık) ilk eleman (`SYN`) eklendiğinde **512 Baytlık** bir iç yığın bloğu + harita dizisi (`~600+ B`) tahsis ediyor ve `clear()` çağrılsa bile bu bloğu ömrü boyunca bırakmıyordu.
   * `unacked` alanı düz `std::vector<OutstandingTx>` (`24 B` başlık) olarak değiştirildi ve el sıkışma `kEstablished` durumuna geçtiği anda `std::vector<OutstandingTx>().swap(flow->unacked)` ile SYN aşamasındaki geçici vektör tamponu sıfırlandı.
2. **`OutstandingTx::opts` Dinamik Vektörünün Sabit Boyutlu Inline Diziye (`std::array<uint8_t, 24>`) Alınması:**
   * Her SYN paketinde 12 baytlık TCP opsiyonları için yapılan ayrı heap tahsisi (`std::vector<uint8_t> opts`) kaldırılarak `uint8_t opts_len` + `std::array<uint8_t, 24> opts` ile doğrudan yapı içine gömüldü.
3. **`std::map<uint32_t, std::vector<uint8_t>> rx_oo_queue` $\to$ Düz `std::vector<RxOoSegment>`:**
   * Sırası bozuk (out-of-order) RX segment kuyruğu `std::map` (`48 B` Red-Black Tree başlığı) yerine doğrudan düz `std::vector<RxOoSegment>` (`24 B`, boşken `0 B` heap, sıfır pointer `if` kontrolü) yapıldı.
4. **Gereksiz `std::set<uint64_t> active_flow_ids_shard_` Ağacının Kaldırılması:**
   * Her aktif akış için ayrı bir Red-Black Tree düğümü (`48 B` + `malloc` başlığı = 1M akışta ~64 MiB) tahsis eden `active_flow_ids_shard_` kaldırıldı; `Poll()` içinde doğrudan `IsCountedActive(it->second.state)` kontrolü kullanıldı.
5. **Düğüm Tabanlı `std::unordered_map` $\to$ Düz Tablolu `ankerl::unordered_dense::map`:**
   * `flows_by_id_shard_` konteyneri, her akışta ayrı bağlı-liste düğümü tahsis eden `std::unordered_map` yerine bitişik bellekli `ankerl::unordered_dense::map<uint64_t, FlowEntry>` yapısına geçirildi.

### 3.1 Bellek ve Performans: Optimizasyon Öncesi vs. Sonrası Özeti

| Metrik | Optimizasyon Öncesi | Optimizasyon Sonrası | Net Kazanım / Değişim |
| :--- | :--- | :--- | :--- |
| **`sizeof(FlowEntry)` (Derleme Zamanı TCB Boyutu)** | `416 Bayt` | **`336 Bayt`** | **`-%19,2` daha kompakt TCB yapısı** |
| **1M Akış `SYN_SENT` Süreç `VmRSS` Artışı** | `1.546,59 MiB` (`1.621,71 B/akış`) | **`538,54 MiB` (`564,70 B/akış`)** | **`-%65,2` RAM tasarrufu (`~1,01 GiB` kazanç)** |
| **1M Akış `ESTABLISHED` Süreç `VmRSS` Artışı** | `1.572,06 MiB` (`1.648,43 B/akış`) | **`577,27 MiB` (`605,31 B/akış`)** | **`-%63,3` RAM tasarrufu (`~995 MiB` kazanç)** |
| **1M Akış Çekirdek Sayfa Hataları (Minor / Major)** | `416.056 / 0` | **`227.714 / 0`** | **`-%45,3` daha az sayfa hatası (page fault)** |
| **1M Akış Yıkım + `malloc_trim(0)` Süresi** | `637,23 ms` | **`74,54 ms`** | **`8,55×` daha hızlı bellek geri kazanımı** |
| **Tek-Çekirdek (`1W`) 1M El Sıkışma Medyan Süresi** | `3.061,60 ms` (`0,33 M-CPS`) | **`1.008,15 ms` (`0,99 M-CPS`, `2,98 M-PPS`)** | **`3,04×` daha hızlı tek çekirdek performansı** |
| **Shared-Nothing (`6W` Fiziksel) Medyan Süresi** | `745,12 ms` (`1,34 M-CPS`, `4,03 M-PPS`) | **`377,13 ms` (`2,65 M-CPS`, `7,95 M-PPS`)** | **`1,98×` daha hızlı çok-çekirdek performansı** |
| **Shared-Nothing (`12W` SMT + RFC 1071 CSUM) Medyan** | `645,63 ms` (`1,55 M-CPS`, `4,65 M-PPS`) | **`369,55 ms` (`2,71 M-CPS`, `8,12 M-PPS`)** | **`1,75×` daha hızlı tam doğrulamalı performans** |

---

## 4. Faz Bazlı Doğrulama ve Tekil Motor Yaşam Döngüsü Sonuçları (Optimizasyon Sonrası)

| Faz / Metrik | Ölçülen Değer | Matematiksel Bağıntı / Doğrulama | Durum |
| :--- | :--- | :--- | :--- |
| **Faz 0 — RFC 1071 Checksum Kapısı** | `Bozuk IP=Red, Bozuk TCP=Red, Geçerli=Kabul` | `InternetChecksum == 0` ve `TcpChecksum == 0` doğrulaması | **PASS** |
| **Faz 1 — Başlangıç (Baseline) `VmRSS`** | `4.120 KB` (`4,02 MiB`) | `/proc/self/status` başlangıç fiziksel RAM | **PASS** |
| **Faz 2 — 1M SYN Üretim Süresi ($T_{\text{syn}}$)** | `848,802 ms` (`0,848802 s`) | 4.096'lık partiler halinde Enqueue + Strided Ring Drain | **PASS** |
| **Faz 2 — 1M SYN Hızı ($\text{CPS}_{\text{syn}}$)** | `1.178.131,98 akış/sn` (`1,18 M-CPS`) | $\text{CPS} = \frac{1.000.000}{0,848802\text{ s}} = 1.178.131,98\text{ s}^{-1}$ | **PASS** |
| **Faz 2 — Çekilen SYN Tel Çerçeveleri** | `1.000.000 / 1.000.000` | `66 B` $\times 10^6 = 66,00\text{ MB}$ (`62,94 MiB`), Kayıp: `%0,00` | **PASS** |
| **Faz 3 — 64-Shard Dağılımı (Min / Ort / Max)** | `15.620 / 15.625,00 / 15.630` | $\sigma = 2,94$, Maksimum Sapma: **`%0,0320`** (Hedef $\le \%5,0$) | **PASS** |
| **Faz 4 — 1M SYN-ACK + ACK Süresi ($T_{\text{hs}}$)** | `520,735 ms` (`0,520735 s`) | 1M `IngestRxFrame` (66B SYN-ACK) + 1M ACK TX Drain | **PASS** |
| **Faz 4 — El Sıkışma Tamamlama Hızı** | `1.920.361,67 el sıkışma/sn` (`1,92 M/sn`) | $\frac{1.000.000}{0,520735\text{ s}} = 1.920.361,67\text{ s}^{-1}$ | **PASS** |
| **Faz 4 — Kurulan (`kEstablished`) Akış Sayısı** | `1.000.000 / 1.000.000` | `%100,00` başarılı durum geçişi, `unexpected_rx = 0` | **PASS** |
| **Faz 4 — Çekilen ACK Tel Çerçeveleri** | `1.000.000 / 1.000.000` | `54 B` $\times 10^6 = 54,00\text{ MB}$ (`51,50 MiB`), Kayıp: `%0,00` | **PASS** |
| **Faz 2+4 — Toplam Paket Süresi ($T_{\text{single}}$)** | `1.369,54 ms` (`1,36954 s`) | $T_{\text{syn}} + T_{\text{hs}} = 848,80 + 520,74\text{ ms}$, $N_{\text{pkt}} = 3.000.000$ | **PASS** |
| **Faz 2+4 — Toplam Paket Hızı ($\text{PPS}_{\text{single}}$)** | `2.190.520,89 paket/sn` (`2,19 M-PPS`) | $\text{PPS} = \frac{3.000.000}{1,36954\text{ s}} = 2.190.520,89\text{ PPS}$ | **PASS** |
| **Faz 5 — 1M `SYN_SENT` Süreç `VmRSS` Artışı** | `551.464 KB` (`538,54 MiB`) | $\mathbf{564,70\text{ B/akış}}$ (`syn_sent_rss_delta_per_flow_bytes`) | **PASS** |
| **Faz 5 — 1M `ESTABLISHED` Süreç `VmRSS` Artışı** | `591.120 KB` (`577,27 MiB`) | $\mathbf{605,31\text{ B/akış}}$ (`established_rss_delta_per_flow_bytes`) | **PASS** |
| **Faz 5 — Çekirdek Sayfa Hataları (`getrusage`)** | `227.714 Minor / 0 Major` | Sıfır disk takaslı (`0 major fault`) sayfa tahsisi | **PASS** |
| **Faz 6 — 12-Thread Lockless Okuma Hızı** | **`66,85 M-lookups/sn`** (`44,87 ms`) | $3.000.000$ `GetFlowLockless` çağrısı, `%100` isabet ve RFC opsiyon teyidi | **PASS** |
| **Faz 7 — Bellek Yıkım ve `malloc_trim(0)`** | `5.800 KB` (`5,66 MiB`) (`74,54 ms`) | `581,29 MiB` $\to$ `5,66 MiB` (**`%99,03` RAM işletim sistemine iade**) | **PASS** |

---

## 5. Kontrollü Elma-Elma (Apples-to-Apples) Çoklu Koşum (`--runs 5`) Ölçeklenebilirlik Analizi

Faz 8'de tüm mimari modlar **birebir aynı zamanlama sınırları** ve **birebir aynı 2.048'lik partili 1M tam el sıkışma (3M paket) döngüsü** ile 5'er kez koşturulmuştur:

| Mimari Mod | Worker / Sabitlenen CPU'lar (`sched_getcpu` Doğrulandı) | Süre Medyan (ms) | Süre Min / Max (ms) | Süre $\sigma$ (ms) | Medyan CPS (Akış/sn) | Medyan PPS (Paket/sn) | Kontrollü Hızlanma ($S_{\text{median}}$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Tek-Çekirdek (`Single-Core 1W`)** | `1W` $\to$ `[0]` | **`1.008,15 ms`** | `985,38 / 1.083,54` | `33,49 ms` | **`991.917 CPS` (`0,99 M-CPS`)** | **`2.975.751 PPS` (`2,98 M-PPS`)** | **`1,00×`** (Referans) |
| **2. Shared-Nothing Fiziksel (`6W Physical`)** | `6W` $\to$ `[0, 2, 4, 6, 8, 10]` | **`377,13 ms`** | `351,63 / 408,28` | `22,60 ms` | **`2.651.590 CPS` (`2,65 M-CPS`)** | **`7.954.769 PPS` (`7,95 M-PPS`)** | **`2,67×`** (6 Fiziksel Çekirdek) |
| **3. Shared-Nothing Tam SMT (`12W SMT`)** | `12W` $\to$ `[0..11]` | **`373,34 ms`** | `362,85 / 387,01` | `8,43 ms` | **`2.678.550 CPS` (`2,68 M-CPS`)** | **`8.035.651 PPS` (`8,04 M-PPS`)** | **`2,70×`** (`6W`'a göre `1,01×`) |
| **4. Shared-Nothing SMT + RFC 1071 Checksum (`12W + CSUM`)** | `12W` $\to$ `[0..11]` (`verify_rx_checksum=true`) | **`369,55 ms`** | `367,86 / 397,78` | `11,29 ms` | **`2.705.986 CPS` (`2,71 M-CPS`)** | **`8.117.958 PPS` (`8,12 M-PPS`)** | **`2,73×`** |

### 5.1 Tekrarlanan Döngülerde Sıfır Bellek Sızıntısı Kanıtı
Faz 8 boyunca `Shared-Nothing SMT (12W)` modunda 5 ardışık turda (her turda 1.000.000 akış oluşturulup 3M paket işlenip yıkıldıktan ve `malloc_trim(0)` çağrıldıktan sonra) ölçülen süreç `VmRSS` değerleri:
* **1. Tur Sonu:** `8.064 KB` (`7,88 MiB`)
* **2. Tur Sonu:** `8.064 KB` (`7,88 MiB`)
* **3. Tur Sonu:** `8.064 KB` (`7,88 MiB`)
* **4. Tur Sonu:** `8.064 KB` (`7,88 MiB`)
* **5. Tur Sonu:** `8.064 KB` (`7,88 MiB`)

Beş ardışık 1M akış turu boyunca `VmRSS` **bayt düzeyinde sabit (`8.064 KB`)** kalmıştır (`0 byte leak`).

---

## 6. Bellek Mimarisi: `sizeof(FlowEntry)` vs. Süreç `VmRSS` Artışı Dağılımı

[`TcpDataplaneCore::GetMemoryLayout()`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1395-L1404) ile alınan derleme zamanı yapı boyutları ve 1.000.000 aktif akışta ölçülen `605,31 B/akış` süreç `VmRSS` dağılımı:

| Yapı / Metrik Adı | Boyut (Bayt) | Açıklama ve Bellek Muhasebesindeki Rolü |
| :--- | :--- | :--- |
| **`sizeof(FlowKey)`** | `12 B` | `src_ip (4B) + dst_ip (4B) + src_port (2B) + dst_port (2B)` |
| **`sizeof(TimerEntry)`** | `24 B` | `due_ns (8B) + flow_id (8B) + kind (1B) + generation (4B) + padding` |
| **`sizeof(OutstandingTx)`** | `88 B` | Gönderilmiş/onay bekleyen segment метаverisi + inline `std::array<uint8_t, 24> opts` (`0 B` heap) |
| **`sizeof(FlowEntry)`** | **`336 B`** | Ham TCB yapısı: dizi numaraları, pencere/cwnd/RTT, RFC 6675 SACK, düz `unacked` (`24B`), düz `rx_oo_queue` (`24B`), `sack_blocks` (`24B`) |
| **`sizeof(PerShardTxRing)`** | `256 B` | `alignas(64)` kilit + strided halka vektör başlıkları |
| **`sizeof(TcpDataplaneCore)`** | `51.712 B` (`50,5 KiB`) | 64 şeritli spinlock, düz tablo ve sayaç dizilerinin toplam statik nesne boyutu |
| **Akış Başına Süreç `VmRSS` Artışı (`SYN_SENT`)** | **`564,70 B`** | `FlowEntry` (`336 B`) + `ankerl::unordered_dense` kova/değer tablosu + `flow_index_shard_` (`FlowKey -> uint64_t`) + `timer_heap_shard_` (`TimerEntry`) |
| **Akış Başına Süreç `VmRSS` Artışı (`ESTABLISHED`)** | **`605,31 B`** | `SYN_SENT` üzerine el sıkışma tamamlama (`completions_` + idle timer kaydı) sonrası süreçte yerleşik toplam fiziksel bellek |

---

## 7. Gerçek Tel (`netns + veth + AF_PACKET`) ve Canlı Linux Kernel TCP Yığını Doğrulaması

Laboratuvar (bellek-içi) testlerinin ötesinde, [`test_tcpdp_veth_wire.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_tcpdp_veth_wire.cpp) ve [`bench_tcpdp_veth_wire.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_tcpdp_veth_wire.sh) ile izole bir Linux ağ isim alanı (`unshare -n`) içinde sanal Ethernet çifti (`v_cli <==> v_srv`) kurulmuş, `ethtool -K v_cli/v_srv tx off rx off` ile donanım checksum offload kapatılarak gerçek RFC 1071 tel checksum'ları zorunlu kılınmış ve 3 aşamalı gerçek paket G/Ç doğrulaması gerçekleştirilmiştir:

| Faz / Gerçek Tel Testi | Hedef | Ölçülen Sonuç | Doğrulanan Çekirdek / Protokol Kanıtı | Durum |
| :--- | :--- | :--- | :--- | :--- |
| **Faz 1 — Canlı Linux Kernel TCP Dinleyicisi (`accept4()`) ile Birlikte Çalışabilirlik** | `2.000` gerçek soket (`10.77.0.2:18088`) | **`2.000 / 2.000` Established & `accept4()`** (`65,70 ms`, **`30,44 kCPS`**) | `TcpDataplaneCore` (`v_cli`) tarafından üretilen ham SYN ve ACK paketleri Linux çekirdeğinin kendi TCP/IP yığını (`v_srv`) tarafından kabul edilmiş ve `accept4()` ile 2.000 gerçek soket dosya tanımlayıcısı döndürülmüştür. | **PASS** |
| **Faz 2 — Yüksek Ölçekli `veth + AF_PACKET` Tam 3-Yollu El Sıkışma** | `100.000` akış (`300.000` gerçek Ethernet paketi) | **`100.000 / 100.000` Established** (`749,11 ms`, **`133,49 kCPS` / `400,48 kPPS`**) | `sendmmsg`/`recvmmsg` üzerinden `100.000 SYN` + `100.000 SYN-ACK` + `100.000 ACK` = **`300.000` gerçek paket**; `/proc/net/dev` sayaçları: `v_cli TX=200.001, RX=100.001` \| `v_srv RX=200.001, TX=100.001`; Bozuk Checksum: **`0`**. | **PASS** |
| **Faz 2 — Gerçek Tel Üzerinde Akış Başına `VmRSS` Artışı** | `100.000` aktif akış | **`70.360 KB` (`68,71 MiB`) $\to$ `720,49 B/akış`** | Kernel `AF_PACKET` soket tamponları dahil süreçteki net fiziksel bellek artışı. | **PASS** |
| **Faz 3 — Shared-Nothing Multi-Shard L7 HTTP/1.1 (`test_customtcp_ownwire_l7`)** | `16` Shard / `16` Eşzamanlı HTTP/1.1 Akışı | **`sent=16, status_2xx=16, errors=0, tcp_connect_established=16`** | `veth` üzerinde tam 3-yollu el sıkışma + `GET /` HTTP/1.1 isteği + `HTTP/1.1 200 OK` yanıt ayrıştırma + temiz `FIN` kapanışı. | **PASS** |

---

## 8. Tekrar Çalıştırma Komutları

```bash
# 1) Tam 1M in-memory benchmark script'ini çalıştırma (5 tekrarlı modlar + JSON/Markdown rapor üretimi):
./tests/bench_1m_tcp_flows.sh

# 2) Gerçek tel (netns + veth + AF_PACKET + Canlı Linux Kernel TCP accept() + L7 HTTP/1.1) doğrulamasını çalıştırma:
./tests/bench_tcpdp_veth_wire.sh

# 3) Python/unittest otomasyon doğrulamasını çalıştırma:
python3 -m unittest tests/test_1m_tcp_flows.py -v
```
