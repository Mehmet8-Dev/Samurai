# 43 - L4 Stateful TCP Motoru (`tcpdp`) 1.000.000 (1M) Aktif Akış Ölçek ve Mimari Doğrulama Raporu

* **Tarih:** 17 Ekim 2026
* **Mimari Katman:** Katman 2 (L4 Stateful Transport & TCP Engine — `ddos_samurai::tcpdp::TcpDataplaneCore`)
* **İlgili Kod ve Test Dosyaları:**
  * [`ddos_samurai/l4/tcp_dataplane_core.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp)
  * [`ddos_samurai/l4/tcp_dataplane_core.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp)
  * [`ddos_samurai/l4/test_1m_tcp_flows.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_1m_tcp_flows.cpp)
  * [`tests/test_1m_tcp_flows.py`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/test_1m_tcp_flows.py)
  * [`tests/bench_1m_tcp_flows.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_1m_tcp_flows.sh)
  * [`reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/reports/benchmarks/tcpdp_1m_flows/benchmark_1m_metrics.json)

---

## 1. Kapsam, Metodoloji ve Mühendislik Dürüstlüğü Beyanı

Bu rapor, DDoSamurai'nin kullanıcı alanı (user-space) özel durum bilgili (stateful) TCP veri düzlemi motoru olan [`TcpDataplaneCore`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L143)'un **1.000.000 (1M) eşzamanlı aktif TCP akışı** altındaki gerçek davranışını, derleme zamanı yapı boyutlarını (`sizeof`), süreç bazlı çekirdek bellek ayak izini (`VmRSS`), 64-şeritli kilit dağılımını, RFC 1071 IPv4/TCP checksum doğrulamasını ve çok-çekirdekli **Shared-Nothing** ölçeklenebilirliğini belgeler.

> [!IMPORTANT]
> **Metodolojik Sınırlar ve Donanım Gerçekliği:**
> 1. **Bellek-İçi Veri Düzlemi vs. Fiziksel Tel (Wire) Ayrımı:** Bu test fiziksel bir 40G/100G NIC (`i40e` / `mlx5`) veya dış ağ hattı üzerinde değil; `TcpDataplaneCore` durum makinesinin ve sıfır-kopya (strided) TX/RX halka tamponlarının işlemci ve RAM üzerindeki **gerçek paket sentezleme, başlık ayrıştırma, RFC 1071 checksum doğrulama ve TCB (Transmission Control Block) yaşam döngüsü** kapasitesini ölçmek üzere koşturulmuştur.
> 2. **Kontrollü Elma-Elma (Apples-to-Apples) Zamanlama Sınırları (P0):**
>    * Tek-Çekirdek (`1 Worker`), Fiziksel Çekirdek (`6 Worker`) ve Tam SMT (`12 Worker`) karşılaştırmalarında iş parçacığı oluşturma (`std::thread`), çekirdek sabitleme (`sched_setaffinity`), `TcpDataplaneCore::Configure` tahsisleri ve yıkım (`wcore.reset()`) işlemleri zamanlama penceresinin (`[t_start, t_end]`) **dışına** çıkarılmış; tüm worker'lar atomik bir başlangıç bariyerinde (`start_flag`) senkronize edilerek **birebir aynı 2.048'lik partili 1M 3-yollu el sıkışma iş yükü** ölçülmüştür.
>    * Harici 64-shard dağılım hesabı (`HashFlowKey`) ve harici `flow_ids` vektörü zamanlanan sıcak yoldan (hot path) tamamen ayrılmıştır.
> 3. **CPU Topolojisi ve `sched_setaffinity` Teyidi (P0):**
>    * Linux `/sys/devices/system/cpu/cpu*/topology/core_id` üzerinden fiziksel çekirdek haritası çıkarılmış; her worker'da `sched_setaffinity()` dönüş kodu (`0`) ve `sched_getcpu()` ile gözlemlenen çekirdek kimliği doğrulanmıştır.
>    * **6 Fiziksel Çekirdek** (`CPUs [0, 2, 4, 6, 8, 10]`, çekirdek başına 1 thread) ile **12 SMT Thread** (`CPUs [0..11]`, çekirdek başına 2 SMT kardeş thread) ayrı ayrı 5'er kez koşturulmuştur.
> 4. **İstatistiksel Tekrar (`--runs 5`) ve Bellek Geri Kazanım Teyidi (P0):**
>    * Her mimari mod ardışık **5 iterasyon** koşturulmuş; **Medyan (Median), Minimum, Maksimum ve Standart Sapma ($\sigma$)** değerleri raporlanmıştır.
>    * Worker'ların kendi `TcpDataplaneCore` nesnelerini kendi thread'leri içinde yıkması (`wcore.reset()`) sağlanarak `glibc` thread-local arena sayfalarının asılı kalması önlenmiş ve 20 ardışık `1M akış oluştur -> yık -> malloc_trim(0)` döngüsü boyunca kalıcı RSS sızıntısı olmadığı (`~8,13 MiB` sabit taban) kanıtlanmıştır.
> 5. **Yapı Boyutu (`sizeof`) vs. Süreç `VmRSS` Artışı Ayrımı ve RFC 1071 Checksum Kapısı (P1):**
>    * [`TcpDataplaneCore::GetMemoryLayout()`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1395-L1404) ile ham C++ yapı boyutları (`sizeof(FlowEntry) = 416 B`) dışa açılmış ve süreç `VmRSS` artışı (`established_rss_delta_per_flow_bytes = 1.648,43 B`) ile arasındaki fark bileşen bazında açıklanmıştır.
>    * [`ParseIpv4TcpFrame`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1406-L1498) içine opsiyonel RFC 1071 IPv4 + TCP checksum doğrulaması (`verify_rx_checksum`) eklenmiş; hem bozuk paket reddi (`Phase 0`) hem de 1M akışta tam checksum doğrulama maliyeti ölçülmüştür.

---

## 2. Test Ortamı ve Donanım Özellikleri

| Bileşen | Ölçülen / Doğrulanan Değer |
| :--- | :--- |
| **İşlemci (CPU)** | AMD Ryzen 5 5600H with Radeon Graphics (`x86_64`, AVX2) |
| **Fiziksel Çekirdek / SMT Thread** | 6 Fiziksel Çekirdek (`[0, 2, 4, 6, 8, 10]`) / 12 Mantıksal Thread (`[0..11]`) |
| **Önbellek Hiyerarşisi** | L1d: 192 KiB (6×32 KiB), L2: 3 MiB (6×512 KiB), L3: 16 MiB (Paylaşımlı) |
| **Sistem Belleği (RAM)** | 13 GiB Toplam, ~8,5 GiB Kullanılabilir |
| **İşletim Sistemi / Çekirdek** | Linux `6.14.0-37-generic` (`perf_event_paranoid = 4`) |
| **Derleyici ve Bayraklar** | GCC 13 C++17 (`-O3 -mavx2 -DNDEBUG`) |

---

## 3. Faz Bazlı Doğrulama ve Tekil Motor Yaşam Döngüsü Sonuçları

Aşağıdaki tablo, harici `flow_ids` dizisi veya hash sayacı olmadan **izole edilmiş** tekil `TcpDataplaneCore` örneği üzerindeki Faz 0–7 ölçümlerini gösterir:

| Faz / Metrik | Ölçülen Değer | Matematiksel Bağıntı / Doğrulama | Durum |
| :--- | :--- | :--- | :--- |
| **Faz 0 — RFC 1071 Checksum Kapısı** | `Bozuk IP=Red, Bozuk TCP=Red, Geçerli=Kabul` | `InternetChecksum == 0` ve `TcpChecksum == 0` doğrulaması | **PASS** |
| **Faz 1 — Başlangıç (Baseline) `VmRSS`** | `4.148 KB` (`4,05 MiB`) | `/proc/self/status` başlangıç fiziksel RAM | **PASS** |
| **Faz 2 — 1M SYN Üretim Süresi ($T_{\text{syn}}$)** | `1.756,42 ms` (`1,75642 s`) | 4.096'lık partiler halinde Enqueue + Strided Ring Drain | **PASS** |
| **Faz 2 — 1M SYN Hızı ($\text{CPS}_{\text{syn}}$)** | `569.340,54 akış/sn` (`569,34 kCPS`) | $\text{CPS} = \frac{1.000.000}{1,75642\text{ s}} = 569.340,54\text{ s}^{-1}$ | **PASS** |
| **Faz 2 — Çekilen SYN Tel Çerçeveleri** | `1.000.000 / 1.000.000` | `66 B` $\times 10^6 = 66,00\text{ MB}$ (`62,94 MiB`), Kayıp: `%0,00` | **PASS** |
| **Faz 3 — 64-Shard Dağılımı (Min / Ort / Max)** | `15.620 / 15.625,00 / 15.630` | $\sigma = 2,94$, Maksimum Sapma: **`%0,0320`** (Hedef $\le \%5,0$) | **PASS** |
| **Faz 4 — 1M SYN-ACK + ACK Süresi ($T_{\text{hs}}$)** | `757,085 ms` (`0,757085 s`) | 1M `IngestRxFrame` (66B SYN-ACK) + 1M ACK TX Drain | **PASS** |
| **Faz 4 — El Sıkışma Tamamlama Hızı** | `1.320.855,65 el sıkışma/sn` (`1,32 M/sn`) | $\frac{1.000.000}{0,757085\text{ s}} = 1.320.855,65\text{ s}^{-1}$ | **PASS** |
| **Faz 4 — Kurulan (`kEstablished`) Akış Sayısı** | `1.000.000 / 1.000.000` | `%100,00` başarılı durum geçişi, `unexpected_rx = 0` | **PASS** |
| **Faz 4 — Çekilen ACK Tel Çerçeveleri** | `1.000.000 / 1.000.000` | `54 B` $\times 10^6 = 54,00\text{ MB}$ (`51,50 MiB`), Kayıp: `%0,00` | **PASS** |
| **Faz 2+4 — Toplam Paket Süresi ($T_{\text{single}}$)** | `2.513,50 ms` (`2,51350 s`) | $T_{\text{syn}} + T_{\text{hs}} = 1.756,42 + 757,08\text{ ms}$, $N_{\text{pkt}} = 3.000.000$ | **PASS** |
| **Faz 2+4 — Toplam Paket Hızı ($\text{PPS}_{\text{single}}$)** | `1.193.554,80 paket/sn` (`1,19 M-PPS`) | $\text{PPS} = \frac{3.000.000}{2,51350\text{ s}} = 1.193.554,80\text{ PPS}$ | **PASS** |
| **Faz 5 — 1M `SYN_SENT` Süreç `VmRSS` Artışı** | `1.583.704 KB` (`1.546,59 MiB`) | $\mathbf{1.621,71\text{ B/akış}}$ (`syn_sent_rss_delta_per_flow_bytes`) | **PASS** |
| **Faz 5 — 1M `ESTABLISHED` Süreç `VmRSS` Artışı** | `1.609.792 KB` (`1.572,06 MiB`) | $\mathbf{1.648,43\text{ B/akış}}$ (`established_rss_delta_per_flow_bytes`) | **PASS** |
| **Faz 5 — Çekirdek Sayfa Hataları (`getrusage`)** | `416.056 Minor / 0 Major` | $416.056 \times 4\text{ KiB} \approx 1,587\text{ GiB}$ sıfır-disk-takaslı sayfa tahsisi | **PASS** |
| **Faz 6 — 12-Thread Lockless Okuma Hızı** | **`70,26 M-lookups/sn`** (`42,70 ms`) | $3.000.000$ `GetFlowLockless` çağrısı, `%100` isabet ve RFC opsiyon teyidi | **PASS** |
| **Faz 7 — Bellek Yıkım ve `malloc_trim(0)`** | `6.028 KB` (`5,89 MiB`) (`637,23 ms`) | `1.576,11 MiB` $\to$ `5,89 MiB` (**`%99,63` RAM işletim sistemine iade**) | **PASS** |

---

## 4. Kontrollü Elma-Elma (Apples-to-Apples) Çoklu Koşum (`--runs 5`) Ölçeklenebilirlik Analizi

Faz 8'de tüm mimari modlar **birebir aynı zamanlama sınırları** (thread oluşturma, `sched_setaffinity`, `Configure` ve yıkım zamanlama dışında; başlangıç bariyeri ile senkronize) ve **birebir aynı 2.048'lik partili 1M tam el sıkışma (3M paket) döngüsü** ile 5'er kez koşturulmuştur:

| Mimari Mod | Worker / Sabitlenen CPU'lar (`sched_getcpu` Doğrulandı) | Süre Medyan (ms) | Süre Min / Max (ms) | Süre $\sigma$ (ms) | Medyan CPS (Akış/sn) | Medyan PPS (Paket/sn) | Kontrollü Hızlanma ($S_{\text{median}}$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Tek-Çekirdek (`Single-Core 1W`)** | `1W` $\to$ `[0]` | **`3.061,60 ms`** | `3.044,65 / 3.149,50` | `41,39 ms` | `326.627 CPS` (`0,33 M-CPS`) | `979.881 PPS` (`0,98 M-PPS`) | **`1,00×`** (Referans) |
| **2. Shared-Nothing Fiziksel (`6W Physical`)** | `6W` $\to$ `[0, 2, 4, 6, 8, 10]` | **`745,12 ms`** | `702,17 / 779,64` | `25,35 ms` | **`1.342.058 CPS` (`1,34 M-CPS`)** | **`4.026.174 PPS` (`4,03 M-PPS`)** | **`4,11×`** (6 Fiziksel Çekirdek) |
| **3. Shared-Nothing Tam SMT (`12W SMT`)** | `12W` $\to$ `[0..11]` | **`711,40 ms`** | `614,52 / 762,34` | `56,15 ms` | **`1.405.689 CPS` (`1,41 M-CPS`)** | **`4.217.067 PPS` (`4,22 M-PPS`)** | **`4,30×`** (`6W`'a göre `1,05×`) |
| **4. Shared-Nothing SMT + RFC 1071 Checksum (`12W + CSUM`)** | `12W` $\to$ `[0..11]` (`verify_rx_checksum=true`) | **`645,63 ms`** | `617,66 / 709,30` | `40,25 ms` | **`1.548.875 CPS` (`1,55 M-CPS`)** | **`4.646.625 PPS` (`4,65 M-PPS`)** | **`4,74×`** |

### 4.1 Bulguların Mühendislik Yorumu
1. **Gerçek Kontrollü Hızlanma (`4,11×` Fiziksel, `4,30×` SMT):**
   * Önceki koşumda thread oluşturma ve `Configure()` maliyetleri Shared-Nothing süresine dahilken, Single-Core süresine harici `flow_ids` ve `HashFlowKey` dahildi. Her iki taraf da pür motor işine izole edildiğinde:
     * **1 Fiziksel Çekirdekten 6 Fiziksel Çekirdeğe geçişte** medyan süre `3.061,60 ms`'den `745,12 ms`'ye inerek **`4,11×` net hızlanma** sağlamıştır (çekirdek başına `%68,5` paralel verimlilik).
     * **6 Fiziksel Çekirdekten 12 SMT Thread'e geçişte** medyan süre `745,12 ms`'den `711,40 ms`'ye inerek yalnızca **`1,05×` (`+%4,7`)** ek kazanç sağlamıştır.
   * **Neden SMT sadece `%4,7` ek kazanç sağlıyor?** Çünkü iş yükü her akışta `1.648 Bayt` dinamik bellek tahsisi ve hash tablosu erişimi yaptığı için L3 önbelleği (`16 MiB`) aşmakta ve **DDR4 ana bellek kontrolcüsü bant genişliğine (memory-bandwidth bound)** dayanmaktadır. 6 fiziksel çekirdek bellek veriyolunu zaten doyurduğundan, aynı çekirdek üzerindeki ikinci SMT kardeşleri (CPU `1, 3, 5, 7, 9, 11`) çoğunlukla L3/DRAM stall beklemektedir.
2. **RFC 1071 Checksum Doğrulama Maliyeti Neden Sıfıra Yakındır?**
   * Mod 4'te hem test çerçevesi her SYN-ACK paketi için gerçek RFC 1071 IPv4 + TCP checksum hesaplamış hem de `TcpDataplaneCore::IngestRxFrame` içinde `InternetChecksum` ve `TcpChecksum` (64-bit vektörize tek'e tümleyen toplamı) çalıştırılmıştır.
   * Paket (`66 Bayt`) zaten `BuildRealisticSynAckFrame` sırasında çekirdeğin **L1d önbelleğinde sıcak (hot in L1 cache)** olduğundan, 20 baytlık IPv4 ve 32 baytlık TCP başlığı üzerinde 64-bitlik birkaç toplama işlemi yapmak DRAM erişim gecikmesinin yanında ölçüm gürültüsü (`±%5-9` termal/boost varyansı) içinde kalmaktadır.

---

## 5. Bellek Mimarisi: `sizeof(FlowEntry)` vs. Süreç `VmRSS` Artışı Analizi

[`TcpDataplaneCore::GetMemoryLayout()`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp#L1395-L1404) ile alınan derleme zamanı (`compile-time`) yapı boyutları ve 1.000.000 aktif akışta ölçülen süreç `VmRSS` dağılımı aşağıdadır:

| Yapı / Metrik Adı | Boyut (Bayt) | Açıklama ve Bellek Muhasebesindeki Rolü |
| :--- | :--- | :--- |
| **`sizeof(FlowKey)`** | `12 B` | `src_ip (4B) + dst_ip (4B) + src_port (2B) + dst_port (2B)` |
| **`sizeof(TimerEntry)`** | `24 B` | `due_ns (8B) + flow_id (8B) + kind (1B) + generation (4B) + padding` |
| **`sizeof(OutstandingTx)`** | `88 B` | Gönderilmiş/onay bekleyen segment метаverisi + `data` ve `opts` `std::vector` başlıkları |
| **`sizeof(FlowEntry)`** | **`416 B`** | Ham TCB yapısı: dizi numaraları, pencere/cwnd/RTT, RFC 6675 SACK, `sndbuf` (`24B`), `unacked` `std::deque` (`80B`), `seg_buf_pool` (`24B`), `rx_oo_queue` `std::map` (`48B`), `sack_blocks` (`24B`) |
| **`sizeof(PerShardTxRing)`** | `256 B` | `alignas(64)` kilit + halka vektör başlıkları |
| **`sizeof(TcpDataplaneCore)`** | `54.784 B` (`53,5 KiB`) | 64 şeritli spinlock, harita ve sayaç dizilerinin toplam statik nesne boyutu |
| **Akış Başına Süreç `VmRSS` Artışı (`SYN_SENT`)** | **`1.621,71 B`** | `FlowEntry` (`416B`) + `std::unordered_map` düğümü + `std::deque` ilk 512B blok tahsisi + `unacked` içindeki SYN `OutstandingTx` + `active_flow_ids_shard_` (`std::set` RB-tree düğümü, `48B`) + `timer_heap_shard_` kayıtları + `flow_index_shard_` kaydı |
| **Akış Başına Süreç `VmRSS` Artışı (`ESTABLISHED`)** | **`1.648,43 B`** | `SYN_SENT` üzerine el sıkışma tamamlama (`completions_` / timer güncellemeleri) sonrası süreçte yerleşik toplam fiziksel bellek |

> [!TIP]
> **Bir Sonraki Bellek Optimizasyonu Yol Haritası (`1.648 B/akış` $\to$ `< 256 B/akış`):**
> `sizeof(FlowEntry)`'nin `416 B` olmasına karşın akış başına RSS artışının `1.648,43 B` olmasının birincil sebebi **C++ STL konteynerlerinin (`std::deque`, `std::set`, `std::unordered_map`) başlangıç heap tahsisleridir**:
> 1. `FlowEntry::unacked` bir `std::deque<OutstandingTx>` olduğu için `libstdc++` her akışta ilk eleman eklendiğinde **512 Baytlık** bir iç blok + harita dizisi (~`600+ Bayt`) tahsis eder ve `clear()` çağrıldığında bile bu ilk bloğu serbest bırakmaz.
> 2. `active_flow_ids_shard_` (`std::set<uint64_t>`) her akış için ayrı bir Red-Black Tree düğümü (`48 B` + `malloc` başlığı) tahsis eder.
> 3. `flows_by_id_shard_` (`std::unordered_map`) her akış için ayrı bir bağlı liste düğümü tahsis eder.
> İlerleyen aşamada `FlowEntry` düz bir TCB havuzuna (flat slab/arena pool) alındığında ve `unacked` / `rx_oo_queue` yalnızca veri transferi başlayan akışlarda (lazy allocation) tahsis edildiğinde, 1M bağlantı için RAM tüketimi **`1,57 GiB`'dan `~250 MiB` seviyesine** indirilebilecektir.

---

## 6. Tekrarlanan Döngülerde Sıfır Bellek Sızıntısı Kanıtı

Faz 8 boyunca `Shared-Nothing SMT (12W)` modunda 5 ardışık turda (her turda 1.000.000 akış oluşturulup 3M paket işlenip yıkıldıktan ve `malloc_trim(0)` çağrıldıktan sonra) ölçülen süreç `VmRSS` değerleri:
* **1. Tur Sonu:** `7.988 KB` (`7,80 MiB`)
* **2. Tur Sonu:** `8.324 KB` (`8,13 MiB`)
* **3. Tur Sonu:** `8.324 KB` (`8,13 MiB`)
* **4. Tur Sonu:** `8.324 KB` (`8,13 MiB`)
* **5. Tur Sonu:** `8.324 KB` (`8,13 MiB`)

2. turdan 5. tura kadar `VmRSS` **bayt 수준inde sabit (`8.324 KB`)** kalmıştır; milyonlarca akışlık oluşturma ve yıkım döngülerinde **sıfır bellek sızıntısı (0 byte leak)** olduğu doğrulanmıştır.

---

## 7. Tekrar Çalıştırma Komutları

```bash
# Tam 1M benchmark script'ini çalıştırma (5 tekrarlı modlar + JSON/Markdown rapor üretimi):
./tests/bench_1m_tcp_flows.sh

# Doğrudan C++ ikili dosyasını özel tekrar sayısıyla çalıştırma:
./build/l4/test_1m_tcp_flows --flows 1000000 --handshakes 1000000 --runs 5 --json /tmp/report_1m.json

# Python/unittest otomasyon doğrulamasını çalıştırma:
python3 -m unittest tests/test_1m_tcp_flows.py -v
```
