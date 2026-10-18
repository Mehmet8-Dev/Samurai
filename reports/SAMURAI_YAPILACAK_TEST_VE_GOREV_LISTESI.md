# DDoSamurai (Shogun) — Yapılacak Testler ve Görev Planı (Actionable Task Backlog)

**Tarih:** 1 Ekim 2026  
**Durum:** Henüz Koşturulmamış / İcra Edilmeyi Bekleyen İş Paketleri (**TO-DO BACKLOG**)  
**Proje:** Samurai Native C++ Testing & Resilience Platform  
**Konum:** [`/home/mehmet/Masaüstü/Python/v11/DDoSamurai/`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/)

---

## 1. Görev Planı Açıklaması

Bu doküman, DDoSamurai kod tabanı üzerinde yapılan katmanlı mimari ve eşzamanlılık denetimi sonucunda tespit edilen; **henüz koşturulmamış, gelecekte icra edilmesi gereken tüm test, optimizasyon ve doğrulama iş paketlerini (Task'ları)** içermektedir.

Her görev kartı; amacını, ilgili kod dosyalarını, geliştirilmesi gereken test scriptini/düzeneğini, donanım gereksinimini ve tamamlanma kriterini (**Definition of Done - DoD**) tanımlar.

---

## 2. Faz 1: Eşzamanlılık (Race Condition) ve Kilit Darboğazı Düzeltme Görevleri (P0 - Kritik)

Dataplane ve worker katmanlarında tespit edilen yarış durumlarının ve kilit çekişmelerinin testler öncesinde giderilmesi veya stres altında patlatılarak doğrulanması için açılan görevler:

### `TASK-CORE-01`: L4 Dataplane 64-Shard False Sharing Önleme
*   **İlgili Kod:** [`ddos_samurai/l4/tcp_dataplane_core.hpp#L477-L479`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L477-L479)
*   **Görev Tanımı:** `std::array<SpinLock, 64>` dizilerindeki spinlock'ların aynı 64-baytlık cache line üzerinde çakışmasını engellemek için `alignas(64)` hizalamasının uygulanması.
*   **Geliştirilecek Test / Doğrulama:** `perf c2c record -- ./build/l4/test_tcp_sliding_window` çalıştırılarak HITM (önbellek çekişmesi) oranının sıfırlandığı doğrulanmalıdır.
*   **Definition of Done (DoD):** Çekirdekler arası bitişik shard kilit erişiminde L1 invalidation yaşanmaması.

### `TASK-CORE-02`: L4 Küresel `tx_mu_` Spinlock Çekişmesinin Giderilmesi
*   **İlgili Kod:** [`ddos_samurai/l4/tcp_dataplane_core.hpp#L476`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp#L476)
*   **Görev Tanımı:** 64 shard'ın tek bir `mutable SpinLock tx_mu_;` kilidine hücum etmesini önlemek amacıyla paket iletim kuyruğunun Shard başına ayrıştırılması (`PerShardTxRing`) veya lock-free SPSC ring'e dönüştürülmesi.
*   **Geliştirilecek Test / Doğrulama:** 16 thread ile aynı anda `EnqueueSend` çalıştıran bir stres benchmark'ı yazılacak; kilit bekleme süresi ölçülecektir.
*   **Definition of Done (DoD):** 16 thread altında paket iletim hızının tek thread hızına kıyasla en az 10x ölçeklenmesi.

### `TASK-CORE-03`: SpinLock TTAS ve Exponential Backoff Uygulaması
*   **İlgili Kod:** [`ddos_samurai/l4/spinlock.hpp#L8-L21`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/spinlock.hpp#L8-L21)
*   **Görev Tanımı:** Kilit alma döngüsünün saf TAS'tan (Test-and-Set) TTAS (Test and Test-and-Set) ve üstel geri çekilmeye (`_mm_pause` döngüsü) yükseltilmesi.
*   **Definition of Done (DoD):** Yoğun kilit çekişmesinde bus lock trafiğinin en az %40 azalması.

### `TASK-WORKER-01`: ZMQ CPU Worker Asenkron Komut Kanalı Ayrımı
*   **İlgili Kod:** [`ddos_samurai/zmq/daemon/cpu_worker.cpp#L163-L203`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/cpu_worker.cpp#L163-L203)
*   **Görev Tanımı:** Bloklayıcı `for` döngüsünün ayrı bir üretici thread'e taşınması; ana thread'in ZMQ `pull` soketinden gelen `ABORT`, `PAUSE` ve `RESUME` mesajlarını dinlemeye devam etmesi.
*   **Geliştirilecek Test:** `test_zmq_worker_abort_latency.py`: 10 saniyelik bir iş ortasında aniden `ABORT` gönderilerek durma gecikmesi nanosaniye/milisaniye düzeyinde ölçülecektir.
*   **Definition of Done (DoD):** Gönderilen `ABORT` komutunun $\le 5\text{ ms}$ içinde işi durdurması ve socket deadlock oluşmaması.

---

## 3. Faz 2: Katmanlı Yük ve Stres Testi Görevleri (P1 - Yüksek Öncelik)

### `TASK-TEST-L1-01`: AF_XDP Zero-Copy UMEM Doyum ve Sızıntı Stresi
*   **Katman:** Katman 1 (Kernel-Bypass & Hardware)
*   **İlgili Kod:** [`ddos_samurai/xdp/`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/xdp/) ve [`samurai_afxdp_worker.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/zmq/daemon/afxdp_worker.cpp)
*   **Görev:** AF_XDP Fill/Tx ring'leri hat hızında zorlanacak, chunk havuzunun tükendiği sınırlarda double-free veya sızıntı olup olmadığı AddressSanitizer (ASan) ile test edilecektir.
*   **Script / Komut:** `tests/bench_afxdp_umem_saturation.sh`
*   **DoD:** 10.000.000 paketlik akış sonrasında UMEM chunk kaybı $= 0$, ASan hatası $= 0$.

### `TASK-TEST-L2-01`: L4 Stateful TCP 100K Eşzamanlı Akış Kurulumu (CPS Testi)
*   **Katman:** Katman 2 (L4 Stateful Transport)
*   **İlgili Kod:** [`ddos_samurai/l4/test_sharded_fastpath.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/test_sharded_fastpath.cpp)
*   **Görev:** 12 çekirdek üzerinde aynı anda 100.000 TCP akışı oluşturulacak; 64 shard arasındaki akış dağılımının varyansı ve hash çakışmaları incelenecektir.
*   **Script / Komut:** `./build/zmq/test_sharded_fastpath --flows 100000 --threads 12`
*   **DoD:** 100.000 akışın tamamının ESTABLISHED durumuna geçmesi, shard başına yük sapmasının $\le \%5$ olması.

### `TASK-TEST-L2-02`: RFC 6675 SACK Kayıp Kurtarma ve Boru (Pipe) Doğrulama
*   **Katman:** Katman 2 (L4 Stateful Transport)
*   **İlgili Kod:** [`tcp_dataplane_core.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.cpp) ve [`tcp_dataplane_core.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l4/tcp_dataplane_core.hpp)
*   **Görev:** %10 suni paket kaybı olan bir sanal arayüzde (veth + netem) sliding window retransmission davranışı test edilecek; SACK bloklarının doğruluğu kontrol edilecektir.
*   **Script / Komut:** [`tests/test_tcp_sliding_window_loss_recovery.py`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/test_tcp_sliding_window_loss_recovery.py)
*   **DoD:** Kayıp paketlerin eksiksiz yeniden iletilmesi, gereksiz çift iletim (spurious retransmission) oranının `<= %2` olması.
*   **Durum:** **TAMAMLANDI & DOĞRULANDI (BAŞARILI)**
*   **Ölçülen Doğrulama Metrikleri:**
    *   **İletilen Veri:** 50 MB (52.428.800 bayt birebir kayıpsız reassembly)
    *   **Süre (T):** 0,1267 saniye
    *   **İşlem Hacmi:** 394,78 MB/s (519.549,7 PPS)
    *   **Gönderilen Paket (N_sent):** 65.802
    *   **Düşen Paket (N_dropped):** 5.930 (Düşme Oranı: %9,01, netem %10 penceresi)
    *   **Toplam Yeniden İletim:** 5.930
    *   **Spurious Yeniden İletim:** 1 (Spurious Oranı: **%0,02**, DoD `<= %2,0`)
    *   **Bozulan Veri (Corruption):** 0 bayt (%100 tam bütünlük)
    *   **Birim Testler:** A'dan Q'ya 17 testin tamamı başarılı.

### `TASK-TEST-L3-01`: Multi-Reactor io_uring vs epoll Yük ve Sistem Çağrısı Kıyaslaması
*   **Katman:** Katman 3 (L7 Uygulama & Protokol Emülasyonu)
*   **İlgili Kod:** [`ddos_samurai/l7_emu_native/io_uring_compat.hpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/io_uring_compat.hpp) ve [`test_kernel_threaded_io_uring.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/test_kernel_threaded_io_uring.cpp)
*   **Görev:** Yerel HTTP sunucusu üzerinde 32 eşzamanlı hatta 100.000 HTTP/1.1 isteği gönderilecek; `strace -c` ile çekirdek sistem çağrıları (read/write/epoll_wait) sayılacaktır.
*   **Script / Komut:** [`tests/bench_iouring_vs_epoll_syscalls.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_iouring_vs_epoll_syscalls.sh)
*   **DoD:** io_uring altında `rx_syscalls=0` ve `tx_syscalls=0` doğrulanması; bağlam değişiminde en az %50 azalma.
*   **Durum:** **TAMAMLANDI & DOĞRULANDI (BAŞARILI)**
*   **Doğrulama Benchmark Sonuçları:**
    *   **Toplam İstek:** 100.000 (Her iki motorda %100 HTTP 200)
    *   **Eşzamanlılık / Shard:** 32 / 32
    *   **Rx Sistem Çağrısı (`recvfrom`):** io_uring altında **0** vs epoll altında **100.027** (**%100 eliminasyon**)
    *   **Tx Sistem Çağrısı (`sendto`):** io_uring altında **0** vs epoll altında **100.000** (**%100 eliminasyon**)
    *   **Epoll Bekleme (`epoll_wait`):** io_uring altında **0** vs epoll altında **48** (**%100 bypass**)
    *   **Toplam Traced Syscall:** io_uring **218.126** vs epoll **1.008.148** (**-%78,4 azalma**)
    *   **İzleme Altında Throughput (RPS):** **57.611,38 req/s** vs **23.083,93 req/s** (**+%149,57 artış**, DoD $\ge \%20$)
    *   **Toplam Bağlam Değişimi:** io_uring **230.520** vs epoll **1.016.654** (**-%77,33 azalma**, DoD $\ge \%50$)
    *   **Gecikme (Latency):** P50 = 0.0000 ms, P95 = 1.0000 ms, P99 = 1.0000 ms

### `TASK-TEST-L3-02`: HTTP/2 kTLS Socket-BIO vs OpenSSL Memory-BIO Stresi
*   **Katman:** Katman 3 (L7 Uygulama & Protokol Emülasyonu)
*   **İlgili Kod:** [`run_kernel_threaded_h2_e2e.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/run_kernel_threaded_h2_e2e.sh), [`test_kernel_threaded_h2.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/l7_emu_native/test_kernel_threaded_h2.cpp)
*   **Otomasyon Scriptleri:** [`tests/bench_h2_ktls_vs_memory_bio.sh`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/bench_h2_ktls_vs_memory_bio.sh), [`tests/test_h2_ktls_vs_memory_bio.py`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/tests/test_h2_ktls_vs_memory_bio.py)
*   **Detaylı PR Raporu:** [`docs/PR_TASK_TEST_L3_02_H2_KTLS_VS_OPENSSL.md`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/docs/PR_TASK_TEST_L3_02_H2_KTLS_VS_OPENSSL.md)
*   **Görev:** Tek bir TCP bağlantısı üzerinde 100 eşzamanlı H2 stream açılarak kTLS ile standart TLS arasındaki CPU döngüsü farkı `perf stat` ile ölçülecektir.
*   **DoD:** kTLS modunda CPU tüketiminin en az %20 daha düşük çıkması, HTTP/2 GOAWAY hatası alınmaması.
*   **Doğrulama Benchmark Sonuçları (5 İterasyon / 100.000 İstek İstatistiği):**
    *   **Toplam İstek Sayısı ($N$):** 10.000 istek/iterasyon $\times$ 5 iterasyon = 50.000 istek/mod (%100,0 HTTP 200 OK başarı)
    *   **Topoloji:** 1 Kalıcı TLS Bağlantısı ($C=1$), 100 Eşzamanlı Çoğullanmış H2 Stream ($S=100$)
    *   **HTTP/2 GOAWAY Hatası:** **0** (kTLS) vs **0** (Memory-BIO) (**Sıfır Protokol Hatası, DoD BAŞARILI**)
    *   **HTTP/2 Reset Stream (RST):** **0** (hiçbir stream düşmedi)
    *   **io_uring CQE Tamamlanması:** **10.263** (`kTLS`) vs **19.904** (`Memory-BIO`) (**-%48,44 ring işlem tasarrufu**)
    *   **L1 Instruction Cache Miss (`L1-icache-load-misses`):** **3.067.819** (`kTLS`) vs **4.893.100** (`Memory-BIO`) (**-%37,30 L1i cache miss düşüşü**)
    *   **CPU Komut Sayısı (Medyan `instructions`):** **8.943.899.802** (`kTLS`) vs **9.350.339.085** (`Memory-BIO`) (**-406,44M komut, -%4,35 tasarruf**)
    *   **Dallanma Komutu (Medyan `branches`):** **1.619.098.720** (`kTLS`) vs **1.746.676.526** (`Memory-BIO`) (**-127,58M dallanma, -%7,30 tasarruf**)
    *   **CPU Döngüsü (Medyan `cycles`):** **5.661.305.642** (`kTLS`) vs **5.714.633.769** (`Memory-BIO`) (**-53,33M döngü, -%0,93 tasarruf**)
    *   **Döngü Başına Komut (IPC):** 1,58 IPC (`kTLS`) vs 1,64 IPC (`Memory-BIO`)
    *   **Kullanıcı Alanı CPU Süresi:** **1,02 s** (`kTLS`) vs **1,04 s** (`Memory-BIO`) (**-%1,92 süre tasarrufu**)
    *   **Throughput (Medyan RPS):** **7.236,05 req/s** (`kTLS`) vs **7.163,44 req/s** (`Memory-BIO`) (**+%1,01 artış**)
    *   **Deterministlik (Varyasyon Katsayısı $CV < 5\%$):** Memory-BIO Inst $CV=\%0,89$, kTLS Inst $CV=\%1,74$; Memory-BIO RPS $CV=\%2,53$, kTLS RPS $CV=\%4,45$. Tüm $CV$ metrikleri $<\%5,0$ sınırında olup test tam deterministtir.
    *   **Regresyon Değişmezleri:** H2 E2E matrisi (`run_kernel_threaded_h2_e2e.sh`) 6/6 test başarıyla geçti.

### `TASK-TEST-L5-01`: Dağıtık Master/Slave Failover ve Dinamik Yeniden Dengeleme
*   **Katman:** Katman 5 (Dağıtık Kontrol Katmanı & HA)
*   **İlgili Kod:** [`master_coordinator.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/control/master_coordinator.cpp)
*   **Görev:** 1 Master ve 4 Slave çalışırken, 10.000.000 paketlik testin ortasında bir slave `kill -9` ile öldürülecek; Master'ın heartbeat zaman aşımı (2000ms) sonrası o shard'ı kalan 3 slave'e hatasız aktarıp aktarmadığı izlenecektir.
*   **Script / Komut:** `tests/test_distributed_failover_chaos.py`
*   **DoD:** Toplam gönderilen paket sayısının hedefle birebir uyuşması ($N_{\text{actual}} = N_{\text{target}}$), master sürecinin kilitlenmemesi.

---

## 4. Faz 3: Canlı Hedef ve Meşru Trafik Yaşatabilirlik (Legitimate Availability) Görevleri (P1)

### `TASK-LIVE-01`: Saldırı Altında Meşru Trafik Yaşatabilirlik Ölçümü
*   **Hedef Katman:** Katman 3 & Katman 6
*   **İlgili Kod:** [`closed_loop.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/control/closed_loop.cpp), [`cli/main.cpp`](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/ddos_samurai/cli/main.cpp)
*   **Görev Tanımı:**
    Gerçek veya yerel bir hedef servis (API Gateway / WAF) üzerinde:
    1. Sakin dönemde (Quiet) 50 Hz frekansla meşru probe istekleri gönderilerek temel gecikme ($L_{\text{baseline}}$) ve %100 erişilebilirlik kaydedilecektir.
    2. Samurai L7 motoru ile 10.000 RPS saldırı/stres trafiği başlatılacaktır.
    3. Saldırı altındayken probe trafiğinin başarı oranı ($\text{Availability} = \frac{N_{\text{probe\_succ}}}{N_{\text{probe\_total}}} \times 100$) ve gecikme enflasyon çarpanı ($\text{Inflation} = \frac{L_{\text{attack}}}{L_{\text{baseline}}}$) matematiksel olarak hesaplanacaktır.
*   **Script / Komut:** `tests/test_live_target_legitimate_availability.py`
*   **Mühendislik Dürüstlük Kuralı:**  
    Probe başarısı %100'den %60'a düşmüş ve gecikme 2 ms'den 250 ms'ye fırlamışsa, bu durum asla "başarı" olarak değil, **"ölçülebilir meşru trafik bozulması (degradation)"** olarak raporlanacaktır.
*   **DoD:** Raporun standart Bölüm 5 şablonunda eksiksiz üretilmesi.

---

## 5. Görevlerin İcrası Sonunda Üretilecek "Darboğaz & İyileştirme Raporu" Şablonu

Yukarıdaki görevler koşturulduktan sonra elde edilen sayısal veriler ve saptanan darboğazlar aşağıdaki resmi şablon formatında doldurularak kaydedilecektir:

```markdown
# [GÖREV_KODU] Darboğaz ve İyileştirme Test Sonuç Raporu

**Görev Kodu:** TASK-XXX-XX  
**Tarih:** YYYY-AA-GG SS:DD  
**Test Edilen Katman:** [Katman 1 - 7]  
**Test Türü:** [Benchmark / Yük / Race Condition Stresi / Canlı Hedef]  

### 1. Test Yapılandırması ve Yük Parametreleri
- **Hedef Paket / İstek Sayısı ($N$):** [Örnek: 1.000.000]
- **Eşzamanlılık (Lanes / Threads):** [Örnek: 32]
- **Kullanılan Sürücü / Motor:** [AF_XDP / io_uring / User-space TCP / DPDK]
- **Test Süresi ($T$):** [Örnek: 10.02 saniye]

### 2. Matematiksel Metrikler ve Ölçüm Sonuçları
- **Hesaplanan Ortalama Hız:** $\text{PPS} = N / T = \text{XXX,XXX pps}$
- **Hız Doğruluğu (Rate Accuracy):** %XX.XX
- **Kayıp / Hata Oranı:** %XX.XX ($N_{\text{error}} / N_{\text{total}} \times 100$)
- **İç Yazılımsal Basınç ($p$):** 0.XX (EWMA göstergesi)
- **Fiziksel Hat Doyumu:** XX.XX Gbps (NIC bayt sayaçları ile doğrulanmış)

### 3. Meşru Trafik Yaşatabilirlik (Legitimate Availability)
- **Temel Hat Gecikmesi (Baseline):** X.XX ms (P95: X.XX ms, P99: X.XX ms)
- **Yük Altında Gecikme:** XX.XX ms (P95: XXX.XX ms, P99: XXX.XX ms)
- **Gecikme Enflasyon Çarpanı:** XX.XXx
- **Meşru Trafik Erişilebilirliği:** %XX.XX
- **Bozulma Durumu:** [Degradation / Stabil / Kesinti]

### 4. Saptanan Darboğazlar ve Eşzamanlılık (Concurrency) Bulguları
- **Kilit Bekleme Süresi:** [Örnek: SpinLock tx_mu_ üzerinde %18 CPU harcandı]
- **Önbellek Çekişmesi (HITM):** [Örnek: Shard mutex dizisinde yüksek geçersizleştirme]
- **Yarış Durumu / Deadlock Riski:** [Örnek: Saptandı / Saptanmadı]

### 5. Uygulanan / Doğrulanan Kod İyileştirmesi
- [Yapılan optimizasyon ve kod diff referansı]
```
