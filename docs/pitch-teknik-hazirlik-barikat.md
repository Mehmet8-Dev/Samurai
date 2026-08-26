# Samurai — Teknik Hazırlık Rehberi (Barikat / kurumsal görüşme öncesi)

Bu liste dokümanlardan değil, doğrudan koddan (dosya:satır referanslı) çıkarıldı —
bazı `docs/*.md` dosyaları güncelliğini yitirmiş olabilir, gerçeği kod söylüyor.
Her madde: **ne var → neden önemli → nasıl anlatılır.** Çalıştıkça kutucuğu işaretle.

---

## 0. ÖNCE OKU: Abartmaman gereken 2 nokta

Kod taraması sırasında iki yer, README'nin "tamamen Python'dan arındırıldı /
tam üretim seviyesi" iddiasını gölgeliyor. Bunları bilerek konuş, sorulursa
şaşırma ve abartma:

- [ ] **AF_XDP köprüsü (`xdp/xdp_core.c`)** hâlâ `Python.h` import ediyor ve
  `PyObject *xdp_mod` üzerinden bir Python modülüne köprü kuruyor
  (`use_native_api` bayrağıyla native bir yol da var, ikisi bir arada).
  Yani AF_XDP tarafı **%100 saf native değil**, native+python-bridge hibrit.
  Soru gelirse: "AF_XDP worker'da native API'ye geçiş kısmen tamamlandı,
  bridge katmanı hâlâ mevcut" de — yalan söylememiş olursun.
- [ ] **TensorRT savunma çıkarımı (`gpu_packet_cuda/kernels_defense_tensorrt.cuh`)**
  gerçek bir TensorRT motoru değil, `SAMURAI_WITH_TENSORRT` derlenmediğinde
  **tek satırlık bir eşik sezgiseli** (`score > 0.2f ? anomali : normal`) çalışıyor.
  "VAE + TensorRT anomali tespiti" derken bunun bir **stub/iskelet** olduğunu,
  gerçek modelin `models/vae/` altında Python tarafında (train/service/rules)
  ayrı durduğunu bil. Demo isterlerse hangi mod çalıştığını netleştir.

Bunları saklama — teknik bir alıcı (CISM'li biri) bunu er ya da geç sorar,
sen söylersen "dürüst mühendis", o bulursa "abartan satıcı" izlenimi bırakırsın.

---

## 1. L4 User-Space TCP Stack (`ddos_samurai/l4/tcp_dataplane_core.*`)

- [ ] **64 shard'lı lock-striping** — `kFlowLockShards = 64`
  (`tcp_dataplane_core.hpp:315`). Dikkat: tek bir shard sayısı değil, **üç ayrı
  shard dizisi** var — flow lookup kilidi, flow-index kilidi, timer kilidi
  ayrı ayrı 64'e bölünmüş (`:348-352`). Yani sadece bağlantı tablosu değil,
  **timer wheel de shard'lı** — bu ince bir detay, sorulursa bilmen iyi olur.
- [ ] **Retransmit mekanizması** — `max_retransmits = 5` varsayılan, ayrıca
  `fast_retransmit_count` ve `retransmit_exhausted_count` sayaçları var —
  yani hem klasik timeout-tabanlı hem fast-retransmit (duplicate ACK tabanlı)
  yolu ayrı izleniyor.
- [ ] **Out-of-order alım** — `out_of_order_rx_count` sayacı var; paketlerin
  sırasız geldiği gerçek ağ koşullarını simüle edip toparlayabiliyor.
- [ ] **Neden önemli:** Kernel-bypass (AF_XDP/DPDK) sadece ham hızı verir.
  Bu shard'lı state motoru olmadan, milyonlarca stateful bağlantıyı aynı anda
  tutmaya çalıştığında darboğaz NIC'ten değil **kendi kilit çakışmandan**
  çıkar. "Biz gerçekten Mpps seviyesinde stateful TCP simüle edebiliyoruz"
  iddiasının kanıtı burası.

## 2. Kernel-Bypass Dataplane (AF_XDP / DPDK)

- [ ] **AF_XDP** — NIC sürücüsü kernelde kalır, XDP hook paketi skb
  oluşmadan/network stack'e girmeden yakalayıp zero-copy UMEM ring'e
  yönlendirir. Standart NIC + standart sürücü üzerinde çalışır, NIC
  paylaşılabilir. (Yukarıdaki 0. bölümdeki python-bridge notunu unutma.)
- [ ] **DPDK** (`dpdk/dpdk_core.hpp`) — gerçekten saf native, `<rte_*.h>` ve
  `<Python.h>` içermiyor (kasıtlı olarak ayrılmış, dosyanın kendi yorumunda
  yazıyor). `SAMURAI_WITH_DPDK` derleme bayrağıyla şartlı — libdpdk yoksa
  fonksiyonlar güvenli şekilde 0/başarısız döner (crash etmez).
  Port yetenekleri (`PortCapabilities`: RSS desteği, checksum offload,
  max TX/RX queue) NIC'ten otomatik okunuyor, elle varsayım yapılmıyor.
- [ ] **Multi-queue TX/RSS** — `OpenConfig` içinde `num_tx_queues`,
  `enable_rss` var; yani tek çekirdeğe değil, birden fazla kuyruğa/CPU
  çekirdeğine dağıtılmış gönderim destekleniyor (RSS = Receive Side Scaling,
  NIC'in gelen trafiği donanımsal olarak kuyruklara/çekirdeklere dağıtması).
- [ ] **Neden önemli:** İkisini de desteklemenin sebebi donanım/ortam esnekliği
  — dedicated lab kutusunda DPDK ile tavana vurursun, paylaşımlı/standart
  sunucuda AF_XDP ile daha az müdahaleyle çalışırsın. Bu bir "ya biri ya
  diğeri" seçimi değil, kullanım senaryosuna göre worker seçimi.

## 3. Kontrol Düzlemi — HA, RBAC, Audit (`ddos_samurai/control/`)

- [ ] **HA lider seçimi (`ha.hpp`)** — üç elector var, hepsi gerçek kod,
  stub değil:
  - `StaticLeaderElector`: node id'lerin sözlüksel en küçüğü lider olur
    (bootstrap/basit HA, gerçek konsensüs değil — dosyanın kendi yorumu
    bunu açıkça söylüyor).
  - `FileLeaseLeaderElector`: dosya tabanlı kira (`flock` + atomic rename ile
    `{"owner":..,"expires_at":..}` yazılıyor), renew loop ile kira yenileniyor.
  - `RedisLeaseLeaderElector`: Redis/KvStore soyutlaması üzerinden, **fencing
    epoch** ile (SET NX PX / INCR / compare-and-PEXPIRE) — split-brain'i
    epoch numarasıyla engelleyen daha olgun bir model.
  - Dikkat: Raft tabanlı tam konsensüs elector'ü **henüz yok**, yorumda
    "deferred to later increments" diye açıkça belirtilmiş. Sorulursa
    "üç seviyeli HA var, tam Raft konsensüsü roadmap'te" de.
- [ ] **RBAC + JWT (`auth.hpp`, `jwt.hpp`)** — HS256 JWT (HMAC-SHA256,
  OpenSSL ile, **sabit-zamanlı imza karşılaştırması** — timing attack'a karşı
  önlem alınmış). Roller: admin > operator > viewer > worker, secret'lar
  çakışırsa en güçlü rol kazanıyor (`ResolveRoleFromSecret`).
- [ ] **Tahrif edilemez audit log (`audit_log.hpp`)** — her satır bir önceki
  satırın hash'ini taşıyor (`prev_hash`), her satırın kendi hash'i
  (`entry_hash`) sıralı-anahtarlı JSON üzerinden SHA-256 ile hesaplanıyor.
  Zincirleme yapı sayesinde bir satırı silme/değiştirme/sıralamayı bozma,
  `Verify()` fonksiyonunda anında yakalanıyor. **Blockchain değil**, ama aynı
  "hash-chain" prensibi — bunu doğru kelimeyle anlat, blockchain deme,
  gereksiz abartı gibi durur ve teknik biri düzeltir.
- [ ] **Cross-region multi-master (`multimaster.hpp`)** — `KvStore`
  soyutlaması (gerçek Redis backend'i "deferred", in-memory test backend'i
  var) üzerinden heartbeat/snapshot/event yayını + bölgeler arası iş
  kuyruğu (enqueue/dequeue). Yani "multi-region koordinasyon" iddiası kod
  seviyesinde gerçek, ama prod Redis bağlantısı henüz bağlanmamış — bunu
  netleştir, sorulursa.
- [ ] **Neden önemli:** Barikat gibi banka/havalimanı müşterisi olan bir
  firma için "kim, ne zaman, hangi testi çalıştırdı" sorusunun **tahrif
  edilemez** kaydı, ürünün kurumsal/denetim (audit) gereksinimlerini
  karşıladığının kanıtı. Bu, DDoS test kapasitesinden bile önce sorulacak
  bir şey olabilir.

## 4. Dağıtık İş Bölme (`control/shard.hpp`)

- [ ] Üç strateji: `equal` (eşit böl), `capability` (worker'ın GPU/XDP
  yeteneğine ve `capacity_score`'una göre ağırlıklandır), `region`
  (hedef bölgeye göre). Saf mantık, I/O yok — test edilmesi kolay,
  deterministik.
- [ ] **Neden önemli:** "10 milyon paketlik bir işi 4 worker'a nasıl
  dağıtıyorsunuz" sorusuna somut cevap — kör eşit bölme değil, worker'ın
  gerçek kapasitesine göre akıllı dağıtım da var.

## 5. SLA Denetleyici (`scenario_engine_native/sla.hpp`)

- [ ] `evaluate_sla_native()` gerçek sayaçlarla çalışıyor: başlatılan/tamamlanan
  oturum sayısı, denenen/başarısız adım sayısı, p95 gecikme, TCP bağlanma
  denemesi/başarısı, retransmit sayısı, timeout-close sayısı → tek bir
  pass/fail kararı üretiyor.
- [ ] **Neden önemli:** Bu, "sadece paket atmıyoruz, gerçek kullanıcı
  deneyimi SLA'sını (p95 gecikme, oturum tamamlama oranı) yük altında
  gerçek zamanlı doğruluyoruz" iddiasının doğrudan kanıtı — LoDDoS gibi
  "paket/saniye" odaklı araçlarla arandaki en somut fark burada.

## 6. L7 Protokol Genişliği (`l7_emu_native/engine.hpp`)

- [ ] Sadece HTTP değil: `FlowOp` yapısında **TLS** (SNI, ALPN, cipher list,
  verify), **DNS** (EDNS0, ECS subnet dahil), **DHCP**, **IGMP**, **IPv6 ND**
  (Neighbor Discovery) action alanları var. Yani L7 senaryo motoru web
  trafiğiyle sınırlı değil, ağ protokolü seviyesinde de senaryo kurabiliyor.
- [ ] `Profile` içinde `transport_backend` (custom_tcp / kernel) ve
  `stateful_runtime_backend` ayrı ayrı seçilebiliyor — yani L7 motoru
  kendi user-space TCP stack'ini kullanabildiği gibi kernel soketine de
  düşebiliyor (esneklik + karşılaştırma imkanı).
- [ ] **Neden önemli:** Bir havalimanı/banka müşterisi sadece HTTP değil,
  DNS amplifikasyonuna, DHCP/ND seviyesinde saldırılara karşı da dayanıklılık
  test etmek isteyebilir — bu genişlik farklılaştırıcı bir satış noktası.

## 7. Lisanslama / Feature-Gate (`licensing/gates.hpp`)

- [ ] `EnforceFeatureGates()` — istenen çalıştırma parametrelerini (attack
  vector, compute backend, XDP/spoof/ninja_mode, KPI gate profili) lisans
  seviyesine göre kabul/red ediyor, süre/RPS'i tier limitine göre kırpıyor.
  "Kritik yetenekler" (muhtemelen en agresif modlar) için ayrıca sunucu
  taraflı bir **exec grant token** isteniyor (`ExecGrantClient`) — yani
  tehlikeli modlar sadece lisans dosyasıyla değil, çalışma anında sunucudan
  onay alarak açılıyor.
- [ ] **Neden önemli:** Bu, ürünün baştan **ticarileştirilebilir/tier'lı**
  tasarlandığının kanıtı — "hobi projesi" değil, lisans/paket mantığı en
  başından mimaride var. Kurumsal alıcıya güven verir.

## 8. Savunma Tarafı — VAE / Defense Worker

- [ ] `zmq/daemon/defense_worker.cpp` var, gerçek bir worker. Ama GPU
  tarafındaki TensorRT çıkarımı şu an **stub** (bkz. Bölüm 0). Gerçek VAE
  eğitim/servis kodu `models/vae/` altında Python tarafında
  (`train.py`, `service.py`, `rules.py`, `windowing.py`) — yani "savunma"
  hikayesi iki parçalı: üretim tarafı native C++, model tarafı hâlâ Python.
  Bunu olduğu gibi anlat, gizleme.

---

## Barikat görüşmesine özel eşleme

| Konuşma anında gelebilecek soru | Hangi bölüme bak |
|---|---|
| "LoDDoS'tan farkınız ne?" | Bölüm 5 (SLA denetleyici) + Bölüm 6 (protokol genişliği) |
| "Ne kadar native, ne kadar hâlâ Python?" | Bölüm 0 (dürüst ol) |
| "Denetim/uyumluluk tarafı nasıl?" | Bölüm 3 (audit log + RBAC) |
| "Dağıtık/çok bölgeli çalışıyor mu?" | Bölüm 3 (multimaster) + Bölüm 4 (shard) |
| "Gerçekten kernel bypass mı?" | Bölüm 2 |
| "Milyonlarca bağlantıyı nasıl tutuyorsunuz?" | Bölüm 1 |

## Çalışma önerisi

Bu listeyi tek seferde ezberleme. Her gün 2-3 madde al, ilgili dosyayı aç,
kodun kendisine bak (yorumlar genelde çok açıklayıcı yazılmış), kendi
cümlenle 2-3 cümlede anlat. Görüşmeden önce en az Bölüm 0, 1, 3, 5'i
tereddütsüz anlatabiliyor olman lazım — geri kalanı "biliyorum ama"
seviyesinde yeterli.
