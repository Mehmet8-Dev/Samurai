# 23 - Benchmark ve Acceptance Handbook

## Amac

Bu dokuman, `ddos_samurai.cli` ve benchmark pipeline'i ile alinan kosularin
sadece "calisti mi?" seviyesinde degil, "gecerli mi, karsilastirilabilir mi,
yayinlanabilir mi?" seviyesinde yorumlanmasi icin yazilmistir.

Bu belge su sorulara standart cevap vermeyi hedefler:

- Bu run teknik olarak kabul edilebilir mi?
- Bu sonuc benchmark olarak yayinlanabilir mi?
- Bu kosu sadece gozlemsel mi, yoksa karar verdirici mi?
- Sonraki adim debug mu olmali, tuning mi olmali, yoksa parity onayi mi?

Bu belge yalnizca yetkili ve izole test/lab ortamlari icin yazilmistir.

## Kimler Icin

- benchmark operatorleri
- performans muhendisleri
- SRE ve platform ekipleri
- parity/KPI gate sonucu yorumlayan teknik liderler
- CPU, TX_RING, AF_XDP ve GPU yollarini karsilastiran gelistiriciler

## Bu Belge Ne Degildir

Bu dokuman:

- tum CLI bayraklarinin referansi degildir
- "hangi komutu yazayim?" sorusunun birincil cevabi degildir
- troubleshooting dokumaninin yerine gecmez

Bu nedenle birlikte okunmasi gereken temel belgeler:

- `docs/22-cli-operational-playbook.md`
- `docs/19-benchmark-profiles.md`
- `docs/10-troubleshooting.md`
- `docs/20-env-cli-reference.md`

## Temel Karar Modeli

Her run sonunda su sirayla karar verilmelidir:

1. Run teknik olarak tamamladi mi?
2. Run kalitesi `valid` mi?
3. KPI gate sonucu `pass` mi?
4. Sender/backend davranisi beklenen yol ile uyumlu mu?
5. Ortam profili (`dev`, `ci_safe`, `dedicated_lab`) sonucun iddiasi ile uyumlu mu?
6. Artifact seti tekrar incelenebilir ve tekrar uretilebilir mi?
7. Sonuc benchmark, baseline, soak gozlemi veya debug artifact'i olarak siniflanmali mi?

Kisa kural:

- `run_quality != valid` ise benchmark iddiasi kurma
- KPI gate fail ise parity sonucu yayinlama
- fallback veya mixed path varsa "deterministik backend sonucu" diye sunma
- artifact yoksa veya eksikse uzun kosuyu kalici kabul etme

## Run Siniflari ve Guven Seviyeleri

| Run tipi | Amac | Karar gucu |
|---|---|---|
| Dry-run | Parse, config ve preflight dogrulama | Operasyonel hazirlik |
| Smoke run | Hizli canlilik/temel davranis kontrolu | Dusuk |
| Baseline | Referans davranis cizgisi olusturma | Orta |
| Benchmark | KPI/parity odakli olcum | Yuksek |
| Soak | Uzun sureli stabilite ve drift gozlemi | Yuksek |
| Fault-injection soak | Dayaniklilik ve bozucu kosul toleransi | Yuksek |
| Debug run | Koku neden arastirmasi | Analitik, benchmark degil |

Onemli ayrim:

- Her benchmark bir run'dir
- Ama her run benchmark degildir

## Gecerli Run Icin Asgari Kriterler

Bir run'in "gecerli" kabul edilmesi icin asgari olarak su sartlar aranmalidir:

- `workers_total > 0`
- `attempted_total > 0`
- run kullanici veya sistem tarafindan erken kesilmemis olmali
- run raporunda metrik zemini olusmus olmali
- hedeflenen backend ve run tipi ile ilgili temel telemetry alanlari dolu olmali

Pratikte ilk bakilacak alanlar:

- `results.run_quality`
- `results.warnings`
- `results.sender_path` veya `results.sender_paths_used`
- `results.sender_fallback_reason`
- `parity.normalized_results.kpi_gate_status`
- `parity.normalized_results.score_eligible`

## Gecersiz veya Supheli Run Isaretleri

Asagidaki durumlardan biri varsa run benchmark olarak sunulmamalidir:

- `run_quality == interrupted`
- `run_quality == invalid_metrics`
- `attempted_total == 0`
- `workers_total == 0`
- `sender_fallback_reason != none` ve hedef profil deterministik backend bekliyorsa
- `sender_paths_used` birden fazla aktif path iceriyorsa
- dedicated lab iddiasi var ama run root/privileged gerektiren yolda degrade olmus ise
- artifact seti eksik ise

Bu durumda run tamamen cop degildir. Ancak sinifi degisir:

- benchmark degil, debug artifact'i olabilir
- parity sonucu degil, gozlemsel sonuc olabilir
- yayinlik sonuc degil, tuning girdisi olabilir

## Baseline, Benchmark ve Soak Arasindaki Fark

### Baseline

Baseline, sistemin belirli bir anda beklenen davranisini kaydetmek icin alinir.

Ne zaman yeterlidir:

- yeni branch sonrasi hizli karsilastirma
- tuning oncesi referans alma
- buyuk regresyon var mi diye bakma

Ne zaman yeterli degildir:

- profil bazli parity iddiasi kurarken
- yayinlik performans beyaninda
- uzun sureli stabilite iddiasi kurarken

### Benchmark

Benchmark, onceden tanimli profile ve KPI gate'e gore yorumlanan kontrollu
olcumdur.

Benchmark icin ek beklentiler:

- profil secimi acik olmali
- ortam sinifi net olmali
- sender/backend davranisi deterministik olmali
- artifact standardi eksiksiz olmali

### Soak

Soak, anlik tepe performanstan cok su sorulara cevap verir:

- zamanla memory growth var mi?
- PPS/RPS drift olusuyor mu?
- fallback veya degradasyon gec ortaya cikiyor mu?
- fault-injection altinda run halen kabul edilebilir mi?

Soak sonucu, kisa benchmark'tan daha guclu stabilite kaniti verir; fakat kisa
benchmark skorunun yerine tek basina gecmez.

## KPI Gate Okuma Rehberi

Profil bazli kabul mantiginin omurgasi `kpi_gate_status` ve `score_eligible`
alanlaridir.

Temel yorum:

- `kpi_gate_status == pass`: run profilin minimum esiklerini gecmistir
- `kpi_gate_status == fail`: run parity/acceptance icin uygun degildir
- `score_eligible == 1`: run skorlamaya alinabilir
- `score_eligible == 0`: skor ciksa bile yayinlik parity sonucu sayilmaz

Ornek kararlar:

- `run_quality=valid`, `kpi_gate_status=pass`, `score_eligible=1`
  Sonuc: yayinlik benchmark adayi
- `run_quality=valid`, `kpi_gate_status=fail`
  Sonuc: teknik olarak calismis ama acceptance gecememis
- `run_quality=invalid_metrics`, `kpi_gate_status=fail`
  Sonuc: once telemetry/metric zemini duzeltilmeli

## Run Report'tan Tuning Karari Cikarma

Run report okunurken hedef "tek bir sayiya bakip tuning yapmak" olmamalidir.
Su mantik izlenmelidir:

1. once run gecerli mi karar ver
2. sonra ana problem sinifini bul
3. sonra yalniz ilgili knob grubuna dokun
4. her turda az sayida ayari degistir

Pratik kural:

- loss problemi varsa once queue/path/buffer tarafina bak
- rate accuracy problemi varsa once pacing ve worker dagitimina bak
- fallback problemi varsa once backend kararliligini duzelt
- mixed path varsa tuning'den once deterministik path'e gec

### Hangi Alan Ne Soyler?

| Run report alani | Tipik anlami | Ilk bakilacak knob grubu |
|---|---|---|
| `wire_loss_est_pct` | Hatta cikmadan veya cikista kayip baskisi | queue/ring/backend |
| `rate_accuracy_pct` | pacing hedefinden sapma | worker/rps/pacing |
| `sender_fallback_reason` | secilen hizli yolun korunamadigi | backend/policy/capability |
| `sender_paths_used` | run boyunca path drift veya mixed path | backend sabitleme |
| `txring_flush_error_count` | TX_RING flush seviyesinde hata | TX_RING geometri/poll/spin |
| `txring_flush_eagain_count` | ring/gecis tarafinda gecici baski | TX_RING geometri/backpressure |
| `txring_tp_drops` | kernel tarafinda drop baskisi | ring boyutu/queue uyumu |
| `gpu_ring_depth_peak` | GPU producer-consumer baskisi | GPU queue/pipeline |
| `gpu_ring_block_wait_ns` | producer'in kuyruk doldugu icin beklemesi | GPU batch/stream/depth |
| `workers_failed` / `workers_interrupted` | run zemini bozulmus olabilir | once stabilite |
| `dp_queue_id` / `dp_queue_strategy` / `dp_affinity_cpu` | queue-core yerlesimi | NUMA / queue map |
| `afpacket_hugepage_effective` | TX_RING memory policy etkinligi | hugepage/mlock/prefault |

### Tuning Matrisi

| Belirti | Olası neden | Arttirilacak ayar | Azaltilacak ayar | Kapatilabilecek ayar |
|---|---|---|---|---|
| `wire_loss_est_pct` yuksek, `rate_accuracy_pct` makul | gonderim yolu baskida | `--afpacket-ring-target-mb`, `--dp-queues` | `--workers` | gereksiz `--gpu-full-variation` |
| `rate_accuracy_pct` dusuk, loss orta/dusuk | pacing dagilimi bozuk | `--afpacket-spin-limit`, gerekiyorsa `--dp-queues` | `--workers`, `--gpu-batch-size` | agresif `--afpacket-busy-poll-us` |
| `txring_flush_eagain_count` yuksek | ring hizli doluyor/bosalmasi yetismiyor | `--afpacket-ring-target-mb`, `--afpacket-frames-per-block` | `--workers`, `--rps` | - |
| `txring_flush_error_count` yuksek | TX_RING geometri veya kernel baskisi | gerekiyorsa `--afpacket-poll-timeout-ms` az miktar | `--afpacket-spin-limit` veya `--rps` | deneysel `--afpacket-busy-poll-us` |
| `gpu_ring_block_wait_ns` yuksek | GPU producer cok onde | `--gpu-stream-count`, `--gpu-pipeline-depth` | `--gpu-batch-size` | `--gpu-full-variation` |
| GPU throughput artmiyor, latency artiyor | batch fazla buyuk | `--gpu-stream-count` | `--gpu-batch-size` | `--gpu-full-variation` |
| fallback goruluyor | secilen hizli yol korunamiyor | capability uyumlu queue/path | fazla worker veya agresif queue sayisi | `--sender-backend auto` yerine explicit backend |
| `sender_paths_used` mixed | deterministik olmayan route | `--dp-queue-strategy map` veya `pin` | topolojiye gore `--workers` | fallback'e izin veren gevsek policy |

Bu tablo "tek dogru cevap" degil, ilk mudahele yonudur.

## Profil Bazli Kabul Mantigi

### `dev`

Bu profil:

- hizli gelistirme dongusu icindir
- lokal tuning ve regresyon aramasi icin yeterlidir
- kesin urun seviyesi iddia icin yeterli degildir

`dev` sonucu ile sunulabilecek iddia:

- "degisiklik buyuk regresyon yaratmadi"
- "lokal baseline onceki kosuya yakin"

Sunulmamalidir:

- "lab-grade parity saglandi"
- "dedicated benchmark sonucu alindi"

### `ci_safe`

Bu profil:

- daha kontrollu ve tekrarli pipeline yorumlari icindir
- merge oncesi guven eşiği olusturur

`ci_safe` sonucu ile sunulabilecek iddia:

- "CI benchmark gate gecildi"
- "kontrollu ortamda kabul esigi saglandi"

### `dedicated_lab`

Bu profil:

- en ciddi performans ve parity iddialari icindir
- root/privileged ve deterministik backend bekler
- fallback ve mixed path toleransi dusuktur

Bu profil icin ek sert kural:

- `sender_fallback_reason == none`
- `sender_paths_used` tek aktif yol gostermeli

## Sender Path ve Fallback Yorumlama

Benchmark sonucu yorumlarken yalnizca throughput sayisina bakmak yanlistir.
Ilk soru "hangi yol calisti?" olmalidir.

Bakilacak alanlar:

- `sender_path`
- `sender_paths_used`
- `sender_fallback_reason`
- secilen `--sender-backend`

Yorum rehberi:

- Beklenen path ile gercek path ayni ise sonuc karsilastirilabilirlik kazanir
- Fallback varsa sonuc hala degerli olabilir, ama artik o hedef backend'in temiz sonucu degildir
- `MIXED` veya coklu path durumu benchmark yayininda risklidir; hangi path'in ne kadar katkida bulundugu bulaniklasir

Kisa kural:

- "TX_RING benchmark sonucu" diyorsaniz run gercekten TX_RING'de sabit kalmis olmali
- "AF_XDP sonucu" diyorsaniz XDP fallback'siz calismis olmali
- "GPU baseline" diyorsaniz GPU pipeline'in aktif oldugu telemetry ile desteklenmeli

### Fallback Gorüldüğünde Ne Yapilmali?

`sender_fallback_reason` goruldugunde ilk refleks throughput tuning yapmak
degil, once route kararliligini duzeltmek olmalidir.

Operasyon sirası:

1. `--sender-backend` explicit ver
2. benchmark kosusunda `--sender-fallback-policy fail` kullan
3. `sender_paths_used` tek aktif yol veriyor mu kontrol et
4. gerekiyorsa worker ve queue sayisini dusurup tekrar dene
5. backend temizlestikten sonra throughput tuning'e gec

Kisa kural:

- fallback varken "performans problemi" var demek erken olabilir
- once "route problemi" cozulmelidir

## Loss Sonucuna Gore Hangi Ayar Degiştirilir?

Loss sonucu yorumlarken iki sayiya birlikte bak:

- `wire_loss_est_pct`
- `rate_accuracy_pct`

Bu iki alan birlikte su resmi verir:

- loss yuksek + accuracy iyi ise sistem hedef hizda gitmeye calisiyor ama yol tasiyor
- loss yuksek + accuracy dusuk ise hem pacing hem transport baskida
- loss dusuk + accuracy dusuk ise daha cok pacing/topoloji sorunu vardir

### Senaryo 1: Loss yuksek, accuracy iyi

Tipik anlam:

- hedeflenen hiz korunuyor
- ama TX path veya queue duzeyi paketi tasiyamiyor

Oncelikli ayarlar:

- `--afpacket-ring-target-mb` artirilabilir
- `--afpacket-frames-per-block` kademeli artirilabilir
- `--dp-queues` NIC queue kapasitesine uygun sekilde artirilabilir
- `--workers` fazla ise azaltilabilir

Ilk kapatilacak/geri cekilecekler:

- gereksiz `--gpu-full-variation`
- topolojiye gore fazla agresif worker sayisi

### Senaryo 2: Loss yuksek, accuracy de dusuk

Tipik anlam:

- sistem hem hedef ritmi tutturamiyor
- hem de tasima zinciri baski altinda

Oncelikli ayarlar:

- `--workers` azalt
- `--rps` veya toplam yuk seviyesini gecici olarak dusur
- `--gpu-batch-size` buyukse azalt
- `--dp-queue-strategy rr` kullaniyorsan `map` veya `pin` dene

Ek not:

- Bu senaryoda ayni anda hem queue hem pacing sorunu olabilir
- buyuk batch ve fazla worker birlikte kullaniliyorsa once bu ikisini sadeleştir

### Senaryo 3: Loss dusuk, accuracy dusuk

Tipik anlam:

- sistem paket kaybetmiyor olabilir
- ama pacing hedefi tutmuyor, yani benchmark kalitesi yine zayif

Oncelikli ayarlar:

- `--afpacket-spin-limit` kademeli artirilabilir
- `--afpacket-poll-timeout-ms` workload'a gore tekrar ayarlanabilir
- `--workers` ve `--dp-queues` daha dengeli eslestirilebilir
- `--pin-cpu` ile pacing thread'i daha kararlı bir core'a alinabilir

Kisa kural:

- loss dusuk diye run iyi kabul edilmez
- accuracy dusukse parity kalitesi yine bozulur

### Senaryo 4: TX_RING drop ve flush baskisi goruluyor

Ozellikle su alanlara bak:

- `txring_tp_drops`
- `txring_flush_error_count`
- `txring_flush_eagain_count`
- `txring_hold_block_pressure_pct`

Tuning yonu:

- `--afpacket-ring-target-mb` arttir
- `--afpacket-frames-per-block` arttir
- `--afpacket-spin-limit` orta seviyede dene
- `--afpacket-busy-poll-us` sadece kontrollu deneylerde ac

Dikkat:

- bu ayarlari ayni anda buyuk adimlarla degistirme
- ring buyudukce her zaman daha iyi sonuc gelmez; latency ve wait de artabilir

## GPU Sonuclarini Okuma

GPU path yorumunda yalnizca daha yuksek throughput beklemek dogru degildir.
Asagidaki sorular birlikte sorulmalidir:

- GPU readiness dry-run temiz mi?
- smoke run stabil mi?
- throughput artisina karsilik error/fallback artisi var mi?
- pipeline depth, streams, batch gibi tuning alanlari raporlanmis mi?
- CPU vs GPU karsilastirmasi ayni senaryo sinirlarinda mi yapildi?

GPU sonucunu zayiflatan sinyaller:

- readiness gecerken live run'da beklenmeyen fallback
- fault-injection altinda hizli kalite dususu
- artis gorunse bile `run_quality` veya KPI gate tarafinda bozulma

GPU sonucunu guclendiren sinyaller:

- smoke -> baseline -> tuned benchmark zinciri tutarliysa
- soak sonunda drift sinirliysa
- artifact seti karsilastirma icin eksiksizse

### GPU Tuning Yonu

#### Belirti: `gpu_ring_depth_peak` ve `gpu_ring_block_wait_ns` yuksek

Tipik anlam:

- producer, consumer'dan hizli
- host/NIC tarafi GPU tarafini yetistiremiyor

Denenecek ayarlar:

- `--gpu-batch-size` azalt
- `--gpu-stream-count` kademeli artir
- `--gpu-pipeline-depth` 2 -> 3 gibi kademeli artir

Geri cekilebilecek ayar:

- `--gpu-full-variation`

#### Belirti: GPU acik ama throughput artmiyor

Tipik anlam:

- darboğaz GPU degil, sender/backend olabilir

Denenecekler:

- `sender_path` ve fallback durumunu kontrol et
- `--sender-backend` explicit sabitle
- `--dp-queues` ve worker dagilimini yeniden dene

Kisa kural:

- GPU tuning'den once backend darboğazini ele

#### Belirti: GPU ile throughput artsa da accuracy bozuluyor

Tipik anlam:

- batch buyuklugu veya pipeline baskisi pacing kalitesini bozuyor

Denenecek ayarlar:

- `--gpu-batch-size` azalt
- `--workers` sayisini kontrollu azalt
- `--gpu-stream-count` orta seviyede sabitle

## NUMA ve Queue Yerlesimi Rehberi

NUMA tuning'in amaci sudur:

- worker CPU
- queue
- NIC TX queue
- memory yerlesimi

mümkün oldugunca ayni NUMA node uzerinde tutulsun.

### Neden Onemli?

Worker bir NUMA node'da, NIC diger NUMA node'da ise tipik etkiler:

- daha yuksek jitter
- daha dusuk `rate_accuracy_pct`
- artan queue baskisi
- ayni teorik count ile daha dusuk efektif throughput

### Topoloji Okuma

Lab host'ta ilk bakilacak komutlar:

```bash
lscpu
numactl --hardware
ethtool -l <iface>
cat /sys/class/net/<iface>/device/numa_node
```

Amac:

- kac NUMA node var
- NIC hangi NUMA node'a bagli
- NIC kac TX queue destekliyor
- worker/core dagitimi buna nasil oturacak

### Operasyonel Kurallar

1. `--workers` sayisini fiziksel topolojiye gore sec
2. `--dp-queues` NIC TX queue sayisini asmamali
3. benchmark icin `--dp-queue-strategy map` veya `pin` tercih et
4. `--dp-queue-map` ile worker -> queue eslesmesini sabitle
5. gerekiyorsa `--pin-cpu` ile pacing thread'ini kararlı bir CPU'ya al

### Hangi Strateji Ne Zaman?

| Strateji | Ne zaman | Not |
|---|---|---|
| `rr` | hizli baseline, ilk deneme | deterministiklik zayif olabilir |
| `pin` | sabit topoloji, orta seviye lab | daha stabil queue/core baglantisi |
| `map` | en ciddi benchmark | worker -> queue iliskisini acik sabitler |

### NUMA Tuning Akisi

#### Asama 1: Basit ve temiz baslangic

- `--workers` sayisini NIC queue sayisini asmadan sec
- `--dp-queue-strategy rr`
- kisa baseline al

#### Asama 2: Deterministik yerlesime gec

- `--dp-queue-strategy map`
- `--dp-queues` ile queue sayisini netlestir
- `--dp-queue-map` ile her worker'i tek queue'ya bagla

#### Asama 3: CPU affinity sabitle

- `dp_affinity_cpu` alanlarini run report'ta kontrol et
- eger ayni worker farkli kosularda farkli CPU davranisi sergiliyorsa `--pin-cpu` kullan

### NUMA Sorunu Oldugunu Dusunduren Isaretler

- ayni count/rps ile run-to-run oynaklik fazla
- `rate_accuracy_pct` beklenmedik dusuk
- throughput bazen iyi bazen kotu
- mixed path veya fallback yok ama yine de jitter yuksek
- `dp_queue_strategy=rr` ile dagilim kararsiz, `map` ile belirgin iyilesme geliyor

### NUMA Sorununda Ne Artirilir, Ne Azaltilir?

Artirilabilecekler:

- `--dp-queues` (NIC queue kapasitesi dahilinde)
- deterministik `map` kullanimi

Azaltilabilecekler:

- `--workers` sayisi
- ayni queue uzerine binen worker yogunlugu

Kapatilabilecekler:

- benchmark kosusunda belirsizlik ureten `rr` dagitimi

Kisa kural:

- NUMA/topoloji problemi varken buyuk ring veya buyuk batch tek basina cozum olmaz
- once yerlesim, sonra throughput tuning

## CPU vs GPU A/B Karsilastirma Kurallari

CPU ve GPU sonucu ayni tabloda gostermek istiyorsaniz en az su sabitler korunmalidir:

- ayni hedef/senaryo
- ayni run tipi
- ayni kabul profili
- benzer sure veya count zemini
- ayni rapor/telemetry standardi

Asagidaki durumlarda A/B sonucu zayif kabul edilir:

- biri baseline, digeri soak ise
- biri `dev`, digeri `dedicated_lab` ise
- biri fallback'li, digeri fallback'siz ise
- biri mixed path, digeri tek path ise

## Artifact Inceleme Checklist'i

Her ciddi benchmark sonrasi su kontrol listesi uygulanmalidir:

1. `run_report` mevcut mu?
2. JSON ve gerekiyorsa Markdown ozeti uretilmis mi?
3. Profil/metadata artifact'e yazilmis mi?
4. `sender_path`, fallback ve KPI alanlari gorunuyor mu?
5. Log dosyasi saklanmis mi?
6. Gerekli ise loss telemetry veya realism report mevcut mu?
7. Dosya isimleri tekrar bulunabilir ve tarihsel arsive uygun mu?

Artifact eksikse:

- sonucu "kalici benchmark kaydi" olarak kabul etme
- gerekirse ayni kosuyu artifact zorunlulugu ile tekrar al

## Sonuc Yayinlama Standardi

Bir benchmark sonucunu ekip icinde veya dokumanda yayinlamadan once su format
kullanilmalidir:

- run tipi
- profil
- hedef backend/path
- KPI gate sonucu
- run_quality
- fallback durumu
- ana throughput/loss/rate_accuracy ozeti
- artifact konumu

Ornek ozet kalibi:

```text
Run tipi: dedicated benchmark
Profil: dedicated_lab
Sender path: txring
Run quality: valid
KPI gate: pass
Fallback: none
Not: score_eligible=1, artifact seti tam
```

## Sonraki Adimi Secme Rehberi

### Durum 1: Run calisti ama KPI gate fail

Sonraki adim:

- once debug degil, fark analizi yap
- hedef profil esiklerinin hangisinin patladigini cikar
- gerekirse `dev` baseline ile karsilastir
- tuning veya backend sabitleme yap

### Durum 2: Run valid degil

Sonraki adim:

- benchmark yorumunu durdur
- troubleshooting moduna gec
- metric zemini, worker sayisi, interrupt ve fallback nedenlerini incele

### Durum 3: Run valid ve gate pass ama fallback var

Sonraki adim:

- sonucu "calisan run" olarak kaydet
- ama deterministik backend benchmark'i diye yayinlama
- backend sabitleyip run'i tekrar et

### Durum 4: Run valid, gate pass, fallback yok

Sonraki adim:

- artifact setini kilitle
- gerekiyorsa tekrar kosu ile tekrarlanabilirlik kontrolu yap
- benchmark ozeti veya parity raporu yayinla

## Sik Yapilan Yanlis Yorumlar

### Throughput yuksekse run iyidir

Yanlis. Yuksek throughput, fallback veya metric bozulmasi ile birlikte geliyorsa
benchmark kalitesi dusmus olabilir.

### `valid` olmak benchmark icin yeterlidir

Yanlis. `valid`, sadece teknik olarak metrik zemininin olustugunu gosterir.
Acceptance icin KPI gate ve profil uyumu da gerekir.

### `dev` sonucu dedicated lab yerine gecer

Yanlis. `dev`, regresyon ve gelistirme hizini destekler; lab-grade parity iddiasi
icin yeterli degildir.

### Mixed sender path yine de temiz benchmark sayilir

Genellikle yanlis. Mixed path sonucu gozlemsel olabilir ama deterministik backend
iddiasi zayiflar.

## Profesyonel Calisma Kaliplari

### Kalip 1: Yeni tuning sonrasi

1. Dry-run
2. Smoke run
3. Baseline
4. Benchmark
5. Gerekirse soak

Bu zincirden dogrudan benchmark'a sicrama yapma.

### Kalip 2: Benchmark sonucu yayinlamadan once

1. `run_quality` kontrol et
2. KPI gate kontrol et
3. fallback/path kontrol et
4. artifact tamligini kontrol et
5. profil iddiasini sonuc ile eslestir

### Kalip 3: Regresyon raporu hazirlarken

Her iki tarafta da sunlari esitle:

- profil
- backend
- run tipi
- artifact standardi

## Sonuc

Iyi benchmark kulturu, sadece komut calistirmakla kurulmaz. Asil farki yaratan
sey, her kosuyu dogru siniflamak, gecersiz sonuclari benchmark gibi sunmamak ve
yayinlanan her sonucun tekrar uretilebilir oldugunu gostermektir.

Bu dokumanin ana ilkesi sudur:

- once gecerlilik
- sonra kabul
- en son performans iddiasi
