# 24 - Kurumsal Test Senaryolari El Kitabi

## Amac

Bu dokuman, gercek is ortamlarinda kullanilan kurumsal seviye performans,
dayaniklilik ve savunma-dogrulama testlerinin nasil planlanacagini anlatir.

Hedef:

- "test calistirmak" ile "kurumsal test programi yürütmek" arasindaki farki netlestirmek
- testin teknik kismini is riski, onay, rollback ve raporlama ile birlikte ele almak
- gercek hayata yakin ama etik ve yetkili kullanim sinirlari icinde kalan ornek senaryolar sunmak
- operator, teknik lider ve platform ekibine ortak bir dil vermek

Bu belge yalnizca yetkili, yazili onayli ve izole test/staging/lab ortamlari
icin yazilmistir.

## Kimler Icin

- performans muhendisleri
- platform ve SRE ekipleri
- mavi takim / savunma odakli guvenlik ekipleri
- on-prem veya cloud ag topolojisi yoneten teknik liderler
- musteri ortami icin kontrollu dayanıklılık testi tasarlayan profesyonel hizmet ekipleri

## Bu Belge Ne Degildir

Bu belge:

- yetkisiz hedeflere karsi test rehberi degildir
- public internet uzerinde rastgele yuk uretme kilavuzu degildir
- "daha sert trafik nasil gonderilir" odakli saldiri tarifnamesi degildir

Bu nedenle tum ornekler:

- private IP / staging / lab mantigi ile verilir
- savunma, kapasite ve dayaniklilik dogrulama amaci tasir
- yazili kapsam ve geri alma plani varsayar

## Kurumsal Testin Temel Ilkeleri

Kurumsal testte teknik basari tek basina yeterli degildir. Test ancak su
kosullar birlikte saglanirsa "profesyonel" sayilir:

1. Kapsam yazili ve onaylidir
2. Hedefler ve zaman penceresi nettir
3. Basari ve durdurma kriterleri once belirlenmistir
4. Geri alma (rollback) ve acil durdurma sorumlulari bellidir
5. Test artefact'lari kalici sekilde toplanir
6. Sonuc teknik ve is etkisi diliyle birlikte raporlanir

Kisa kural:

- yetki belgesi yoksa test yok
- rollback yoksa canliya cikis yok
- baseline yoksa benchmark anlamsiz
- kabul kriteri yoksa test "gozlem" olarak kalir

## Kurumsal Test Turleri

| Test tipi | Amac | Tipik ciktisi |
|---|---|---|
| Smoke / readiness | Ortam hazir mi? | preflight onayi |
| Baseline | Normal davranis nedir? | referans throughput / latency |
| Kapasite testi | Nerede darbogaz basliyor? | esik ve doygunluk noktasi |
| Dayaniklilik testi | Sistem bozulmadan ne kadar sure surdurur? | soak ve drift raporu |
| Savunma dogrulama testi | WAF/CDN/rate limit/capability bekleneni yapiyor mu? | policy etkinlik raporu |
| Degisiklik sonrasi regresyon testi | Yeni release zarar verdi mi? | once/sonra karsilastirma |
| Olay provasi | Gercek incident'e hazir miyiz? | runbook ve ekip koordinasyon raporu |

## Kurallar Altinda Test Nasil Yurutulur?

Kurumsal bir test su sira ile yürütülmelidir:

1. Is hedefi tanimlanir
2. Teknik kapsam ve sinirlar yazilir
3. Yetki/onay kaydi alinır
4. Ortam siniflandirilir: lab, staging, pre-prod, dedicated prod window
5. Baseline alinir
6. Test dozu kademeli artirilir
7. Guardrail metrikleri canli izlenir
8. Gerekirse test durdurulur ve rollback uygulanir
9. Sonuc, teknik + is etkisi birlikte raporlanir

## Testten Once Sorulmasi Gereken Sorular

### Is Tarafi

- Hangi hizmet dogrulaniyor?
- Basarisiz olursa is etkisi ne?
- Test penceresi hangi saatlerde guvenli?
- Kim "durdur" deme yetkisine sahip?

### Teknik Taraf

- Hedef ortam staging mi, canliya yakin pre-prod mu?
- WAF/CDN/LB/ingress zinciri net mi?
- Baseline metrikler mevcut mu?
- Hangi backend/path testte bekleniyor?
- Hangi alarm esikleri test boyunca takip edilecek?

### Operasyon Tarafi

- Iletisim kanali ne? (`Slack/Teams/telefon bridge`)
- Incident commander kim?
- Rollback sahibi kim?
- Log, report, pcap, dashboard snapshot nerede tutulacak?

## Kurumsal Guardrail'ler

Kurumsal testte yalnizca "maksimum throughput" izlenmez. Asagidaki alanlar
guardrail olarak onceden ilan edilmelidir:

- hata orani
- timeout orani
- `5xx` oranı
- WAF / rate-limit kararları
- LB health check bozulmasi
- DB queue backlog
- worker restart sayisi
- CPU, memory, NIC queue ve packet drop sinyalleri

Kisa kural:

- throughput artisiyla birlikte servis kalitesi bozuluyorsa test "basarili" sayilmaz

## Kurumsal Kabul Kriterleri

Testten once su ifade net olmalidir:

- hangi seviyeye kadar sistem "kabul edilebilir"
- hangi noktada "degrade ama kabul"
- hangi noktada "testi durdur"

Ornek kabul siniflari:

- `pass`: hizmet hedeflenen yukte kararlı
- `pass_with_constraints`: hizmet calisiyor ama tuning veya kapasite siniri var
- `fail`: savunma/pacing/kapasite hedefi saglanmadi
- `abort`: test guardrail ihlali nedeniyle bilincli durduruldu

## Senaryo Tasarlama Formulu

Her kurumsal test senaryosu asagidaki 7 alanla tanimlanabilir:

1. Is amaci
2. Teknik hedef
3. Trafik modeli
4. Basari kriteri
5. Stop kriteri
6. Artefact listesi
7. Sonraki aksiyon

Bu format kullanildiginda farkli ekipler ayni testten ayni seyi anlar.

## Ornek 1 - E-Ticaret Sitesi Altyapi Testi

### Is Baglami

Bir e-ticaret sirketi, indirim gunu veya kampanya penceresi oncesinde:

- ana sayfa
- urun listeleme
- urun detay
- sepet
- login
- odeme oncesi checkout API

akisini bozmadan tasiyabildigini dogrulamak ister.

Buradaki amac "siteyi zorla bozmak" degil, su sorulara cevap bulmaktir:

- altyapi hangi noktaya kadar kontrollu sekilde buyuyebiliyor?
- WAF/CDN/load balancer beklenen davranisi gosteriyor mu?
- checkout'a giden kritik yol, browse trafiğinden ayrisilabiliyor mu?
- kampanya gununde ilk kirilan katman hangisi olur?

### Kapsam

- staging veya pre-prod ortami
- private target listesi
- gercek musteri verisi icermeyen sentetik trafik
- odeme entegrasyonunda sandbox / mock provider

### Trafik Siniflari

Kurumsal e-ticaret testinde trafik tek tip olmamalidir. Ornek dagilim:

- `%50` browse: ana sayfa + kategori + urun detay
- `%20` arama
- `%15` login / session yenileme
- `%10` sepet
- `%5` checkout API (sandbox)

### Teknik Dogrulama Hedefleri

- ingress/LB altinda queue birikimi var mi?
- cache hit/miss degisimi ne?
- API gateway rate limit davranisi stabil mi?
- checkout yolunda ayrica timeout artisi oluyor mu?
- WAF yanlis pozitif uretmeden korunma sagliyor mu?

### Stop Kriterleri

Asagidakilerden biri olursa test durdurulur:

- checkout sandbox akisi kabul edilen timeout esigini asarsa
- `5xx` oranı onceden belirlenen guardrail'i gecerse
- health check basarisizligi nedeniyle node drain baslarsa
- DB veya queue backlog tehlikeli seviyeye cikarsa

### Beklenen Artefact'lar

- run report
- upstream / ingress dashboard snapshot
- `5xx`, latency ve saturation grafigi
- WAF / rate limit kararlari
- artifact dizini icinde log + config snapshot

### Olası Sonuc Siniflari

- browse tasiyor ama checkout bozuluyor
  Sonuc: kritik yol ayrimi yetersiz
- WAF koruyor ama login'de yanlis pozitif var
  Sonuc: savunma kurali ince tuning ister
- LB / ingress stabil ama app worker saturasyonunda gecikme buyuyor
  Sonuc: uygulama katmani bottleneck

### Profesyonel Kullanim Ornegi - E-Ticaret Pre-Prod Penceresi

Asagidaki ornek, kampanya oncesi pre-prod ortaminda "browse + login + checkout"
karisimini kontrollu sekilde dogrulamak icin kullanilabilir.

Ortam varsayimi:

- pre-prod VIP: `10.20.30.40`
- ingress TLS sonlandirma aktif
- checkout sandbox upstream'i ayri
- test penceresi: 22:00 - 23:00

#### Ornek Config

`artifacts/configs/ecommerce_preprod_baseline.yaml`

```yaml
target: 10.20.30.40
port: 443
attack_vector: http
http_scheme: https
http_method: GET
http_path:
  - /
  - /category/kampanya
  - /product/sku-1001
  - /login
  - /cart
  - /api/checkout/health
http_concurrency: 120
http_timeout: 3.0
workers: 8
count: 80000
rps: 2000
profile: web-stress
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/ecommerce_preprod
log: artifacts/logs/ecommerce_preprod_baseline.log
```

#### Adim 1 - Dry-Run

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/ecommerce_preprod_baseline.yaml \
  --dry-run \
  --confirm
```

Beklenen:

- config parse temiz
- hedef, protokol ve path seti kabul edilir
- operasyona girmeden once teknik zemin dogrulanir

#### Adim 2 - Baseline Kosusu

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/ecommerce_preprod_baseline.yaml \
  --confirm
```

Bu kosudan sonra kaydedilecekler:

- `run_report.json`
- `run_report.md`
- ingress dashboard screenshot
- app `5xx` ve latency grafikleri
- WAF/rate-limit karar ozetleri

#### Adim 3 - Kontrollu Artis

Ayni config uzerinden yalnizca doz artisina gidilir:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/ecommerce_preprod_baseline.yaml \
  --rps 2600 \
  --count 120000 \
  --run-report-dir artifacts/reports/ecommerce_preprod_step2 \
  --log artifacts/logs/ecommerce_preprod_step2.log \
  --confirm
```

#### Profesyonel Yorumlama

Asagidaki tablo, bu is orneginde nasil karar verilecegini gosterir:

| Gozlem | Teknik yorum | Is yorumu | Aksiyon |
|---|---|---|---|
| browse stabil, checkout timeout artiyor | kritik yol ayrimi zayif | kampanya gunu odeme once etkilenir | checkout upstream ayristir |
| WAF login path'te fazla challenge atiyor | yanlis pozitif | gercek kullanici giris akisi etkilenebilir | login kurali tuning |
| `5xx` yok ama latency sert artis var | kapasite sinirina yaklasiliyor | musteri deneyimi bozulabilir | autoscaling / queue tuning |

#### Bu Ornekten Cikan Kurumsal Sonuc Cumlesi

"Pre-prod kampanya testinde browse akisları hedef hacimde kararlı kaldi; ancak
checkout health yolunda timeout trendi erken basladi. Sonuc olarak kampanya
oncesi checkout upstream ayrimi ve ingress-level kritik yol korumasi önerildi."

### GPU Tabanli E-Ticaret Senaryolari

GPU burada "tam L7 network stack" degil, uretim/planning hizlandiricisi olarak
dusunulmelidir. Bu nedenle GPU tabanli senaryolar en cok su amaclarla deger
uretir:

- buyuk hacimli browse/payload varyasyonu uretmek
- edge/cache/LB katmanlarini kontrollu sekilde beslemek
- CPU vs GPU uretim zincirini karsilastirmak
- staged `GPU -> host pinned RAM -> NIC` yolunda darbogazi bulmak

Kisa kural:

- checkout gibi kritik stateful is yollarinda GPU'yu "yardimci producer" olarak dusun
- asil karar noktasi yine ag yolu, queue yapisi ve servis davranisidir

#### GPU Senaryo 1 - Kampanya Browse Katmani Baseline

Bu senaryo, ana sayfa + kategori + urun detay agirlikli browse akisini GPU
uretim zinciri ile besleyip edge/cache/ingress davranisini gozlemlemek icindir.

`artifacts/configs/ecommerce_gpu_browse_baseline.yaml`

```yaml
target: 10.20.30.40
port: 443
protocol: tcp
attack_vector: basic
compute_backend: cuda
workers: 6
count: 1200000
rps: 2500
gpu_template_pool_size_l4: 24
gpu_ring_capacity: 4
gpu_batch_size: 100000
gpu_stream_count: 3
gpu_pipeline_depth: 2
gpu_pinned_max_mb: 512
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/ecommerce_gpu_browse
log: artifacts/logs/ecommerce_gpu_browse.log
```

Dry-run:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/ecommerce_gpu_browse_baseline.yaml \
  --dry-run \
  --confirm
```

Baseline:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/ecommerce_gpu_browse_baseline.yaml \
  --confirm
```

Bu kosuda özellikle bakilacaklar:

- `gpu_ring_depth_peak`
- `gpu_ring_block_wait_ns`
- ingress saturation sinyalleri
- cache hit/miss degisimi
- `rate_accuracy_pct`

Profesyonel yorum:

- GPU acik ama throughput artmiyorsa once sender/backend tarafina bak
- cache katmani stabil ama app latency artiyorsa edge degil uygulama darboğazi vardir
- `gpu_ring_block_wait_ns` yuksekse GPU producer host/NIC tarafini bekliyor olabilir

#### GPU Senaryo 2 - Statik Icerik / Edge Katmani Isitma ve Karsilastirma

Bu senaryo, kampanya oncesi statik varliklarin veya CDN/edge tarafinin
hazirlik seviyesini olcmek icin kullanilir. Amaç checkout degil, browse ve
asset dagitim zinciridir.

Ornek kosu:

```bash
python -m ddos_samurai.cli \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 4 \
  --count 800000 \
  --gpu-template-pool-size-l4 16 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 65536 \
  --gpu-stream-count 2 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 256 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_edge_warmup \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_edge_warmup.log
```

Bu örnekte aranacak cevaplar:

- edge/LB katmani hizli doyuyor mu?
- GPU uretimi ile besleme artinca ilk kirilan katman ingress mi?
- queue/pinning ayarlari degisince edge throughput fark ediyor mu?

Karar rehberi:

| Gozlem | Teknik yorum | Is yorumu | Aksiyon |
|---|---|---|---|
| edge stabil, origin bozuluyor | sorun cache arkasinda | kampanya gunu origin riskli | origin autoscaling/tuning |
| edge de erken saturation var | LB/CDN/ingress sınıri | kampanya başında ilk kirilim burada olabilir | edge kapasite gözden geçir |
| GPU degisince fark az | uretim degil ağ yolu darboğaz | GPU optimizasyonu erken olabilir | once TX/queue/NUMA |

#### GPU Senaryo 3 - Kampanya Oncesi GPU Soak

Bu senaryo, uzun sureli browse agirlikli yukte GPU producer + host pinned pool
+ sender zincirinin drift uretip uretmedigini gormek icindir.

Ornek kosu:

```bash
python -m ddos_samurai.cli \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 6 \
  --count 50000000 \
  --rps 3000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 5 \
  --gpu-batch-size 120000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 768 \
  --soak-profile 1h \
  --soak-warmup-s 180 \
  --soak-snapshot-interval 15 \
  --soak-max-error-rate-pct 0.5 \
  --soak-max-pps-drop-pct 10 \
  --soak-max-pinned-growth-mb 256 \
  --soak-max-backlog 12000 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_soak \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_soak.log
```

Bu senaryoda guardrail'ler:

- pinned memory growth
- backlog birikimi
- uzun kosuda `rate_accuracy_pct` drift'i
- ingress/app timeout trendi

Kurumsal yorum:

- kisa benchmark iyi olsa da soak'ta drift varsa kampanya gunu riski devam eder
- GPU producer kararlı ama app timeout artiyorsa sorun yine servis katmanindadir
- soak boyunca `gpu_ring_depth_peak` ve backlog buyuyorsa producer-consumer dengesi yeniden ayarlanmalidir

#### GPU Senaryo 4 - CPU vs GPU A/B E-Ticaret Browse Karsilastirmasi

Bu senaryo, "GPU eklemek gercekten is degeri uretmis mi?" sorusunu cevaplamak
icin kullanilir. Iki kosuda da ayni hedef, ayni worker sayisi ve ayni run
report standardi korunur.

CPU kosusu:

```bash
python -m ddos_samurai.cli \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --workers 6 \
  --count 1200000 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_cpu_ab \
  --confirm \
  --log artifacts/logs/ecommerce_cpu_ab.log
```

GPU kosusu:

```bash
python -m ddos_samurai.cli \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 6 \
  --count 1200000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 100000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 512 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_ab \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_ab.log
```

Beklenen profesyonel soru:

- GPU eklenince gercek kazanc throughput'ta mi, CPU bosalmasinda mi, yoksa hicbirinde mi?

Bu A/B karsilastirma ile su ayrim yapilir:

- GPU fayda sagliyor ama edge/LB yine ayni yerde tikanıyor
- GPU fayda saglamiyor, darboğaz TX path / NUMA / queue tarafinda
- GPU fayda sagliyor ama soak kararliligi düşüyor

## Ornek 2 - Savunma Odakli Guvenlik Sirketi Icin Is Senaryosu

### Is Baglami

Bir savunma odakli guvenlik sirketi veya SOC/MDR hizmeti veren kurum, kendi
platformu ya da musteri icin su sorulari cevaplamak isteyebilir:

- koruma katmani dogru tetikleniyor mu?
- telemetry pipeline yuk altinda kayip veriyor mu?
- alarm ve escalation zinciri test sirasinda gecikiyor mu?
- "servis devam ederken savunma" ilkesi gercekten calisiyor mu?

Bu senaryoda odak:

- mavi takim operasyonu
- koruma kurali dogrulama
- log/telemetry devamlıligi
- incident response koordinasyonu

### Kapsam

- izole musteri lab'i veya sozlesmeli test ortami
- onayli IP/CIDR allowlist
- zaman penceresi ve acil durdurma kisileri yazili
- testte kullanilan tum pattern'ler onceden kabul edilmis

### Teknik Hedefler

- WAF / anti-DDoS politika zinciri dogru devreye giriyor mu?
- yanlis pozitif olmadan koruma aktivasyonu oluyor mu?
- telemetry pipeline'da event drop var mi?
- rate limit / challenge / block politikasi kontrollu sekilde isliyor mu?
- SOC ekranlarina dusen alarm ile sahadaki olay arasinda gecikme ne kadar?

### Kurumsal Dogrulama Noktalari

- Koruma acildi ama servis ayakta kaldi mi?
- Savunma acildi ama kritik API'ler de etkilenip kapanmadi mi?
- Runbook'taki kisiler dogru sirada devreye girdi mi?
- Metrik ve log'lar olay sonrasinda forensik icin yeterli mi?

### Stop Kriterleri

- telemetri kaybi kabul edilemez seviyeye cikarsa
- koruma politikasi kritik servisleri bloke ederse
- alarm yorgunlugu yaratacak kadar noise olusursa
- musteri SLA guardrail'i ihlal edilirse

### Beklenen Artefact'lar

- run report
- WAF/policy event kayitlari
- SIEM / telemetry pipeline ozetleri
- escalation timeline
- "ne oldu / ne dogru calisti / ne bozuldu" ozet notu

### Olası Sonuc Siniflari

- koruma var ama telemetry gec geliyor
  Sonuc: savunma gorunurlugu eksik
- telemetry saglam ama policy gec devreye giriyor
  Sonuc: detect var, react gec
- policy hizli ama yanlis pozitif yuksek
  Sonuc: operasyonel tuning gerekir

### Profesyonel Kullanim Ornegi - Savunma Dogrulama Penceresi

Asagidaki ornek, bir guvenlik/savunma sirketinin musteri lab ortaminda koruma
politikasini ve telemetry akislarini birlikte dogrulamak icin kullanilabilir.

Ortam varsayimi:

- test VIP: `10.50.60.70`
- onunde WAF/CDN/policy zinciri var
- musteri lab'i private agda
- escalation kanali aktif

#### Ornek Config

`artifacts/configs/defense_validation_http2.yaml`

```yaml
target: 10.50.60.70
port: 443
attack_vector: http2
http_scheme: https
http_path:
  - /
  - /status
  - /api/v1/events
profile: web-bypass
tls_profile: chrome_120
h2_profile: chrome_120
h2_transport: hyper-h2
http2_concurrency: 240
http2_connections: 6
http2_streams_per_conn: 40
workers: 6
count: 60000
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/defense_validation
log: artifacts/logs/defense_validation_http2.log
```

#### Adim 1 - Dry-Run ve Scope Dogrulama

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/defense_validation_http2.yaml \
  --dry-run \
  --confirm
```

Beklenen:

- transport secimi dogrulansin
- path seti, concurrency ve worker dagilimi parse edilsin
- test penceresi oncesi teknik hata kalmasin

#### Adim 2 - Savunma Dogrulama Kosusu

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/defense_validation_http2.yaml \
  --confirm
```

Bu kosuda teknik ekip yalnizca run report bakmaz. Eszamanli izlenecekler:

- WAF / challenge / block event'leri
- SIEM ingestion gecikmesi
- telemetry pipeline queue/backlog durumu
- escalation kanalinda alarm dusme zamani

#### Adim 3 - Policy Reaksiyonunu Karsilastirmali Gozlem

Ayni test, daha dusuk concurrency ile tekrar edilip "erken policy tetigi mi,
yoksa hacimle gelen reaksiyon mu" ayrilir:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/defense_validation_http2.yaml \
  --http2_concurrency 120 \
  --count 30000 \
  --run-report-dir artifacts/reports/defense_validation_step2 \
  --log artifacts/logs/defense_validation_step2.log \
  --confirm
```

#### Profesyonel Yorumlama

| Gozlem | Teknik yorum | Is yorumu | Aksiyon |
|---|---|---|---|
| policy aciliyor ama telemetry gec geliyor | koruma var, gorunurluk zayif | olay sonrasi analiz riskli | telemetry pipeline boyutlandir |
| challenge hizli ama kritik API de etkileniyor | false positive | musteri servisi etkilenebilir | policy ayrimi yap |
| alarm gec dusuyor | detect/react zinciri yavas | SOC operasyon gec kalabilir | escalation ve SIEM tuning |

#### Bu Ornekten Cikan Kurumsal Sonuc Cumlesi

"Koruma katmani test penceresinde beklendigi gibi devreye girdi; ancak telemetry
ingestion gecikmesi nedeniyle SOC ekranina yansiyan olay ile sahadaki karar
arasinda fark olustu. Sonuc olarak policy tarafi kabul edildi, telemetry hattı
icin ek kapasite ve alarm zinciri iyilestirmesi onerildi."

## Profesyonel Kullanimda Dosya ve Artefact Duzeni

Gercek ekipler testleri tek komutla degil, kalici artefact duzeni ile yürütür.
Tavsiye edilen dizin:

```text
artifacts/
├── configs/
├── reports/
│   ├── ecommerce_preprod/
│   └── defense_validation/
├── logs/
└── snapshots/
```

Kisa kural:

- her is senaryosunun config'i ayri dosyada olsun
- her step ayri report dizinine yazilsin
- log ve dashboard snapshot'lari ayni test id'si ile isimlendirilsin

## Test Dozunu Artirma Kurali

Kurumsal testlerde yuk aniden verilmez. Tipik artis modeli:

1. smoke
2. kisa baseline
3. kademeli artis
4. hedef seviye
5. gerekirse soak

Kisa kural:

- once davranis, sonra hacim
- once stabilite, sonra stres

## Teknik ve Is Dili Birlikte Raporlanmalidir

Kurumsal raporlar yalnizca teknik jargon icermemelidir. Her sonuc iki dilde
anlatilmalidir:

### Teknik Ozet

- hangi path / backend kullanildi
- hangi guardrail ihlal edildi
- hangi metrikler pass/fail oldu
- hangi bottleneck goruldu

### Is Ozet

- musteri etkisi olur muydu?
- hangi servisler riskli?
- kampanya / SLA / mavi takim operasyonu acisindan sonucu nedir?
- sonraki aksiyon ne?

## Ornek Sonuc Cumleleri

### E-Ticaret

"Browse trafiği hedef hacimde tasindi; ancak checkout API timeout oranı kabul
esigini astigi icin kritik yol ayrimi yetersiz bulundu. Sonraki adim,
checkout upstream'i icin ayrik queue ve rate guardrail calismasidir."

### Savunma Odakli Guvenlik Sirketi

"Koruma politikasi devreye girdi ve servis ayakta kaldi; ancak SIEM tarafinda
event gecikmesi kabul edilebilir seviyenin uzerine cikti. Sonraki adim,
telemetry ingestion hattinin yuk altinda yeniden boyutlandirilmasidir."

## Sık Yapilan Kurumsal Hatalar

### Hata 1: Yetki ile kapsamı karistirmak

"Test icin izin var" ifadesi tek basina yeterli degildir.
Hangi hedef, hangi saat, hangi hacim, hangi guardrail sorulari yazili olmali.

### Hata 2: Tek endpoint ile tum sistemi temsil ettigini sanmak

Gercek is akislari cok endpoint'li ve farkli oncelik katmanlarina sahiptir.
Tek endpoint testi kurumsal riskin tam resmini vermez.

### Hata 3: Stop kriterini test sirasinda uydurmak

Kurumsal testte "biraz daha bakalim" yaklasimi risklidir.
Stop kriteri testten once tanimli olmali.

### Hata 4: Sadece throughput'a bakmak

Kurumsal testte servis kalitesi, savunma davranisi ve gozlemlenebilirlik en az
throughput kadar onemlidir.

### Hata 5: Raporu yalnizca teknik ekibe yazmak

Kurumsal kararlar teknik + is dilinin birlikte kullanildigi raporlar uzerinden verilir.

## Profesyonel Senaryo Sabonu

Asagidaki sablon yeni testler icin tekrar kullanilabilir:

```text
Senaryo adi:
Is amaci:
Hedef ortam:
Yetki/kapsam referansi:
Teknik hedef:
Trafik siniflari:
Kabul kriteri:
Stop kriteri:
Rollback sahibi:
Artefact listesi:
Sonraki aksiyon:
```

## Bu Rehber Nasil Kullanilmali?

Bu belge en iyi su kombinasyonla kullanilir:

- testi neden yaptiginizi anlamak icin bu belge
- testi nasil kosturacaginizi belirlemek icin `docs/22-cli-operational-playbook.md`
- sonucu nasil yorumlayacaginizi belirlemek icin `docs/23-benchmark-acceptance-handbook.md`
- hedef ve etik sinirlari netlestirmek icin `docs/07-safety.md`

## Sonuc

Kurumsal seviye test, yalnizca teknik arac kullanimi degildir. Asil deger:

- dogru is sorusunu sormak
- test sinirlarini profesyonelce koymak
- dayaniklilik ve savunma davranisini birlikte dogrulamak
- sonucu karar verdiren bir rapora donusturmektir

Bu nedenle en iyi testler:

- net yetki ile baslar
- guardrail ile yürür
- rollback ile korunur
- is etkisi diliyle biter
