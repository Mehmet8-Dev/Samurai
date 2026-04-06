# 22 - CLI Operasyonel Playbook

## Amac

Bu dokuman, `ddos_samurai.cli` icin sadece bayrak referansi degil, gercek is akislarina uygun bir kullanim rehberi sunar.

Hedef:

- yeni bir operatoru hizli sekilde uretken hale getirmek
- dogru komutu secmeyi kolaylastirmak
- preflight, benchmark, soak, replay ve artifact uretimi gibi farkli operasyon tiplerini ayirmak
- kopyalanip uyarlanabilecek dolu komut ornekleri vermek

Bu belge yalnizca yetkili ve izole test/lab ortamlari icin yazilmistir.

## Kimler Icin

- performans muhendisleri
- platform/SRE ekipleri
- lab benchmark operatorleri
- L7 ve dataplane regresyon testi yapan gelistiriciler
- run-report ve artifact standardi olusturmak isteyen teknik liderler

## Operasyon Ilkeleri

Her ciddi calisma su sirayla ilerlemelidir:

1. Parametreleri dogrula
2. Hedefin izinli oldugunu dogrula
3. Dry-run ile parse/preflight gec
4. Kisa baseline kosusu al
5. Gerekirse benchmark veya soak kos
6. Rapor ve artifact topla
7. Sonucu tekrar uretilebilir hale getir

Kisa kural:

- `--dry-run` gecmeden live run baslatma
- root gerektiren yollari ancak lab host'ta calistir
- `--run-report` kullanmadan uzun kosulari kalici kabul etme
- dedicated benchmark icin `--lab-profile dedicated` + KPI gate kullan

## Ne Zaman Hangi Akis?

| Ihtiyac | Uygun Akis |
|---|---|
| Bayraklar dogru mu, config parse oluyor mu? | Dry-run |
| Kod/ortam saglikli mi? | Self-test |
| Uygulama seviyesinde HTTP/L7 davranisini hizli dogrulamak | L7 baseline |
| TX path veya sender fallback davranisini olcmek | Dataplane benchmark |
| Uzun sureli stabilite, memory growth ve PPS drift gormek | Soak |
| Gercek trafikten bagimsiz sentetik test verisi uretmek | GPU PCAP |
| Elinizdeki PCAP'i kontrollu sekilde tekrar oynatmak | PCAP replay |
| Planner/veri modeli entegrasyonunu trafiksiz dogrulamak | Traffic-model dry-validate |

## Ortam Hazirlik Kontrol Listesi

Asagidaki dizin yapisi tavsiye edilir:

```text
artifacts/
├── reports/
├── pcaps/
├── logs/
└── configs/
```

Ornek hazirlik:

```bash
mkdir -p artifacts/reports artifacts/pcaps artifacts/logs artifacts/configs
```

Temel kurulum dogrulamasi:

```bash
python -m ddos_samurai.cli --self-test
```

CLI yardim ve profil listesi:

```bash
python -m ddos_samurai.cli --help
python -m ddos_samurai.cli --list-profiles
```

## Katman 1: Parse ve Preflight Dogrulama

Bu asama trafik gondermez. Yeni config, yeni bayrak kombinasyonu veya CI validasyonu icin ilk kapidir.

### Ornek 1: Temel TCP dry-run

```bash
python -m ddos_samurai.cli \
  --target 10.10.20.15 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --count 5000 \
  --workers 8 \
  --dry-run \
  --confirm \
  --log artifacts/logs/basic_dry_run.log
```

Bu komutun amaci:

- parser + profile + validation zincirini gecmek
- worker dagitimini gormek
- hedef/port/protocol kombinasyonunun kabul edildigini dogrulamak

### Ornek 2: HTTP/2 preflight

```bash
python -m ddos_samurai.cli \
  --target 10.10.30.25 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --http-path /health /api/status \
  --http-method GET \
  --http2-concurrency 200 \
  --http2-connections 4 \
  --http2-streams-per-conn 50 \
  --tls-profile chrome_120 \
  --h2-profile chrome_120 \
  --h2-transport auto \
  --dry-run \
  --confirm \
  --log artifacts/logs/http2_dry_run.log
```

Ne zaman kullanilir:

- yeni bir L7 senaryosunu live kosudan once dogrulamak istediginizde
- HTTP/2 transport secimi ve TLS profil kombinasyonunu test ederken

## Katman 2: Config Dosyasi Ile Calisma

Tek seferlik komutlar yerine tekrar uretilebilir kosular icin config dosyasi tercih edilmelidir.

### Ornek Config

`artifacts/configs/web_stress_dev.yaml`

```yaml
target: 10.10.40.12
port: 443
attack_vector: http
http_scheme: https
http_method: GET
http_path:
  - /
  - /health
  - /ready
http_concurrency: 120
http_timeout: 5.0
workers: 8
count: 60000
rps: 2000
profile: web-stress
run_report: true
run_report_format: both
run_report_dir: artifacts/reports
log: artifacts/logs/web_stress_dev.log
```

Bu config ile dry-run:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/web_stress_dev.yaml \
  --dry-run \
  --confirm
```

Bu config ile live run:

```bash
python -m ddos_samurai.cli \
  --config artifacts/configs/web_stress_dev.yaml \
  --confirm
```

Pratik kural:

- kalici senaryolari `--config` ile sakla
- tek seferlik override'lari CLI'dan ver
- final karar mercisinin CLI oldugunu unutma

## Katman 3: Uygulama Seviyesi Baseline Kosulari

Bu katman, hedef sistemin L7 davranisini kisa ve kontrollu bir sekilde olcmek icindir.

### Akis A: HTTP servis baseline

```bash
python -m ddos_samurai.cli \
  --target 10.10.50.20 \
  --port 8443 \
  --attack-vector http \
  --http-scheme https \
  --http-method GET \
  --http-path / /login /api/health \
  --http-concurrency 80 \
  --http-timeout 3 \
  --workers 6 \
  --count 30000 \
  --rps 1500 \
  --profile web-stress \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/http_baseline.log
```

Bu komut neyi verir:

- uygulama seviyesi throughput ve timeout davranisi
- kisa sureli, raporlanabilir bir baseline
- sonraki benchmark veya soak kosulari icin referans

### Akis B: WAF/CDN etkisini gozlemleme

```bash
python -m ddos_samurai.cli \
  --target 10.10.50.30 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --http-path / /search /api/v1/items \
  --profile web-bypass \
  --tls-profile chrome_120 \
  --h2-profile chrome_120 \
  --h2-transport hyper-h2 \
  --ninja-mode \
  --http2-concurrency 300 \
  --http2-connections 6 \
  --http2-streams-per-conn 60 \
  --workers 8 \
  --count 50000 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/web_bypass_baseline.log
```

Bu senaryo ne zaman mantikli:

- reverse proxy, WAF veya CDN arkasindaki uygulamanin davranisini anlamak istediginizde
- browser-assisted davranis ile normal HTTP/2 davranisini ayirmak istediginizde

## Katman 4: Stateful ve Ozel L7 Senaryolari

### Akis A: WebSocket senaryo testi

```bash
python -m ddos_samurai.cli \
  --target 10.10.60.15 \
  --port 443 \
  --attack-vector websocket \
  --http-scheme https \
  --ws-path /ws/stream \
  --ws-scenario \
  --ws-auth-message '{"type":"auth","token":"lab-token-001"}' \
  --ws-subscribe-message '{"type":"subscribe","channel":"prices"}' \
  --ws-subscribe-message '{"type":"subscribe","channel":"orders"}' \
  --ws-ping-count 3 \
  --ws-await-response \
  --ws-concurrency 120 \
  --workers 6 \
  --count 15000 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/ws_scenario.log
```

### Akis B: QUIC native capability gate

```bash
python -m ddos_samurai.cli \
  --target 10.10.70.40 \
  --port 443 \
  --attack-vector quic \
  --http-scheme https \
  --quic-path /api/ping \
  --quic-method GET \
  --quic-concurrency 200 \
  --quic-conn-pool-size 4 \
  --l7-quic-engine c_state \
  --l7-quic-require-native \
  --l7-capability-strict \
  --quic-expect-status-min 200 \
  --quic-expect-status-max 299 \
  --quic-require-response-headers true \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/quic_native_strict.log
```

Bu senaryo neden profesyonelce faydali:

- py-bridge fallback istemediginizde fail-fast davranis saglar
- capability eksikligini benchmark ortasinda degil, baslangicta gorursunuz

## Katman 5: Dataplane ve Sender Benchmark Akislari

Bu kisim root/capability gerektirebilir. Lab host'ta kosulmalidir.

### Akis A: TX_RING kontrollu benchmark

```bash
sudo python -m ddos_samurai.cli \
  --target 10.20.10.50 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cpu \
  --sender-backend txring \
  --sender-fallback-policy fail \
  --dataplane-core-mode required \
  --afpacket-hugepage-mode required \
  --afpacket-ring-target-mb 256 \
  --afpacket-frames-per-block 128 \
  --afpacket-poll-timeout-ms 1 \
  --lab-profile dedicated \
  --dp-queue-strategy pin \
  --dp-queues 8 \
  --workers 8 \
  --count 5000000 \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/txring_dedicated.log
```

Ne zaman kullanilir:

- sender fallback istemediginizde
- dataplane core ve hugepage politikasini zorunlu tutmak istediginizde
- tekrarlanabilir laboratuvar benchmark'i yapmak istediginizde

### Akis B: AF_XDP benchmark

```bash
sudo python -m ddos_samurai.cli \
  --target 10.20.20.60 \
  --port 53 \
  --protocol udp \
  --attack-vector basic \
  --sender-backend xdp \
  --sender-fallback-policy fail \
  --xdp-enable \
  --xdp-interface eth2 \
  --xdp-queue-id 0 \
  --xdp-mode 1 \
  --xdp-attach-bpf \
  --workers 4 \
  --count 3000000 \
  --lab-profile dedicated \
  --kpi-gate-profile dedicated_lab \
  --kpi-hard-fail \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/afxdp_benchmark.log
```

Not:

- `--xdp-mode 1` native/driver mod icin uygundur
- BPF object/section gerekiyorsa bunlari acikca override edin

## Katman 6: Soak ve Uzun Sureli Stabilite Kosulari

Soak, throughput kadar istikrar da olcmek icin kullanilir.

### Akis A: 1 saatlik uygulama seviyesi soak

```bash
python -m ddos_samurai.cli \
  --target 10.30.10.70 \
  --port 443 \
  --attack-vector http \
  --http-scheme https \
  --http-path /api/health \
  --http-method GET \
  --http-concurrency 100 \
  --workers 8 \
  --rps 1200 \
  --count 100000000 \
  --profile web-stress \
  --soak-profile 1h \
  --soak-warmup-s 120 \
  --soak-snapshot-interval 15 \
  --soak-max-error-rate-pct 0.5 \
  --soak-max-pps-drop-pct 8 \
  --soak-max-rss-growth-mb 256 \
  --soak-max-backlog 10000 \
  --run-report \
  --run-report-format both \
  --run-report-dir artifacts/reports \
  --loss-telemetry auto \
  --loss-fail-pct 3 \
  --confirm \
  --log artifacts/logs/http_soak_1h.log
```

### Akis B: Fault-injection ile soak

```bash
python -m ddos_samurai.cli \
  --target 10.30.20.80 \
  --port 443 \
  --attack-vector http2 \
  --http-scheme https \
  --profile web-stress \
  --h2-transport auto \
  --http2-concurrency 250 \
  --workers 8 \
  --rps 1800 \
  --count 100000000 \
  --soak-profile 6h \
  --fault-inject sender-restart gpu-stream-error \
  --fault-after-s 900 \
  --fault-duration-s 5 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/http2_fault_soak.log
```

Bu akisin degeri:

- sadece iyi hava performansini degil, toparlanma davranisini da olcersiniz
- backlog, error-rate ve memory growth gibi KPI'lari tek raporda toplarsiniz

## Katman 7: GPU PCAP Artifact Uretimi

Bu akis trafik gondermez; lab ve CI icin sentetik paket verisi uretir.

### Akis A: Kisa sentetik PCAP

```bash
python -m ddos_samurai.cli \
  --gpu-pcap \
  --gpu-pcap-duration 10 \
  --gpu-pcap-pps 50000 \
  --gpu-pcap-mode mix \
  --gpu-pcap-src-ip 10.40.1.10 \
  --gpu-pcap-dst-ip 10.40.2.20 \
  --gpu-pcap-tcp-port 443 \
  --gpu-pcap-udp-port 53 \
  --gpu-pcap-out artifacts/pcaps/gpu_mix_10s_50k.pcap
```

### Akis B: Gercekcilik raporlu dataset artifact'i

```bash
python -m ddos_samurai.cli \
  --gpu-pcap \
  --gpu-pcap-duration 30 \
  --gpu-pcap-pps 75000 \
  --gpu-pcap-mode mix \
  --gpu-pcap-realistic \
  --gpu-pcap-variable-size \
  --gpu-pcap-size-profile mixed \
  --gpu-pcap-flow-count 4096 \
  --gpu-pcap-realism-report \
  --gpu-pcap-realism-sample 25000 \
  --gpu-pcap-realism-out artifacts/pcaps/gpu_realistic_mix.realism.json \
  --gpu-pcap-run-report \
  --gpu-pcap-run-report-format both \
  --gpu-pcap-run-report-out artifacts/reports/gpu_realistic_mix \
  --gpu-pcap-out artifacts/pcaps/gpu_realistic_mix.pcap
```

Bu artifact hangi islerde kullanilir:

- replay pipeline dogrulama
- parser/decoder benchmark'i
- sentetik dataset olusturma
- realism regression kontrolu

## Katman 8: PCAP Replay Akislari

### Akis A: Bilgi cikar ve filtre planla

```bash
python -m ddos_samurai.cli \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-info
```

### Akis B: Timing-aware replay

```bash
python -m ddos_samurai.cli \
  --target 10.50.10.90 \
  --port 443 \
  --attack-vector pcap-replay \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-timing multiplier \
  --pcap-speed 1.5 \
  --pcap-loops 3 \
  --pcap-filter-proto tcp udp \
  --pcap-filter-dst-port 443 \
  --pcap-batch-size 1024 \
  --workers 4 \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/pcap_replay_multiplier.log
```

### Akis C: L2 replay ile TX_RING yolu

```bash
sudo python -m ddos_samurai.cli \
  --target 10.50.20.91 \
  --port 443 \
  --attack-vector pcap-replay \
  --pcap-file artifacts/pcaps/gpu_realistic_mix.pcap \
  --pcap-use-l2 \
  --pcap-timing topspeed \
  --sender-backend txring \
  --sender-fallback-policy fail \
  --lab-profile dedicated \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/pcap_l2_txring.log
```

## Katman 9: Traffic Model ve Dataset Akislari

Bu yolun runtime entegrasyonu kisitli oldugu icin ilk durak dry-validate olmalidir.

### Akis A: Planner validasyonu

```bash
python -m ddos_samurai.cli \
  --traffic-model mamba2 \
  --traffic-model-checkpoint artifacts/models/mamba2_lab.ckpt \
  --traffic-model-config artifacts/models/mamba2_lab.yaml \
  --traffic-model-device cpu \
  --traffic-model-seed 42 \
  --traffic-model-label-mix benign=0.5,evasive=0.3,aggressive=0.2 \
  --traffic-model-session-len 32 \
  --traffic-model-planner-batch 64 \
  --traffic-model-timeout-ms 1500 \
  --traffic-model-fallback fail \
  --traffic-model-export-events artifacts/reports/mamba2_events.jsonl \
  --traffic-model-dry-validate
```

### Akis B: Dataset capture ile kontrollu live run

```bash
python -m ddos_samurai.cli \
  --target 10.60.10.100 \
  --port 443 \
  --attack-vector http \
  --http-scheme https \
  --http-path /api/check \
  --workers 4 \
  --count 20000 \
  --rps 800 \
  --traffic-model-dataset-capture artifacts/reports/runtime_events.jsonl \
  --run-report \
  --run-report-dir artifacts/reports \
  --confirm \
  --log artifacts/logs/runtime_dataset_capture.log
```

## Katman 10: Profesyonel Calisma Kaliplari

### Kalip 1: Yeni senaryo eklemeden once

1. `--help` ve `--list-profiles` bak
2. `--dry-run` gec
3. Kisa baseline al
4. Run report incele
5. Sonra benchmark veya soak'a gec

### Kalip 2: Benchmark sonucunu yayinlamadan once

1. `--sender-fallback-policy fail` kullan
2. Metrikleri `--run-report` ile kaydet
3. Root/capability gereksinimini not et
4. Queue, worker, backend bilgilerini artefact adina yansit

### Kalip 3: Soak sonucu kabul etmek icin

1. Warmup tanimla
2. Snapshot araligini sabitle
3. Error-rate ve PPS drop esiklerini acik ver
4. Loss telemetry sonucunu rapora dahil et

## SIk Yapilan Hatalar

### Dry-run atlamak

Sonuc:

- parse/preflight hatalari live run'da gorulur
- benchmark sonucu gecersizlesir

### `allow` fallback ile benchmark yapmak

Sonuc:

- sistem farkli bir sender/backend'e dusup sizi yaniltabilir

Benchmark icin tercih:

- `--sender-fallback-policy fail`
- `--l7-fallback-policy fail`

### Root gerektiren yolu normal kullanici ile kosmak

Ornek riskli alanlar:

- `txring`
- `xdp`
- bazi raw socket senaryolari

## Artefact Isimlendirme Onerisi

Ornek:

```text
artifacts/reports/2026-04-06_http2_webstress_10k_rps_dev
artifacts/reports/2026-04-06_txring_dedicated_8q_failfast
artifacts/pcaps/2026-04-06_gpu_mix_30s_75k_realistic.pcap
```

Onerilen alanlar:

- tarih
- vektor
- profil
- hedef throughput veya sure
- backend/lab tipi

## Sonuc

`ddos_samurai.cli`, en iyi sonucunu bayraklari tek tek ezberleyerek degil, operasyon tipine uygun akisi secerek verir.

Onerilen varsayilan davranis:

1. once `--dry-run`
2. sonra kisa baseline
3. sonra benchmark veya soak
4. sonunda `--run-report`

Bu belge, referans dokumanlarin yerine gecmez. Ayrintili bayrak davranislari icin:

- `docs/01-cli.md`
- `docs/08-config.md`
- `docs/18-afpacket-hugepage-policy.md`
- `docs/19-benchmark-profiles.md`
- `docs/20-env-cli-reference.md`
