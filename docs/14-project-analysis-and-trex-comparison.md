# Samurai — Detaylı Proje Analizi ve Cisco TRex Karşılaştırması

Bu doküman Samurai (Ronin) projesinin kapsamlı analizini ve Cisco TRex ile detaylı karşılaştırma/puanlamasını içerir.

## Guncel Durum Ozeti (2026-03-07)

Bu dosyadaki asagidaki bolumler tarihsel analiz kaydi olarak korunmustur. Guncel repo durumuna gore teknik ozet:

- Control-plane (CLI/orchestrator) ile dataplane (dataplane_core/fast_sender/pacing/xdp) ayrimi guclendirildi.
- Worker-omru `DataplaneSession` ve sender context reuse aktif mimari hedef haline geldi.
- L7 tarafinda route modeli `l7.dispatch` uzerinden `c_state` onceleyecek sekilde duzenlendi.
- QUIC path, `h3_stateful` native mod / `h3_stateful_py` bridge / `unavailable` ayrimini acikca raporluyor.
- KPI gate (`run_quality`, `kpi_gate_*`, `score_eligible`) parity matrisi ile baglandi.

Mimari-temelli guncel puan (benchmark degil, kod/entegrasyon odakli):

| Boyut | Samurai | TRex |
|---|---:|---:|
| Control-plane / dataplane ayrimi | 8.2 | 9.6 |
| L4 hot-path determinism | 7.4 | 9.7 |
| L4 telemetry + gate disiplini | 8.6 | 9.0 |
| L7 stateful engine mimarisi | 7.5 | 8.8 |
| GPU-assisted packet generation | 8.8 | 5.5 |
| Genel teknik olgunluk | 7.9 | 9.3 |

Not:
- Samurai'nin guclu farki GPU-assisted generation ve vektor cesitliligidir.
- TRex'in guclu farki tek dataplane disiplini ve olgun L4 performans hattidir.

---

## BÖLÜM 1: Samurai Proje Analizi

### 1.1 Amaç ve Kapsam

**Samurai**, izinli ortamlarda WAF/IPS ve benzeri savunma sistemlerini test etmek için tasarlanmış, yüksek performanslı ve modüler bir **ağ stres testi ve sızma testi** aracıdır. Temel özellikleri:

- **Hedef kitle:** Güvenlik testçileri, DevOps/SRE, stres testi ekipleri
- **Kullanım:** Yalnızca yetkili sistemlerde (allowlist, etik uyarı mekanizması)
- **Lisans:** MIT
- **Release modeli:** Ronin

---

### 1.2 Mimari Özet

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Giriş: advv2.py → ddos_samurai.cli.main()                              │
├─────────────────────────────────────────────────────────────────────────┤
│  CLI (cli.py)                                                            │
│  • Argparse + YAML config merge                                          │
│  • Safety gate (allowlist, public block)                                 │
│  • Dry-run, self-test, profile uygulama                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Orchestrator (orchestrator.py)                                          │
│  • Worker process spawn + CPU affinity                                   │
│  • attack_vector + compute_backend → sender/engine seçimi                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Senders (senders.py)          │  Packet/Payload Üretimi                 │
│  • packet_sender (Scapy)       │  • CPU: packet.py, cpu_packet_engine.py │
│  • raw_socket_sender + C ext  │  • GPU: gpu_packet.py, gpu_payload.py   │
│  • xdp_sender / AF_XDP        │  • Anomaly: anomaly_packet.py           │
│  • http_app_sender, http2_*   │  • PCAP: pcap_replay.py, gpu_pcap_gen   │
│  • websocket_sender, quic_*   │                                          │
│  • amplification_sender       │                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

Veri akışı: **CLI → Safety → Worker spawn → Orchestrator (per-worker) → Sender + Packet/Payload engine**.

---

### 1.3 Ana Bileşenler (Detay)

#### 1.3.1 CLI Katmanı (`ddos_samurai/cli.py`)

- **Argparse** ile tüm parametreler; `--config <YAML>` ile varsayılanlar yüklenir, CLI değerleri override eder.
- **Safety:** `utils.validate_target_safety()` — IPv4, multicast/unspecified blok; allowlist yoksa sadece private/loopback; `--allow-target`, `--allow-public-target` ile gevşetme.
- **Etik uyarı:** `utils.ethical_warning()` (interaktif); `--confirm` ile atlanabilir.
- **Modlar:** dry-run (paket doğrulama), self-test (unittest discover), soak test, run report (JSON/MD).
- **Profiller:** `--profile <name>` ile `workload_profiles.TEST_PROFILES` (web-stress, web-bypass, stateful-exhaustion, volumetric-udp, dns-infrastructure, slow-exhaustion, amplification-simulation, custom). `profiles` alias'i geriye donuk uyumluluk icin gecici olarak korunur ve deprecate durumundadir (bir sonraki minorde kaldirilmasi planli).

#### 1.3.2 Orkestratör (`ddos_samurai/orchestrator.py`)

- **start_worker(worker_id, args, progress, …):** Process entry; Linux’ta CPU affinity dener; `asyncio.run(worker_process(...))` ile async akış.
- **Backend/vektör dispatch:**
  - **CPU L4:** `packet_sender` + `packet.create_packet` (Scapy).
  - **CPU L7:** `http_app_sender`, `http2_sender`, `websocket_sender`, `quic_sender`, `slow_attack_sender`.
  - **CPU Amplification:** `amplification_sender` (DNS/NTP/SSDP/Memcached/LDAP).
  - **GPU L4:** Template pool + `gpu_packet.generate_packets_from_template_pool()` → `raw_socket_sender` / `paced_raw_socket_sender`.
  - **GPU HTTP:** `gpu_payload.GPUPayloadEngine` + fused HTTP → paced raw socket.
  - **GPU Amplification:** `gpu_packet.generate_amplification_packets()` + reflector listesi.
  - **GPU Anomaly:** `anomaly_packet` (malformed paketler).
  - **PCAP replay:** `pcap_replay` + timing modları.
- **Template pool (GPU):** CPU’da Scapy ile şablonlar; normalize (sabit byte uzunluğu) → GPU’da kopyalama + per-packet randomizasyon/spoof.

#### 1.3.3 Sender Katmanı (`ddos_samurai/senders.py`)

| Yol | Açıklama |
|-----|----------|
| **packet_sender** | Scapy ile paket üret + async gönderim; fragmentation sender tarafında. |
| **raw_socket_sender** | Contiguous buffer (sabit `packet_size`); `fast_sender` C eklentisi (sendmmsg / TX_RING) varsa kullanır; yoksa Python sendmmsg/sendto. |
| **paced_raw_socket_sender** | Aynı buffer + C `pacing_engine` ile deterministik pacing. |
| **xdp_sender** | AF_XDP uygunsa `af_xdp_sender`; değilse raw_socket_sender fallback. |
| **L7** | httpx (HTTP/1.1, HTTP/2), websockets, aioquic (QUIC/HTTP3), slow_* (keep-alive/slow read/post). |

Buffer formatı: Çoklu paket ardışık byte buffer; `packet_size = len(buffer) // count`.

#### 1.3.4 Paket/Payload Üretimi

- **CPU (Scapy):** `packet.py` — `PacketConfig`, `SpoofingOptions`, `create_packet`; L4/L7/DNS/amplification yardımcıları.
- **CPU (low-level):** `cpu_packet_engine.py` — IPv4/TCP/UDP/ICMP/DNS başlıkları, checksum, OS profilleri, spoofing, fragmentation, amplification (`create_dns_amp_packet`, `create_ntp_amp_packet`, vb.).
- **GPU (L4):** `gpu_packet.py` — Numba CUDA + CuPy; TCP/UDP/ICMP, checksum, template/template-pool/stateful-pool/fragmented/amplification kernel’ları; constant memory optimizasyonu; `GPUMemoryPool`, `PinnedHostBufferPool`.
- **GPU (L7 benzeri):** `gpu_payload.py` — HTTP payload, fused HTTP generator, cookie/referrer, HTTP/2 frame üretimi.
- **Anomaly:** `anomaly_packet.py` — Malformed paket varyasyonları (CUDA).

#### 1.3.5 C Eklentileri (`setup.py`)

- **fast_sender:** sendmmsg / TX_RING (L2) ile yüksek PPS; SO_TXTIME desteği (kernel ≥ 4.19).
- **pacing_engine:** Deterministik pacing.
- **xdp_sender:** AF_XDP (Linux, kernel ≥ 4.18; libbpf opsiyonel). Build başarısız olursa sadece uyarı, uygulama düşmez.

#### 1.3.6 Ek Modüller

- **stealth.py:** JA3/JA4 taklidi, TCP parametreleri (pencere, MSS, TTL) — OS/tarayıcı profili.
- **pacing.py:** Pacing konfigürasyonu (C pacing_engine ile kullanım).
- **reporting.py:** Run/self-test raporları (JSON, MD), metrik dosyaları, RFC uyumluluk.
- **metrics:** Prometheus metrikleri (API `/metrics`).

---

### 1.4 Saldırı Vektörleri (Attack Vectors)

| Vektör | Açıklama | Backend |
|--------|----------|---------|
| **basic** | TCP/UDP/ICMP flood (bayrak, spoofing, fragment) | CPU / CUDA |
| **http** | HTTP/1.1 flood (GPU polymorphic veya CPU) | CPU / CUDA |
| **http2** | HTTP/2 flood | CPU (+ opsiyonel Ninja) |
| **slowloris / slow-post / slow-read** | Yavaş bağlantı tüketimi | CPU |
| **dns** | DNS sorgu flood | CPU |
| **dns-amp, ntp-amp, ssdp-amp, memcached-amp, ldap-amp** | Amplification simülasyonu (reflector listesi) | CPU / CUDA |
| **websocket** | WebSocket flood | CPU |
| **quic** | QUIC/HTTP3 | CPU |
| **anomaly** | Malformed paketler | Yalnızca CUDA |
| **pcap-replay** | PCAP dosyasından tekrarlama | CPU (timing modları) |

**Ninja mod:** Playwright ile headless tarayıcı; WAF/JS challenge aşma (Cloudflare, Akamai vb.).

---

### 1.5 Gözlemlenebilirlik ve Raporlama

- **Rich TUI:** Terminal tabanlı canlı panel.
- **Prometheus:** `api.py` üzerinden `/metrics` endpoint.
- **Run report:** `--run-report`, `--run-report-format`, `--run-report-dir`; JSON/MD + metrik dosyaları.
- **Self-test report:** `--self-test` + report; test sayısı, hata, süre, metrik snapshot.

---

### 1.6 Opsiyonel SaaS Katmanı

- **API:** `ddos_samurai/api.py` (FastAPI) — port 5099; auth (JWT), plan/abonelik, billing, test start/stop, run geçmişi, loglar.
- **Dashboard:** `dashboard/` (React 18 + Vite) — login, plan, usage, test başlat/durdur, run listesi.
- **Veritabanı:** PostgreSQL (docker-compose: samurai/samurai).

---

### 1.7 Bağımlılıklar (Özet)

- **Ağ/taşıma:** scapy, uvloop, aiohttp, websockets, aioquic, httpx[http2]
- **Otomasyon:** playwright, requests
- **API:** fastapi, uvicorn, prometheus-client, psutil
- **Auth/DB:** SQLAlchemy, psycopg[binary], python-jose, passlib[bcrypt], email-validator
- **GPU:** numpy, numba-cuda[cu13], cupy-cuda12x
- **CLI:** rich, colorama, PyYAML

---

### 1.8 Test Yapısı

- **Konum:** `tests/`; 28+ test dosyası.
- **Kapsam:** CLI parser, dry-run, packet/cpu_packet_engine, senders (import fallback, comprehensive, GPU, ring buffer, fast_sender), orchestrator (CPU), integration, hybrid, safety, reporting, RFC uyumluluk, stealth, anomaly, pacing, utils.
- **Çalıştırma:** `python3 -m unittest discover -s tests -p "test_*.py"` veya `--self-test`.

---

## BÖLÜM 2: Cisco TRex ile Karşılaştırma

### 2.1 TRex Kısa Özet

- **TRex:** Cisco destekli, açık kaynak, **DPDK tabanlı** L3–L7 trafik jeneratörü.
- **Stateless (STL):** L3–L4; Scapy ile paket şablonları; çekirdek başına ~10–30 Mpps; 200 Gb/s’e kadar (tek sunucu).
- **Stateful (ASTF):** L7 uygulama emülasyonu (HTTP/HTTPS, Citrix); gerçekçi TCP oturumları; ~200 Gb/s, MCPS mertebesinde bağlantı hızı; milyonlarca aktif akış.
- **Emülasyon:** ARP, IPv6 ND, MLD, IGMP, ICMP, 802.1X, DHCPv4/v6, DNS; BIRD ile RIP/BGP/OSPF.
- **Ölçüm:** Donanım tabanlı istatistik, BPF filtreleri; yazılım tabanlı mikrosaniye gecikme/jitter; Python API, interaktif konsol, GUI.

---

### 2.2 Karşılaştırma Matrisi

| Kriter | Samurai | Cisco TRex | Notlar |
|--------|------------|------------|--------|
| **Temel teknoloji** | Python + C ext (sendmmsg/TX_RING) + opsiyonel AF_XDP | DPDK (user-space driver) | TRex ağ stack’i tamamen bypass; Samurai kernel + C/GPU hızlandırma |
| **L4 throughput** | C ext + GPU ile yüksek PPS; dokümanda “milyonlarca PPS” | ~10–30 Mpps/çekirdek, 200 Gb/s’e kadar | TRex L4’te tipik olarak daha yüksek ham throughput |
| **L7 stateful** | HTTP/1.1, HTTP/2, WebSocket, QUIC (gerçek kütüphaneler) | ASTF: HTTP/HTTPS, Citrix; milyonlarca akış, MCPS | TRex L7’de çok yüksek ölçek; Samurai gerçek stack + Ninja (WAF bypass) |
| **GPU kullanımı** | Evet (CuPy/Numba): paket/payload üretimi | Hayır (CPU/DPDK) | Samurai farklılaştırıcı özellik |
| **WAF bypass / Ninja** | Evet (Playwright, JS challenge) | Yok (genel L7 emülasyon) | Samurai Cloudflare/Akamai benzeri senaryolar için |
| **Amplification** | DNS, NTP, SSDP, Memcached, LDAP (CPU+GPU) | Trafik şablonu ile mümkün; özel “amplification modu” vurgusu yok | Samurai hazır amplification vektörleri |
| **Slowloris / slow-* ** | Evet (slowloris, slow-post, slow-read) | Profil ile benzeri yapılabilir; hazır modül vurgusu sınırlı | Samurai hazır |
| **Anomaly / malformed** | Evet (GPU anomaly_packet) | Özel paket şablonları ile | Samurai özelleşmiş modül |
| **PCAP replay** | Evet (pcap_replay, gpu_pcap_gen) | Evet (büyük dosya, 1 TB vb.) | İkisi de var; TRex ölçek vurgusu |
| **Kurulum / taşınabilirlik** | pip + CUDA (opsiyonel) + Linux headers (XDP); Python merkezli | DPDK, NIC binding, büyük sayfa, root; daha ağır | Samurai daha hafif kurulum |
| **API / otomasyon** | FastAPI (REST), dashboard (React), JWT, billing | Python API, 1 ms test çalıştırma; GUI/konsol | Samurai SaaS tarafı (abonelik, dashboard); TRex test odaklı API |
| **Güvenlik kapıları** | Allowlist, public blok, etik uyarı | Kullanıcı sorumluluğunda | Samurai yerleşik safety |
| **Lisans** | MIT | BSD benzeri (Cisco) | İkisi de açık kaynak |
| **Dokümantasyon** | İç doküman (00–13), README, profil açıklamaları | Geniş resmi doküman, FAQ | TRex daha geniş; Samurai iyi yapılandırılmış iç doküman |

---

## BÖLÜM 3: Puanlama (1–10)

Ortak kriterler üzerinden 1 (zayıf) – 10 (mükemmel) arası değerlendirme.

| Kriter | Ağırlık | Samurai | TRex | Kısa gerekçe |
|--------|---------|------------|------|----------------------|
| **L4 ham throughput** | 20% | 7 | 9 | TRex DPDK ile çekirdek başı 10–30 Mpps; Samurai C+GPU ile güçlü ama TRex seviyesinde değil. |
| **L7 gerçekçilik ve ölçek** | 15% | 7 | 9 | TRex ASTF milyonlarca akış/MCPS; Samurai gerçek HTTP/2/QUIC ve Ninja ile WAF senaryolarında güçlü. |
| **WAF / saldırı senaryoları** | 15% | 9 | 5 | Samurai: Ninja, amplification, slowloris, anomaly; TRex genel trafik, özel “saldırı modu” vurgusu az. |
| **Kurulum ve taşınabilirlik** | 10% | 8 | 6 | Samurai: pip + opsiyonel GPU; TRex: DPDK, NIC binding, daha fazla sistem gereksinimi. |
| **Gözlemlenebilirlik / raporlama** | 10% | 8 | 9 | TRex donanım istatistik, BPF, mikro gecikme; Samurai Rich, Prometheus, run/self-test raporları iyi. |
| **API ve otomasyon** | 10% | 8 | 8 | Samurai: REST + dashboard + billing; TRex: güçlü Python API ve hızlı test çalıştırma. |
| **Güvenlik ve güvenli kullanım** | 10% | 9 | 6 | Samurai: allowlist, public blok, etik uyarı; TRex’te bu tür yerleşik kapılar belirgin değil. |
| **Dokümantasyon** | 5% | 7 | 9 | Samurai iyi iç doküman; TRex çok geniş resmi doküman. |
| **Esneklik (protokol / vektör)** | 5% | 9 | 8 | Samurai: çok sayıda hazır vektör (amplification, anomaly, slow-*, Ninja); TRex Scapy ile esnek. |

**Ağırlıklı ortalama (örnek formül):**

- **Samurai:**  
  (7×0.20 + 7×0.15 + 9×0.15 + 8×0.10 + 8×0.10 + 8×0.10 + 9×0.10 + 7×0.05 + 9×0.05) = **7.95 ≈ 8.0**

- **TRex:**  
  (9×0.20 + 9×0.15 + 5×0.15 + 6×0.10 + 9×0.10 + 8×0.10 + 6×0.10 + 9×0.05 + 8×0.05) = **7.65 ≈ 7.7**

(Bu puanlar seçilen ağırlık ve yorumlara göre değişir; amacı göreceli güç/zayıflıkları göstermektir.)

---

## BÖLÜM 4: Sonuç ve Öneriler

### 4.1 Samurai Ne Zaman Tercih Edilmeli?

- **WAF/IPS testi:** Ninja (Playwright), JA3/JA4 taklidi, polymorphic HTTP, slowloris/slow-*.
- **Hazır saldırı vektörleri:** Amplification (DNS/NTP/SSDP/Memcached/LDAP), anomaly (malformed), DNS flood.
- **Hafif kurulum:** Sadece Python + pip; GPU ve XDP opsiyonel.
- **Güvenli kullanım:** Allowlist, public blok, etik uyarı.
- **SaaS/ekip kullanımı:** Dashboard, abonelik, billing, run geçmişi ihtiyacı.

### 4.2 TRex Ne Zaman Tercih Edilmeli?

- **Maksimum L4/L7 throughput:** 200 Gb/s, 10–30 Mpps/çekirdek, MCPS, milyonlarca akış.
- **DPDK tabanlı ölçek:** Donanım istatistik, mikrosaniye gecikme/jitter, büyük PCAP.
- **Standart uyumlu trafik:** BIRD ile routing protokolleri, geniş protokol emülasyonu.
- **Kurulum ve NIC kontrolü:** DPDK binding ve büyük sayfa yönetimine hazır ortam.

### 4.3 Özet Tablo

| İhtiyaç | Daha uygun |
|---------|------------|
| WAF bypass, Cloudflare/Akamai benzeri test | **Samurai** |
| Amplification / anomaly / slow-* hazır modüller | **Samurai** |
| Yerleşik safety (allowlist, etik uyarı) | **Samurai** |
| Hafif kurulum, Python odaklı | **Samurai** |
| Maksimum ham throughput (L4/L7), 200 Gb/s | **TRex** |
| Mikrosaniye gecikme ölçümü, donanım istatistik | **TRex** |
| Çok büyük ölçekte stateful L7 (ASTF) | **TRex** |

### 4.4 Parity Harness (2026-03-05)

TRex kiyasini ayni cikti semasinda uretmek icin benchmark sozlesmesi eklendi:

- `benchmarks/parity_matrix.json`
- CI-safe benchmark: `tests/test_benchmark_ci.py` (`developer_fallback` profili)
- Full benchmark: `tests/test_benchmark_full.py` (`dedicated_lab` profili)

Parity raporunda normalize edilen ana alanlar:

- `run_quality`, `sender_paths_used`, `sender_fallback_reason`
- `wire_loss_est_pct`, `rate_accuracy_pct`
- `txring_batch_target`, `txring_backoff_ns`
- `l7_active_sessions_peak`, `l7_conn_rate`, `l7_handshake_p99_ms`, `l7_step_fail_ratio`

`run_quality != valid` olan kosular parity skoruna dahil edilmemelidir.

---

*Samurai Team — 2026*
