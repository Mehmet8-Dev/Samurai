# Env + CLI Tam Referans

Bu belge `python -m ddos_samurai.cli` icin tum CLI bayraklarini ve CLI katmaninda gecen tum `SAMURAI_*` environment variable'larini tek yerde toplar.

Kapsam:
- CLI option sayisi: `394`
- CLI paketinde referanslanan `SAMURAI_*` env sayisi: `111`

## 1) Calistirma Komutlari

Temel entrypoint:

```bash
python -m ddos_samurai.cli [FLAGLER]
```

Sik kullanilan komut ornekleri:

```bash
# Profilleri goster
python -m ddos_samurai.cli --list-profiles

# Dry-run / guvenli parser+config kontrolu
python -m ddos_samurai.cli --dry-run -t 10.0.0.10 -p 443 --attack-vector http

# Self-test
python -m ddos_samurai.cli --self-test

# Standalone canli kosu (ornek)
python -m ddos_samurai.cli --role standalone -t 10.0.0.10 -p 443 --attack-vector http --workers 4

# Master
python -m ddos_samurai.cli --role master --control-listen 0.0.0.0:5099 --management-api-enable

# Slave
python -m ddos_samurai.cli --role slave --control-endpoints 10.0.0.5:5099 --cluster-secret xxxx
```

Komut katalogu (amac bazli):

```bash
# L4 basic
python -m ddos_samurai.cli --attack-vector basic -t 10.0.0.10 -p 443 --protocol tcp --count 100000

# HTTP/1.1
python -m ddos_samurai.cli --attack-vector http -t 10.0.0.10 -p 443 --http-scheme https --http-concurrency 200

# HTTP/2
python -m ddos_samurai.cli --attack-vector http2 -t 10.0.0.10 -p 443 --http2-concurrency 200

# WebSocket
python -m ddos_samurai.cli --attack-vector websocket -t 10.0.0.10 -p 443 --ws-concurrency 100

# QUIC/H3
python -m ddos_samurai.cli --attack-vector quic -t 10.0.0.10 -p 443 --quic-concurrency 100

# DNS
python -m ddos_samurai.cli --attack-vector dns -t 10.0.0.53 -p 53 --dns-name example.com --dns-qtype A AAAA

# Amplification simulasyonu
python -m ddos_samurai.cli --attack-vector dns-amp -t 10.0.0.53 -p 53 --reflector-file reflectors.txt

# Anomaly suite
python -m ddos_samurai.cli --attack-vector anomaly -t 10.0.0.10 -p 443 --anomaly-suite

# PCAP replay
python -m ddos_samurai.cli --attack-vector pcap-replay --pcap-file sample.pcap --pcap-timing topspeed

# Run report
python -m ddos_samurai.cli -t 10.0.0.10 -p 443 --run-report --run-report-format both --run-report-dir reports

# Lisans bilgi
python -m ddos_samurai.cli --license-info

# Lisans aktivasyon
python -m ddos_samurai.cli --license-activate --license-key SAM-XXXX-XXXX-XXXX-XXXX
```

## 2) Tum CLI Bayraklari

Notlar:
- `ENV` sutununda gorunen degiskenler, o flag icin parser default'unda dogrudan kullanilan env baglantilaridir.
- Bazi flagler parser'da env okumasa da runtime'da `sync_runtime_env(...)` ile env'e yazilir; bunun tam listesi 3. bolumdedir.

### options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--config` | `-` | `-` | - | Tüm ayarların okunacağı YAML konfigürasyon dosyasının yolu. |
| `--list-profiles` | `False` | `-` | - | Kullanılabilir kurumsal saldırı test profillerini listele. |
| `-t, --target` | `-` | `-` | - | Hedef IP adresi (config dosyasında da belirtilebilir) |
| `-p, --port` | `-` | `-` | - | Hedef port (config dosyasında da belirtilebilir) |
| `--source-port` | `0` | `-` | - | Kaynak port (0: rastgele) |
| `-c, --count` | `10` | `-` | - | Gönderilecek toplam paket/istek sayısı (soak profilinde per-iterasyon batch boyutu). |
| `-P, --protocol` | `tcp` | `tcp, udp, icmp` | - | Kullanılacak protokol (tcp/udp/icmp) |
| `-d, --delay` | `0` | `-` | - | Paketler arası gecikme (saniye cinsinden) - RPS ile birlikte kullanılmaz |
| `--payload` | `-` | `-` | - | Tek bir istek için gönderilecek sabit payload. |
| `--payload-file` | `-` | `-` | - | Her satırı bir payload olan ve isteklerde rastgele kullanılacak dosyanın yolu. |
| `--tcp-flags` | `S` | `S, A, F, R, SA, FA, RA, PA, U, E, C` | - | TCP bayrakları (örn: S, A, F, R, SA, FA, RA, PA, U, E, C vb.) |
| `--ttl` | `-` | `-` | - | IP paketi için TTL değeri |
| `--tos` | `-` | `-` | - | IP TOS değeri (ondalık formatta, örn: 16) |
| `--window` | `-` | `-` | - | TCP pencere boyutu |
| `--os-fingerprint` | `False` | `-` | - | Enable OS fingerprint randomization for packets. |
| `--pad` | `0` | `-` | - | Minimum paket boyutu (bayt). |
| `--ninja-mode` | `False` | `-` | - | Enable WAF Bypass (Ninja Mode) using Headless Browser. |
| `--fragment` | `False` | `-` | - | IP fragmentasyonunu etkinleştir (CPU native yol). |
| `--fragment-size` | `800` | `-` | - | Fragment boyutu (bayt). (Varsayılan: 800) |
| `--attack-vector` | `basic` | `basic, http, http2, dns, websocket, quic, slowloris, slow-post, slow-read, ntp-amp, ssdp-amp, dns-amp, memcached-amp, ldap-amp, anomaly, pcap-replay` | - | Saldırı vektörü seçimi |
| `--dns-name` | `example.com` | `-` | - | DNS vektörü için sorgu adı |
| `--dns-qtype` | `['A']` | `-` | - | DNS sorgu tipleri (birden fazla belirtilebilir: A AAAA MX TXT NS) |
| `--dns-edns` | `False` | `-` | - | DNS için EDNS0 OPT kaydı ekle |
| `--dns-nord` | `False` | `-` | - | DNS recursive desired kapat (rd=0) |
| `--http-path` | `['/']` | `-` | - | HTTP vektörü için istek yolları (birden fazla belirtilebilir) |
| `--http-method` | `GET` | `-` | - | HTTP vektörü için metod (GET, POST, ...) |
| `--http-concurrency` | `50` | `-` | - | HTTP vektörü eşzamanlı istek sayısı (worker başına) |
| `--http-timeout` | `5.0` | `-` | - | HTTP istek zaman aşımı (s) |
| `--http-retries` | `0` | `-` | - | HTTP istek retry sayısı |
| `--http-scheme` | `http` | `http, https` | - | HTTP vektörü için şema |
| `--http-verify` | `true` | `-` | - | HTTPS sertifika doğrulama (true/false) |
| `--rps` | `0` | `-` | - | Hedef toplam istek/paket saniye (tüm worker'lar için, 0: sınırsız) |
| `--jitter` | `0.0` | `-` | - | Rastgele zamanlama jitter oranı (0..1) |
| `--ramp` | `0.0` | `-` | - | RPS'e ramp-up süresi (s) |
| `--profile` | `custom` | `web-stress, web-bypass, stateful-exhaustion, volumetric-udp, dns-infrastructure, slow-exhaustion, amplification-simulation, custom` | - | Kurumsal saldırı testi profili (varsayılan: custom) |
| `--scenario-file` | `-` | `-` | - | Persona tabanli senaryo YAML dosyasi. |
| `--scenario-mode` | `off` | `off, shadow, enforce` | - | Senaryo calistirma modu. |
| `--scenario-vus` | `0` | `-` | - | Hedef eszamanli VU (0: senaryo dosyasindan). |
| `--scenario-ramp-seconds` | `0` | `-` | - | VU ramp suresi (0: senaryo dosyasindan). |
| `--scenario-max-session-seconds` | `0` | `-` | - | Maksimum session suresi (0: senaryo dosyasindan). |
| `--scenario-sla-profile` | `-` | `-` | - | Senaryo SLA override JSON (inline) veya profile adi. |
| `--scenario-seed` | `1337` | `-` | - | Scenario scheduler deterministic seed. |
| `--role` | `standalone` | `standalone, master, slave` | - | Distributed attack modu |
| `--confirm` | `False` | `-` | - | Etik uyarıyı atlamak için |
| `--dry-run` | `False` | `-` | - | Ayarları doğrular, örnek bir paket oluşturur ve gönderim yapmadan çıkar. |
| `-v, --verbose` | `False` | `-` | - | Detaylı çıktı |
| `--log` | `ddos_logs.txt` | `-` | - | Log dosyası yolu |
| `--workers` | `12` | `-` | - | Kullanılacak işçi (worker) süreç sayısı. Varsayılan: 12 |
| `--tls-profile` | `none` | `none, chrome_120, firefox_120, safari_17` | - | TLS/JA3 parmak izi profili |
| `--h2-profile` | `none` | `none, chrome_120, firefox_120, safari_17` | - | HTTP/2 profil adı |
| `--h2-transport` | `auto` | `auto, httpx, hyper-h2` | - | HTTP/2 transport secimi: auto\|httpx\|hyper-h2 (varsayilan: auto). |
| `--ja3-profile` | `-` | `none, chrome_120, firefox_120, safari_17` | - | DEPRECATED: --tls-profile alias (1 minor sürüm) |
| `--ech` | `False` | `-` | - | Encrypted Client Hello (ECH) desteğini etkinleştir (deneysel) |
| `--http2-concurrency` | `100` | `-` | - | HTTP/2 vektörü için eşzamanlı stream sayısı |
| `--http2-connections` | `1` | `-` | - | HTTP/2 için bağlantı sayısı (connection pool). |
| `--http2-streams-per-conn` | `100` | `-` | - | HTTP/2 bağlantı başına maksimum eşzamanlı stream. |
| `--l7-profile-file` | `-` | `-` | - | Yeni L7 emulation engine için JSON profile dosyası. |
| `--l7-template-mode` | `compat` | `compat, profile` | - | L7 emulation compiler modu: compat\|profile. |
| `--ws-path` | `/` | `-` | - | WebSocket vektörü için bağlantı yolu |
| `--ws-message` | `ping` | `-` | - | WebSocket vektörü için gönderilecek mesaj |
| `--ws-concurrency` | `50` | `-` | - | WebSocket vektörü eşzamanlı bağlantı sayısı |
| `--ws-scenario` | `False` | `-` | - | WebSocket senaryo modu (auth->subscribe->ping/pong state machine). |
| `--ws-auth-message` | `-` | `-` | - | WS senaryo modu auth adımı mesajı. |
| `--ws-subscribe-message` | `-` | `-` | - | WS senaryo modu subscribe adımı mesaj(ları). |
| `--ws-ping-count` | `1` | `-` | - | WS senaryo modu ping adım sayısı (varsayılan: 1). |
| `--ws-await-response` | `False` | `-` | - | WS senaryo adımlarında send sonrası recv bekle. |
| `--quic-path` | `/` | `-` | - | QUIC/HTTP3 vektörü için istek yolu |
| `--quic-method` | `GET` | `-` | - | QUIC/HTTP3 vektörü için HTTP metodu |
| `--quic-concurrency` | `50` | `-` | - | QUIC/HTTP3 vektörü eşzamanlı istek sayısı |
| `--quic-streams-per-conn` | `0` | `-` | - | Native QUIC için bağlantı başına eşzamanlı stream (0=concurrency tabanlı auto) |
| `--quic-requests-per-conn` | `0` | `-` | - | Native QUIC için bağlantı başına toplam istek (0=tek bağlantıda mümkün olduğunca çok) |
| `--quic-conn-pool-size` | `1` | `-` | - | Worker başına native QUIC bağlantı havuzu boyutu |
| `--quic-expect-status-min` | `200` | `-` | - | Native QUIC response status alt sınırı |
| `--quic-expect-status-max` | `399` | `-` | - | Native QUIC response status üst sınırı |
| `--quic-require-response-headers` | `True` | `-` | - | Native QUIC response header/status doğrulaması zorunlu (true/false) |
| `--quic-require-response-body` | `False` | `-` | - | Native QUIC için response body gelmesi zorunlu |
| `--quic-min-response-body-bytes` | `0` | `-` | - | Native QUIC response body minimum byte eşiği |
| `--quic-expect-header-name` | `-` | `-` | - | Native QUIC response'da zorunlu header adı (opsiyonel, küçük/büyük harf duyarsız). |
| `--quic-expect-header-value-contains` | `-` | `-` | - | Native QUIC response'da beklenen header değer alt dizesi (quic-expect-header-name ile birlikte). |
| `--quic-expect-body-substring` | `-` | `-` | - | Native QUIC response body içinde zorunlu alt dize (opsiyonel). |
| `--slowloris-concurrency` | `200` | `-` | - | Slowloris vektörü eşzamanlı bağlantı sayısı |
| `--stealth-mode` | `False` | `-` | - | DEPRECATED (no-op): kaldırılacak |
| `--payload-mutation` | `False` | `-` | - | Payload mutation - her istekte payload'u değiştir |
| `--proxy-list` | `-` | `-` | - | Proxy listesi dosyası (her satırda bir proxy) |
| `--aggressive-mode` | `False` | `-` | - | Agresif mod - daha hızlı ve yoğun saldırı |
| `--connection-pool` | `100` | `-` | - | Maksimum bağlantı havuzu boyutu |
| `--burst-mode` | `False` | `-` | - | Burst mod - kısa süreli yoğun saldırı |
| `--spoof-ip` | `-` | `-` | - | Belirli bir IP adresi ile spoofing yap (örn: 1.1.1.1) |
| `--realistic-spoof` | `False` | `-` | - | Gerçekçi IP aralıklarından spoofing yap |
| `--evasion-techniques` | `-` | `case, url, comment` | - | DEPRECATED (no-op): kaldırılacak |
| `--compute-backend` | `cpu` | `cpu, cuda` | - | Paket oluşturma için kullanılacak işlem birimi (cpu veya cuda) |
| `--stateful` | `False` | `-` | - | Enable Stateful TCP Engine (Viper-State) for full 3-way handshake. |
| `--sender-backend` | `xdp` | `xdp` | - | Raw sender backend seçimi: xdp (zorunlu). |
| `--sender-fallback-policy` | `fail` | `fail` | - | Backend fallback politikası: fail (zorunlu). |
| `--stateful-runtime-backend` | `afxdp` | `afxdp` | - | Yeni stateful runtime backend seçimi: afxdp (zorunlu). |
| `--dataplane-core-mode` | `required` | `off, auto, required` | - | Dataplane core kullanım modu: off\|auto\|required (required=tek hot-path, legacy zincir kapalı). |
| `--afpacket-hugepage-mode` | `off` | `off, auto, required` | - | AF_PACKET TX_RING hugepage politikası: off\|auto\|required. |
| `--afpacket-hugepage-size-kb` | `2048` | `-` | `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | AF_PACKET hugepage hedef boyutu (kB), varsayılan: 2048. |
| `--afpacket-ring-target-mb` | `64` | `-` | `SAMURAI_AF_PACKET_RING_TARGET_MB` | AF_PACKET TX_RING hedef toplam boyutu (MB), varsayılan: 64. |
| `--afpacket-block-size-kb` | `0` | `-` | `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | AF_PACKET TX_RING block boyutu (kB). 0=auto (frame-size ve frames-per-block'e gore). |
| `--afpacket-frame-size` | `0` | `-` | `SAMURAI_AF_PACKET_FRAME_SIZE` | AF_PACKET TX_RING frame boyutu (byte). 0=auto. |
| `--afpacket-frames-per-block` | `64` | `-` | `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | AF_PACKET block basina hedef frame sayisi (block-size auto modunda kullanilir). |
| `--afpacket-poll-timeout-ms` | `1` | `-` | `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | AF_PACKET frame bekleme poll timeout tabani (ms). |
| `--afpacket-spin-limit` | `2000` | `-` | `SAMURAI_AF_PACKET_SPIN_LIMIT` | AF_PACKET frame bekleme spin sayisi limiti. |
| `--afpacket-busy-poll-us` | `0` | `-` | `SAMURAI_AF_PACKET_BUSY_POLL_US` | SO_BUSY_POLL mikro saniye degeri (0=kapali, best-effort). |
| `--afpacket-qdisc-bypass` | `True` | `-` | - | AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kullan (varsayilan: acik). |
| `--no-afpacket-qdisc-bypass` | `True` | `-` | - | AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kapat. |
| `--afpacket-mlock-ring` | `False` | `-` | - | AF_PACKET ring bellek sayfalarını mlock ile sabitlemeyi dene. |
| `--no-afpacket-mlock-ring` | `False` | `-` | - | AF_PACKET ring mlock denemesini kapat. |
| `--afpacket-prefault-ring` | `True` | `-` | - | AF_PACKET ring mmap sonrası sayfaları prefault et. |
| `--no-afpacket-prefault-ring` | `True` | `-` | - | AF_PACKET ring prefault davranışını kapat. |
| `--lab-profile` | `off` | `off, dedicated` | `SAMURAI_LAB_PROFILE` | Lab çalışma profili: off=genel geliştirici, dedicated=hard benchmark profili. |
| `--dp-queue-strategy` | `rr` | `rr, pin, map` | `SAMURAI_DP_QUEUE_STRATEGY` | Dataplane queue dağıtımı: rr=round-robin, pin=worker->queue, map=explicit map. |
| `--dp-queues` | `1` | `-` | `SAMURAI_DP_QUEUES` | Dataplane queue sayısı (dedicated profilde NIC TX queue kontrolüne girer). |
| `--dp-queue-map` | `-` | `-` | `SAMURAI_DP_QUEUE_MAP` | Explicit worker->queue haritası. Format: '1:0,2:1,3:2'. |
| `--xdp-enable` | `False` | `-` | - | AF_XDP sender yolunu etkinleştir (xdp backend). |
| `--xdp-interface` | `-` | `-` | - | AF_XDP için NIC adı (örn: eth0). |
| `--xdp-queue-id` | `0` | `-` | - | AF_XDP queue id (varsayılan: 0). |
| `--xdp-mode` | `0` | `0, 1, 2` | `SAMURAI_XDP_MODE` | AF_XDP mode: 0=SKB/Copy, 1=Native/DRV, 2=Offload. |
| `--xdp-attach-bpf` | `True` | `-` | - | XDP backend start anında eBPF programı attach et (varsayılan: açık). |
| `--no-xdp-attach-bpf` | `True` | `-` | - | XDP backend için eBPF attach adımını kapat. |
| `--xdp-bpf-section` | `xdp_sock` | `-` | `SAMURAI_XDP_BPF_SECTION` | Attach edilecek BPF section adı (örn: xdp_sock, xdp_sock_filter). |
| `--xdp-bpf-obj` | `-` | `-` | `SAMURAI_XDP_BPF_OBJ` | XDP BPF object yolu (boşsa ddos_samurai/xdp_prog.o varsayımı). |
| `--xdp-xskmap-pin` | `-` | `-` | `SAMURAI_XDP_XSKMAP_PIN` | Pinned xsks_map yolu (opsiyonel, queue->xsk fd map update için). |
| `--state-engine-mode, --engine-mode` | `auto` | `auto, required` | `SAMURAI_STATE_ENGINE_MODE` | Legacy L4 state engine modu: auto\|required. |
| `--state-table-size` | `65536` | `-` | `SAMURAI_STATE_TABLE_SIZE` | Legacy L4 state engine tablo boyutu. |
| `--state-lock-count` | `256` | `-` | `SAMURAI_STATE_LOCK_COUNT` | Legacy L4 state engine shard/lock sayısı. |
| `--state-timeout-sec` | `60` | `-` | `SAMURAI_STATE_TIMEOUT_SEC` | Legacy L4 state engine timeout süresi (saniye). |
| `--state-sweep-interval-ms` | `1000` | `-` | `SAMURAI_STATE_SWEEP_INTERVAL_MS` | Legacy L4 state engine sweep aralığı (ms). |
| `--custom-tcp-mode` | `required` | `off, auto, required` | `SAMURAI_CUSTOM_TCP_MODE` | Custom TCP dataplane modu: off\|auto\|required. |
| `--topo-spec-json` | `-` | `-` | - | ASTF-benzeri topology JSON tanımı (CLI-only). |
| `--topo-seed` | `-1` | `-` | - | Topology tuple üretimi için deterministik seed (topology açıkken zorunlu). |
| `--topo-strict, --no-topo-strict` | `True` | `-` | - | Topology schema/semantic strict validation (varsayılan: açık). |
| `--custom-tcp-backend` | `af_xdp` | `af_xdp` | `SAMURAI_CUSTOM_TCP_BACKEND` | Custom TCP dataplane backend hedefi: af_xdp (zorunlu). |
| `--custom-tcp-initial-rto-ms` | `250` | `-` | `SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS` | Custom TCP başlangıç RTO değeri (ms). |
| `--custom-tcp-max-retransmits` | `5` | `-` | `SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS` | Custom TCP maksimum retransmit sayısı. |
| `--custom-tcp-connect-timeout-ms` | `3000` | `-` | `SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS` | Custom TCP connect timeout değeri (ms). |
| `--custom-tcp-idle-timeout-ms` | `30000` | `-` | `SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS` | Custom TCP idle timeout değeri (ms). |
| `--kpi-gate-profile` | `off` | `off, dev, ci_safe, developer_fallback, dedicated_lab, persistent_stream_strict` | `SAMURAI_KPI_GATE_PROFILE` | KPI gate profili: off\|dev\|ci_safe\|developer_fallback\|dedicated_lab\|persistent_stream_strict. |
| `--kpi-hard-fail` | `False` | `-` | - | Dedicated gate ihlalinde non-zero exit döndür. |
| `--l7-engine` | `python` | `python, c_state` | `SAMURAI_L7_ENGINE` | L7 state engine seçimi: python\|c_state. |
| `--l7-http2-engine` | `auto` | `python, c_state, auto` | `SAMURAI_L7_HTTP2_ENGINE` | HTTP/2 L7 engine seçimi: python\|c_state\|auto. |
| `--l7-quic-engine` | `auto` | `python, c_state, auto` | `SAMURAI_L7_QUIC_ENGINE` | QUIC L7 engine seçimi: python\|c_state\|auto. |
| `--l7-quic-require-native` | `False` | `-` | `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | QUIC için yalnızca native C custom_native modunu kabul et (py-bridge kabul edilmez). |
| `--l7-quic-auto-bridge` | `False` | `-` | `SAMURAI_L7_QUIC_AUTO_BRIDGE` | Native QUIC yoksa py-bridge yolunu otomatik etkinleştir. |
| `--l7-quic-bridge-autopromote` | `False` | `-` | `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | Capability map içinde py-bridge'i otomatik custom_native olarak terfi ettir. |
| `--l7-fallback-policy` | `allow` | `allow, fail` | `SAMURAI_L7_FALLBACK_POLICY` | L7 C->Python fallback politikası: allow\|fail. |
| `--l7-capability-strict` | `False` | `-` | `SAMURAI_L7_CAPABILITY_STRICT` | L7 capability strict modu: eksik capability varsa fallback yerine preflight/run fail. |
| `--l7-session-repeats` | `1` | `-` | - | Stateful L7 oturumlarını kullanıcı başına tekrar sayısı. |
| `--l7-max-active-sessions` | `0` | `-` | - | Stateful L7 için eşzamanlı aktif session üst limiti (0=sınırsız). |
| `--gpu-template-pool-size-l4` | `10` | `-` | `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | CUDA template-pool L4 varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4). |
| `--gpu-template-pool-size-l7` | `50` | `-` | `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | CUDA template-pool L7 set varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7). |
| `--gpu-ring-capacity` | `3` | `-` | `SAMURAI_GPU_RING_CAPACITY` | CUDA producer-consumer ring kapasitesi (env: SAMURAI_GPU_RING_CAPACITY). |
| `--gpu-batch-size` | `100000` | `-` | `SAMURAI_GPU_BATCH` | CUDA üretim batch boyutu (env: SAMURAI_GPU_BATCH). |
| `--gpu-stream-count` | `3` | `-` | `SAMURAI_GPU_STREAMS` | CUDA stream sayısı (gen/copy/send overlap için). |
| `--gpu-pipeline-depth` | `2` | `-` | `SAMURAI_GPU_PIPELINE_DEPTH` | GPU pipeline overlap derinliği (ready batch kuyruk eşiği). |
| `--gpu-full-variation, --no-gpu-full-variation` | `True` | `-` | `SAMURAI_GPU_FULL_VARIATION` | Basic L4 akışında varyasyonları tamamen GPU hot-path üzerinden üret. |
| `--gpu-pinned-max-mb` | `512` | `-` | `SAMURAI_GPU_PINNED_MAX_MB` | Pinned host buffer pool üst sınırı MB (env: SAMURAI_GPU_PINNED_MAX_MB). |
| `--gpu-packet-zerocopy-output, --no-gpu-packet-zerocopy-output` | `False` | `-` | `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | CUDA native path çıktı tamponu için mapped host zero-copy yolunu aç/kapat (env: SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT). |
| `--gpu-kernel-mode` | `batch` | `batch, persistent` | `SAMURAI_GPU_KERNEL_MODE` | CUDA kernel çalışma modu: batch veya persistent (env: SAMURAI_GPU_KERNEL_MODE). |
| `--gpu-stream-api` | `compat` | `compat, stream` | `SAMURAI_GPU_STREAM_API` | GPU stream API modu: compat (batch wrapper) veya stream (lifecycle API) (env: SAMURAI_GPU_STREAM_API). |
| `--gpu-epoch-ms` | `50` | `-` | `SAMURAI_GPU_EPOCH_MS` | Persistent mode quota epoch süresi (ms). |
| `--gpu-queue-count` | `1` | `-` | `SAMURAI_GPU_QUEUE_COUNT` | Persistent mode per-queue ring sayısı. |
| `--gpu-heartbeat-ms` | `500` | `-` | `SAMURAI_GPU_HEARTBEAT_MS` | Persistent runtime heartbeat yayın periyodu (ms). |
| `--gpu-no-progress-ms` | `2000` | `-` | `SAMURAI_GPU_NO_PROGRESS_MS` | Persistent runtime no-progress recovery eşiği (ms). |
| `--gpu-rng-seed` | `1234` | `-` | `SAMURAI_GPU_RNG_SEED` | GPU payload RNG seed (varsayılan: deterministik 1234, env: SAMURAI_GPU_RNG_SEED). |
| `--gpu-defense-mode` | `off` | `on, off` | `SAMURAI_GPU_DEFENSE_MODE` | GPU defense/classifier hattı: on\|off (varsayılan: off). |
| `--gpu-classifier-runtime` | `tensorrt` | `tensorrt` | `SAMURAI_GPU_CLASSIFIER_RUNTIME` | GPU classifier runtime: tensorrt. |
| `--gpu-classifier-engine-path` | `-` | `-` | `SAMURAI_GPU_CLASSIFIER_ENGINE_PATH` | Offline-build edilmiş TensorRT .engine dosya yolu. |
| `--gpu-rdma-mode` | `auto` | `auto, direct, host_staging, doca_gpunetio` | `SAMURAI_GPU_RDMA_MODE` | GPU RDMA modu: auto\|direct\|host_staging\|doca_gpunetio. |
| `--gpu-rdma-strict, --no-gpu-rdma-strict` | `False` | `-` | `SAMURAI_GPU_RDMA_STRICT` | RDMA strict mod: fallback yerine fail-visible hard fail. |
| `--gpu-batch-max` | `1024` | `-` | `SAMURAI_GPU_BATCH_MAX` | Defense dinamik batching max batch boyutu. |
| `--gpu-batch-flush-timeout-ms` | `2` | `-` | `SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS` | Defense batch flush timeout (ms). |
| `--gpu-rx-pipeline` | `off` | `on, off` | `SAMURAI_GPU_RX_PIPELINE` | NIC RX -> GPU classifier pipeline modu: on\|off. |
| `--gpu-rx-iface` | `-` | `-` | `SAMURAI_GPU_RX_IFACE` | GPU RX pipeline için capture interface (boşsa default route iface). |
| `--gpu-rx-duration-s` | `10` | `-` | `SAMURAI_GPU_RX_DURATION_S` | GPU RX pipeline çalışma süresi (s). |
| `--gpu-rx-batch-size` | `256` | `-` | `SAMURAI_GPU_RX_BATCH_SIZE` | GPU RX pipeline classify batch boyutu. |
| `--gpu-rx-max-packets` | `100000` | `-` | `SAMURAI_GPU_RX_MAX_PACKETS` | GPU RX pipeline en fazla işlenecek paket adedi. |
| `--gpu-rx-snaplen` | `2048` | `-` | `SAMURAI_GPU_RX_SNAPLEN` | GPU RX pipeline packet capture snaplen (byte). |
| `--gpu-vector-engine` | `gpu_cuda` | `gpu_cuda` | - | GPU vector planner engine: gpu_cuda (legacy planner kaldırıldı). |

### IP Spoofing Options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--spoof` | `False` | `-` | - | IP sahtekarlığını etkinleştir (varsayılan mod: realistic) |
| `--spoof-mode` | `realistic` | `random, realistic, subnet, list` | - | IP sahtekarlık modu |
| `--spoof-subnet` | `-` | `-` | - | 'subnet' modu için CIDR formatında alt ağ (örn: 192.168.1.0/24) |
| `--spoof-list-file` | `-` | `-` | - | 'list' modu için her satırda bir IP içeren dosya yolu |

### Amplification Attack Options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--reflector-file` | `-` | `-` | - | Yansıtıcı sunucu IP'lerini içeren dosyanın yolu (amplification saldırısı için gereklidir). |

### Distributed Control Plane

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--control-listen` | `0.0.0.0:5099` | `-` | - | Master gRPC listen adresi (varsayılan: 0.0.0.0:5099). |
| `--control-endpoints` | `-` | `-` | - | Slave: master endpoint(ler). Format: host1:5099,host2:5099 |
| `--cluster-secret` | `-` | `-` | `SAMURAI_CLUSTER_SECRET` | Cluster authentication token (tüm node'larda aynı olmalı). |
| `--control-tls-cert` | `-` | `-` | - | gRPC server TLS sertifika dosyası (PEM). |
| `--control-tls-key` | `-` | `-` | - | gRPC server TLS private key dosyası (PEM). |
| `--control-tls-ca` | `-` | `-` | - | gRPC TLS CA bundle (slave tarafında server doğrulaması için). |
| `--control-tls-client-ca` | `-` | `-` | - | mTLS için client certificate CA bundle (master server doğrulaması). |
| `--control-tls-client-cert` | `-` | `-` | - | mTLS için client certificate dosyası (PEM, slave/master client tarafı). |
| `--control-tls-client-key` | `-` | `-` | - | mTLS için client private key dosyası (PEM, slave/master client tarafı). |
| `--control-require-client-auth` | `False` | `-` | - | Master gRPC server için mTLS client auth zorunlu kıl. |
| `--control-insecure` | `False` | `-` | - | TLS olmadan plaintext gRPC (sadece dev/lab için). |
| `--heartbeat-interval-ms` | `2000` | `-` | - | Slave heartbeat gönderme aralığı (ms). |
| `--heartbeat-timeout-ms` | `6000` | `-` | - | Master: heartbeat timeout süresi (3x interval). |
| `--worker-registration-timeout-s` | `30` | `-` | - | Master: worker register bekleme süresi (s). |
| `--master-poll-interval-ms` | `250` | `-` | - | Master: heartbeat/shard durum poll aralığı (ms). |
| `--control-max-workers` | `0` | `-` | - | Master gRPC thread pool boyutu (0=otomatik). |
| `--control-dispatch-workers` | `32` | `-` | - | Master start/stop shard RPC paralellik limiti. |
| `--control-stop-grace-s` | `1.0` | `-` | - | Master gRPC server shutdown grace süresi (s). |
| `--worker-status-probe` | `True` | `-` | - | Master wait-loop sırasında worker GetWorkerStatus probe ile shard completion fallback. |
| `--stop-shard-retries` | `3` | `-` | - | Master graceful StopShard retry sayısı. |
| `--stop-shard-retry-delay-ms` | `250` | `-` | - | Master StopShard retry denemeleri arası bekleme (ms). |
| `--slave-master-timeout-s` | `30` | `-` | - | Slave: master heartbeat RPC başarısızlığında çıkış eşiği (s, 0=kapalı). |
| `--stats-stream-enable` | `True` | `-` | - | Slave->master stats stream RPC yolunu etkinlestir (fallback: unary ReportStats). |
| `--stats-stream-interval-ms` | `500` | `-` | - | Shard calisirken stream uzerinden canli stats yayin araligi (ms). |
| `--distributed-metrics-textfile` | `-` | `-` | - | Master distributed summary Prometheus textfile export yolu (opsiyonel). |
| `--distributed-metrics-prefix` | `samurai_distributed` | `-` | - | Distributed Prometheus metric isim prefix'i. |
| `--shard-kpi-max-error-rate-pct` | `-1.0` | `-` | - | Per-shard KPI gate: maksimum hata oranı (%%). -1=kapalı. |
| `--shard-kpi-fail-on-exitcode` | `True` | `-` | - | Per-shard KPI gate: shard exitcode!=0 ise fail say. |
| `--management-api-enable` | `False` | `-` | - | Master uzerinde runtime management REST API'yi ac. |
| `--management-api-listen` | `127.0.0.1:8089` | `-` | - | Management API listen adresi (host:port). |
| `--management-api-auth-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_AUTH_TOKEN` | Management API Bearer token (bos ise auth kapali). |
| `--management-api-admin-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_ADMIN_TOKEN` | Management API admin rol token'i (opsiyonel). |
| `--management-api-operator-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` | Management API operator rol token'i (opsiyonel). |
| `--management-api-viewer-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_VIEWER_TOKEN` | Management API viewer rol token'i (opsiyonel). |
| `--management-api-jwt-secret` | `-` | `-` | `SAMURAI_MANAGEMENT_API_JWT_SECRET` | Management API JWT HS256 secret (opsiyonel). |
| `--management-api-jwt-role-claim` | `role` | `-` | - | Management API JWT role claim adı. |
| `--management-api-jwt-tenant-claim` | `tenant_namespace` | `-` | - | Management API JWT tenant claim adı. |
| `--management-api-trusted-identity-secret` | `-` | `-` | `SAMURAI_MANAGEMENT_API_TRUSTED_IDENTITY_SECRET` | Reverse-proxy SSO headerlarini dogrulamak icin paylasimli secret (opsiyonel). |
| `--management-api-trusted-identity-secret-header` | `x-samurai-auth-proxy-secret` | `-` | - | Reverse-proxy secret header adi. |
| `--management-api-trusted-identity-role-header` | `x-auth-request-role` | `-` | - | Reverse-proxy role header adi (OIDC/SAML proxy). |
| `--management-api-trusted-identity-tenant-header` | `x-auth-request-tenant` | `-` | - | Reverse-proxy tenant header adi. |
| `--management-api-live-interval-ms` | `1000` | `-` | - | Management API live SSE/WS publish interval (ms). |
| `--management-events-max` | `200` | `-` | - | Management API event timeline maksimum kayit sayisi. |
| `--control-rbac-enable` | `False` | `-` | - | gRPC control plane icin role-based authorization etkinlestir. |
| `--control-rbac-default-role` | `viewer` | `admin, operator, viewer, worker` | - | RBAC role secret eslesmezse varsayilan rol. |
| `--control-rbac-admin-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_ADMIN_SECRET` | RBAC admin rol secret'i. |
| `--control-rbac-operator-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_OPERATOR_SECRET` | RBAC operator rol secret'i. |
| `--control-rbac-viewer-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_VIEWER_SECRET` | RBAC viewer rol secret'i. |
| `--control-rbac-worker-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_WORKER_SECRET` | RBAC worker rol secret'i. |
| `--control-jwt-secret` | `-` | `-` | `SAMURAI_CONTROL_JWT_SECRET` | gRPC control-plane JWT HS256 secret (opsiyonel). |
| `--control-jwt-role-claim` | `role` | `-` | - | gRPC control-plane JWT role claim adı. |
| `--control-jwt-tenant-claim` | `tenant_namespace` | `-` | - | gRPC control-plane JWT tenant claim adı. |
| `--ha-enable` | `False` | `-` | - | Master için HA leader election iskeletini etkinleştir. |
| `--ha-mode` | `static` | `static, file-lock, redis, etcd, raft` | - | HA modu: static, file-lock, redis, etcd veya native raft. |
| `--ha-node-id` | `-` | `-` | - | HA node kimliği (boş ise hostname kullanılır). |
| `--ha-peer-nodes` | `-` | `-` | - | HA peer node id listesi (CSV). Static modda leader seçimi için kullanılır. |
| `--ha-lease-path` | `/tmp/ddos_samurai_master_lease.json` | `-` | - | file-lock HA modu için lease dosya yolu. |
| `--ha-lease-seconds` | `15.0` | `-` | - | file-lock HA lease TTL süresi (s). |
| `--ha-renew-interval-s` | `5.0` | `-` | - | file-lock HA lease yenileme aralığı (s). |
| `--ha-wait-for-leader` | `True` | `-` | - | file-lock HA follower node, liderlik düşmesini bekleyip takeover denesin. |
| `--ha-acquire-timeout-s` | `0.0` | `-` | - | file-lock HA liderlik bekleme timeout'u (0=sınırsız). |
| `--ha-retry-interval-s` | `1.0` | `-` | - | file-lock HA liderlik acquire retry aralığı (s). |
| `--ha-redis-url` | `redis://127.0.0.1:6379/0` | `-` | - | ha-mode redis için Redis bağlantı URL'i. |
| `--ha-redis-key` | `samurai:ha:master` | `-` | - | ha-mode redis için lease key. |
| `--ha-etcd-endpoints` | `127.0.0.1:2379` | `-` | - | ha-mode etcd için endpoint listesi (CSV, host:port). |
| `--ha-etcd-key` | `samurai/ha/master` | `-` | - | ha-mode etcd için lease key yolu. |
| `--ha-etcd-timeout-s` | `3.0` | `-` | - | ha-mode etcd istemci timeout (s). |
| `--ha-raft-listen` | `127.0.0.1:7000` | `-` | - | ha-mode raft için node içi consensus RPC listen adresi (host:port). |
| `--ha-raft-peers` | `-` | `-` | - | ha-mode raft peer listesi (CSV): node-id@host:port,node2@host:port |
| `--ha-raft-election-timeout-min-ms` | `900` | `-` | - | ha-mode raft election timeout alt sınır (ms). |
| `--ha-raft-election-timeout-max-ms` | `1500` | `-` | - | ha-mode raft election timeout üst sınır (ms). |
| `--ha-raft-heartbeat-interval-ms` | `250` | `-` | - | ha-mode raft leader heartbeat aralığı (ms). |
| `--ha-raft-snapshot-threshold` | `2048` | `-` | - | ha-mode raft compaction tetik eşiği (committed entry sayısı). |
| `--ha-raft-snapshot-keep-entries` | `512` | `-` | - | ha-mode raft compaction sonrası bellekte tutulacak son entry sayısı. |
| `--multi-master-enable` | `False` | `-` | - | Cross-region multi-master coordinator'u etkinlestir (Redis backend). |
| `--multi-master-region-id` | `-` | `-` | `SAMURAI_MULTI_MASTER_REGION_ID` | Bu master node'un bolge kimligi (orn: eu-central). Bos ise --worker-region kullanilir. |
| `--multi-master-redis-url` | `redis://127.0.0.1:6379/0` | `-` | `SAMURAI_MULTI_MASTER_REDIS_URL` | Multi-master coordinator Redis URL. |
| `--multi-master-namespace` | `default` | `-` | `SAMURAI_MULTI_MASTER_NAMESPACE` | Multi-master coordinator namespace (key prefix izolasyonu). |
| `--multi-master-heartbeat-ttl-s` | `15` | `-` | `SAMURAI_MULTI_MASTER_HEARTBEAT_TTL_S` | Multi-master region heartbeat TTL suresi (s). |
| `--multi-master-dequeue-max` | `3` | `-` | `SAMURAI_MULTI_MASTER_DEQUEUE_MAX` | Bir polling turunda kuyruktan cekilecek max delegated job sayisi. |
| `--control-rbac-audit-log-path` | `-` | `-` | `SAMURAI_CONTROL_RBAC_AUDIT_LOG_PATH` | RBAC audit JSONL append-only log dosya yolu (opsiyonel). |
| `--control-rbac-audit-success` | `False` | `-` | - | RBAC audit log'a sadece red edilenleri degil basarili istekleri de yaz. |
| `--control-tls-watch-files` | `True` | `-` | - | Master TLS dosyalarini izle ve degisince gRPC listener'i hot-reload et. |
| `--control-tls-reload-interval-s` | `2.0` | `-` | `SAMURAI_CONTROL_TLS_RELOAD_INTERVAL_S` | TLS file watcher polling araligi (s). |
| `--job-timeout-s` | `0` | `-` | - | Dağıtık job max süresi (0=sınırsız). |
| `--job-queue-json` | `-` | `-` | - | Master icin coklu job kuyrugu (JSON list/dict). Ornek: '[{"count":1000},{"count":2000,"job_timeout_s":30}]' |
| `--shard-unit-count` | `0` | `-` | - | Dynamic rebalance icin micro-shard paket boyutu (0=otomatik). |
| `--shard-strategy` | `equal` | `equal, capability, region` | - | Shard dağıtım stratejisi: equal=eşit, capability=kapasite, region=bölge öncelikli. |
| `--region-aware-routing` | `False` | `-` | - | Master dispatch worker seçimini target/worker region yakınlığına göre yap. |
| `--worker-region` | `-` | `-` | `SAMURAI_WORKER_REGION` | Node/worker bölge etiketi (örn: eu-central, us-east). |
| `--target-region` | `-` | `-` | `SAMURAI_TARGET_REGION` | İş hedef bölgesi (region-aware-routing ile birlikte kullanılır). |
| `--cross-region-heartbeat-factor` | `1.6` | `-` | - | Cross-region worker heartbeat timeout çarpanı (>=1.0). |
| `--on-worker-loss` | `continue` | `abort, continue` | - | Worker kaybında davranış: abort=testi durdur, continue=loss olarak raporla. |
| `--control-discovery-k8s` | `False` | `-` | - | Manual endpoint yoksa master endpointlerini Kubernetes pod discovery ile bul. |
| `--control-k8s-namespace` | `default` | `-` | - | Kubernetes namespace (control discovery için). |
| `--control-k8s-selector` | `-` | `-` | - | Kubernetes label selector (örn: app=ddos-samurai-slave). |
| `--control-k8s-port` | `5099` | `-` | - | Kubernetes discovery endpoint portu (varsayılan: 5099). |
| `--tenant-namespace` | `-` | `-` | `SAMURAI_TENANT_NAMESPACE` | Control-plane tenant namespace izolasyonu (opsiyonel). |
| `--control-autoscale-enable` | `False` | `-` | - | Master pending/inflight shard durumuna gore K8s replica autoscale yap. |
| `--control-autoscale-namespace` | `default` | `-` | - | Autoscale hedef namespace. |
| `--control-autoscale-target-kind` | `deployment` | `deployment, statefulset` | - | Autoscale hedef resource tipi. |
| `--control-autoscale-target-name` | `-` | `-` | - | Autoscale hedef Deployment/StatefulSet adi. |
| `--control-autoscale-min-replicas` | `1` | `-` | - | Autoscale min replica. |
| `--control-autoscale-max-replicas` | `100` | `-` | - | Autoscale max replica. |
| `--control-autoscale-step` | `1` | `-` | - | Scale up/down adim boyutu. |
| `--control-autoscale-cooldown-s` | `15.0` | `-` | - | Scale islemleri arasinda cooldown (s). |
| `--control-autoscale-shards-per-worker` | `4` | `-` | - | Autoscale kapasite modeli: worker basina shard hedefi. |
| `--control-autoscale-idle-scale-down-s` | `60.0` | `-` | - | Idle sure sonunda min replica'ya inme esigi (s). |

### Traffic Model (Mamba-2 Planner v1)

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--traffic-model` | `none` | `none, mamba2` | - | Stateful trafik planner seçimi: none\|mamba2. Not: mamba2 runtime entegrasyonu devre dışıdır; training/mamba2_monolith.py kullanın. |
| `--traffic-model-checkpoint` | `-` | `-` | - | Planner checkpoint dosya yolu. |
| `--traffic-model-config` | `-` | `-` | - | Planner config dosya yolu (opsiyonel). |
| `--traffic-model-device` | `cpu` | `cpu` | - | Planner device (v1: sadece cpu). |
| `--traffic-model-seed` | `1337` | `-` | - | Deterministic planner seed. |
| `--traffic-model-label-mix` | `benign=0.4,evasive=0.4,aggressive=0.2` | `-` | - | Label dağılımı: benign=0.4,evasive=0.4,aggressive=0.2 |
| `--traffic-model-session-len` | `24` | `-` | - | Session başına maksimum event sayısı. |
| `--traffic-model-planner-batch` | `128` | `-` | - | Tek plan üretim çağrısındaki session batch boyutu. |
| `--traffic-model-timeout-ms` | `2500` | `-` | - | Planner inference timeout (ms). |
| `--traffic-model-fallback` | `static` | `static, fail` | - | Planner fail olduğunda davranış: static\|fail. |
| `--traffic-model-export-events` | `-` | `-` | - | Generated planner event log JSONL yolu (opsiyonel). |
| `--traffic-model-dataset-capture` | `-` | `-` | - | Runtime worker event'lerini JSONL dataset olarak yaz. |
| `--traffic-model-pcap-profile` | `-` | `-` | - | PCAP extractor profile adı (dataset pipeline için). |
| `--traffic-model-dry-validate` | `False` | `-` | - | Sadece planner üretimi+validation çalıştır, trafik gönderme. |

### GPU PCAP Generator (Test)

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--gpu-pcap` | `False` | `-` | - | GPU üzerinde sentetik PCAP üret ve çık (trafik göndermez). |
| `--gpu-pcap-duration` | `10` | `-` | - | PCAP süresi (s) |
| `--gpu-pcap-pps` | `10000` | `-` | - | Saniye başı paket sayısı (PPS) |
| `--gpu-pcap-mode` | `mix` | `mix, tcp, udp` | - | Trafik modu |
| `--gpu-pcap-src-ip` | `192.168.1.100` | `-` | - | Kaynak IPv4 |
| `--gpu-pcap-dst-ip` | `-` | `-` | - | Hedef IPv4 (boşsa: --target veya 127.0.0.1) |
| `--gpu-pcap-tcp-port` | `0` | `-` | - | TCP hedef port (0 ise: --port veya 80) |
| `--gpu-pcap-udp-port` | `0` | `-` | - | UDP hedef port (0 ise: --port veya 53) |
| `--gpu-pcap-chunk` | `200000` | `-` | - | Chunk başına paket sayısı |
| `--gpu-pcap-seed` | `0` | `-` | - | RNG seed (0: rastgele) |
| `--gpu-pcap-flow-count` | `4096` | `-` | - | Flow havuzu boyutu (gerçekçi modda kaynak port/IP çeşitliliği için). |
| `--gpu-pcap-realistic` | `False` | `-` | - | Gerçekçiliği artırılmış flow-aware profil (TTL/TOS varyasyonu, stateful TCP, UDP checksum). |
| `--gpu-pcap-udp-checksum` | `False` | `-` | - | UDP checksum hesaplamasını etkinleştir. |
| `--gpu-pcap-variable-size` | `False` | `-` | - | Değişken paket boyutu üretimini etkinleştir (V2). |
| `--gpu-pcap-mtu` | `1500` | `-` | - | L3 MTU değeri (128-1500). Paket boyutu dağılımı bu sınıra göre üretilir. |
| `--gpu-pcap-size-profile` | `mixed` | `mixed, web, dns` | - | Değişken paket boyutu profili. |
| `--gpu-pcap-realism-report` | `False` | `-` | - | Üretilen PCAP için V3 gerçekçilik skoru ve metrik raporu üret. |
| `--gpu-pcap-realism-baseline` | `-` | `-` | - | Gerçekçilik skorunu bu referans PCAP'a göre hesapla (opsiyonel). |
| `--gpu-pcap-realism-sample` | `100000` | `-` | - | Gerçekçilik analizinde incelenecek maksimum paket sayısı. |
| `--gpu-pcap-realism-out` | `-` | `-` | - | Gerçekçilik raporu JSON dosya adı (varsayılan: <out>.realism.json). |
| `--gpu-pcap-out` | `-` | `-` | - | Çıktı dosya adı (proje klasörüne kaydedilir) |
| `--gpu-pcap-run-report` | `False` | `-` | - | GPU PCAP calismasi icin musteri-odakli run raporu uret (JSON/Markdown). |
| `--gpu-pcap-run-report-format` | `both` | `json, md, both` | - | Run raporu cikti formati. |
| `--gpu-pcap-run-report-out` | `-` | `-` | - | Run raporu dosya adi (bossa: <out>.run.json/.md). |

### Pacing Options (Deterministic Timing)

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--pacing-mode` | `none` | `none, rps, ipg, burst` | - | Paket pacing stratejisi: none=sınırsız burst, rps=rate-limit, ipg=sabit gap, burst=batch+gap |
| `--ipg` | `0` | `-` | - | Inter-Packet Gap (nanosaniye). --pacing-mode ipg ile kullanılır. Örnek: 10000 = 10µs |
| `--burst-size` | `64` | `-` | - | Burst modunda tek seferde gönderilecek paket sayısı (varsayılan: 64) |
| `--burst-gap` | `0` | `-` | - | Burst'ler arası bekleme süresi (nanosaniye) |
| `--jitter-model` | `none` | `none, uniform, gaussian, exponential` | - | Jitter dağılım modeli (pacing üzerine uygulanır) |
| `--jitter-pct` | `0.0` | `-` | - | Jitter yüzdesi (0.0-1.0). Base gap'in bu kadarı kadar sapma uygulanır. |
| `--pin-cpu` | `-1` | `-` | - | Pacing engine'i belirli bir CPU çekirdeğine sabitle (-1: otomatik) |
| `--use-so-txtime` | `False` | `-` | - | Kernel SO_TXTIME/ETF offload kullan (Linux 4.19+, root gerektirir) |

### Safety Options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--allow-target` | `[]` | `-` | - | İzin verilen hedef(ler). IP veya CIDR. Çoklu kullanım: --allow-target 10.0.0.0/8 --allow-target 192.168.1.10 |
| `--allow-public-target` | `False` | `-` | - | Public (internet) hedeflere izin ver (tehlikeli). Varsayılan: engelli. |
| `--safety-global-deny-target` | `[]` | `-` | - | Her kosulda yasak hedef(ler): IP veya CIDR. Coklu kullanim desteklenir. |
| `--safety-auto-abort` | `True` | `-` | - | Canli izleme alarmi olusursa tum worker'lari otomatik sonlandir. |
| `--disable-safety-auto-abort` | `False` | `-` | - | Canli izleme alarminda otomatik abort'u kapat. |

### Anomaly Packet Options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--anomaly-types` | `-` | `-` | - | Anomaly types to use (0=InvalidIHL, 1=InvalidIPLen, 2=InvalidIPVer, 3=InvalidProto, 4=TCPFlagAbuse, 5=InvalidTCPOffset, 6=OverlapFrags, 7=TinyFrags, 8=LandAttack, 9=InvalidChecksum, 10=TTLAnomaly, 11=MalformedOptions). Default: all. |
| `--anomaly-intensity` | `75` | `-` | - | Anomaly intensity 0-100 (how malformed the packets are). Default: 75 |
| `--anomaly-suite` | `False` | `-` | - | Use full anomaly suite (standard + overlapping frags + tiny frags) |

### PCAP Replay Options

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--pcap-file` | `-` | `-` | - | PCAP / PCAP-NG dosyası yolu (pcap-replay vektörü için gereklidir). |
| `--pcap-timing` | `original` | `original, topspeed, multiplier, rps` | - | Replay zamanlama modu: original=orijinal gap, topspeed=maks hız, multiplier=N× hız çarpanı, rps=sabit paket/sn. |
| `--pcap-speed` | `1.0` | `-` | - | Hız çarpanı (multiplier modu için). 2.0 = 2× hızlı. Varsayılan: 1.0 |
| `--pcap-loops` | `1` | `-` | - | PCAP dosyasını kaç kez tekrar oynat (0 = sonsuz). Varsayılan: 1 |
| `--pcap-max-packets` | `0` | `-` | - | Oynatılacak maksimum paket sayısı (0 = hepsi). Varsayılan: 0 |
| `--pcap-filter-proto` | `-` | `-` | - | Protokol filtresi (tcp, udp, icmp). Birden fazla belirtilebilir. |
| `--pcap-filter-src-ip` | `-` | `-` | - | Kaynak IP filtresi (IP veya CIDR). Örn: 192.168.1.0/24 |
| `--pcap-filter-dst-ip` | `-` | `-` | - | Hedef IP filtresi (IP veya CIDR). |
| `--pcap-filter-src-port` | `-` | `-` | - | Kaynak port filtresi. |
| `--pcap-filter-dst-port` | `-` | `-` | - | Hedef port filtresi. |
| `--pcap-filter-min-len` | `0` | `-` | - | Minimum paket boyutu filtresi (byte). |
| `--pcap-filter-max-len` | `0` | `-` | - | Maksimum paket boyutu filtresi (byte, 0=sınırsız). |
| `--pcap-strip-eth` | `False` | `-` | - | Ethernet başlığını soyup sadece raw IP olarak gönder. |
| `--pcap-use-l2` | `False` | `-` | - | PCAP replay'i L2 TX_RING yolu ile gönder (Ethernet frame korunur). |
| `--pcap-no-flow-aware` | `False` | `-` | - | PCAP replay TCP flow-aware seq/ack delta rewrite'i kapat. |
| `--pcap-src-ip-override` | `-` | `-` | - | Tüm paketlerin kaynak IP'sini bu değerle değiştir. |
| `--pcap-src-port-override` | `-` | `-` | - | Tüm paketlerin kaynak portunu bu değerle değiştir. |
| `--pcap-batch-size` | `512` | `-` | - | Timing-aware modda batch boyutu. Varsayılan: 512 |
| `--pcap-info` | `False` | `-` | - | PCAP dosyasının özetini göster ve çık (trafik göndermez). |

### Reporting / Self-Test

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--self-test` | `False` | `-` | - | Unittest discovery calistir ve cik (trafik gondermez). |
| `--run-report` | `False` | `-` | - | Calisma raporu uret (live + offline/test modlari). |
| `--run-report-format` | `both` | `json, md, both` | - | Run raporu cikti formati. |
| `--run-report-out` | `-` | `-` | - | Run raporu base dosya adi (bossa otomatik). Uzanti eklemeyin (ornek: reports/run_001). |
| `--run-report-dir` | `reports/runs` | `-` | - | Run raporu cikti dizini (varsayilan: reports/runs). |
| `--soak-profile` | `none` | `none, 1h, 6h, 24h` | - | Soak test profili (1h/6h/24h) ve varsayilan pass/fail esikleri. |
| `--soak-snapshot-interval` | `0` | `-` | - | Soak snapshot araligi (s). 0=profile default, aralik 10-30s. |
| `--soak-warmup-s` | `0` | `-` | - | Soak warm-up suresi (s). 0=profile default; baseline bu sureden sonra kilitlenir. |
| `--soak-max-error-rate-pct` | `-` | `-` | - | Soak pass/fail: maksimum hata orani (%%). |
| `--soak-max-pps-drop-pct` | `-` | `-` | - | Soak pass/fail: baseline'e gore maksimum PPS dusus (%%). |
| `--soak-max-rss-growth-mb` | `-` | `-` | - | Soak pass/fail: maksimum RSS artis limiti (MB). |
| `--soak-max-vram-growth-mb` | `-` | `-` | - | Soak pass/fail: maksimum VRAM artis limiti (MB). |
| `--soak-max-pinned-growth-mb` | `-` | `-` | - | Soak pass/fail: maksimum pinned-memory artis limiti (MB). |
| `--soak-max-backlog` | `-` | `-` | - | Soak pass/fail: maksimum backlog limiti (paket). |
| `--loss-telemetry` | `auto` | `auto, 0, 1` | - | Wire-loss telemetry modu: auto\|0\|1 (varsayilan: auto). |
| `--loss-iface` | `-` | `-` | - | Loss telemetry icin arayuz ismi (opsiyonel, bossa otomatik). |
| `--loss-fail-pct` | `5.0` | `-` | - | Wire-loss fail esigi (%%). Varsayilan: 5. |
| `--loss-report-out` | `-` | `-` | - | Canli run sonunda loss telemetry JSON ciktisi (opsiyonel dosya yolu). |

### Fault Injection

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--fault-inject` | `[]` | `sender-restart, nic-blip, gpu-stream-error, mix` | - | Soak test fault senaryolari (simulasyon). Birden fazla verilebilir. |
| `--fault-after-s` | `0.0` | `-` | - | Fault injection tetikleme suresi (s). 0=kapali. |
| `--fault-duration-s` | `2.0` | `-` | - | Fault simulasyon suresi (s). |

### License Management

| Flag | Default | Choices | ENV | Aciklama |
|---|---|---|---|---|
| `--license-key` | `-` | `-` | `SAMURAI_LICENSE_KEY` | Lisans anahtarı (SAM-XXXX-XXXX-XXXX-XXXX). Alternatif: SAMURAI_LICENSE_KEY env veya ~/.samurai/license.key dosyası. |
| `--license-file` | `-` | `-` | - | Lisans anahtarını içeren dosya yolu. |
| `--license-info` | `False` | `-` | - | Aktif lisans bilgilerini göster ve çık. |
| `--license-deactivate` | `False` | `-` | - | Bu cihazı lisanstan kaldır ve çık. |
| `--license-activate` | `False` | `-` | - | Bu cihazı lisans anahtarıyla etkinleştir ve çık. |
| `--license-account` | `False` | `-` | - | Lisans hesabı özetini göster (abonelik, cihazlar, süreler). |
| `--license-trial` | `False` | `-` | - | 14 günlük Pro deneme sürümü başlat. |

## 3) Tum CLI ENV Degiskenleri (`SAMURAI_*`)

Bu liste, `ddos_samurai/cli/*.py` altinda referanslanan tum env adlarini icerir.

| ENV | Iliskili CLI Flag(ler) | Kod Referansi |
|---|---|---|
| `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | `--afpacket-block-size-kb` | `ddos_samurai/cli/args.py:876`<br>`ddos_samurai/cli/env.py:103` |
| `SAMURAI_AF_PACKET_BUSY_POLL_US` | `--afpacket-busy-poll-us` | `ddos_samurai/cli/args.py:906`<br>`ddos_samurai/cli/env.py:108` |
| `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | `--afpacket-frames-per-block` | `ddos_samurai/cli/args.py:888`<br>`ddos_samurai/cli/env.py:105` |
| `SAMURAI_AF_PACKET_FRAME_SIZE` | `--afpacket-frame-size` | `ddos_samurai/cli/args.py:882`<br>`ddos_samurai/cli/env.py:104` |
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | - | `ddos_samurai/cli/args.py:853`<br>`ddos_samurai/cli/env.py:100` |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `--afpacket-hugepage-size-kb` | `ddos_samurai/cli/args.py:864`<br>`ddos_samurai/cli/env.py:101` |
| `SAMURAI_AF_PACKET_MLOCK_RING` | - | `ddos_samurai/cli/args.py:937`<br>`ddos_samurai/cli/env.py:110` |
| `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | `--afpacket-poll-timeout-ms` | `ddos_samurai/cli/args.py:894`<br>`ddos_samurai/cli/env.py:106` |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | - | `ddos_samurai/cli/args.py:952`<br>`ddos_samurai/cli/env.py:111` |
| `SAMURAI_AF_PACKET_QDISC_BYPASS` | - | `ddos_samurai/cli/args.py:922`<br>`ddos_samurai/cli/env.py:109` |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `--afpacket-ring-target-mb` | `ddos_samurai/cli/args.py:870`<br>`ddos_samurai/cli/env.py:102` |
| `SAMURAI_AF_PACKET_SPIN_LIMIT` | `--afpacket-spin-limit` | `ddos_samurai/cli/args.py:900`<br>`ddos_samurai/cli/env.py:107` |
| `SAMURAI_CLUSTER_SECRET` | `--cluster-secret` | `ddos_samurai/cli/args.py:121` |
| `SAMURAI_CONTROL_JWT_SECRET` | `--control-jwt-secret` | `ddos_samurai/cli/args.py:405` |
| `SAMURAI_CONTROL_RBAC_ADMIN_SECRET` | `--control-rbac-admin-secret` | `ddos_samurai/cli/args.py:381` |
| `SAMURAI_CONTROL_RBAC_AUDIT_LOG_PATH` | `--control-rbac-audit-log-path` | `ddos_samurai/cli/args.py:591` |
| `SAMURAI_CONTROL_RBAC_OPERATOR_SECRET` | `--control-rbac-operator-secret` | `ddos_samurai/cli/args.py:387` |
| `SAMURAI_CONTROL_RBAC_VIEWER_SECRET` | `--control-rbac-viewer-secret` | `ddos_samurai/cli/args.py:393` |
| `SAMURAI_CONTROL_RBAC_WORKER_SECRET` | `--control-rbac-worker-secret` | `ddos_samurai/cli/args.py:399` |
| `SAMURAI_CONTROL_TLS_RELOAD_INTERVAL_S` | `--control-tls-reload-interval-s` | `ddos_samurai/cli/args.py:610` |
| `SAMURAI_CUSTOM_TCP_BACKEND` | `--custom-tcp-backend` | `ddos_samurai/cli/args.py:1080`<br>`ddos_samurai/cli/env.py:141` |
| `SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS` | `--custom-tcp-connect-timeout-ms` | `ddos_samurai/cli/args.py:1098` |
| `SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS` | `--custom-tcp-idle-timeout-ms` | `ddos_samurai/cli/args.py:1104` |
| `SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS` | `--custom-tcp-initial-rto-ms` | `ddos_samurai/cli/args.py:1086` |
| `SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS` | `--custom-tcp-max-retransmits` | `ddos_samurai/cli/args.py:1092` |
| `SAMURAI_CUSTOM_TCP_MODE` | `--custom-tcp-mode` | `ddos_samurai/cli/args.py:1056`<br>`ddos_samurai/cli/env.py:140` |
| `SAMURAI_DATAPLANE_CORE_ENABLE` | - | `ddos_samurai/cli/env.py:97` |
| `SAMURAI_DATAPLANE_CORE_MODE` | - | `ddos_samurai/cli/args.py:842`<br>`ddos_samurai/cli/env.py:96` |
| `SAMURAI_DP_QUEUES` | `--dp-queues` | `ddos_samurai/cli/args.py:969`<br>`ddos_samurai/cli/env.py:115` |
| `SAMURAI_DP_QUEUE_MAP` | `--dp-queue-map` | `ddos_samurai/cli/args.py:975`<br>`ddos_samurai/cli/env.py:116` |
| `SAMURAI_DP_QUEUE_STRATEGY` | `--dp-queue-strategy` | `ddos_samurai/cli/args.py:963`<br>`ddos_samurai/cli/env.py:114` |
| `SAMURAI_GPU_BATCH` | `--gpu-batch-size` | `ddos_samurai/cli/args.py:1258`<br>`ddos_samurai/cli/args.py:1259`<br>`ddos_samurai/cli/env.py:39` |
| `SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS` | `--gpu-batch-flush-timeout-ms` | `ddos_samurai/cli/args.py:1378`<br>`ddos_samurai/cli/env.py:78` |
| `SAMURAI_GPU_BATCH_MAX` | `--gpu-batch-max` | `ddos_samurai/cli/args.py:1372`<br>`ddos_samurai/cli/env.py:77` |
| `SAMURAI_GPU_CLASSIFIER_ENGINE_PATH` | `--gpu-classifier-engine-path` | `ddos_samurai/cli/args.py:1354`<br>`ddos_samurai/cli/env.py:71` |
| `SAMURAI_GPU_CLASSIFIER_RUNTIME` | `--gpu-classifier-runtime` | `ddos_samurai/cli/args.py:1348`<br>`ddos_samurai/cli/env.py:70` |
| `SAMURAI_GPU_DEFENSE_MODE` | `--gpu-defense-mode` | `ddos_samurai/cli/args.py:1342`<br>`ddos_samurai/cli/env.py:69` |
| `SAMURAI_GPU_EPOCH_MS` | `--gpu-epoch-ms` | `ddos_samurai/cli/args.py:1312`<br>`ddos_samurai/cli/env.py:61` |
| `SAMURAI_GPU_FULL_VARIATION` | `--gpu-full-variation, --no-gpu-full-variation` | `ddos_samurai/cli/args.py:1276`<br>`ddos_samurai/cli/env.py:42` |
| `SAMURAI_GPU_HEARTBEAT_MS` | `--gpu-heartbeat-ms` | `ddos_samurai/cli/args.py:1324`<br>`ddos_samurai/cli/env.py:63` |
| `SAMURAI_GPU_KERNEL_MODE` | `--gpu-kernel-mode` | `ddos_samurai/cli/args.py:1291`<br>`ddos_samurai/cli/args.py:1298`<br>`ddos_samurai/cli/env.py:51` |
| `SAMURAI_GPU_NO_PROGRESS_MS` | `--gpu-no-progress-ms` | `ddos_samurai/cli/args.py:1330`<br>`ddos_samurai/cli/env.py:64` |
| `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | `--gpu-packet-zerocopy-output, --no-gpu-packet-zerocopy-output` | `ddos_samurai/cli/args.py:1288`<br>`ddos_samurai/cli/args.py:1289`<br>`ddos_samurai/cli/env.py:44` |
| `SAMURAI_GPU_PINNED_MAX_MB` | `--gpu-pinned-max-mb` | `ddos_samurai/cli/args.py:1282`<br>`ddos_samurai/cli/args.py:1283`<br>`ddos_samurai/cli/env.py:43` |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `--gpu-pipeline-depth` | `ddos_samurai/cli/args.py:1270`<br>`ddos_samurai/cli/env.py:41` |
| `SAMURAI_GPU_QUEUE_COUNT` | `--gpu-queue-count` | `ddos_samurai/cli/args.py:1318`<br>`ddos_samurai/cli/env.py:62` |
| `SAMURAI_GPU_RDMA_MODE` | `--gpu-rdma-mode` | `ddos_samurai/cli/args.py:1360`<br>`ddos_samurai/cli/env.py:75` |
| `SAMURAI_GPU_RDMA_STRICT` | `--gpu-rdma-strict, --no-gpu-rdma-strict` | `ddos_samurai/cli/args.py:1366`<br>`ddos_samurai/cli/env.py:76` |
| `SAMURAI_GPU_RING_CAPACITY` | `--gpu-ring-capacity` | `ddos_samurai/cli/args.py:1252`<br>`ddos_samurai/cli/args.py:1253`<br>`ddos_samurai/cli/env.py:38` |
| `SAMURAI_GPU_RNG_SEED` | `--gpu-rng-seed` | `ddos_samurai/cli/args.py:1336`<br>`ddos_samurai/cli/args.py:1337`<br>`ddos_samurai/cli/env.py:65` |
| `SAMURAI_GPU_RX_BATCH_SIZE` | `--gpu-rx-batch-size` | `ddos_samurai/cli/args.py:1402`<br>`ddos_samurai/cli/env.py:85` |
| `SAMURAI_GPU_RX_DURATION_S` | `--gpu-rx-duration-s` | `ddos_samurai/cli/args.py:1396`<br>`ddos_samurai/cli/env.py:84` |
| `SAMURAI_GPU_RX_IFACE` | `--gpu-rx-iface` | `ddos_samurai/cli/args.py:1390`<br>`ddos_samurai/cli/env.py:83` |
| `SAMURAI_GPU_RX_MAX_PACKETS` | `--gpu-rx-max-packets` | `ddos_samurai/cli/args.py:1408`<br>`ddos_samurai/cli/env.py:86` |
| `SAMURAI_GPU_RX_PIPELINE` | `--gpu-rx-pipeline` | `ddos_samurai/cli/args.py:1384`<br>`ddos_samurai/cli/env.py:82` |
| `SAMURAI_GPU_RX_SNAPLEN` | `--gpu-rx-snaplen` | `ddos_samurai/cli/args.py:1414`<br>`ddos_samurai/cli/env.py:87` |
| `SAMURAI_GPU_STREAMS` | `--gpu-stream-count` | `ddos_samurai/cli/args.py:1264`<br>`ddos_samurai/cli/env.py:40` |
| `SAMURAI_GPU_STREAM_API` | `--gpu-stream-api` | `ddos_samurai/cli/args.py:1300`<br>`ddos_samurai/cli/args.py:1307`<br>`ddos_samurai/cli/env.py:52` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | `--gpu-template-pool-size-l4` | `ddos_samurai/cli/args.py:1240`<br>`ddos_samurai/cli/args.py:1241`<br>`ddos_samurai/cli/env.py:36` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | `--gpu-template-pool-size-l7` | `ddos_samurai/cli/args.py:1246`<br>`ddos_samurai/cli/args.py:1247`<br>`ddos_samurai/cli/env.py:37` |
| `SAMURAI_GPU_TX_BACKEND` | - | `ddos_samurai/cli/env.py:53`<br>`ddos_samurai/cli/env.py:59`<br>`ddos_samurai/cli/validation.py:704`<br>`ddos_samurai/cli/validation.py:712`<br>... |
| `SAMURAI_GPU_TX_BACKEND_STRICT` | - | `ddos_samurai/cli/env.py:54`<br>`ddos_samurai/cli/env.py:60`<br>`ddos_samurai/cli/validation.py:706`<br>`ddos_samurai/cli/validation.py:723`<br>... |
| `SAMURAI_GPU_VECTOR_ENGINE` | - | `ddos_samurai/cli/args.py:1417` |
| `SAMURAI_KPI_GATE_PROFILE` | `--kpi-gate-profile` | `ddos_samurai/cli/args.py:1110`<br>`ddos_samurai/cli/env.py:126` |
| `SAMURAI_KPI_HARD_FAIL` | - | `ddos_samurai/cli/env.py:127` |
| `SAMURAI_L7_CAPABILITY_STRICT` | `--l7-capability-strict` | `ddos_samurai/cli/args.py:1163`<br>`ddos_samurai/cli/env.py:135` |
| `SAMURAI_L7_ENGINE` | `--l7-engine` | `ddos_samurai/cli/args.py:1121`<br>`ddos_samurai/cli/env.py:128` |
| `SAMURAI_L7_FALLBACK_POLICY` | `--l7-fallback-policy` | `ddos_samurai/cli/args.py:1157`<br>`ddos_samurai/cli/env.py:134` |
| `SAMURAI_L7_HTTP2_ENGINE` | `--l7-http2-engine` | `ddos_samurai/cli/args.py:1127`<br>`ddos_samurai/cli/env.py:129` |
| `SAMURAI_L7_QUIC_AUTO_BRIDGE` | `--l7-quic-auto-bridge` | `ddos_samurai/cli/args.py:1145`<br>`ddos_samurai/cli/env.py:132` |
| `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | `--l7-quic-bridge-autopromote` | `ddos_samurai/cli/args.py:1151`<br>`ddos_samurai/cli/env.py:133` |
| `SAMURAI_L7_QUIC_ENGINE` | `--l7-quic-engine` | `ddos_samurai/cli/args.py:1133`<br>`ddos_samurai/cli/env.py:130` |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `--l7-quic-require-native` | `ddos_samurai/cli/args.py:1139`<br>`ddos_samurai/cli/env.py:131` |
| `SAMURAI_LAB_PROFILE` | `--lab-profile` | `ddos_samurai/cli/args.py:957`<br>`ddos_samurai/cli/env.py:113` |
| `SAMURAI_LICENSE_KEY` | `--license-key` | `ddos_samurai/cli/app.py:32`<br>`ddos_samurai/cli/app.py:165`<br>`ddos_samurai/cli/app.py:182`<br>`ddos_samurai/cli/args.py:1813` |
| `SAMURAI_LOSS_FAIL_PCT` | - | `ddos_samurai/cli/env.py:24` |
| `SAMURAI_LOSS_IFACE` | - | `ddos_samurai/cli/env.py:27`<br>`ddos_samurai/cli/env.py:29` |
| `SAMURAI_LOSS_REPORT_OUT` | - | `ddos_samurai/cli/env.py:32`<br>`ddos_samurai/cli/env.py:34` |
| `SAMURAI_LOSS_TELEMETRY` | - | `ddos_samurai/cli/env.py:23` |
| `SAMURAI_MANAGEMENT_API_ADMIN_TOKEN` | `--management-api-admin-token` | `ddos_samurai/cli/args.py:298` |
| `SAMURAI_MANAGEMENT_API_AUTH_TOKEN` | `--management-api-auth-token` | `ddos_samurai/cli/args.py:292` |
| `SAMURAI_MANAGEMENT_API_JWT_SECRET` | `--management-api-jwt-secret` | `ddos_samurai/cli/args.py:316` |
| `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` | `--management-api-operator-token` | `ddos_samurai/cli/args.py:304` |
| `SAMURAI_MANAGEMENT_API_TRUSTED_IDENTITY_SECRET` | `--management-api-trusted-identity-secret` | `ddos_samurai/cli/args.py:334` |
| `SAMURAI_MANAGEMENT_API_VIEWER_TOKEN` | `--management-api-viewer-token` | `ddos_samurai/cli/args.py:310` |
| `SAMURAI_MULTI_MASTER_DEQUEUE_MAX` | `--multi-master-dequeue-max` | `ddos_samurai/cli/args.py:585` |
| `SAMURAI_MULTI_MASTER_HEARTBEAT_TTL_S` | `--multi-master-heartbeat-ttl-s` | `ddos_samurai/cli/args.py:579` |
| `SAMURAI_MULTI_MASTER_NAMESPACE` | `--multi-master-namespace` | `ddos_samurai/cli/args.py:573` |
| `SAMURAI_MULTI_MASTER_REDIS_URL` | `--multi-master-redis-url` | `ddos_samurai/cli/args.py:567` |
| `SAMURAI_MULTI_MASTER_REGION_ID` | `--multi-master-region-id` | `ddos_samurai/cli/args.py:561` |
| `SAMURAI_PROM_TEXTFILE_RESULTS` | - | `ddos_samurai/cli/reporting.py:20` |
| `SAMURAI_QUIC_BUILD_MODE` | - | `ddos_samurai/cli/validation.py:657`<br>`ddos_samurai/cli/validation.py:659`<br>`ddos_samurai/cli/validation.py:660` |
| `SAMURAI_SENDER_BACKEND` | - | `ddos_samurai/cli/env.py:92` |
| `SAMURAI_SENDER_FALLBACK_POLICY` | - | `ddos_samurai/cli/env.py:93` |
| `SAMURAI_STATEFUL_RUNTIME_BACKEND` | - | `ddos_samurai/cli/args.py:830`<br>`ddos_samurai/cli/env.py:139` |
| `SAMURAI_STATE_ENGINE_MODE` | `--state-engine-mode, --engine-mode` | `ddos_samurai/cli/args.py:1026` |
| `SAMURAI_STATE_LOCK_COUNT` | `--state-lock-count` | `ddos_samurai/cli/args.py:1038`<br>`ddos_samurai/cli/env.py:89` |
| `SAMURAI_STATE_SWEEP_INTERVAL_MS` | `--state-sweep-interval-ms` | `ddos_samurai/cli/args.py:1050`<br>`ddos_samurai/cli/env.py:91` |
| `SAMURAI_STATE_TABLE_SIZE` | `--state-table-size` | `ddos_samurai/cli/args.py:1032`<br>`ddos_samurai/cli/env.py:88` |
| `SAMURAI_STATE_TIMEOUT_SEC` | `--state-timeout-sec` | `ddos_samurai/cli/args.py:1044`<br>`ddos_samurai/cli/env.py:90` |
| `SAMURAI_TARGET_REGION` | `--target-region` | `ddos_samurai/cli/args.py:655` |
| `SAMURAI_TENANT_NAMESPACE` | `--tenant-namespace` | `ddos_samurai/cli/args.py:696` |
| `SAMURAI_WORKER_REGION` | `--worker-region` | `ddos_samurai/cli/args.py:649` |
| `SAMURAI_XDP_ATTACH_BPF` | - | `ddos_samurai/cli/args.py:1001`<br>`ddos_samurai/cli/env.py:121` |
| `SAMURAI_XDP_BPF_OBJ` | `--xdp-bpf-obj` | `ddos_samurai/cli/args.py:1012`<br>`ddos_samurai/cli/env.py:123` |
| `SAMURAI_XDP_BPF_SECTION` | `--xdp-bpf-section` | `ddos_samurai/cli/args.py:1006`<br>`ddos_samurai/cli/env.py:122` |
| `SAMURAI_XDP_ENABLE` | - | `ddos_samurai/cli/env.py:117` |
| `SAMURAI_XDP_INTERFACE` | - | `ddos_samurai/cli/env.py:118` |
| `SAMURAI_XDP_MODE` | `--xdp-mode` | `ddos_samurai/cli/args.py:985`<br>`ddos_samurai/cli/env.py:120` |
| `SAMURAI_XDP_QUEUE_ID` | - | `ddos_samurai/cli/env.py:119` |
| `SAMURAI_XDP_XSKMAP_PIN` | `--xdp-xskmap-pin` | `ddos_samurai/cli/args.py:1018`<br>`ddos_samurai/cli/env.py:124` |

## 4) Oncelik ve Deger Kurallari

Genel precedence (tipik):
1. CLI flag degeri
2. YAML config degeri (`--config`)
3. Env/default degeri

Lisans ozel notu: `--license-key` > `SAMURAI_LICENSE_KEY` > `~/.samurai/license.key`.

Control-plane ozel notu: bazi token/secret degerleri yalniz env uzerinden tasinmaya daha uygundur (ornek: `SAMURAI_CLUSTER_SECRET`, `SAMURAI_MANAGEMENT_API_*`).

## 5) ZMQ Worker ve DOCA/DPU-GPU Native Env Notlari

Asagidaki env adlari ZMQ worker runtime veya native CUDA/DOCA katmaninda
kullanilir; hepsi parser flag'i olarak gecmeyebilir.

### ZMQ worker runtime

- `SAMURAI_ZMQ_WORKER_DIR`
  - Native worker binary'leri icin arama dizini.
  - `zmq_worker_search_dir` runtime/config alanı verilirse o deger onceliklidir.
- `SAMURAI_XDP_NATIVE_LIB`
  - AF_XDP worker icin native sender library path override.

Varsayilan endpoint'ler `ddos_samurai/zmq/wire.py` icindedir:

- `ipc:///tmp/samurai_jobs_<kind>`
- `ipc:///tmp/samurai_events_<kind>`

Detay: `docs/36-zmq-worker-architecture.md`

### DOCA/GPUNetIO ve DPU/GPU contract

- `SAMURAI_GPU_DOCA_ENABLE`
- `SAMURAI_GPU_DOCA_DEVICE`
- `SAMURAI_GPU_DOCA_GPU_ID`
- `SAMURAI_GPU_DOCA_SHIM_SO`
- `SAMURAI_GPU_DOCA_RX_QUEUE_ID`
- `SAMURAI_GPU_DOCA_RX_QUEUE_COUNT`
- `SAMURAI_GPU_DOCA_RX_DEVICE_PATH`
- `SAMURAI_GPU_DOCA_RX_DEVICE_PATH_STRICT`
- `SAMURAI_GPU_DOCA_FLOW_STEERING`
- `SAMURAI_GPU_DOCA_FLOW_STEERING_STRICT`
- `SAMURAI_GPU_DOCA_FLOW_PROTO_MASK`
- `SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS`
- `SAMURAI_GPU_DOCA_FLOW_STREAMS_MULTI_PIPE`
- `SAMURAI_GPU_DOCA_FLOW_SHIM_SO`
- `SAMURAI_GPU_JOB_ENDPOINT`
- `SAMURAI_DPU_STATE_PUBLISH`
- `SAMURAI_DPU_TCP_RX_FEEDBACK`
- `SAMURAI_DPU_TCP_PASSIVE_OPEN`
- `SAMURAI_DPU_TCP_PASSIVE_OPEN_TIMEOUT_MS`
- `SAMURAI_DPU_CONTRACT_RDMA`
- `SAMURAI_DPU_CONTRACT_RDMA_SPEC`
- `SAMURAI_GPU_CONTRACT_EXPORT_KIND`
- `SAMURAI_GPU_CONTRACT_EXPORT_SPEC`
- `SAMURAI_GPU_CONTRACT_EXPORT_PATH`

Strict calisma beklentisi:

1. `SAMURAI_GPU_TX_BACKEND=doca_gpunetio`
2. `SAMURAI_GPU_TX_BACKEND_STRICT=1`
3. `SAMURAI_GPU_DOCA_ENABLE=1`
4. `SAMURAI_GPU_DOCA_DEVICE` dolu
5. `--xdp-interface` verilmis

Bu kombinasyonda amac fallback degil, ortam hazir degilse net fail-visible davranistir.

DOCA worker runtime flag'leri:

- `--gpu-job-endpoint`
- `--dpu-state-publish 0|1`
- `--dpu-contract-rdma`
- `--dpu-contract-rdma-spec <spec>`
- `--dpu-tcp-rx-feedback`
- `--no-dpu-tcp-rx-feedback`
- `--dpu-tcp-passive-open`
- `--doca-interface <iface>`
- `--doca-device <device>`
- `--doca-queue-id <id>`
- `--doca-rx-queue-id <id>`
- `--doca-gpu-id <id>`
- `--doca-batch-size <n>`

Detay: `docs/37-dpu-gpu-dataplane-architecture.md`

## 6) Bakim Notu

Bu dosya `ddos_samurai.cli.args.build_parser()` introspection'i + `ddos_samurai/cli/*.py` env taramasi ile guncellenebilir. Yeni flag/env eklediginde bu referansi da birlikte guncelle.
