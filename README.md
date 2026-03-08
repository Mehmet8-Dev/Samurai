# DDoSamurai v2.0

DDoSamurai, **yalnizca yetkili ortamlarda** kullanilmak uzere tasarlanmis, moduler bir ag stres ve guvenlik test platformudur.

Proje; tek bir CLI uzerinden CPU/GPU veri yollari, C hizlandirma katmanlari, opsiyonel SaaS API + dashboard ve dis monitoring yiginini birlestirir.

## Durum Ozeti

- Mimari: Python + C extension + opsiyonel CUDA + FastAPI + React
- Olgunluk: Guclu teknik beta / pilot-ready
- Odak: Yetkili ortamlarda L4/L7 yuk testi, davranis testi, gozlemlenebilirlik

## Yasal ve Etik Sinir

Bu proje sadece izinli hedeflerde kullanilmalidir.
Yetkisiz sistemlere trafik gondermek yasa disi olabilir ve tum sorumluluk kullanicidadir.

## Ana Bilesenler

- CLI giris noktasi: `advv2.py`, `ddos_samurai/cli.py`
- Worker / dispatch: `ddos_samurai/orchestrator.py`
- Sender katmani: `ddos_samurai/senders.py`
- CPU paket uretimi: `ddos_samurai/packet.py`, `ddos_samurai/cpu_packet_engine.py`
- GPU paket/payload: `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_payload.py`, `ddos_samurai/anomaly_packet.py`
- C hizlandirma: `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c`, `ddos_samurai/xdp_sender.c`
- API/SaaS: `ddos_samurai/api.py`
- Dashboard: `dashboard/`
- Monitoring stack: `monitoring/`

## Desteklenen Modlar ve Vektorler

- Backend: `cpu`, `cuda`
- L4/L3: TCP, UDP, ICMP, spoofing, pcap replay
- L7: HTTP, HTTP/2, WebSocket, QUIC
- Diger: slow-* senaryolari, amplification simule akislari, anomaly paket akislari
- Yardimci modlar: `--dry-run`, `--self-test`, run report, soak profile

## Kurulum

### 1) Temel kurulum (CPU odakli)

```bash
pip install -r requirements.txt
```

### 2) C extension build (onerilen)

```bash
python setup.py build_ext --inplace
```

### 3) Opsiyonel GPU kurulum

GPU kullaniminda CUDA uyumlu ortama ihtiyac vardir.

```bash
pip install cupy-cuda12x numba-cuda[cu13]
```

### CUDA Hybrid Raw Knob'lari (Yeni)

- `--gpu-template-pool-size-l4` (vars: `10`, env: `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4`)
- `--gpu-template-pool-size-l7` (vars: `50`, env: `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7`)
- `--gpu-ring-capacity` (vars: `3`, env: `SAMURAI_GPU_RING_CAPACITY`)
- `--gpu-pinned-max-mb` (vars: `512`, env: `SAMURAI_GPU_PINNED_MAX_MB`)
- `--state-table-size` (vars: `65536`, env: `SAMURAI_STATE_TABLE_SIZE`)
- `--state-lock-count` (vars: `256`, env: `SAMURAI_STATE_LOCK_COUNT`)
- `--state-timeout-sec` (vars: `60`, env: `SAMURAI_STATE_TIMEOUT_SEC`)
- `--state-sweep-interval-ms` (vars: `1000`, env: `SAMURAI_STATE_SWEEP_INTERVAL_MS`)

### AF_PACKET HugePage Policy (Yeni)

TX_RING yolunda explicit HugePage policy first-class olarak desteklenir:

- `--afpacket-hugepage-mode {off,auto,required}`
- `--afpacket-hugepage-size-kb` (default: `2048`)
- `--afpacket-ring-target-mb` (default: `64`)
- `--afpacket-block-size-kb` (default: `0`, auto)
- `--afpacket-frame-size` (default: `0`, auto)
- `--afpacket-frames-per-block` (default: `64`)
- `--afpacket-poll-timeout-ms` (default: `1`)
- `--afpacket-spin-limit` (default: `2000`)
- `--afpacket-busy-poll-us` (default: `0`)
- `--afpacket-qdisc-bypass` / `--no-afpacket-qdisc-bypass`
- `--afpacket-mlock-ring` / `--no-afpacket-mlock-ring`
- `--afpacket-prefault-ring` / `--no-afpacket-prefault-ring`

`--lab-profile dedicated` + `--sender-backend txring` kombinasyonunda mode otomatik `required` olur.
Detay: `docs/18-afpacket-hugepage-policy.md`

### 4) Opsiyonel browser automation (Ninja)

```bash
pip install playwright
playwright install chromium
```

## Hizli Baslangic (Guvenli)

### Self-test (trafik gondermez)

```bash
python -m ddos_samurai.cli --self-test
```

### Dry-run (konfig dogrular, gonderim yapmaz)

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 8080 \
  --protocol tcp --attack-vector basic \
  --count 100 --dry-run --confirm
```

### Profil listesi

```bash
python -m ddos_samurai.cli --list-profiles
```

## SaaS Stack (Opsiyonel)

```bash
docker compose up -d --build
```

Servisler:

- API: `http://localhost:5099`
- Dashboard: `http://localhost:8080`
- PostgreSQL: `localhost:5432` (`samurai/samurai`)
- Metrics endpoint: `http://localhost:5099/metrics`

Not: Varsayilan compose ayarlari gelistirme odaklidir. Uretimde secret, CORS, auth policy ve rate-limit hardening gereklidir.

## Monitoring (Opsiyonel, uygulama disi)

```bash
cd monitoring
docker compose up -d
```

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

Detay: `monitoring/README.md`

## Test ve CI

### Lokal test

```bash
pytest tests -q -rs
```

Frontend test:

```bash
cd dashboard
npm ci
npm run test -- --run
```

### GitHub Actions

Workflow: `.github/workflows/ci.yml`

- `Backend Tests (Python 3.11)`
- `Dashboard Tests (Node 20)`

CI ortaminda GPU/root gerektiren testler otomatik olarak skip olabilir.

## Dokumantasyon Haritasi

Detayli teknik dokumantasyon:

- `docs/README.md`
- `docs/00-overview.md`
- `docs/01-cli.md`
- `docs/02-orchestrator.md`
- `docs/03-senders.md`
- `docs/05-gpu.md`
- `docs/12-dashboard.md`
- `docs/13-api.md`
- `docs/18-afpacket-hugepage-policy.md`

## AF_PACKET HugePage Hizli Ornek

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 80 --protocol tcp \
  --attack-vector basic --count 100000 --confirm \
  --sender-backend txring --sender-fallback-policy fail \
  --afpacket-hugepage-mode auto \
  --run-report --run-report-out artifacts/live_run_hp
```

## Proje Dizini (kisa)

```text
.
├── advv2.py
├── ddos_samurai/
├── tests/
├── dashboard/
├── monitoring/
├── docs/
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Bilinen Operasyon Notlari

- Bazi sender yollari root/capability gerektirir.
- GPU yolu, CUDA surucu/runtime uyumuna baglidir.
- CI ortaminda Scapy/GPU/root kosullarina bagli skip beklenir.
- Uretim kullaniminda varsayilan ayarlarin hardening'i zorunludur.

## Lisans

Bu repoda `setup.py` siniflandirmasinda MIT lisansi belirtilmistir.
