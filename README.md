# Samurai (Kenjaku)

Samurai, **yalnızca yetkili/lab ortamlarında** kullanılmak üzere geliştirilen modüler bir ağ stres ve güvenlik test platformudur.

## Sürüm

- SemVer: `2.2.0`
- Kod adı: `Kenjaku`
- Son doğrulama tarihi: `2026-04-28`

## Hızlı Özet

- Tek giriş noktası: `python -m ddos_samurai.cli`
- Katı lisans geçidi: canlı çalıştırma öncesi lisans doğrulaması zorunlu
- L3/L4/L7 test yolları
- `cpu` + opsiyonel `cuda` üretim yolu
- Sender backend: **zorunlu `xdp`**, fallback policy: **zorunlu `fail`**
- Stateful runtime backend: **zorunlu `afxdp`**
- Native RX->GPU classify hattı: `AF_XDP RX` + `GPU defense backend`

## Yasal ve Etik Sınır

Bu proje sadece izinli hedeflerde kullanılmalıdır. Yetkisiz sistemlere trafik göndermek yasal sorunlara yol açabilir; tüm sorumluluk kullanıcıdadır.

## Kurulum

### 1) Python bağımlılıkları

```bash
pip install -r requirements.txt
```

### 2) Native/C uzantıları derleme

```bash
python setup.py build_ext --inplace
```

### 3) Opsiyonel CUDA

```bash
pip install cupy-cuda12x numba-cuda[cu13]
python setup.py build_ext --inplace
```

### 4) Opsiyonel DPDK (system dependency tree)

DPDK backend (`ddos_samurai.dpdk_pmd_core`) Python paketi ile degil, sistem kutuphaneleri ile derlenir.

- System paketleri:
  - `libdpdk-dev` (veya dagitimdaki esdegeri)
  - `pkg-config`
  - `build-essential` / `gcc` / `g++`
- Runtime gereksinimleri:
  - hugepage konfigurasyonu
  - DPDK-uyumlu NIC + uygun driver binding (`vfio-pci` / uygun PMD)

Ornek derleme:

```bash
SAMURAI_WITH_DPDK=1 python setup.py build_ext --inplace
```

Gerekirse strict build:

```bash
SAMURAI_WITH_DPDK=1 SAMURAI_REQUIRE_DPDK_BUILD=1 python setup.py build_ext --inplace
```

Hazirlik kontrolu (tek komut):

```bash
bash tools/check_dpdk_env.sh
```

## Çalıştırma

### Self-test (trafik göndermez)

```bash
python -m ddos_samurai.cli --self-test
```

### Dry-run (gönderim yapmaz)

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

## Scenario Engine (L7 Persona)

Scenario Engine, web/mobile persona tabanlı L7 kullanıcı davranışı üretir.

- Destek: `http` (HTTP/1.1), `http2` (HTTP/2)
- Modlar: `off`, `shadow`, `enforce`
- DSL: YAML (`personas`, `flows`, `load_model`, `sla`)

Hızlı örnek:

```bash
python -m ddos_samurai.cli \
  --scenario-file docs/scenario_web_mobile.yaml \
  --scenario-mode enforce \
  --scenario-vus 100000 \
  --scenario-ramp-seconds 120 \
  --scenario-max-session-seconds 60 \
  --confirm
```

Detaylar:
- [Scenario Engine Dokümantasyonu](docs/28-scenario-engine-web-mobile-persona.md)
- [Scenario Örnek Dosyası](docs/scenario_web_mobile.yaml)

## Temel Mimari

- CLI paketi: `ddos_samurai/cli/`
- Worker orchestration: `ddos_samurai/orchestrator.py`
- Sender facade + iç modüller: `ddos_samurai/senders.py`, `ddos_samurai/_senders/*`
- L7 stateful emulation: `ddos_samurai/l7_emu/*`, `ddos_samurai/l7_emu_native/*`
- Dataplane / AF_PACKET / XDP: `ddos_samurai/dataplane.py`, `fast_sender.c`, `xdp_sender.c`
- GPU paket/payload: `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_cuda_payload/*`
- AF_XDP Python wrapper + RX pipeline bridge: `ddos_samurai/af_xdp_sender.py`

## Önemli Notlar

- Bu checkout içinde `dashboard/` yok.
- Bu checkout içinde `ddos_samurai/api.py` yok.
- `docker-compose.yml` içinde görülen `api/dashboard` servisleri bu checkout ile birebir çalışmayabilir.

## Test

```bash
pytest tests -q -rs
```

## Dokümantasyon

- [Dokümantasyon İndeksi](docs/README.md)
- [Scenario Engine (Web/Mobile Persona)](docs/28-scenario-engine-web-mobile-persona.md)
- [L7 Native Custom QUIC/H3 Parity Planı](docs/PLAN_L7_NATIVE_CUSTOM_QUIC_H3_PARITY.md)
- [DOCA GPUNetIO Geçiş Durumu](docs/33-doca-gpunetio-migration-status.md)

## Lisans

`setup.py` sınıflandırmasına göre: MIT.
