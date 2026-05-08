# CLI

Bu belge `python -m ddos_samurai.cli` giris noktasinin gercek akisini ve operasyonel kullanimini aciklar.

## Giris Noktasi ve Baslangic

- Entrypoint: `ddos_samurai/cli/__main__.py`
- Start method: `multiprocessing.spawn`
- Ana akıs: `ddos_samurai/cli/app.py::main()`

Sirayla yapilanlar:

1. Banner + uvloop denemesi
2. Parser olusturma (`build_parser`)
3. YAML config defaultlari merge (`load_config_defaults`)
4. Arguman parse
5. Lisans gate
6. Profile/preflight/validation
7. Offline mode dispatch veya live mode dispatch

## Lisans Akisi (Canli Run Oncesi Zorunlu)

`app.py` asagidaki komutlari ayri ele alir:

- `--license-activate`
- `--license-deactivate`
- `--license-info`
- `--license-account`
- `--license-trial`

Canli run'da:

- `validate_license()` cagrilir
- Gecersizse process `EX_CONFIG (78)` ile sonlanir
- Gecerliyse tier/feature/limit bilgisi args'e inject edilir

## Offline Modlar

`ddos_samurai/cli/offline_modes.py`

- `--self-test`: test discovery calistirir
- `--dry-run`: paket olusturma ve raporlama smoke
- `--gpu-pcap`: GPU tabanli sentetik PCAP
- `--pcap-info`: PCAP metadata ozeti

Bu modlar trafik gondermeden pipeline dogrulama icin idealdir.

## Live Mod

`ddos_samurai/cli/runtime.py::run_live_mode`

Ana adimlar:

1. Arguman validasyonu
2. Lisans feature gate enforcement
3. Root/yetki kontrolu (raw path gereksinimleri)
4. Payload yukleme
5. Profile cozumleme
6. Safety gate (`validate_target_safety`)
7. Worker process spawn
8. Live monitor + telemetry + soak evaluasyon
9. Rapor/artefakt yazimi

## Distributed Mod

- `--role master`: `ddos_samurai/control/master.py`
- `--role slave`: `ddos_samurai/control/slave.py`

Management API enable oldugunda master tarafinda REST/SSE/WS endpointleri acilir.

## Sık Kullanilan Komutlar

Self-test:

```bash
python -m ddos_samurai.cli --self-test
```

Dry-run:

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 8080 \
  --protocol tcp --attack-vector basic \
  --count 100 --dry-run --confirm
```

Distributed master (dev/insecure):

```bash
python -m ddos_samurai.cli \
  --role master \
  --control-insecure \
  --control-listen 127.0.0.1:5099 \
  --management-api-enable \
  --management-api-listen 127.0.0.1:8089 \
  --target 127.0.0.1 --port 80 --protocol tcp --count 100000 --confirm
```

## Operasyonel Notlar

- `--sender-backend` ve `--sender-fallback-policy` preflight tarafinda kisitli calisir.
- `--traffic-model mamba2` runtime entegrasyonu kaldirildi; egitim/infer yolu `training/mamba2_monolith.py` altindadir.
- `--run-report` aktifse JSON/Markdown/Prom artefaktlari uretilir.
