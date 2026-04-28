# 00 - Genel Bakış

## Proje Kimliği

- Ürün: `Samurai`
- Kod adı: `Kenjaku`
- Sürüm: `2.1.1`
- Doğrulama tarihi: `2026-04-28`

## Sistem Akışı

1. Giriş: `python -m ddos_samurai.cli`
2. CLI parse + config merge: `ddos_samurai/cli/app.py`
3. Lisans + preflight + safety gate
4. Worker spawn: `ddos_samurai/cli/runtime.py`
5. Worker dispatch: `ddos_samurai/orchestrator.py`
6. Vektöre göre sender yolu: `ddos_samurai/senders.py` + `_senders/*`

## Ana Katmanlar

- CLI katmanı: `ddos_samurai/cli/*`
- Orchestration: `ddos_samurai/orchestrator.py`
- Sender facade: `ddos_samurai/senders.py`
- L4/L3 dataplane: `ddos_samurai/dataplane.py`, `fast_sender.c`, `xdp_sender.c`
- L7 emulation: `ddos_samurai/l7_emu/*`, `ddos_samurai/l7_emu_native/*`
- GPU üretim yolları: `ddos_samurai/gpu_packet.py`, `ddos_samurai/gpu_cuda_payload/*`

## Güncel Kısıtlar (Kod Gerçeği)

- `--sender-backend` yalnızca `xdp`
- `--sender-fallback-policy` yalnızca `fail`
- `--stateful-runtime-backend` yalnızca `afxdp`
- `--custom-tcp-backend` yalnızca `af_xdp`

Bu nedenle eski dokümanlarda geçen `auto/txring/python/c_ext_l3` gibi sender seçimleri bu sürümde aktif kullanıcı seçimi değildir.

## Repo Notu

- `dashboard/` dizini yok
- `ddos_samurai/api.py` yok
