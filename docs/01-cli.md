# 01 - CLI (`ddos_samurai/cli/`)

## Rol

CLI paketi parse, config merge, lisans doğrulama, preflight, safety gate ve live/offline dispatch sorumluluklarını taşır.

## Giriş Noktaları

- `python -m ddos_samurai.cli`
- `ddos_samurai/cli/__main__.py`
- `ddos_samurai/cli/app.py:main()`

## Modül Sorumlulukları

- `args.py`: tüm argüman tanımları
- `app.py`: parse sırası + lisans akışı + mode dispatch
- `config.py`: YAML default merge
- `validation.py`: preflight/guard kontrolleri
- `env.py`: `args -> SAMURAI_*` senkronizasyonu
- `runtime.py`: canlı çalışma (worker spawn, monitor, rapor)
- `offline_modes.py`: self-test, dry-run, pcap-info, gpu-pcap vb.

## Parse ve Precedence

1. `build_parser()` ile defaultlar kurulur
2. `parse_known_args()` ile `--config` yakalanır
3. config defaultları parser'a yazılır
4. `parse_args()` ile nihai değerler alınır
5. profile/preflight adımları gerekli alanları policy gereği güncelleyebilir
6. `sync_runtime_env(args)` ile runtime env yazılır

## Lisans Akışı

`app.py` içinde lisans doğrulaması canlı çalıştırmadan önce zorunludur.

- Yardımcı komutlar: `--license-info`, `--license-account`, `--license-activate`, `--license-deactivate`, `--license-trial`
- Geçersiz lisans: non-zero exit

## Kritik CLI Kısıtları

Kodda zorunlu olarak sabitlenen seçimler:

- `--sender-backend {xdp}`
- `--sender-fallback-policy {fail}`
- `--stateful-runtime-backend {afxdp}`
- `--custom-tcp-backend {af_xdp}`

## Güvenlik Akışı

Canlı modda:

- root/capability kontrolü (`runtime.py`)
- etik uyarı (`--confirm` yoksa)
- hedef güvenlik doğrulaması (`validate_target_safety`)

## Not

CLI yüzeyi geniştir ve sık değişir. Güncel seçenekler için birincil kaynak:

```bash
python -m ddos_samurai.cli --help
```
