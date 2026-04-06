# 20) Env ve CLI Referans Dokumani

Bu dokuman, yeni `ddos_samurai/cli/` paket yapisini baz alarak:
- CLI argumanlarini
- `SAMURAI_*` environment variable akislarini
- CLI -> runtime env bridge davranisini

tek yerde toplar.

## Kapsam

Bu dokuman su kaynaklardan derlendi:
- `ddos_samurai/cli/app.py`
- `ddos_samurai/cli/args.py`
- `ddos_samurai/cli/config.py`
- `ddos_samurai/cli/env.py`
- `ddos_samurai/cli/profile_resolver.py`
- `ddos_samurai/cli/validation.py`
- `ddos_samurai/dataplane.py`
- `ddos_samurai/fast_sender.c`
- `ddos_samurai/pacing_engine.c`
- `ddos_samurai/senders.py`
- `ddos_samurai/orchestrator.py`
- `ddos_samurai/l7_state_engine.c`

Not: Eskiden bu akisin tamami `ddos_samurai/cli.py` icindeydi. 2026-04-06 itibariyla ayni davranis `ddos_samurai/cli/` paketine dagitilmistir.

Uyumluluk notu:
- `from ddos_samurai import cli` halen calisir
- `python -m ddos_samurai.cli` halen calisir
- Ancak fiziksel kaynak artik `ddos_samurai/cli.py` degil, `ddos_samurai/cli/` paketidir

## Konfigurasyon Onceligi (Precedence)

`ddos_samurai.cli.main()` akisina gore oncelik su sekildedir:

1. `args.py` icindeki `build_parser()` parser defaultlarini kurar.
2. `parse_known_args()` ile sadece `--config` yakalanir.
3. Config dosyasi `config.py` icinde okunur ve `parser.set_defaults(**defaults_from_config)` ile parser defaultlari override edilir.
4. Son `parse_args(argv)` ile CLI'da acik verilen argumanlar en yuksek oncelige sahip olur.
5. `profile_resolver.py` ve `validation.py` icindeki preflight/validasyon adimlari bazi alanlari policy geregi mutasyona ugratabilir.
6. Son asamada secilen ayarlar `env.py` icindeki `sync_runtime_env(args)` ile `os.environ[...]` uzerinden runtime modullere bridge edilir.

Pratik kural:
- Explicit CLI > config dosyasi > env default > hardcoded default
- Ancak profil/preflight zorlamalari bu degerleri bilincli olarak degistirebilir

## CLI Paketindeki Sorumluluk Dagilimi

| Modul | Sorumluluk |
|---|---|
| `ddos_samurai/cli/app.py` | main orchestration, parse sirasi, offline/live dispatch |
| `ddos_samurai/cli/args.py` | `build_parser()` ve tum CLI option tanimlari |
| `ddos_samurai/cli/config.py` | `--config` YAML merge ve soak config uretimi |
| `ddos_samurai/cli/profile_resolver.py` | profil uygulama ve TLS/H2 alias normalization |
| `ddos_samurai/cli/validation.py` | `_validate_*`, `_preflight_*`, queue map ve capability guard'lari |
| `ddos_samurai/cli/env.py` | parser default env okumasi ve `args -> os.environ` bridge |
| `ddos_samurai/cli/offline_modes.py` | self-test, dry-run, gpu-pcap, pcap-info, traffic-model dry-validate |
| `ddos_samurai/cli/runtime.py` | live run, root gate, ninja mode, worker spawn, monitor, final report |
| `ddos_samurai/cli/reporting.py` | CLI-specific report helper'lari |

## CLI Tarafindan Okunan Env Varsayilanlari

Bu env anahtarlari parser defaultlari icin agirlikla `args.py` ve `env.py` tarafinda okunur:

- `SAMURAI_AF_PACKET_BLOCK_SIZE_KB`
- `SAMURAI_AF_PACKET_BUSY_POLL_US`
- `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK`
- `SAMURAI_AF_PACKET_FRAME_SIZE`
- `SAMURAI_AF_PACKET_HUGEPAGE_MODE`
- `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB`
- `SAMURAI_AF_PACKET_MLOCK_RING`
- `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS`
- `SAMURAI_AF_PACKET_PREFAULT_RING`
- `SAMURAI_AF_PACKET_QDISC_BYPASS`
- `SAMURAI_AF_PACKET_RING_TARGET_MB`
- `SAMURAI_AF_PACKET_SPIN_LIMIT`
- `SAMURAI_DATAPLANE_CORE_ENABLE`
- `SAMURAI_DP_QUEUES`
- `SAMURAI_DP_QUEUE_MAP`
- `SAMURAI_DP_QUEUE_STRATEGY`
- `SAMURAI_GPU_BATCH`
- `SAMURAI_GPU_FULL_VARIATION`
- `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT`
- `SAMURAI_GPU_PINNED_MAX_MB`
- `SAMURAI_GPU_PIPELINE_DEPTH`
- `SAMURAI_GPU_RING_CAPACITY`
- `SAMURAI_GPU_RNG_SEED`
- `SAMURAI_GPU_STREAMS`
- `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4`
- `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7`
- `SAMURAI_KPI_GATE_PROFILE`
- `SAMURAI_L7_CAPABILITY_STRICT`
- `SAMURAI_L7_ENGINE`
- `SAMURAI_L7_FALLBACK_POLICY`
- `SAMURAI_L7_HTTP2_ENGINE`
- `SAMURAI_L7_QUIC_AUTO_BRIDGE`
- `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE`
- `SAMURAI_L7_QUIC_ENGINE`
- `SAMURAI_L7_QUIC_REQUIRE_NATIVE`
- `SAMURAI_LAB_PROFILE`
- `SAMURAI_STATE_LOCK_COUNT`
- `SAMURAI_STATE_SWEEP_INTERVAL_MS`
- `SAMURAI_STATE_TABLE_SIZE`
- `SAMURAI_STATE_TIMEOUT_SEC`

Ozel not:
- `SAMURAI_QUIC_BUILD_MODE` parser default degil; `validation.py` icindeki native QUIC preflight'i tarafindan gerekli durumda override edilir.

## CLI Tarafindan Export Edilen Env Degiskenleri

Asagidaki env anahtarlari `env.py` icindeki `sync_runtime_env(args)` ile runtime modullere bridge edilir:

- `SAMURAI_LOSS_TELEMETRY`
- `SAMURAI_LOSS_FAIL_PCT`
- `SAMURAI_LOSS_IFACE`
- `SAMURAI_LOSS_REPORT_OUT`
- `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4`
- `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7`
- `SAMURAI_GPU_RING_CAPACITY`
- `SAMURAI_GPU_BATCH`
- `SAMURAI_GPU_STREAMS`
- `SAMURAI_GPU_PIPELINE_DEPTH`
- `SAMURAI_GPU_FULL_VARIATION`
- `SAMURAI_GPU_PINNED_MAX_MB`
- `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT`
- `SAMURAI_GPU_RNG_SEED`
- `SAMURAI_STATE_TABLE_SIZE`
- `SAMURAI_STATE_LOCK_COUNT`
- `SAMURAI_STATE_TIMEOUT_SEC`
- `SAMURAI_STATE_SWEEP_INTERVAL_MS`
- `SAMURAI_SENDER_BACKEND`
- `SAMURAI_SENDER_FALLBACK_POLICY`
- `SAMURAI_DATAPLANE_CORE_MODE`
- `SAMURAI_DATAPLANE_CORE_ENABLE`
- `SAMURAI_AF_PACKET_HUGEPAGE_MODE`
- `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB`
- `SAMURAI_AF_PACKET_RING_TARGET_MB`
- `SAMURAI_AF_PACKET_BLOCK_SIZE_KB`
- `SAMURAI_AF_PACKET_FRAME_SIZE`
- `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK`
- `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS`
- `SAMURAI_AF_PACKET_SPIN_LIMIT`
- `SAMURAI_AF_PACKET_BUSY_POLL_US`
- `SAMURAI_AF_PACKET_QDISC_BYPASS`
- `SAMURAI_AF_PACKET_MLOCK_RING`
- `SAMURAI_AF_PACKET_PREFAULT_RING`
- `SAMURAI_LAB_PROFILE`
- `SAMURAI_DP_QUEUE_STRATEGY`
- `SAMURAI_DP_QUEUES`
- `SAMURAI_DP_QUEUE_MAP`
- `SAMURAI_XDP_ENABLE`
- `SAMURAI_XDP_INTERFACE`
- `SAMURAI_XDP_QUEUE_ID`
- `SAMURAI_XDP_MODE`
- `SAMURAI_XDP_ATTACH_BPF`
- `SAMURAI_XDP_BPF_SECTION`
- `SAMURAI_XDP_BPF_OBJ`
- `SAMURAI_XDP_XSKMAP_PIN`
- `SAMURAI_KPI_GATE_PROFILE`
- `SAMURAI_KPI_HARD_FAIL`
- `SAMURAI_L7_ENGINE`
- `SAMURAI_L7_HTTP2_ENGINE`
- `SAMURAI_L7_QUIC_ENGINE`
- `SAMURAI_L7_QUIC_REQUIRE_NATIVE`
- `SAMURAI_L7_QUIC_AUTO_BRIDGE`
- `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE`
- `SAMURAI_L7_FALLBACK_POLICY`
- `SAMURAI_L7_CAPABILITY_STRICT`
- `SAMURAI_LEGACY_PATH_ENABLE`

## CLI Disi / Ileri Seviye Env Degiskenleri

Asagidaki env anahtarlari parser tarafinda degil, downstream runtime modullerinde tuketilir:

| Env | Tuketici Moduller | Aciklama |
|---|---|---|
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | `ddos_samurai/dataplane.py`, `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET tuning |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `ddos_samurai/dataplane.py` | TX_RING/AF_PACKET tuning |
| `SAMURAI_AF_PACKET_MLOCK_RING` | `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET tuning |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET tuning |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `ddos_samurai/dataplane.py` | TX_RING/AF_PACKET tuning |
| `SAMURAI_CPU_FIXED_OS_PROFILE` | `ddos_samurai/cpu_packet_engine.py` | Runtime override / internal tuning |
| `SAMURAI_DATAPLANE_CORE_MODE` | `ddos_samurai/dataplane.py` | Runtime override / internal tuning |
| `SAMURAI_ENABLE_BROWSER_AUTOMATION` | `ddos_samurai/stealth.py` | Stealth/browser automation davranisi |
| `SAMURAI_GATEWAY_CACHE_TTL_SEC` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_GPU_BATCH` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_STREAMS` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_KPI_GATE_PROFILE` | `ddos_samurai/reporting.py` | Runtime override / internal tuning |
| `SAMURAI_KPI_HARD_FAIL` | `ddos_samurai/reporting.py` | Runtime override / internal tuning |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `ddos_samurai/l7_state_engine.c` | L7 capability policy |
| `SAMURAI_LOSS_FAIL_PCT` | `ddos_samurai/reporting.py` | Loss telemetry / KPI akisi |
| `SAMURAI_LOSS_IFACE` | `ddos_samurai/loss_telemetry.py`, `ddos_samurai/senders.py` | Loss telemetry / KPI akisi |
| `SAMURAI_LOSS_TELEMETRY` | `ddos_samurai/loss_telemetry.py`, `ddos_samurai/senders.py` | Loss telemetry / KPI akisi |
| `SAMURAI_SENDER_BACKEND` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_SENDER_FALLBACK_POLICY` | `ddos_samurai/senders.py` | Runtime override / internal tuning |

## Tum CLI Argumanlari

Tum arguman envanteri halen `ddos_samurai/cli/args.py` icindeki `build_parser()` tarafindan uretilir. Bu dokumanin geri kalan kisimlari parser davranisina referans olmaya devam eder; ancak kaynak dosya artik `ddos_samurai/cli.py` degil `ddos_samurai/cli/args.py`'dir.
