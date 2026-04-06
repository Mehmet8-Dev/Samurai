# 01 - CLI (`ddos_samurai/cli/`)

## Rol

CLI artik tek bir `cli.py` dosyasi degil, `ddos_samurai/cli/` paketi altinda moduler bir yapi olarak tutulur. Bu paket, tum calistirma parametrelerini toplar ve worker'lara dagitilacak "args snapshot" olusturur.

Ana moduller:

- `app.py`: `main(argv=None)` orchestration
- `args.py`: `build_parser()`
- `config.py`: YAML config merge + soak config
- `profile_resolver.py`: `apply_profile()` ve `_resolve_profile_args()`
- `validation.py`: `_validate_*` ve `_preflight_*`
- `env.py`: `args -> os.environ` bridge
- `offline_modes.py`: self-test, dry-run, gpu-pcap, pcap-info
- `runtime.py`: live attack akisi
- `reporting.py`: CLI-specific report glue helper'lari

## Guncel Durum (2026-04-06)

Refactor sonrasi beklenen giris noktasi:

- `python -m ddos_samurai.cli ...`
- `from ddos_samurai import cli`
- `cli.build_parser()`
- `cli.main()`

Uyumluluk notu:

- `ddos_samurai/cli.py` artik yoktur.
- `ddos_samurai.cli` artik bir dosya degil, paket olarak cozulur.
- Testlerin ve dis importlarin kullandigi bazi internal helper'lar `ddos_samurai/cli/__init__.py` uzerinden bilincli olarak re-export edilir.

CLI tarafi artik yalniz parser degil, ayni zamanda profile-aware preflight katmanidir.

- Dataplane route kontrolu:
  - `--sender-backend {auto,txring,c_ext_l3,python,xdp}`
  - `--sender-fallback-policy {allow,fail}`
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
  - `--lab-profile {off,dedicated}`
  - `--dp-queue-strategy {rr,pin,map}`, `--dp-queues`, `--dp-queue-map`
- KPI gate:
  - `--kpi-gate-profile {off,dev,ci_safe,developer_fallback,dedicated_lab}`
  - `--kpi-hard-fail`
- L7 engine route:
  - `--l7-engine {python,c_state}`
  - `--l7-http2-engine {python,c_state,auto}`
  - `--l7-quic-engine {python,c_state,auto}`
  - `--l7-capability-strict`
  - `--l7-quic-require-native`
- GPU pipeline:
  - `--gpu-ring-capacity`, `--gpu-stream-count`, `--gpu-pipeline-depth`
  - `--gpu-full-variation`

Dedicated profil (`--lab-profile dedicated`) secildiginde CLI otomatik olarak:

- `kpi_gate_profile=dedicated_lab`
- `kpi_hard_fail=true`
- `l7_capability_strict=true`
- QUIC vektorunde `l7_quic_require_native=true`
- TX_RING backend seciliyse `afpacket_hugepage_mode=required`

ve queue/NIC preflight kontrollerini kosmadan run baslatmaz.

## AF_PACKET HugePage Politikasi

- `off`: hugepage policy kapali, mevcut davranis.
- `auto`: `madvise(MADV_HUGEPAGE)` + opsiyonel `mlock/prefault`, basarisizlik run'i durdurmaz.
- `required`: TX_RING sonucu `afpacket_hugepage_effective!=1` ise fail-visible.

Ortama yansitilan env anahtarlari:

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

## Onemli Giris Noktalari

- `ddos_samurai.cli.build_parser()`: tum bayraklari/opsiyonlari tanimlar.
- `ddos_samurai.cli.main()`: config merge, safety gate, offline mode dispatch ve live worker spawn akisini baslatir.
- `ddos_samurai.cli.__main__`: `python -m ddos_samurai.cli` icin module execution bootstrap'i saglar.

## YAML Config Merge Mantigi

Akis:

1. `--config` ile YAML dosyasi okunur.
2. YAML icindeki key'ler argparse dest isimlerine map edilir:
   - Ust seviye dict -> dogrudan `set_defaults`.
   - Ic dict (nested) -> `"{main_key}_{sub_key}"` seklinde flatten edilip `set_defaults`'a eklenir.

Kod: `ddos_samurai/cli/config.py` icindeki flatten dongusu.

Not: Bu flatten kuralini degistirirken testler ve mevcut config dosyalariyla uyumu gozden gecirin.

## Safety Gate

`--dry-run` degilse:

- `--confirm` verilmemisse `utils.ethical_warning()` calisir (interaktif).
- Ardindan `utils.validate_target_safety()` ile hedef kontrol edilir.

Gelistirme icin kritik nokta:

- "public hedef kilidi" default olarak aktif.
- CI/sandbox gibi ortamlarda interaktif input istemeyen senaryolar icin `--confirm` ve allowlist bayraklari kullanilir (urun akisi ihtiyacina gore yeniden tasarlanabilir).

## Worker Bolme

- `--workers` default: CPU core sayisi
- `count` toplam is parcaciklarina bolunur; remainder ilk worker'lara dagitilir.
- `--rps` verilirse worker basina rps bolunur (toplam rps hedefi korunur).

## CUDA + Multiprocessing

`if __name__ == '__main__'` altinda `spawn` start method'u ayarlanir.
Bu, CUDA context ve fork etkileisimlerini daha kontrol edilebilir hale getirir.

## Faz 2/3 ile Eklenen Bayraklar

HTTP/2:

- `--h2-transport {auto,httpx,hyper-h2}`
  - `auto`: uygun kosulda `hyper-h2`, degilse `httpx` fallback
  - `httpx`: mevcut transport davranisini zorlar
  - `hyper-h2`: profile-aware transportu zorlar (destek yoksa fail-visible)

WebSocket scenario:

- `--ws-scenario`
- `--ws-auth-message`
- `--ws-subscribe-message ...`
- `--ws-ping-count`
- `--ws-await-response`

PCAP replay:

- `--pcap-use-l2`
  - PCAP replay yolunu L2 TX_RING hattina zorlar
- `--pcap-no-flow-aware`
  - TCP seq/ack flow-aware rewrite'i kapatir

Run report input snapshot alanlari da guncellendi:

- `ws_scenario`
- `h2_transport`

## Not

Bu dosyada listelenen eski bayraklar halen gecerli olsa da, benchmark/disiplinli run semantigi icin asagidaki yeni eksenler artik birincil kabul edilmelidir:

- sender backend + fallback policy
- lab profile + queue strategy
- KPI gate profile + hard fail
- L7 capability strict + native QUIC zorunlulugu
