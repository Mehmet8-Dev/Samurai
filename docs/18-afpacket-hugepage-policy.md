# 18 - AF_PACKET HugePage Policy

Bu dokuman AF_PACKET/TX_RING yolunda explicit HugePage policy davranisini, telemetry alanlarini ve KPI gate etkisini tek yerde toplar.

## Kapsam ve Sinir

- Kapsam: `AF_PACKET + THP enforce` (TX_RING icinde policy + telemetry + gate).
- Not: AF_PACKET ring bellegi kernel tarafinda ayrilir. Bu nedenle `MAP_HUGETLB` benzeri "mutlak hugetlb garantisi" bu yol icin teknik olarak sinirlidir.
- Sonuc: Buradaki politika, "enforce edilebilir hugepage policy" saglar; tam hugetlb garantisi gerektiren senaryoda XDP/DPDK ayri yol olarak degerlendirilmelidir.

## Mode Semantigi

- `off`: HugePage policy kapali, geriye uyumlu davranis.
- `auto`: Best-effort policy. `madvise(MADV_HUGEPAGE)` + opsiyonel `mlock/prefault` uygulanir, basarisizlik run'i durdurmaz.
- `required`: TX_RING kurulumundan sonra `afpacket_hugepage_effective != 1` ise fail-visible olur.

## Dedicated Profil Davranisi

`--lab-profile dedicated` ve TX_RING yolu birlikte secildiginde:

- `afpacket_hugepage_mode` otomatik `required` olur.
- KPI gate tarafinda hugepage kosulu fail kapisina girer.
- Hard-fail aciksa (`--kpi-hard-fail`) run non-zero exit ile biter.

## CLI Bayraklari

- `--afpacket-hugepage-mode {off,auto,required}`
- `--afpacket-hugepage-size-kb <int>` (varsayilan: `2048`)
- `--afpacket-ring-target-mb <int>` (varsayilan: `64`)
- `--afpacket-block-size-kb <int>` (varsayilan: `0`, auto)
- `--afpacket-frame-size <int>` (varsayilan: `0`, auto)
- `--afpacket-frames-per-block <int>` (varsayilan: `64`)
- `--afpacket-poll-timeout-ms <int>` (varsayilan: `1`)
- `--afpacket-spin-limit <int>` (varsayilan: `2000`)
- `--afpacket-busy-poll-us <int>` (varsayilan: `0`)
- `--afpacket-qdisc-bypass` / `--no-afpacket-qdisc-bypass`
- `--afpacket-mlock-ring` / `--no-afpacket-mlock-ring`
- `--afpacket-prefault-ring` / `--no-afpacket-prefault-ring`

## Ortam Degiskenleri

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

## Ring Tuning Notlari

- Ring geometrisi: `frame_size`, `frames_per_block`, `block_size`, `block_nr`.
- Auto modda geometri paket boyuna gore hizalama/pow2 kurallariyla secilir.
- `poll_timeout_ms` + `spin_limit` TX frame bekleme stratejisini belirler.
- `busy_poll_us` ve `qdisc_bypass` best-effort kernel tuning knob'laridir.
- `tp_retire_blk_tov` TX_RING icin RX-ozel bir alan oldugu icin sifir tutulur.

## Runtime Telemetry Alanlari

Run report / metrics tarafinda beklenen temel alanlar:

- `afpacket_hugepage_mode`
- `afpacket_hugepage_effective`
- `afpacket_hugepage_reason`
- `afpacket_hugepage_size_kb`
- `afpacket_madvise_hugepage_ok`
- `afpacket_mlock_ok`
- `afpacket_prefault_pages`
- `afpacket_smaps_kernel_page_kb`
- `afpacket_smaps_anon_hugepages_kb`
- `afpacket_ring_block_size`
- `afpacket_ring_block_nr`
- `afpacket_ring_size_bytes`

## KPI Gate Baglantisi

Gate motoru TX_RING scope icinde su kosulu uygular:

- `afpacket_hugepage_effective == 1`

Profile davranisi:

- `dedicated_lab`: fail/hard-fail politikasi uygulanir.
- `developer_fallback`: ihlal raporlanir; hard-fail zorunlu degildir.

## Ornek Komutlar

### Developer fallback (warn/observe)

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 80 --protocol tcp \
  --attack-vector basic --count 100000 --confirm \
  --sender-backend txring --sender-fallback-policy allow \
  --afpacket-hugepage-mode auto \
  --run-report --run-report-out artifacts/live_run_hp_auto
```

### Dedicated strict (hard gate)

```bash
python -m ddos_samurai.cli \
  --target 192.168.1.10 --port 80 --protocol tcp \
  --attack-vector basic --count 1000000 --confirm \
  --lab-profile dedicated \
  --sender-backend txring --sender-fallback-policy fail \
  --kpi-gate-profile dedicated_lab --kpi-hard-fail \
  --afpacket-hugepage-mode required \
  --run-report --run-report-out artifacts/live_run_hp_required
```

## Hata Tanilama Ozeti

Belirti:

- `sender_fallback_reason=afpacket_hugepage_required_not_met`

Bakilacak alanlar:

- `afpacket_hugepage_effective`
- `afpacket_hugepage_reason`
- `afpacket_smaps_kernel_page_kb`
- `afpacket_smaps_anon_hugepages_kb`
- `sender_paths_used` (gercekten TX_RING mi?)

Ilgili dokumanlar:

- `docs/01-cli.md`
- `docs/08-config.md`
- `docs/10-troubleshooting.md`
