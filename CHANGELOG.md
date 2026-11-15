# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 

### Changed
- ZMQ worker architecture and DPU/GPU dataplane documentation refreshed.
- Stale ZMQ legacy cleanup documentation removed.

### Fixed
- 

## [2.2.0] - 2026-05-13

### Added
- Scenario Engine (web/mobile persona) dokumantasyonu ve operasyonel kullanim akislari.
- DOCA GPUNetIO native backend entegrasyonu (hybrid mimariyi koruyarak).
- DOCA RX queue + GPU handle export hattinin defense pipeline'a baglanmasi.
- DOCA Flow steering tarafinda stream-rule tabanli multi-pipe programlama altyapisi.

### Changed
- GPU RDMA modu secenekleri `doca_gpunetio` secenegini kapsayacak sekilde genisletildi.
- Persistent + stream yolunda DOCA backend icin strict/fail-fast preflight kontrati sertlestirildi.
- Dokumantasyon indeksi, ADR ve perf raporlari DOCA gecis durumunu kapsayacak sekilde guncellendi.

## [2.1.1] - 2026-04-23

### Fixed
- XDP sender safety hardening for frame submit/release validation paths.
- XDP sender cleanup path now unmaps TX ring on bind failure.
- Pacing engine responsiveness improvements around long-running send loops and stats lock contention.
- Pacing fallback sender now returns the actual sent packet count instead of requested count.

### Changed
- Project SemVer bumped to `2.1.1`.

## [2.0.0] - 2026-04-20

### Added
- First formal GitHub Release workflow with SemVer tag strategy.
- Single-source package versioning (`samurai/__init__.py` as source of truth).

### Changed
- Replaced codename-only runtime version exposure with SemVer (`2.0.0`).
- Updated README version section to separate technical version from codename.

### Notes
- `Kenjaku` is retained as codename.
- Previous codename: `Ronin`.
