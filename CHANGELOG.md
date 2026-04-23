# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 

### Changed
- 

### Fixed
- 

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
- Single-source package versioning (`ddos_samurai/__init__.py` as source of truth).

### Changed
- Replaced codename-only runtime version exposure with SemVer (`2.0.0`).
- Updated README version section to separate technical version from codename.

### Notes
- `Kenjaku` is retained as codename.
- Previous codename: `Ronin`.
