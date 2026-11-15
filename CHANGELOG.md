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

## [3.0.0] - 2026-11-15

### Added
- **Native C++ CLI, Core & Licensing (`samurai`, `samurai_core`, `samurai_license`)**:
  - Replaced legacy Python CLI/utils entrypoints with native C++17 `samurai` CLI and `samurai_core` library.
  - Added offline and HTTP-backed `samurai_license` engine, fail-closed license gating, `--license-key` / `--license-file` flags, and anti-tamper self-integrity checks in CLI and `samurai_master`.
- **Distributed Control Plane, Federation & Clustering (`samurai_master`, `samurai_slave`)**:
  - Multi-master region federation, native Redis/Kubernetes/file-lease leadership election, autoscale controller, management API rate limiting, and in-memory blob cache.
  - Live ZMQ shard reconfigure RPC, dynamic worker chaos failover rebalancing (`TASK-TEST-L5-01`), and native SSH agent push provisioner with `POST /v1/cluster/provision`.
  - Hierarchical ASN/PoP `RegionTopology` weighting for multi-region shard affinity and isolated RFC 1918/6598/2544 `TelcoLabSizingProfile` BNG/CGNAT pools.
- **Carrier Telecom Engine (`samurai/telecom`, `samurai_telco_worker`)**:
  - Stateful PPPoE FSM, DHCPv4 DORA / DHCPv6 SARR (Option 82), RFC 5880/5881 BFD, 4G/5G GTP-U & PFCP N4 control plane, SCTP (multihoming, PR-SCTP `FORWARD_TSN`, ASCONF/ASCONF_ACK, SSE4.2 CRC32c), Diameter (RFC 6733 & 3GPP Ro/Gx dictionary), and SIP (RFC 3261 + RFC 2617 digest) / RTP (RFC 3550 jitter filter) / SRTP (RFC 3711 AES-128-CM KDF).
  - Stateless wire-speed GTP-U TEID cycling, Carrier Ethernet QinQ VLAN sweep, and RFC 826 ARP/GARP generators.
  - `HierarchicalTimingWheel`, 64-byte seqlock/lock-free ARP and ND tables, L2/L3 fastpath classifier wiring, subscriber range sharding, telecom CLI profiles, and RFC 2544 / RFC 2889 telemetry audit logger (CSV/JSON).
- **DPU-GPU CUPS Bridge & Telemetry**:
  - `aarch64` DPU ARM PFCP/CUPS shared-memory bridge, zero-copy telecom CUDA datapath, and GPU P2P ring.
  - Wire-speed live IPFIX and NetFlow v9/v10 flow table and exporter integrated into telemetry reporting.
- **GeForce BAR1 P2P DMA & GPU-Initiated Doorbell**:
  - `GeforceP2pApiV1` Vulkan-CUDA BAR1 external memory arena, multi-vendor hardware TX descriptor layouts, and persistent GPU-initiated doorbell pipeline.
  - DPDK `rte_extmem` multi-queue BAR1 zero-copy external mbuf burst TX (`dpdk_worker`) and persistent GPU BAR1 P2P dataplane modes (`gpu_worker`, `doca_gpunetio_worker`).
- **L4/L7 Dataplane, Kernel-Bypass & Pacing**:
  - DPDK PMD backend and consolidated `dpdk_core` TX/steering engine.
  - Sharded asynchronous `io_uring` multi-reactor pipeline for HTTP/2 and QUIC/HTTP-3 (`TASK-TEST-L3-01`), opt-in HTTP/2 kTLS Socket-BIO offload (`TASK-TEST-L3-02`), and QUIC CUDA crypto helper with multi-stream pipelining.
  - Persistent HTTP keep-alive and dynamic session authentication across 12 normalization variants.
  - TSC-based high-precision pacing and ETF qdisc probing utilities.
- **ZMQ Wire Protocol ABI v3 & Worker Lifecycle**:
  - Evolved `wire_protocol.h` through `JobEnvelopeV2` (auth, evasion, and telecom control payloads) to ABI v3 with structured worker telemetry, `WarmWorkerPool`, async control channel decoupling, and `ABORT`/`STOP_JOB` shutdown handling.
- **RL Autopilot (`Mahoraga`) & VAE Defense**:
  - 7-D Mahoraga action space with categorical auth and evasion heads synchronized with native `kActionFields`, defense-aware served throughput reward, opt-in flow-level IPS/NSM state axis, and 2-hour multi-profile WAF training harness.
  - Variational Autoencoder (`VAE`) anomaly detection model and runtime reporting integration.
- **Build, Packaging, Containers & Docs**:
  - Unified CMake build system replacing `setup.py`, multi-stage `Dockerfile` packaging native CLI and `samurai_telco_worker`, and native `deploy/helm/samurai` Helm chart (CURVE TLS, env secrets, autoscale).
  - Standardized SVG architecture diagrams and modernized operational guides for core runtime, kernel-bypass, GPU P2P doorbell, DPU-GPU CUPS, telecom, and distributed clustering.

### Changed
- **Project Identity & Versioning**: Rebranded repository, Python package, C++ namespaces, Helm chart, CI workflows, and documentation from `DDoSamurai` / `ddos_samurai` to `Samurai` / `samurai`, retired project codenames, and bumped canonical SemVer to `3.0.0`.
- **L4 TCP Flow Efficiency & False-Sharing Removal**: Cut 1M flow RAM footprint by 63.3% (605 B/flow) and added 64-shard `PaddedMutex` / cache-line alignment across L4 and worker structs.
- **Worker & Pacing Consolidation**: Consolidated pacing engine into `samurai/zmq/lib` and harmonized DPDK, GPU, and telecom ZMQ worker daemons around zero-copy interfaces.
- **CLI Safety & Native Reporting**: Gated `--run-rfc-suite` behind `cli::Validate()` target safety checks using real RFC 2544 / 3511 / 8219 timings, and extended `--report-json` / `--report-text` with live IPFIX and Telco telemetry.
- **Repository & Documentation Hygiene**: Archived completed PR task reports under `docs/archive/`, refreshed ZMQ/DPU/GPU documentation, and removed obsolete benchmark/task/plan drafts (`KOZALAK_WAF_RESILIENCE_BENCHMARK_REPORT.md`, `test_task.md`, `reports/SAMURAI_YAPILACAK_TEST_VE_GOREV_LISTESI.md`, and `plan/`).

### Fixed
- **TCP Loss Recovery**: Implemented user-space TCP out-of-order segment reassembly, RFC 2018 SACK generation, and RFC 6675 SACK loss recovery (`TASK-TEST-L2-02`) to prevent spurious retransmissions.
- **L7 Reactor, kTLS & QUIC**: Resolved `io_uring` reactor stalls and multishot completion mix-ups, switched kTLS ULP detection to `tcp_available_ulp`, removed mock QUIC peer bypass in favor of authentic network sockets, and added zero-allocation HTTP/2 `:status` parsing.
- **Control Plane & Concurrency**: Fixed omitted `tcp://` endpoint scheme auto-prefixing, `ActiveShardId` idle echo, and `pop_ready_shard` queue race conditions.
- **Telecom Protocol Hardening**: Fixed timing wheel recursive reentrancy, SCTP INIT-ACK RFC 4960 TLV state cookie formatting, Diameter SCTP RX demux linear scan, RTP session binding / VLAN VID clamping, and strict RFC 5881 BFD validation.
- **GPU Datapath**: Removed Vulkan BAR1 emulation fallback to enforce native CUDA P2P pipeline execution.

### Removed
- Dropped `setup.py`, dead `dataplane_core.c` CPython extension, legacy root Python modules, superseded Python ZMQ launcher/orchestration layer, legacy pybind `l7_emu` + `gpu_cuda_payload` stacks, unused `L4StateEngineCore` / `l4se` FFI, and legacy attack sender implementations.

### Notes
- Retired project codenames; releases use SemVer (`3.0.0`) exclusively.

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

[Unreleased]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.0.0...v2.1.1
[2.0.0]: https://github.com/Mehmet8-Dev/Samurai/releases/tag/v2.0.0
