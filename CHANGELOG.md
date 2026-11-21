# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.3.0] - 2026-11-21

### Added
- **Full Worker & Distributed Cluster Job Dispatch in MCP (`samurai/mcp/`)**:
  - Exposed full L7/TLS/Telco/GPU/IPFIX worker flags on `samurai_run_benchmark` and added `samurai_cluster_run_job` for distributed multi-worker execution (including closed-loop RL autopilot and 5G telco pool profiles).
  - Added AF_XDP SKB/copy (`xdp_mode=0` default) and `custom_tcp` wire selection (`af_xdp`, `af_packet`, `dpdk`, `in_memory`) plus automatic route/interface/IP/MAC discovery (`ResolveCustomTcpEnv`) to `samurai_run_benchmark` and `samurai_scenario_run`.

### Fixed
- **Master–Slave, Multi-Master Federation & Redis HA (`samurai/control/`, `samurai/mcp/cluster_tools.cpp`)**:
  - Parsed `[user]:password@` credentials in `ParseRedisUrl` and wired `AUTH` + `SELECT` error handling into `HiredisKvStore::EnsureConnected`.
  - Enabled serve-only `samurai_master` (`--management-listen` with `--count 0`), real `POST /v1/jobs/abort` mid-flight shard recall, and skipped local worker blocking when delegating jobs to remote regions.
  - Added `--ha-standby` and `--ha-lease-s` for Redis/file-lock HA standby promotion and scaled lease renewal.
  - Populated `ha`, `multi_master`, `multi_master_regions`/`latest`, `shards`, `current_job`, and `latest_snapshot` in Management API state, enriched `region_rollup` with worker region capabilities, and passed resolved `--worker-dir` to `samurai_slave` in `samurai_cluster_local_mesh`.

### Changed
- Bumped canonical SemVer across package, Helm `appVersion`, citation metadata, MCP server, and documentation to `3.3.0`.

## [3.2.0] - 2026-11-21

### Added
- **Distributed Cluster Orchestration via Native MCP (`samurai/mcp/cluster_tools.*`)**:
  - Added 7 native cluster orchestration tools to `samurai_mcp`: `samurai_cluster_discover` (and `samurai_cluster_status` alias querying `/healthz`, `/v1/cluster/{summary,workers,shards,events}`, `/metrics`), `samurai_cluster_provision_node` (`POST /v1/cluster/provision`), `samurai_cluster_reconfigure` (`POST /v1/shards/reconfigure`), `samurai_cluster_abort` (`POST /v1/jobs/abort`), `samurai_cluster_plan_shards` (`SplitJobToShards`, `SplitTelcoSubscribers` with CGNAT/BNG pool profiles, and `AutoscaleController`), and `samurai_cluster_local_mesh` (loopback `samurai_master` + N `samurai_slave` start/scale/status/stop).
- **MCP Resources, Prompts & 5 Portable Agent Skills (`skills/`)**:
  - Extended `samurai/mcp/protocol.*` with standard MCP `2024-11-05` `resources/list`, `resources/read`, `prompts/list`, and `prompts/get` capabilities.
  - Added 5 modular skills covering all 10 dataplane workers, distributed cluster orchestration, Closed-Loop Autopilot / Mahoraga RL, Scenario Engine authoring, and benchmarking (`skills/samurai-*/SKILL.md`), packaged into `/usr/local/share/samurai/skills` in `Dockerfile`.

### Changed
- Bumped canonical SemVer across package, Helm `appVersion`, citation metadata, MCP server, and documentation to `3.2.0`.

## [3.1.1] - 2026-11-21

### Added
- **Modular Native C++17 MCP Server (`samurai_mcp`, `samurai/mcp/`)**:
  - Built zero-Python, zero-external-SDK MCP `2024-11-05` stdio server linked directly against `samurai_core`, `samurai_control`, and `samurai_scenario`.
  - Added Closed-Loop Autopilot & Mahoraga RL tools (`samurai_autopilot_{create,step,run_window,status,reset}` with `AIMD`/`BinSearch`/`kRl`, SRLP MLP & RL² GRU inference, `LeverShield`, and `RlExploreConfig`).
  - Added Scenario Engine tools (`samurai_scenario_{compile,run,evaluate_sla}`).
  - Added native C++17 `test_samurai_mcp` selftest and E2E stdio JSON-RPC pytest suite (`tests/test_mcp_server.py`).
- **Reproducible Benchmarks & Community Reporting**:
  - Packaged `samurai_mcp`, `samurai_bench_1m_tcp`, `samurai_bench_100k_tcp`, and `samurai_bench_l7` into `Dockerfile` / GHCR releases.
  - Added `scripts/reproduce-benchmarks.sh`, `docs/benchmarks/README.md`, `docs/50-open-source-growth-and-launch-playbook.md`, and `.github/ISSUE_TEMPLATE/benchmark_report.md`.

### Fixed
- **Automatic Worker Binary Discovery (`samurai/orchestrator/supervisor.cpp`)**: Automatically resolves worker binaries next to `/proc/self/exe`, `../zmq`, `../../zmq`, `build/zmq`, or `$PATH` without requiring `--worker-dir`.
- **Docker Compose Native Alignment**: Updated `docker-compose.yml` and `docker-compose.distributed.yml` for native `samurai`, `samurai_master`, and `samurai_slave` entrypoints and `curl` healthchecks.

## [3.0.1] - 2026-11-21

### Fixed
- **CI & Compatibility**: Added QUIC/H3 API compatibility checks, pinned CI runners to `ubuntu-24.04`, gated GPU architecture test suite on `ci_safe`/CUDA, and added GHCR container usage documentation.

## [3.0.0] - 2026-11-20

### Added
- **Native C++ CLI & Core (`samurai`, `samurai_core`)**:
  - Replaced legacy Python CLI/utils entrypoints with native C++17 `samurai` CLI and `samurai_core` library (`target_safety.cpp`, fast JSON parser, structured logging, KPI gates, RFC 2544/3511/8219 compliance suites).
- **Open Governance, Security & Licensing (`AGPL-3.0`)**:
  - Licensed under GNU Affero General Public License v3.0 (`LICENSE`), with `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, GitHub Issue/PR templates, Dependabot (`.github/dependabot.yml`), and automated Gitleaks/CodeQL security scanning (`.github/workflows/security.yml`).
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

[Unreleased]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.3.0...HEAD
[3.3.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.1.1...v3.2.0
[3.1.1]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.0.1...v3.1.1
[3.0.1]: https://github.com/Mehmet8-Dev/Samurai/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Mehmet8-Dev/Samurai/compare/v2.0.0...v2.1.1
[2.0.0]: https://github.com/Mehmet8-Dev/Samurai/releases/tag/v2.0.0
