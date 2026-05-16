# DDoSamurai Docs

Bu dizin, projenin teknik ve operasyonel dokumantasyonunu 3 seviyede tutar:

1. Cekirdek teknik akıs (00-13)
2. Derin teknik notlar/handbook'lar (14+)
3. Dagitim, enterprise ve operasyon dokumanlari

## 1) Cekirdek Baslangic Seti

- [00 - Genel Bakis](./00-overview.md)
- [01 - CLI](./01-cli.md)
- [02 - Orchestrator](./02-orchestrator.md)
- [03 - Senders](./03-senders.md)
- [04 - Packet Builder](./04-packet-builder.md)
- [05 - GPU](./05-gpu.md)
- [06 - AF_XDP ve fast_sender](./06-af_xdp-fast_sender.md)
- [07 - Safety](./07-safety.md)
- [08 - Config](./08-config.md)
- [09 - Dev/Testing](./09-dev-testing.md)
- [10 - Troubleshooting](./10-troubleshooting.md)
- [11 - Docker](./11-docker.md)
- [12 - Dashboard](./12-dashboard.md)
- [13 - API](./13-api.md)

## 2) Derin Teknik ve Benchmark Seti

- [22 - CLI Operational Playbook](./22-cli-operational-playbook.md)
- [23 - Benchmark Acceptance Handbook](./23-benchmark-acceptance-handbook.md)
- [24 - Enterprise Test Scenarios Handbook](./24-enterprise-test-scenarios-handbook.md)
- [25 - Core Runtime Modules](./25-core-runtime-modules.md)
- [26 - CLI Package Deep Map](./26-cli-package-deep-map.md)
- [27 - GPU CUDA Payload](./27-gpu-cuda-payload.md)
- [28 - Scenario Engine Web/Mobile Persona](./28-scenario-engine-web-mobile-persona.md)

## 3) Distributed ve Enterprise

- [Distributed Container Native](./distributed-container-native.md)
- [Distributed HA Smoke](./distributed-ha-smoke.md)
- [29 - Distributed Control Plane Deep Dive](./29-distributed-control-plane.md)
- [30 - Licensing and Commercialization](./30-licensing-and-commercialization.md)
- [31 - Security Release Gates](./31-security-release-gates.md)
- [32 - Production Operations Runbook](./32-production-operations-runbook.md)
- [33 - DOCA GPUNetIO Gecis Durumu ve Operasyon Notlari](./33-doca-gpunetio-migration-status.md)
- [34 - DPDK Kurulum ve Hazirlik Rehberi](./34-dpdk-kurulum-ve-hazirlik-rehberi.md)

## 4) Senaryo ve Plan Dokumanlari

- [Scenario Engine Technical Notes](./scenario_engine.md)
- [Scenario Ornek YAML](./scenario_web_mobile.yaml)
- [L7 Native Custom QUIC/H3 Parity Plani](./PLAN_L7_NATIVE_CUSTOM_QUIC_H3_PARITY.md)

## 5) ADR ve Perf Notlari

- [ADR - Native C++ CPU Packet Engine with Python Facade](./adr/2026-04-04-cpu-packet-engine-native.md)
- [ADR - DOCA GPUNetIO Gecisi (Hybrid + Strict Fail-Fast)](./adr/2026-05-13-doca-gpunetio-hybrid-strict.md)
- [Perf - Scenario Engine 1M VU Benchmark Report](./perf/scenario_engine_1m_vu_benchmark_report.md)
- [Perf - DOCA GPUNetIO Progress Report](./perf/doca-gpunetio-progress-report.md)
