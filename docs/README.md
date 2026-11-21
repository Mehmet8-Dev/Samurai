# Samurai Documentation Index (Native C++)

This directory serves as the centralized technical index for the Samurai network resilience and stress testing platform, covering its native C++17 modular runtime, kernel-bypass engines, hardware accelerators, and distributed control planes.

![Samurai End-to-End System Architecture](assets/diagrams/samurai_system_architecture.svg)

---

## 1. Core Architecture & Runtime Subsystems

- [00 - System Architecture & Subsystem Map](./00-overview.md)
- [01 - Native CLI (`samurai`) Reference](./01-cli.md)
- [02 - Orchestrator & Native Supervisor Engine](./02-orchestrator.md)
- [04 - CPU Packet Builder & Traffic Synthesis Engine](./04-packet-builder.md)
- [05 - GPU CUDA & DOCA GPUNetIO Hardware Dataplane](./05-gpu.md)
- [06 - AF_XDP Kernel-Bypass & Zero-Copy Engine](./06-af_xdp-fast_sender.md)
- [07 - Target Safety & RFC Compliance Verification](./07-safety.md)
- [08 - Configuration & Test Profile Management](./08-config.md)
- [09 - Development, CMake Build System & Native Testing](./09-dev-testing.md)
- [10 - Troubleshooting & Operational Diagnostics](./10-troubleshooting.md)
- [11 - Docker & Containerized Distributed Architecture](./11-docker.md)
- [12 - Telemetry Visibility, Prometheus & Grafana Dashboards](./12-dashboard.md)
- [13 - Native HTTP Management REST API (`:8089`)](./13-api.md)

---

## 2. Advanced Hardware, Kernel-Bypass & Benchmarks

- [17 - GPU AI Dataplane Research & Validation Roadmap](./17-gpu-ai-dataplane-research-validation-roadmap.md)
- [18 - AF_PACKET & Hugepage Memory Management Policy](./18-afpacket-hugepage-policy.md)
- [19 - Benchmark Profiles & Workload Definitions](./19-benchmark-profiles.md)
- [20 - Environment Variables & CLI Options Reference](./20-env-cli-reference.md)
- [21 - NUMA Architecture, TX/RX Scaling & AF_XDP/DPDK DMA Guide](./21-numa-tx-rx-afxdp-dpdk-dma-guide.md)
- [22 - CLI Operational Playbook](./22-cli-operational-playbook.md)
- [23 - Benchmark Acceptance & Throughput Handbook](./23-benchmark-acceptance-handbook.md)
- [24 - Enterprise Stress Scenarios Handbook](./24-enterprise-test-scenarios-handbook.md)
- [25 - Core Runtime Modules Deep Dive](./25-core-runtime-modules.md)
- [26 - CLI Package Deep Architectural Map](./26-cli-package-deep-map.md)
- [28 - Scenario Engine (Web & Mobile Persona Modeling)](./28-scenario-engine-web-mobile-persona.md)
- [34 - DPDK Environment Setup & PMD Preparation Guide](./34-dpdk-environment-setup-guide.md)
- [37 - Carrier-Grade Telecom Engine Architecture Guide](./37-telecom-engine-guide.md)
- [45 - Commodity GeForce GPU & NIC P2P Packet Engine Report](./45-commodity-gpu-nic-p2p-packet-engine-report.md)
- [46 - GPU-Initiated NIC MMIO Doorbell & Baremetal PMD](./46-gpu-initiated-doorbell-and-baremetal-pmd.md)
- [47 - Zero-CPU Persistent Kernel Dataplane Architecture](./47-zero-cpu-persistent-dataplane-architecture.md)
- [48 - Commodity Workarounds & Enterprise Hardware Migration Plan](./48-commodity-workarounds-and-enterprise-migration-plan.md)
- [49 - DPU ARM & GPU Telecom CUPS Dataplane Architecture](./49-telecom-gpu-dpu-cups-dataplane-architecture.md)
- [50 - Open-Source Growth & Viral Launch Playbook](./50-open-source-growth-and-launch-playbook.md)
- [Samurai MCP Server (AI Coding Agent Bridge)](../mcp/README.md)

### Benchmarks & Verified Acceptance Reports:
- [43 - L4 Stateful TCP 1M Active Flows Benchmark Report](./benchmarks/43-tcpdp-1m-flows-benchmark-report.md)
- [44 - L7 Stateful Userspace Shared-Nothing Benchmark Report](./benchmarks/44-l7-stateful-userspace-benchmark-report.md)

---

## 3. Distributed Cluster & Operations Architecture

- [29 - Distributed Control Plane & Shard Orchestration](./29-distributed-control-plane.md)
- [31 - Security & Release Gate Validation](./31-security-release-gates.md)
- [32 - Production Operations Runbook](./32-production-operations-runbook.md)
- [33 - DOCA GPUNetIO & DPU-GPU Dataplane Architecture](./33-doca-gpunetio-migration-status.md)
- [35 - Variational Autoencoder (VAE) Defense Verification](./35-vae-defense-integration.md)
- [36 - ZMQ Worker Architecture & IPC Wire Protocol](./36-zmq-worker-architecture.md)
- [37 - DPU/GPU Dataplane Architecture & Contract Specification](./37-dpu-gpu-dataplane-architecture.md)
- [39 - Native Architecture & ZMQ Worker API Reference](./39-native-architecture-and-worker-api.md)
- [40 - Distributed Control Plane Handbook](./40-distributed-control-plane-handbook.md)
- [41 - Scenario JSON Specification & Examples](./41-scenario-json-spec-and-examples.md)
- [42 - Reinforcement Learning (RL) Closed-Loop Autopilot Evaluation](./42-rl-closed-loop-evaluation-and-findings.md)
- [Distributed Container-Native Runbook](./distributed-container-native.md)
- [Distributed High Availability (HA) Failover Testing](./distributed-ha-smoke.md)
