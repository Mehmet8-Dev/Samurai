# DDoSamurai Dokümantasyon İndeksi (Native C++ / Shogun)

Bu dizin, DDoSamurai projesinin teknik mimarisini, native C++ bileşenlerini ve operasyonel kullanım kılavuzlarını içerir.

---

## 1. Çekirdek Sistem ve Çalışma Zamanı

- [00 - Genel Bakış ve Mimari Haritası](./00-overview.md)
- [01 - Native CLI (`samurai`) Kullanımı](./01-cli.md)
- [02 - Orchestrator & Native Supervisor](./02-orchestrator.md)
- [03 - Senders ve Native Dataplane Motorları](./03-senders.md)
- [04 - CPU Packet Builder ve Spoofing Engine](./04-packet-builder.md)
- [05 - GPU CUDA ve DOCA GPUNetIO Dataplane](./05-gpu.md)
- [06 - AF_XDP Kernel-Bypass ve Zero-Copy](./06-af_xdp-fast_sender.md)
- [07 - Hedef Güvenliği (Target Safety) ve RFC Kontrolleri](./07-safety.md)
- [08 - Konfigürasyon ve Profil Yapılandırması](./08-config.md)
- [09 - Geliştirme, CMake Derleme ve Native Testler](./09-dev-testing.md)
- [10 - Sorun Giderme (Troubleshooting)](./10-troubleshooting.md)
- [11 - Docker ve Dağıtık Konteyner Mimarisi](./11-docker.md)
- [12 - İzleme, Grafana ve Telemetri Görünürlüğü](./12-dashboard.md)
- [13 - Native HTTP Management API (`:8089`)](./13-api.md)

---

## 2. Derinlemesine Teknik ve Benchmark Dokümanları

- [20 - Environment Değişkenleri ve CLI Parametreleri](./20-env-cli-reference.md)
- [21 - NUMA, TX/RX, AF_XDP, DPDK ve DMA Mimarisi](./21-numa-tx-rx-afxdp-dpdk-dma-ders-notu.md)
- [22 - CLI Operasyonel El Kitabı (Playbook)](./22-cli-operational-playbook.md)
- [23 - Benchmark Kabul ve Başarım Kriterleri](./23-benchmark-acceptance-handbook.md)
- [24 - Kurumsal Test Senaryoları El Kitabı](./24-enterprise-test-scenarios-handbook.md)
- [25 - Core Runtime Modülleri](./25-core-runtime-modules.md)
- [26 - CLI Paket Detay Haritası](./26-cli-package-deep-map.md)
- [27 - GPU CUDA Payload Motoru](./27-gpu-cuda-payload.md)
- [28 - Scenario Engine (Web/Mobil Persona Modeli)](./28-scenario-engine-web-mobile-persona.md)

---

## 3. Dağıtık Küme (Distributed) ve Kurumsal Özellikler

- [29 - Dağıtık Control Plane Derinlemesine İnceleme](./29-distributed-control-plane.md)
- [30 - Lisanslama ve Ürünleştirme Mimarisi](./30-licensing-and-commercialization.md)
- [31 - Güvenlik ve Sürüm Çıkış Kapıları (Release Gates)](./31-security-release-gates.md)
- [32 - Prodüksiyon Operasyonları Runbook'u](./32-production-operations-runbook.md)
- [33 - DOCA GPUNetIO Göç ve Mimari Durumu](./33-doca-gpunetio-migration-status.md)
- [34 - DPDK Kurulum ve Hazırlık Rehberi](./34-dpdk-kurulum-ve-hazirlik-rehberi.md)
- [35 - VAE Savunma Entegrasyonu](./35-vae-defense-integration.md)
- [36 - ZMQ Worker Mimarisi ve IPC Protokolü](./36-zmq-worker-architecture.md)
- [37 - DPU/GPU Dataplane Mimarisi](./37-dpu-gpu-dataplane-architecture.md)
- [39 - Native Mimari ve ZMQ Worker API Referansı](./39-native-architecture-and-worker-api.md)
- [Distributed Container-Native Kılavuzu](./distributed-container-native.md)
- [Distributed High Availability (HA) Testleri](./distributed-ha-smoke.md)

---

## 4. Özel Protokol ve Senaryo Planları

- [L7 Native Custom QUIC/H3 Parite Planı](./PLAN_L7_NATIVE_CUSTOM_QUIC_H3_PARITY.md)
- [Scenario Engine Teknik Notları](./scenario_engine.md)
- [Örnek Senaryo Yapılandırması (YAML)](./scenario_web_mobile.yaml)
