# 00 - Genel Bakış ve Mimari Haritası

Samurai (Sürüm 2.2+, Kod Adı: **Shogun**), yetkili ve izole lab ortamlarında kullanılmak üzere tasarlanmış, sıfır Python çalışma zamanı gecikmesine sahip, modüler ve yüksek performanslı bir ağ stres ve dayanıklılık test platformudur.

Bu belge, projenin native C++ mimarisini ve bileşenler arası ilişkileri özetleyen ana mimari haritadır.

---

## 1. Mimari Katmanlar

### A) Native CLI Katmanı (`ddos_samurai/cli/`)
- **İkili Dosya:** `samurai`
- **Kaynaklar:** `main.cpp`, `args.cpp`, `validation.cpp`, `profiles.cpp`, `kpi_gate.cpp`, `reporting.cpp`, `rfc_suite.cpp`
- **Sorumluluk:** CLI argümanlarını parse etme, hedef güvenlik kurallarını işletme (`TargetSafety`), profilleri çözümleme, RFC testlerini yürütme ve ZMQ Supervisor üzerinden yerel dataplane işlerini başlatma.

### B) Dağıtık Control-Plane (`ddos_samurai/control/`)
- **Master Daemon:** `samurai_master` (`daemon/master_main.cpp`)
- **Slave Daemon:** `samurai_slave` (`daemon/slave_main.cpp`)
- **İletişim:** ZMQ ROUTER / DEALER asenkron RPC katmanı (`control_server.cpp`, `control_client.cpp`, `control_wire.hpp`).
- **Servisler:**
  - `servicer.cpp`: Worker kayıtları (`RegisterWorker`), heartbeat, telemetri toplama ve shard durum takibi.
  - `shard.cpp`: Yükü kapasite, bölge ve yeteneğe göre shard'lara bölme.
  - `ha.cpp`: Lider seçimi (`StaticLeaderElector`, `FileLeaseLeaderElector`).
  - `management_api.cpp`: POSIX socket tabanlı yerleşik HTTP REST API (`:8089`).
  - `control_auth.cpp` & `jwt.cpp`: HMAC-SHA256 JWT ve RBAC doğrulaması.
  - `multimaster.cpp`: Bölgeler arası koordinasyon.

### C) Native Orchestrator ve ZMQ Supervisor (`ddos_samurai/orchestrator/`)
- **Modüller:** `supervisor.cpp`, `worker_registry.hpp`
- **Sorumluluk:** Master, Slave veya yerel CLI'dan gelen `JobOptions` parametrelerini alarak ilgili native worker binary'sini (`samurai_*_worker`) ZMQ IPC (`ipc:///tmp/samurai_jobs_*`) üzerinden ayağa kaldırır, yönetir ve metrikleri toplar.

### D) ZMQ Native Dataplane Worker İkilleri (`ddos_samurai/zmq/daemon/`)
- `samurai_cpu_worker`: Standart raw socket ve packet ring motoru.
- `samurai_afxdp_worker`: Linux Kernel-Bypass AF_XDP zero-copy motoru.
- `samurai_dpdk_worker`: DPDK PMD donanım halkası motoru.
- `samurai_gpu_worker`: NVIDIA CUDA paralel paket sentez motoru.
- `samurai_doca_worker`: NVIDIA DPU & GPUNetIO doğrudan bellek yolu.
- `samurai_l7_worker`: HTTP/1.1, HTTP/2, QUIC/H3 ve DNS emülasyon motoru.
- `samurai_scenario_worker`: Çok adımlı web/mobil kullanıcı senaryoları.
- `samurai_defense_worker`: VAE savunma bypass ve doğrulama motoru.

### E) Donanım ve Protokol Motorları
- `ddos_samurai/l4/`: `tcp_dataplane_core.cpp` (64-shard kilit şeritli User-Space TCP Stack), `l4_state_engine_core.cpp`.
- `ddos_samurai/l7_emu_native/`: `engine.cpp`, `bridge.cpp`, `custom_quic_stack/`, `l2l3_stack/`.
- `ddos_samurai/scenario_engine_native/`: `compiler.cpp`, `scheduler.cpp`, `sla.cpp`.
- `ddos_samurai/cpu_native/`: `engine.cpp`, `packets.cpp`, `spoofing.cpp`, `amp.cpp`.
- `ddos_samurai/core/`: `json.hpp`, `target_safety.cpp`, `logging.hpp`.

---

## 2. Çalışma Modları

1. **Standalone (Yerel Çalışma):**
   ```bash
   ./build/ddos_samurai/cli/samurai --worker <cpu|afxdp|l7|scenario|...> --target <IP> --count <N> --confirm
   ```
2. **Dağıtık Master/Slave (Distributed):**
   - **Master:** `./build/ddos_samurai/control/daemon/samurai_master --control-listen tcp://0.0.0.0:5099 --count 10000000 ...`
   - **Slave:** `./build/ddos_samurai/control/daemon/samurai_slave --control-endpoints <MASTER_IP>:5099 --worker afxdp ...`
3. **Doğrulama ve Self-Test Modu:**
   - `./build/ddos_samurai/control/samurai_control_selftest`
   - `./build/ddos_samurai/l7_emu_native/samurai_l7_selftest`
   - `./build/ddos_samurai/scenario_engine_native/samurai_scenario_engine_selftest`
