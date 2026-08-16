# 36 - ZMQ Worker Mimarisi ve IPC Protokolü

Bu belge, DDoSamurai'nin yerel süreçler arası (IPC) ve küme seviyesi haberleşmede kullandığı ZeroMQ (ZMQ) mimarisini açıklar.

---

## 1. Katman Ayrımı

1. **Native Supervisor Katmanı (`ddos_samurai/orchestrator/supervisor.cpp`):**
   - CLI veya Slave tarafından başlatılır.
   - Her worker için benzersiz Unix IPC soketleri oluşturur (`ipc:///tmp/samurai_jobs_*` ve `ipc:///tmp/samurai_events_*`).
   - `START_JOB`, `STOP_JOB`, `SHUTDOWN` komutlarını yönlendirir.

2. **ZMQ Native Dataplane Worker'ları (`ddos_samurai/zmq/daemon/`):**
   - `samurai_cpu_worker`
   - `samurai_afxdp_worker`
   - `samurai_dpdk_worker`
   - `samurai_gpu_worker`
   - `samurai_doca_worker`
   - `samurai_l7_worker`
   - `samurai_scenario_worker`
   - `samurai_defense_worker`

3. **ZMQ Dağıtık Control Plane (`ddos_samurai/control/`):**
   - Küme seviyesinde `samurai_master` (ZMQ ROUTER) ve `samurai_slave` (ZMQ DEALER) arasında TCP soketi (`tcp://<MASTER_IP>:5099`) üzerinden asenkron RPC çalıştırır.

---

## 2. Ortak Worker Çatısı (`worker_common.hpp` & `zmq_worker_base.hpp`)

Tüm native worker'lar kod tekrarını önleyen ortak C++ çatı modüllerini kullanır:
- `SendFrame(...)`: Başlık ve yükü tek frame olarak gönderir.
- `BuildSnapshot(...)` / `SerializeSnapshot(...)`: Standart telemetri formatı oluşturur.
- `PacingFromEnvelope(...)`: TSC tabanlı hız sınırlayıcıyı yapılandırır.
- `JsonError(...)`: Hata durumlarını JSON olarak serialize eder.

---

## 3. ZMQ Mesaj Tipleri (`MessageType`)

- `START_JOB` (0x01)
- `STOP_JOB` (0x02)
- `SHUTDOWN` (0x03)
- `ACK` (0x10)
- `HEARTBEAT` (0x20)
- `METRIC_SNAPSHOT` (0x21)
- `JOB_DONE` (0x30)
- `ERROR` (0xFF)
