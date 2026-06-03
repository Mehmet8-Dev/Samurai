# 36 - ZMQ Worker Architecture

Bu belge, mevcut yerel worker mimarisini aciklar. ZMQ burada bir dataplane
degil; CLI runtime ile worker daemon'lari arasindaki local IPC transportudur.

## 1) Katman Ayrimi

| Katman | Sorumluluk | Ana Dosyalar |
|---|---|---|
| CLI/live runtime | Worker sayisini boler, thread wrapper acarak local job dispatch eder | `ddos_samurai/cli/runtime.py` |
| Orchestrator bridge | Worker tipini secer, ZMQ daemon'u baslatir, job/event lifecycle'i izler | `ddos_samurai/orchestrator.py` |
| ZMQ transport | Binary wire format, PUSH/PULL dispatcher, event collector, runtime manager | `ddos_samurai/zmq/wire.py`, `dispatcher.py`, `event_collector.py`, `runtime_manager.py` |
| Native worker daemons | CPU/GPU/DPDK/AF_XDP/DOCA/L7/Defense/Scenario islerini ayri process olarak calistirir | `ddos_samurai/zmq/daemon/*.cpp` |

`ddos_samurai/zmq` dizini bu nedenle "ZMQ tabanli worker runtime" olarak okunmalidir.
Dataplane'e ait domain logic bu dizinde tutulmaz; ZMQ daemon dosyalari sadece
transport adapter ve process boundary kodu icermelidir.

## 2) Worker Tipleri

`WorkerKind` enum'u su worker ailelerini tanimlar:

- `CPU`: CPU native packet path
- `GPU`: CUDA persistent/stream packet path
- `DPDK`: DPDK PMD path
- `AF_XDP`: AF_XDP sender path
- `DOCA`: DOCA GPUNetIO worker
- `L7`: L7 native worker
- `DEFENSE`: defense/classifier worker
- `SCENARIO`: scenario-engine worker

Binary eslesmeleri `ZmqRuntimeManager` icindedir:

| WorkerKind | Binary |
|---|---|
| `CPU` | `samurai_cpu_worker` |
| `GPU` | `samurai_gpu_worker` |
| `DPDK` | `samurai_dpdk_worker` |
| `AF_XDP` | `samurai_afxdp_worker` |
| `DOCA` | `samurai_doca_worker` |
| `L7` | `samurai_l7_worker` |
| `DEFENSE` | `samurai_defense_worker` |
| `SCENARIO` | `samurai_scenario_worker` |

## 3) Socket Modeli

Her worker ailesi icin iki varsayilan IPC endpoint vardir:

- Job endpoint: `ipc:///tmp/samurai_jobs_<kind>`
- Event endpoint: `ipc:///tmp/samurai_events_<kind>`

Normal akista:

1. Worker daemon job endpoint'inde `PULL` socket bind eder.
2. CLI/orchestrator job frame'ini `PUSH` ile gonderir.
3. CLI/orchestrator event endpoint'inde `PULL` socket bind eder.
4. Worker daemon event frame'lerini `PUSH` ile yollar.

Mesajlar `SamuraiWireHeaderV1` + typed payload seklindedir. Temel mesajlar:

- `START_JOB`
- `STOP_JOB`
- `SHUTDOWN`
- `ACK`
- `HEARTBEAT`
- `METRIC_SNAPSHOT`
- `FLOW_UPDATE`
- `FLOW_STREAM_UPSERT`
- `ERROR`
- `JOB_DONE`

## 4) Worker Secimi

`orchestrator._resolve_worker_kind_for_zmq(...)` worker tipini runtime argumanlarindan secer:

- `scenario_mode=shadow|enforce` veya scenario payload varsa `SCENARIO`
- `compute_backend=cuda` icin `GPU`
- `compute_backend=dpdk` icin `DPDK`
- `xdp_enable` veya `sender_backend=xdp` icin `AF_XDP`
- L7 vektorleri icin `L7`
- Aksi halde `CPU`

DOCA worker, DOCA/GPUNetIO iceren GPU TX yolu icin local ZMQ worker ailesinin bir
uyesidir; DPU/GPU state mantiginin sahipligi `gpu_packet_cuda` altindadir.

## 5) Build ve Runtime Notlari

C++ worker binary'leri `ddos_samurai/zmq/CMakeLists.txt` ile uretilir. `libzmq`
bulunmazsa C++ worker binary'leri build edilmez.

Worker binary arama sirasi:

1. `zmq_worker_search_dir` runtime/config alani
2. `SAMURAI_ZMQ_WORKER_DIR`
3. Repo icindeki `build-workers/`
4. `PATH`

## 6) Distributed Control-Plane ile Fark

ZMQ worker architecture local host icinde daemon lifecycle ve job/event transportudur.
Distributed master/slave control-plane ise gRPC tabanlidir ve cluster-level
registration, shard dispatch, HA, RBAC, tenant isolation ve management API
sorumluluklarini tasir.

Kisa kural:

- Local process boundary: ZMQ worker runtime
- Multi-node orchestration: distributed gRPC control-plane
