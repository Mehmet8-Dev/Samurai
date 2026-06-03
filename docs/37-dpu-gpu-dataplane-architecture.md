# 37 - DPU/GPU Dataplane Architecture

Bu belge, DOCA GPUNetIO ile GPU persistent/stream runtime arasindaki DPU/GPU
dataplane kontratini aciklar.

## 1) Sahiplik Sinirlari

| Alan | Sahip | Dosyalar |
|---|---|---|
| GPU CUDA packet runtime ve contract | GPU katmani | `ddos_samurai/gpu_packet_cuda/*` |
| DPU authoritative flow-state model | GPU/DPU contract katmani | `ddos_samurai/gpu_packet_cuda/dpu_state_runtime.hpp` |
| DOCA GPUNetIO backend ABI | GPU CUDA backend | `ddos_samurai/gpu_packet_cuda/tx_backend_doca_gpunetio.cuh`, `doca_gpunetio_backend.cpp` |
| ZMQ process adapter | Worker transport | `ddos_samurai/zmq/daemon/doca_gpunetio_worker.cpp` |

`dpu_state_runtime.hpp` ZMQ transport dosyasi degildir. GPU hot-flow contract,
DPU authoritative state ve DOCA feedback policy icin `gpu_packet_cuda` altinda
durur. DOCA worker bu header'i kullanarak transport boundary'den dataplane
contract'a baglanir.

## 2) Akis

1. CLI/orchestrator `START_JOB` frame'ini DOCA worker'a yollar.
2. DOCA worker, DOCA native backend'i `dlopen` ile yukler.
3. Worker TXQ olusturur; gerekli ise RXQ ve DPU contract writer acar.
4. Packet pool CPU native engine ile hazirlanir veya passive-open icin RX beklenir.
5. `FlowStateTable` ilk flow state'i olusturur.
6. DPU state, GPU worker'a `FLOW_STREAM_UPSERT` ve `FLOW_UPDATE` yayinlar.
7. DOCA TX path `send_vector` ile packet batch yollar.
8. RX feedback aciksa `receive_burst` ile ACK/SYN/FIN/RST gorulur.
9. DPU state TCP timers, retransmit, zero-window ve congestion policy'yi gunceller.
10. GPU stream policy tekrar yayinlanir.

## 3) DPU State Runtime

`dpu_state_runtime.hpp` su isleri yapar:

- Authoritative `FlowState` saklar.
- TCP state machine'i yurutur: closed, listen, syn-sent, syn-received, established,
  fin-wait, close-wait, last-ack, time-wait, migrating, poisoned.
- TCP segmentlerini parse eder: IPv4/TCP header, MSS, window scale, SACK,
  timestamp, ECN.
- TCB tutar: `snd_una`, `snd_nxt`, `rcv_nxt`, cwnd/ssthresh, RTO,
  retransmit queue, receive queue, out-of-order queue.
- Passive open/listen backlog modelini yurutur.
- GPU stream policy uretir: quota, payload length, IPG, pause,
  retransmit ve zero-window-probe bitleri.
- Wire contract event'i uretir: `FlowUpdateEventV1`, `FlowStreamUpsertV1`.

## 4) GPU Contract

DPU tarafindan GPU'ya iki ana event akar:

- `FLOW_UPDATE`: committed DPU flow-state snapshot'i.
- `FLOW_STREAM_UPSERT`: GPU stream/hot-flow policy guncellemesi.

Her iki event de version ve epoch tasir. Version monoton artan committed state
sirasidir; epoch ise migration/ownership sinirini temsil eder.

GPU tarafinda bu event'ler persistent/stream runtime'in hot-flow state'ini
gunceller. DPU state poisoned, migrating, closed veya time-wait durumuna girerse
policy pause'a cekilir.

## 5) DOCA Worker'in Rolu

`samurai_doca_worker` bir transport adapter + DOCA session host process'idir.
Sorumluluklari:

- ZMQ job/event socketlerini acmak.
- DOCA TXQ/RXQ lifecycle'ini yonetmek.
- Packet batch'lerini DOCA backend'e gecmek.
- DPU state runtime'a TX/RX/timer olaylarini bildirmek.
- GPU worker'a flow update ve stream upsert mesajlarini yollamak.
- Opsiyonel RDMA/contract writer yolunu acmak.

Bu dosyada kalmasi gereken kod ZMQ/worker lifecycle ve DOCA oturum orkestrasyonudur.
TCP state machine, GPU contract policy ve DPU state domain logic `gpu_packet_cuda`
altinda kalmalidir.

## 6) Onemli Env ve Flag'ler

| Ayar | Anlam |
|---|---|
| `SAMURAI_GPU_TX_BACKEND=doca_gpunetio` | GPU TX backend olarak DOCA GPUNetIO secilir |
| `SAMURAI_GPU_TX_BACKEND_STRICT=1` | Fallback yerine fail-visible davranis |
| `SAMURAI_GPU_DOCA_ENABLE=1` | DOCA backend enable |
| `SAMURAI_GPU_DOCA_DEVICE=<mlx5_x>` | DOCA device |
| `SAMURAI_GPU_DOCA_GPU_ID=<n>` | GPU id |
| `SAMURAI_GPU_JOB_ENDPOINT` | DPU/DOCA worker'in GPU worker'a publish edecegi job endpoint |
| `SAMURAI_DPU_STATE_PUBLISH=0|1` | DPU->GPU ZMQ state publish ac/kapat |
| `SAMURAI_DPU_TCP_RX_FEEDBACK=1` | RX feedback ile ACK/state update ac |
| `SAMURAI_DPU_TCP_PASSIVE_OPEN=1` | Passive open/listen akisini ac |
| `SAMURAI_DPU_CONTRACT_RDMA=1` | Opsiyonel RDMA contract writer ac |
| `SAMURAI_DPU_CONTRACT_RDMA_SPEC=<spec>` | RDMA contract import/export spec |

DOCA worker CLI flag'leri:

- `--gpu-job-endpoint`
- `--dpu-state-publish 0|1`
- `--dpu-contract-rdma`
- `--dpu-contract-rdma-spec <spec>`
- `--dpu-tcp-rx-feedback`
- `--no-dpu-tcp-rx-feedback`
- `--dpu-tcp-passive-open`
- `--doca-interface <iface>`
- `--doca-device <device>`
- `--doca-queue-id <id>`
- `--doca-rx-queue-id <id>`
- `--doca-gpu-id <id>`
- `--doca-batch-size <n>`

## 7) Dogrulama

Donanim olmadan:

```bash
PYTHONPATH=. pytest tests/test_zmq_wire_contract.py -q
PYTHONPATH=. pytest tests/test_zmq_m3_workers.py -q
PYTHONPATH=. pytest tests/native_gpu/test_backend_facade.py -q
```

Donanimli lab ortaminda ayrica:

- DOCA TX line-rate/Mpps
- RX feedback latency
- DPU->GPU flow update latency
- queue scaling ve jitter
- GPU/NIC PCIe topoloji etkisi

