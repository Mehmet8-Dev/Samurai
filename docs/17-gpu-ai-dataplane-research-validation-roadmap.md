# 17 - GPU + AI Dataplane Research Roadmap ve Validation Checklist

Tarih: 2026-03-05  
Kapsam: TRex-benzeri ama GPU + AI destekli yuksek performansli trafik veri yolu icin arastirma ve dogrulama plani.

## 1) Mimari Harita

Hedef pipeline:

```text
AI Traffic Model
        |
        v
GPU Flow Generator
        |
        v
GPU Packet Builder
        |
        v
GPU -> Host Pinned Memory Copy
        |
        v
DPDK / AF_XDP / netmap / PF_RING TX Engine
        |
        v
NIC
```

Modul sorumluluklari:

- `AI Traffic Model`
  - Trafik dagilimlarini, protocol mix'i, flow life-cycle modelini uretir.
- `GPU Flow Generator`
  - Per-thread/per-flow IP/port/seq/ack/state alanlarini uretir.
- `GPU Packet Builder`
  - Ethernet/IP/TCP/UDP header olusturma, payload kalibi, checksum.
- `GPU -> Host Copy`
  - GPU bellegindeki contiguous packet buffer'in host pinned buffer'a alinmasi.
- `TX Engine (CPU side)`
  - Rate control, queue management, NIC descriptor doldurma, TX submit.
- `NIC`
  - Host memory'den DMA ile okuyup wire'a cikis.

CPU/GPU/NIC gorev paylasimi:

- GPU asamasi:
  - Flow field randomization
  - Header assembly + checksum
  - Template cogaltma
- CPU asamasi:
  - Scheduler (token/leaky/precise timing)
  - Dataplane backend secimi
  - NIC TX queue push
- NIC asamasi:
  - DMA read + fiziksel iletim

Memory transfer noktalari:

1. CPU -> GPU: template, profile, flow parametreleri (H2D)
2. GPU -> CPU: packet batch copy (D2H, tercihen pinned)
3. CPU -> NIC: descriptor/mbuf/umem slot baglama
4. NIC DMA: host memory read

Kontrol sorulari:

- GPU hangi asamada? `Flow generation + packet build`
- CPU hangi asamada? `Scheduling + TX engine`
- NIC hangi asamada? `Final DMA + wire TX`

## 2) Literatur ve Teknoloji Taramasi (Maturity Matrix)

Asagidaki tablo, "packet generation mi, packet processing mi, flow simulation var mi, GPU hangi asamada?" sorusuna odaklanir.

| Calisma / Teknoloji | Packet Generation | Packet Processing | Flow Simulation | GPU'nin Asamasi |
|---|---|---|---|---|
| PacketShader (SIGCOMM'10) | Hayir | Evet | Kisiti | GPU ile packet processing pipeline |
| GPUnet (OSDI'14) | Hayir | Evet | Kisiti | GPU side packet processing |
| GASPP (USENIX ATC'17) | Kismi | Evet | Kisiti | GPU packet processing framework |
| G-NET (NSDI'18) | Hayir | Evet | Kismi | NIC->GPU direct packet processing |
| MoonGen | Evet (CPU tabanli) | Kismi | Yok | GPU yok, CPU packet generator baseline |
| NetBricks (NSDI'16) | Kismi | Evet | Kismi | GPU yok, CPU NFV framework |
| AF_XDP (kernel docs) | Hayir | TX/RX dataplane API | Yok | GPU yok, host-memory UMEM |
| DPDK ethdev | Hayir | TX/RX dataplane API | Yok | GPU yok, userspace host-memory mbuf |
| NVIDIA GPUNetIO | Hayir (dogrudan generator degil) | Evet | Kismi | GPU kernel ile NIC queue etkileşimi |
| GPUDirect RDMA | Hayir | Tasima altyapisi | Yok | NIC <-> GPU memory DMA yolu |
| CUDA pinned memory | Hayir | Tasima altyapisi | Yok | GPU->host transfer hizlandirma |

Kritik sonuc:

- GPU tarafinda "packet processing" literaturu var ve olgun.
- "Line-rate packet generator + direct NIC TX from GPU memory" ancak ozel donanim/driver kombinasyonlarinda gerceklesiyor.
- Genel ortamda hala en yaygin yol: `GPU build -> host pinned -> CPU TX engine -> NIC`.

## 3) Flow Generator Mimarisi Analizi

Flow generator bilesenleri:

- IP dagilimi (src/dst subnet)
- Port dagilimi (ephemeral + target port mix)
- Flow state (SYN_SENT, ESTABLISHED, FIN_WAIT vb.)
- Protocol state (seq/ack penceresi)
- Packet template secimi

GPU uygunluk degerlendirmesi:

- GPU thread basina flow: `Evet`, 1 thread = 1 flow modeli iyi eslesir.
- Warp divergence riski: `Orta`
  - Farkli protocol/state branch'leri arttikca divergence artar.
- Memory access pattern:
  - `SoA (Structure of Arrays)` tercih edilmeli.
  - Coalesced read/write icin per-field array kullanilmali.

Bu repo icin implementasyon dogrulamasi:

- `tests/gpu_dataplane_validation.py` icindeki `gpu_flow_rng` benchmark'i:
  - XOROSHIRO tabanli flow uretimi
  - IP/port/state/seq/ack alanlari
  - throughput + latency olcumu

## 4) Packet Builder Pipeline

Packet builder katmanlari:

- Ethernet
- IPv4
- TCP/UDP
- Payload

GPU tarafinda yapilabilirlik:

- Header olusturma: `Evet`
- Checksum hesaplama: `Evet`
- Payload sentezi: `Evet`

Ornek kernel modeli (pseudo):

```c
kernel generate_packet(i):
    flow = flows[i]
    pkt.eth.src = src_mac
    pkt.eth.dst = dst_mac
    pkt.ip.src = flow.src_ip
    pkt.ip.dst = flow.dst_ip
    pkt.tcp.src_port = flow.src_port
    pkt.tcp.dst_port = flow.dst_port
    pkt.tcp.seq = flow.seq
    pkt.tcp.ack = flow.ack
    pkt.ip.csum = checksum_ipv4(...)
    pkt.tcp.csum = checksum_tcp(...)
```

Bu repo icin implementasyon dogrulamasi:

- `tests/gpu_dataplane_validation.py` icindeki `gpu_packet_builder` benchmark'i:
  - GPU kernel ile Ethernet+IPv4+TCP paket olusturma
  - IP/TCP checksum dogrulama
  - packet/s throughput olcumu

## 5) GPU -> CPU Memory Pipeline (En Kritik Nokta)

Pipeline:

```text
GPU memory
   |
   v
cuda copy (D2H)
   |
   v
host pinned memory
   |
   v
TX backend buffer (mbuf/umem/netmap slot)
   |
   v
NIC DMA
```

Olculecek metrikler:

- Throughput: `GB/s`
- Latency: `mean/p95/p99 ms`
- Batch-size etkisi: `MB bazli sweep`

Bu repo icin benchmark:

```bash
python3 tests/gpu_dataplane_validation.py \
  --count 200000 \
  --iterations 3 \
  --copy-batches-mb 1,4,16,64 \
  --pretty \
  --out reports/runs/artifacts/gpu_dataplane_validation.json
```

## 6) Zero-Copy Arastirmasi (GPUDirect)

Gercek zero-copy benzeri NIC<->GPU yol gereksinimleri:

- NVIDIA GPU
- GPUDirect RDMA uyumlu NIC (tipik olarak Mellanox/ConnectX ailesi)
- Uyumlu kernel/driver/CUDA stack
- PCIe topolojisinde uygun baglanti

Kritik not:

- AF_XDP ve klasik DPDK path, varsayilan olarak host-memory tabanlidir.
- GPUDirect RDMA/GPUNetIO ozel donanim + driver kosullarinda NIC->GPU veya GPU->NIC yolu acabilir.
- Her ortamda "dogrudan GPU memory'den TX" beklemek dogru degildir.

Kontrol checklist:

- [ ] GPU modeli ve driver uyumlu mu?
- [ ] NIC GPUDirect RDMA destekli mi?
- [ ] BIOS/IOMMU/PCIe topolojisi uygun mu?
- [ ] CUDA ve NIC driver versiyonlari dokuman uyumunda mi?

## 7) Data Plane Motoru Karsilastirma Plani

Aday backend'ler:

- DPDK
- AF_XDP
- netmap
- PF_RING (opsiyonel)

Metrik seti (hepsinde ayni):

- PPS
- p50/p95 latency
- CPU usage (% user+sys)
- Drop/error counter

Esit kosul prensibi:

- Ayni NIC/CPU/GPU host
- Ayni packet size/protocol mix
- Ayni rate profile (burst + steady)
- Ayni sure ve warm-up

Bu repo icin otomatik probe:

- `tests/gpu_dataplane_validation.py` -> `runtime_probe.dataplane_backends`
- Backend kurulu/uygunluk durumu ve benchmark hint ciktisi verir.

## 8) Flow Scheduling (Timing)

Test edilmesi gereken scheduler modlari:

- Token bucket
- Leaky bucket
- Precise timer (hybrid sleep+spin)

Olculecekler:

- actual_rps
- rate_accuracy_pct
- iat (inter-arrival) mean/p95/p99
- jitter (absolute error)
- CPU usage

Bu repo icin implementasyon:

- `tests/gpu_dataplane_validation.py` icinde `flow_scheduling` benchmark'i:
  - uc scheduler'i ayni hedef RPS icin karsilastirir
  - pacing engine calibration/capability probe alanlarini da rapora ekler

## Validation Checklist (Systematic)

- [ ] Pipeline diyagrami ve modul ownership net
- [ ] GPU flow RNG benchmark geciyor
- [ ] GPU packet builder + checksum validation geciyor
- [ ] GPU->host copy benchmark'ta batch-size etkisi raporlandi
- [ ] Dataplane backend probe (DPDK/AF_XDP/netmap/PF_RING) toplandi
- [ ] Zero-copy uyumluluk checklist'i dolduruldu
- [ ] Scheduler benchmark'ta rate/jitter/cpu raporu alindi
- [ ] Tum sonuclar tek JSON artefaktinda toplandi

## Kaynaklar

- PacketShader (SIGCOMM'10): https://www.microsoft.com/en-us/research/publication/packetshader-a-gpu-accelerated-software-router/
- GPUnet (OSDI'14): https://www.usenix.org/conference/osdi14/technical-sessions/presentation/zhou
- GASPP (USENIX ATC'17): https://www.usenix.org/conference/atc17/technical-sessions/presentation/kalia
- G-NET (NSDI'18): https://www.usenix.org/conference/nsdi18/presentation/kim
- MoonGen: https://github.com/emmericp/MoonGen
- NetBricks (NSDI'16): https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/panda
- AF_XDP kernel docs: https://docs.kernel.org/networking/af_xdp.html
- DPDK ethdev API: https://doc.dpdk.org/api/rte__ethdev_8h.html
- netmap paper: https://www.usenix.org/system/files/conference/atc12/atc12-final186.pdf
- NVIDIA GPUNetIO: https://docs.nvidia.com/doca/sdk/doca+gpunetio/index.html
- NVIDIA GPUDirect RDMA: https://docs.nvidia.com/cuda/gpudirect-rdma/index.html
- NVIDIA GPUDirect Storage: https://docs.nvidia.com/gpudirect-storage/
- CUDA pinned memory overview: https://docs.nvidia.com/cuda/archive/12.6.3/cuda-c-programming-guide/index.html#page-locked-host-memory

