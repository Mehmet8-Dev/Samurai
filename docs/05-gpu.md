# 05 - GPU CUDA ve DOCA GPUNetIO Dataplane

GPU ve DPU hızlandırma katmanı, donanım kaynaklarını kullanarak 100Gbps+ hat hızlarında paket üretimi ve akış yönetimi sağlar.

---

## 1. Bileşenler ve Mimarisi

1. **`samurai_gpu_worker` (`ddos_samurai/zmq/daemon/gpu_worker.cpp`):**
   - CUDA çekirdekleri (`ddos_samurai/gpu_packet_cuda/`) üzerinde on binlerce GPU iş parçacığıyla (threads) eşzamanlı paket sentezi yapar.
   - GPU VRAM içinde oluşturulan paket halkaları (packet buffers) GPUDirect veya host-staging üzerinden ağ kartına iletilir.

2. **`samurai_doca_worker` (`ddos_samurai/zmq/daemon/doca_gpunetio_worker.cpp`):**
   - NVIDIA BlueField DPU ve DOCA GPUNetIO teknolojisiyle ana işlemciyi (Host CPU) tamamen devre dışı bırakır.
   - GPU VRAM ile DPU NIC RX/TX halkaları arasında sıfır kopyalı (Zero-Copy) doğrudan DMA transferi sağlar.

3. **DPU State Runtime (`dpu_state_runtime.hpp`):**
   - DPU üzerinde çalışan donanım destekli akış tablosu.
   - TCP durum takibi, pasif açılış ve retransmission kararlarını DPU seviyesinde yönetir.

---

## 2. Derleme ve Çalıştırma

CUDA ve DOCA desteği CMake derlemesi sırasında otomatik olarak tespit edilir:

```bash
# GPU Worker ile çalıştırma
./build/ddos_samurai/cli/samurai \
  --worker gpu \
  --target 10.0.0.50 --port 80 \
  --protocol tcp --count 20000000 \
  --confirm

# DOCA GPUNetIO ile çalıştırma
sudo ./build/ddos_samurai/cli/samurai \
  --worker doca \
  --target 10.0.0.50 --port 80 \
  --confirm
```
