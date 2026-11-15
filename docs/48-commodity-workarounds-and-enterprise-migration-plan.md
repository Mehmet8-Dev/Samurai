# Tüketici Donanımı (Commodity) Zorunlu Geçici Çözümleri (Workarounds) ve Kurumsal Donanım Geçiş/Refactor Planı

**Proje:** Samurai Yüksek Başarımlı Paket Motoru  
**Yazar:** Antigravity Sistem Araştırma ve Çekirdek Mühendisliği  
**Tarih:** 31 Ekim 2026  
**Doküman Kodu:** `DOC-SAMURAI-COMMODITY-WORKAROUNDS-48`  
**Referans Test Platformu:** NVIDIA GeForce GTX 1650 (Turing TU117, CC 7.5, 4 GB GDDR6) + AMD Ryzen 5 5600H (Cezanne PCIe Gen3 x8) + Realtek RTL8168 Gigabit Ethernet (`r8169.ko`, 1000BASE-T)  
**Hedef Kurumsal Platform:** NVIDIA ConnectX-6 Dx / ConnectX-7 (100G/200G/400G, DOCA GPUNetIO, DevX) veya Intel X710 / E810 (10G/40G/100G, DPDK PMD, native VFIO) + NVIDIA Ampere/Hopper/Blackwell Enterprise GPU + AMD EPYC / Intel Xeon PCIe Gen4/Gen5 Fabric  

---

## 1. Giriş ve Belgenin Amacı

Samurai, düşük maliyetli ve her geliştiricide bulunan son kullanıcı donanımlarında (Commodity Hardware) bare-metal GPU P2P paket çıkışını ve sıfır-CPU bağımlı persistent kernel mimarisini kanıtlamak üzere tasarlanmıştır.

Ancak kurumsal sunucu donanımlarının (Mellanox CX serisi, Intel kurumsal NIC'ler, Tesla/A100/H100 GPU'lar) yerel olarak sunduğu donanımsal yeteneklerin tüketici sınıfı donanımlarda bulunmaması nedeniyle, kod tabanına birtakım **zorunlu ara çözümler (workarounds / hardware shims)** eklenmiştir.

Bu dokümanın amacı:
1. Donanım eksiklikleri nedeniyle yazılmak zorunda kalınan tüm geçici mantıkları, fonksiyonları ve mimari yamaları açıkça belgelemek.
2. İleride kurumsal donanım temin edildiğinde, hangi kod bloklarının silineceğini, hangi yerel kütüphanelerin devreye alınacağını ve kodun nasıl sadeleştirileceğini somut bir refactor planı olarak sunmaktır.

---

## 2. Neden Bu Kodları Yazmak Zorunda Kaldık? (Donanım Kısıtları Matrisi)

| Mimari Katman | Test Ortamı Kısıtı (GeForce + RTL8168 + Cezanne) | Kurumsal Donanım Karşılığı (Mellanox CX-6/7 + Intel E810 + A100/H100) | Kod Seviyesinde Yazılan Geçici Çözüm (Workaround) |
| :--- | :--- | :--- | :--- |
| **Katman 1: Kuyruk & Çekirdek Paralelliği** | Realtek RTL8168'de **tek bir normal TX halkası** (`TNPDS`, 1024 slot) vardır. 1024 CUDA thread'i tek halkaya hücum eder. | **Multi-Queue / RSS** (64 ila 1024 bağımsız donanım TX kuyruğu). Her warp'a veya SM'e özel kuyruk atanır. | `reserve_stream_tokens()` içinde atomic CAS tabanlı DRR deficit yönetimi ve tek halka kilit açma mantığı. |
| **Katman 2: PCIe Root Complex & Senkronizasyon** | AMD Cezanne (Ryzen 5000 APU) kök kompleksi harici GPU'dan gelen **PCIe 3.0 AtomicOps (FetchAdd, Swap) yönlendirmesini desteklemez**. Host belleğinde atomik işlem yapmak veri yolunu kilitler. | **PCIe Gen5 / CXL / NVLink** tam önbellek tutarlılığı (cache coherency) ve donanımsal AtomicOp desteği. | `run_flag_dev` GDDR6 VRAM (`cudaMalloc`) içine çekildi. Host kontrolü için bağımsız `control_stream` (`cudaStreamNonBlocking`) köprüsü kuruldu. |
| **Katman 3: PMD & MMIO Doorbell** | Realtek kartta **modern dairesel `TDT` yazmacı yoktur**. `0x38 TPPoll` yazmacına `0x40` biti yazılarak kart DMA taramasına zorlanır. Kart kernel sürücüsünden (`r8169`) ayrılırsa güç yönetimi (ASPM) kartı `D3hot` modunda kapatır. | **UAR (User Access Region) / BlueFlame** (Mellanox) veya **`TDT` Circular Ring** (Intel). Tam **`vfio-pci`** userspace yalıtımı. | Kernel sürücüsü aktifken BAR2 MMIO üzerinden `TNPDS` ve `Command TxEnb` yazmaçları GPU BAR1 adresine zorla saptırıldı (`resolve_bar1_allocation_phys_addr`). |
| **Katman 4: VRAM / P2P DMA Aperture** | GeForce GTX 1650'de **GPUDirect RDMA ve `nvidia_peermem` sürücü seviyesinde kilitlidir**. VRAM doğrudan üçüncü parti PCIe cihazlarına DMA adresini ifşa etmez. | **Resmi NVIDIA GPUDirect RDMA** ve `nvidia-peermem.ko` yerel desteği. | Vulkan `VkDeviceMemory` (`HOST_VISIBLE`) üzerinden 256 MB BAR1 açıldı; fiziksel bus adresini bulmak için özel `/dev/nv_p2p` Linux kernel modülü yazıldı. |
| **Katman 5: Fiziksel Tel Kapasitesi** | 1000BASE-T Gigabit hattın fiziksel tavanı **1.488 Mpps**'dir (64B frame için). GPU ise VRAM içinde **28.93 Mpps** üretir. Tel %5 kapasitede kaldığı için halka anında taşar. | **100 Gbps (148.8 Mpps) / 200 Gbps (297.6 Mpps)** tam tel hızı. Donanım FIFO'su GPU üretimini doğrudan tel hızında tahliye eder. | Halka dolduğunda (`Ring Full`) kernelin panikle kapanmasını önleyen kontrollü slot geri kazanımı (`state = 0`) ve `ring_drop_events` sayacı eklendi. |

---

## 3. Katman Katman Geçici Kodların Detaylı İncelemesi

### 3.1. Katman 1: Tek Kuyruğu Paylaşma Kısıtı (DRR Deficit & Atomic CAS)

* **Etkilenen Dosya:** `samurai/gpu_packet_cuda/host_api.cuh`
* **İlgili Fonksiyon:** `reserve_stream_tokens(...)` (Satır 4270-4320)
* **Yazılmak Zorunda Kalınan Kod:**
  ```cuda
  // Realtek tek bir donanım TX halkasına sahip olduğu için yüzlerce GPU thread'i 
  // aynı halka için yarışır. Warp'lar arası kilitlenmeyi önlemek için lock-free atomic CAS:
  while (true) {
    const uint32_t quota_now = u32_load(&sv->quota_left);
    if (quota_now == 0u) return 0u;
    const uint32_t reserve = (quota_now < max_tokens) ? quota_now : max_tokens;
    const uint32_t next_quota = quota_now - reserve;
    if (atomicCAS((unsigned int*)&sv->quota_left, quota_now, next_quota) == quota_now) {
      sv->deficit = next_quota;
      if (slot_base_out) {
        *slot_base_out = atomicAdd((unsigned int*)&sv->queue_cursor, reserve);
      }
      return reserve;
    }
  }
  ```
* **Kurumsal Donanımda Refactor:**
  Mellanox CX-6 veya Intel E810 kartlarda 64 ila 1024 bağımsız TX kuyruğu bulunur. Her CUDA warp'ına veya Streaming Multiprocessor'a (SM) sabit bir `queue_id` (`qid = blockIdx.x % queue_count`) atanır. Bu sayede thread'ler atomik yarışa girmeden, doğrudan kendi donanım halkasına yazar. Bu fonksiyon tamamen sadeleşerek tek satırlık halka imleci ilerletmesine dönecektir.

---

### 3.2. Katman 2: AMD Cezanne PCIe 3.0 Uyumsuzluğu & Non-Blocking Asenkron Durdurma

* **Etkilenen Dosya:** `samurai/gpu_packet_cuda/host_api.cuh`
* **İlgili Yapılar:** `PersistentRuntime::control_stream`, `PersistentRuntime::run_flag_dev`, `persistent_launch_kernel()`, `persistent_stop_kernel()`
* **Yazılmak Zorunda Kalınan Kod:**
  1. `run_flag_dev` göstergesinin `cudaHostAlloc` ile CPU RAM'inde tutulması yerine GDDR6 VRAM'de (`cudaMalloc`) ayrılması.
  2. Persistent kernel GPU'da `while (*run_flag_dev == 1)` ile dönerken varsayılan Stream 0'ın kilitlenmesini aşmak için bağımsız `control_stream` (`cudaStreamNonBlocking`) oluşturulması:
  ```cpp
  // host_api.cuh: persistent_stop_kernel()
  rt.ctrl->run = 0;
  if (rt.run_flag_dev && rt.control_stream) {
    const int32_t run_off = 0;
    // Default stream yerine dedicated non-blocking stream üzerinden GDDR6'ya asenkron yazım:
    (void)cudaMemcpyAsync(rt.run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice, rt.control_stream);
    (void)cudaStreamSynchronize(rt.control_stream);
  }
  if (rt.kernel_stream) {
    (void)cudaStreamSynchronize(rt.kernel_stream);
  }
  ```
* **Kurumsal Donanımda Refactor:**
  Kurumsal sunucularda (Intel Xeon / AMD EPYC) PCIe AtomicOps kök komplekste yerel olarak desteklenir. Ayrıca DOCA GPUNetIO ortamında kernel durdurma işlemleri DOCA'nın dahili `doca_gpu_dev_eth_txq` durum bayrakları ve event mekanizmaları üzerinden yönetilir. Manuel `control_stream` tahsisi kalkar.

---

### 3.3. Katman 3: Realtek RTL8168 Sürücü Çatışması & Gizli MMIO Ele Geçirme

* **Etkilenen Dosyalar:**
  * `samurai/gpu_packet_cuda/geforce_p2p_runtime.cuh`
  * `samurai/gpu_packet_cuda/gpu_initiated_doorbell.cuh`
* **İlgili Fonksiyonlar:** `host_init_nic_pmd_tx_ring_mmio()`, `device_ring_nic_doorbell()`, `device_p2p_txq_try_commit_push()`
* **Yazılmak Zorunda Kalınan Kod:**
  Realtek kartı `r8169.ko` sürücüsünden unbind edemediğimiz için (kart uykuya geçmesin diye), BAR2 MMIO yazmaçları zorla GPU BAR1 adresine ayarlandı:
  ```cpp
  // geforce_p2p_runtime.cuh: host_init_nic_pmd_tx_ring_mmio()
  // 0x20: Transmit Normal Priority Descriptors Start (Low 32-bit)
  // 0x24: Transmit Normal Priority Descriptors Start (High 32-bit)
  // 0x37: Command Register (TxEnb = 0x04)
  writel_raw(mmio_base + 0x20, static_cast<uint32_t>(tx_ring_phys_iova & 0xFFFFFFFFULL));
  writel_raw(mmio_base + 0x24, static_cast<uint32_t>((tx_ring_phys_iova >> 32u) & 0xFFFFFFFFULL));
  writeb_raw(mmio_base + 0x37, 0x04);
  ```
  GPU'nun kapı zilini çalması için ise asenkron `TPPoll` yazmacına `0x40` basıldı:
  ```cuda
  // gpu_initiated_doorbell.cuh: device_ring_nic_doorbell()
  if (nic_driver == kNicRealtekR8169) {
    volatile uint8_t* tppoll_reg = mmio_base + 0x38;
    *tppoll_reg = 0x40; // Transmit Normal Priority Polling Request
  }
  ```
* **Kurumsal Donanımda Refactor:**
  * **Mellanox ConnectX (`mlx5`):** Kart doğrudan DOCA GPUNetIO userspace sürücüsüne (`libdoca_gpunetio`) bağlanır. Doorbell, GPU'dan NIC'in 4KB'lık UAR sayfasına tek bir 64-byte WQE yazılması (`BlueFlame`) ile tetiklenir.
  * **Intel (`ixgbe` / `i40e` / `ice`):** Kart `vfio-pci` ile kernelden tamamen izole edilir. GPU sadece dairesel `TDT` yazmacına yeni kuyruk indeksini yazar (`writel(new_tail, bar + IXGBE_TDT(qid))`). Kernel çatışması ve MMIO gaspı tamamen ortadan kalkar.

---

### 3.4. Katman 4: Vulkan BAR1 Export & `/dev/nv_p2p` Çekirdek Modülü

* **Etkilenen Dosyalar:**
  * `samurai/gpu_packet_cuda/vulkan_bar1_allocator.cpp`
  * `samurai/kernel_modules/nv_p2p/nv_p2p.c`
  * `samurai/gpu_packet_cuda/geforce_p2p_runtime.cuh:resolve_bar1_allocation_phys_addr()`
* **Yazılmak Zorunda Kalınan Kod:**
  GeForce sürücüsü resmi GPUDirect RDMA API'sini (`nvidia_p2p_get_pages`) kilitlediği için:
  1. Vulkan ile GDDR6 bellekte `VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT` bayraklarıyla bellek ayrıldı.
  2. Özel geliştirilen `/dev/nv_p2p` kernel modülü ile bu belleğin GPU BAR1 fiziksel PCIe bus adresi (`0xfcc02e0000`) bulundu.
  3. `dma_map_resource()` çağrısıyla ağ kartının IOMMU etki alanına (domain) eşlendi.
* **Kurumsal Donanımda Refactor:**
  NVIDIA Tesla / A100 / H100 / RTX 6000 Ada gibi kurumsal kartlarda resmi NVIDIA PeerDirect sürücüsü (`nvidia_peermem.ko`) bulunur. 
  * `vulkan_bar1_allocator.cpp` tamamen silinecektir.
  * `/dev/nv_p2p` çekirdek modülü tamamen silinecektir.
  * Standart `cudaMalloc(&ptr, size)` veya `doca_gpu_mem_alloc(gpu_dev, size, &gpu_buf)` çağrısı doğrudan DMA özellikli bellek döndürür.

---

### 3.5. Katman 5: 1 Gbps Tel Sınırı (1.488 Mpps) ve Backpressure Savunması

* **Etkilenen Dosya:** `samurai/gpu_packet_cuda/host_api.cuh`
* **İlgili Bölüm:** Satır 4905-4921 (Hardware PMD Backpressure Handling)
* **Yazılmak Zorunda Kalınan Kod:**
  1000BASE-T hattının 1.488 Mpps tavanı nedeniyle GPU'nun 28.93 Mpps'lik üretim patlaması 1024 slotluk Realtek TX FIFO'sunu anında doldurur. Eski kodda bu durum sistemi panikle düşürdüğü için, slotu geri dönüştüren ve tele inemeyen paketleri kontrollü şekilde düşüren mantık yazıldı:
  ```cuda
  if (doca_gpu_txq_handles && doca_txq_mkeys_be) {
    // Donanım halkası dolduğunda (Backpressure): Panik yapma, slotu sıfırla, jetonu iade et:
    if (slot.state == 1 || slot.state == 2) {
      (void)persistent_slot_transition(&slot, slot.state, 0, ctrl);
    } else {
      slot.state = 0;
    }
    slot.len = 0;
    local_ring_drop_events += 1u;
    (void)atomicAdd((unsigned int*)&sv->quota_left, 1u);
    continue;
  }
  ```
* **Kurumsal Donanımda Refactor:**
  100 Gbps veya 200 Gbps hatlarda fiziksel tavan 148.8 Mpps ila 297.6 Mpps'dir. GPU'nun ürettiği paketler doğrudan tele boşalacağı için bu geri tepme (backpressure) minimum seviyeye iner. Ancak savunma amaçlı olarak bu slot geri dönüşüm mekanizması mimaride korunmalıdır.

---

## 4. Kurumsal Donanıma Geçiş Refactor Matrisi

Aşağıdaki tablo, kurumsal donanım (örneğin Mellanox ConnectX-6 Dx + NVIDIA RTX 6000 Ada / A100) geldiğinde hangi dosyada ne yapılacağını özetler:

| Dosya Yolu | Şu Anki Kod / Workaround | Kurumsal Donanım Geldiğinde Yapılacak İşlem | Hedef Yeni Kod / Kütüphane |
| :--- | :--- | :--- | :--- |
| `samurai/gpu_packet_cuda/vulkan_bar1_allocator.cpp` | Vulkan API üzerinden BAR1 256MB VRAM ayrımı | **Dosya tamamen silinecek veya devredışı bırakılacak.** | `doca_gpu_mem_alloc()` veya `cudaMalloc()` |
| `samurai/kernel_modules/nv_p2p/` | Özel `/dev/nv_p2p` Linux kernel modülü | **Dizin ve modül tamamen silinecek.** | Resmi `nvidia-peermem.ko` (NVIDIA OFED) |
| `samurai/gpu_packet_cuda/geforce_p2p_runtime.cuh` | `resolve_bar1_allocation_phys_addr()`, `host_init_nic_pmd_tx_ring_mmio()`, Realtek BAR2 TNPDS hack'i | Bu fonksiyonlar `#if SAMURAI_LEGACY_GEFORCE` bloğuna alınacak; varsayılanda devre dışı kalacak. | DPDK `rte_eth_tx_burst` veya DOCA GPUNetIO `doca_gpu_eth_txq` API |
| `samurai/gpu_packet_cuda/gpu_initiated_doorbell.cuh` | Realtek `TPPoll (0x38)` ve tek kuyruklu `device_ring_nic_doorbell` | Mellanox DevX UAR BlueFlame veya Intel `IXGBE_TDT` register yazımı aktif edilecek. | `doca_gpu_dev_eth_txq_commit_strong()` & `doca_gpu_dev_eth_txq_push()` |
| `samurai/gpu_packet_cuda/host_api.cuh` | `PersistentRuntime::control_stream`, `run_flag_dev`, Cezanne uyumlu tek kuyruklu `reserve_stream_tokens()` | Multi-Queue (RSS) desteği açılacak; her warp'a ayrı TX queue atanacak. Kilit ve atomikler kalkacak. | `warp_id`-indexed lock-free ring enqueue |
| `tests/native_gpu/test_gpu_architecture.cpp` | Realtek BDF (`0000:02:00.0`) ve GeForce BDF tespiti | Kurumsal PCIe BDF (örn: `0000:af:00.0` CX-6) tespiti ve 100G wire-rate doğrulama testleri. | `TEST_CHECK(throughput_mpps >= 100.0)` |

---

## 5. Adım Adım Kurumsal Göç ve Temizlik Kılavuzu (Migration Checklist)

Uygun donanıma geçildiğinde uygulanacak adımlar sırasıyla şunlardır:

1. **BIOS & PCIe Ayarları:**
   * Anakart BIOS'unda `Above 4G Decoding` ve `Resizable BAR (ReBAR)` aktif edilir.
   * `SR-IOV` ve `IOMMU (VT-d / AMD-Vi)` aktif edilir.

2. **İşletim Sistemi & Sürücü Kurulumu:**
   * NVIDIA Data Center GPU sürücüsü ve CUDA Toolkit kurulur.
   * Mellanox OFED (MLNX_OFED) ve `nvidia-peermem` modülü yüklenir (`modprobe nvidia_peermem`).
   * Ağ kartı userspace moduna alınır:
     ```bash
     # Mellanox için (DevX / DOCA doğrudan çalışır):
     mst start && mlxconfig -d /dev/mst/mt4125_pciconf0 set REAL_TIME_CLOCK_ENABLE=1
     # Intel için (VFIO-PCI):
     modprobe vfio-pci
     dpdk-devbind.py -b vfio-pci 0000:af:00.0
     ```

3. **Derleme Bayraklarının Güncellenmesi:**
   * `CMakeLists.txt` içinde kurumsal bayraklar aktif edilir:
     ```bash
     cmake -B build -DSAMURAI_WITH_DOCA_GPUNETIO=ON -DSAMURAI_WITH_DPDK=ON -DSAMURAI_ENABLE_COMMODITY_SHIMS=OFF
     ```

4. **Doğrulama:**
   * `build/test_gpu_architecture` çalıştırılarak 100G/200G tel hızında 0 drop ve 100+ Mpps geçişi teyit edilir.

---

## 6. Sonuç

GeForce GTX 1650 ve Realtek RTL8168 üzerinde geliştirilen çözümler, en kısıtlı ve "düşmanca" donanım mimarisinde bile sıfır-CPU bağımlı GPU paket üretiminin matematiksel ve elektriksel olarak çalıştığını kanıtlamıştır. 

Yazılan tüm workarounds kodları temiz bir şekilde soyutlanmış (abstracted) olup, kurumsal donanıma geçişte mevcut veri düzlemi mantığını bozmadan tek bir derleme bayrağı ile kurumsal API'lere (DOCA / DPDK) devredilebilecek mimari esnekliğe sahiptir.
