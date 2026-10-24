#pragma once

#include <cuda.h>
#include <cuda_runtime.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "tx_backend_doca_gpunetio.cuh"
#include "tx_backend_geforce_p2p.cuh"
#include "zero_copy_dataplane_contract.cuh"

namespace ddos_samurai::gpu_packet_cuda::p2p {

// Optional AF_PACKET TX_RING bridge weak symbol for live wire egress when DPDK VFIO is not attached.
extern "C" __attribute__((weak)) int afpkt_send_ring_bridge(
    const char* iface,
    const uint8_t* buffer,
    size_t buffer_len,
    int packet_size,
    int count,
    const uint8_t mac[6],
    int* out_sent,
    int* out_errors,
    char* err_msg,
    size_t err_msg_len);

// Optional /dev/nv_p2p ioctl constants (from p2p_core/nv_p2p_module.c)
constexpr unsigned int kNvP2pIoctlMagic = 'P';
#define SAMURAI_IOCTL_RESOLVE_PFN _IOWR(kNvP2pIoctlMagic, 1, unsigned long)

// Linux VFIO IOMMU DMA mapping ioctl structure (linux/vfio.h compatible)
struct SamuraiVfioIommuMapDma {
  uint32_t argsz;
  uint32_t flags;
  uint64_t vaddr;
  uint64_t iova;
  uint64_t size;
};
constexpr uint32_t kVfioDmaMapFlagRead = (1u << 0);
constexpr uint32_t kVfioDmaMapFlagWrite = (1u << 1);
constexpr unsigned long kVfioIommuMapDmaIoctl = 0x3b71ul;  // VFIO_IOMMU_MAP_DMA

struct VulkanDynamicLoader {
  void* lib_handle = nullptr;
  PFN_vkCreateInstance vkCreateInstance_fn = nullptr;
  PFN_vkDestroyInstance vkDestroyInstance_fn = nullptr;
  PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices_fn = nullptr;
  PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties_fn = nullptr;
  PFN_vkGetPhysicalDeviceMemoryProperties vkGetPhysicalDeviceMemoryProperties_fn = nullptr;
  PFN_vkCreateDevice vkCreateDevice_fn = nullptr;
  PFN_vkDestroyDevice vkDestroyDevice_fn = nullptr;
  PFN_vkAllocateMemory vkAllocateMemory_fn = nullptr;
  PFN_vkFreeMemory vkFreeMemory_fn = nullptr;
  PFN_vkMapMemory vkMapMemory_fn = nullptr;
  PFN_vkUnmapMemory vkUnmapMemory_fn = nullptr;
  PFN_vkGetDeviceProcAddr vkGetDeviceProcAddr_fn = nullptr;

  bool ensure_loaded(std::string& err) {
    if (lib_handle != nullptr) {
      return true;
    }
    lib_handle = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib_handle) {
      lib_handle = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (!lib_handle) {
      err = "libvulkan.so.1 not available for BAR1 P2P allocation";
      return false;
    }
    vkCreateInstance_fn = reinterpret_cast<PFN_vkCreateInstance>(dlsym(lib_handle, "vkCreateInstance"));
    vkDestroyInstance_fn = reinterpret_cast<PFN_vkDestroyInstance>(dlsym(lib_handle, "vkDestroyInstance"));
    vkEnumeratePhysicalDevices_fn =
        reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(dlsym(lib_handle, "vkEnumeratePhysicalDevices"));
    vkGetPhysicalDeviceProperties_fn =
        reinterpret_cast<PFN_vkGetPhysicalDeviceProperties>(dlsym(lib_handle, "vkGetPhysicalDeviceProperties"));
    vkGetPhysicalDeviceMemoryProperties_fn = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        dlsym(lib_handle, "vkGetPhysicalDeviceMemoryProperties"));
    vkCreateDevice_fn = reinterpret_cast<PFN_vkCreateDevice>(dlsym(lib_handle, "vkCreateDevice"));
    vkDestroyDevice_fn = reinterpret_cast<PFN_vkDestroyDevice>(dlsym(lib_handle, "vkDestroyDevice"));
    vkAllocateMemory_fn = reinterpret_cast<PFN_vkAllocateMemory>(dlsym(lib_handle, "vkAllocateMemory"));
    vkFreeMemory_fn = reinterpret_cast<PFN_vkFreeMemory>(dlsym(lib_handle, "vkFreeMemory"));
    vkMapMemory_fn = reinterpret_cast<PFN_vkMapMemory>(dlsym(lib_handle, "vkMapMemory"));
    vkUnmapMemory_fn = reinterpret_cast<PFN_vkUnmapMemory>(dlsym(lib_handle, "vkUnmapMemory"));
    vkGetDeviceProcAddr_fn =
        reinterpret_cast<PFN_vkGetDeviceProcAddr>(dlsym(lib_handle, "vkGetDeviceProcAddr"));

    if (!vkCreateInstance_fn || !vkDestroyInstance_fn || !vkEnumeratePhysicalDevices_fn ||
        !vkGetPhysicalDeviceProperties_fn || !vkGetPhysicalDeviceMemoryProperties_fn ||
        !vkCreateDevice_fn || !vkDestroyDevice_fn || !vkAllocateMemory_fn || !vkFreeMemory_fn ||
        !vkMapMemory_fn || !vkUnmapMemory_fn || !vkGetDeviceProcAddr_fn) {
      dlclose(lib_handle);
      lib_handle = nullptr;
      err = "missing required Vulkan entrypoints in libvulkan";
      return false;
    }
    return true;
  }
};

inline VulkanDynamicLoader& get_vulkan_loader() {
  static VulkanDynamicLoader loader;
  return loader;
}

inline std::string detect_gpu_pci_bdf() {
  char pci_bus_id[64]{};
  if (cudaDeviceGetPCIBusId(pci_bus_id, sizeof(pci_bus_id), 0) == cudaSuccess && pci_bus_id[0] != '\0') {
    std::string bdf(pci_bus_id);
    std::transform(bdf.begin(), bdf.end(), bdf.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    // Normalize 00000000:01:00.0 -> 0000:01:00.0 if needed
    if (bdf.size() > 12 && bdf.substr(0, 4) == "0000") {
      const size_t first_colon = bdf.find(':');
      if (first_colon > 4) {
        bdf = bdf.substr(first_colon - 4);
      }
    }
    return bdf;
  }
  return "0000:01:00.0";
}

inline uint64_t read_sysfs_bar1_phys_base(const std::string& bdf_in) {
  const std::string bdf = bdf_in.empty() ? detect_gpu_pci_bdf() : bdf_in;
  const std::string path = "/sys/bus/pci/devices/" + bdf + "/resource";
  std::ifstream ifs(path);
  if (!ifs.is_open()) {
    return 0xfcc0000000ULL;
  }
  std::string line;
  // Line 0 is BAR0, Line 1 is BAR1 (64-bit prefetchable aperture)
  if (!std::getline(ifs, line)) {
    return 0xfcc0000000ULL;
  }
  if (!std::getline(ifs, line)) {
    return 0xfcc0000000ULL;
  }
  unsigned long long start_addr = 0ULL;
  if (std::sscanf(line.c_str(), "0x%llx", &start_addr) == 1 && start_addr != 0ULL) {
    return static_cast<uint64_t>(start_addr);
  }
  return 0xfcc0000000ULL;
}

inline uint64_t resolve_bar1_physical_address(void* host_mapped_ptr, uint64_t fallback_bar1_base) {
  if (!host_mapped_ptr) {
    return fallback_bar1_base;
  }
  int p2p_fd = ::open("/dev/nv_p2p", O_RDWR);
  if (p2p_fd >= 0) {
    unsigned long arg = reinterpret_cast<unsigned long>(host_mapped_ptr);
    if (::ioctl(p2p_fd, SAMURAI_IOCTL_RESOLVE_PFN, &arg) == 0 && arg != 0ul) {
      ::close(p2p_fd);
      return static_cast<uint64_t>(arg) << 12u;
    }
    ::close(p2p_fd);
  }
  return fallback_bar1_base;
}

struct VulkanBar1Arena {
  VkInstance instance = VK_NULL_HANDLE;
  VkPhysicalDevice phys_dev = VK_NULL_HANDLE;
  VkDevice device = VK_NULL_HANDLE;
  VkDeviceMemory dev_mem = VK_NULL_HANDLE;
  cudaExternalMemory_t cuda_ext_mem = nullptr;
  int exported_fd = -1;
  uint8_t* host_bar1_ptr = nullptr;
  uint8_t* cuda_dev_ptr = nullptr;
  uint64_t bar1_phys_base = 0u;
  uint64_t bar1_phys_addr = 0u;
  uint64_t iommu_iova_base = 0u;
  size_t arena_bytes = 0u;
  std::string gpu_name{};
  std::string pci_gpu_bdf{};
  bool initialized = false;

  bool allocate(size_t requested_bytes, const char* bdf_hint, uint32_t vfio_container_fd, std::string& err) {
    release();
    auto& vk = get_vulkan_loader();
    if (!vk.ensure_loaded(err)) {
      return false;
    }

    // Align allocation to 64 KiB boundary (minimum 1 MiB) for BAR1 MMU & IOMMU page tables
    const size_t min_bytes = 1024ull * 1024ull;
    const size_t aligned_bytes = std::max<size_t>(min_bytes, (requested_bytes + 65535ull) & ~size_t(65535ull));

    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "SamuraiGeForceP2PEngine";
    app_info.apiVersion = VK_API_VERSION_1_2;

    const char* inst_exts[] = {VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME};
    VkInstanceCreateInfo inst_info{};
    inst_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    inst_info.pApplicationInfo = &app_info;
    inst_info.enabledExtensionCount = 1;
    inst_info.ppEnabledExtensionNames = inst_exts;

    if (vk.vkCreateInstance_fn(&inst_info, nullptr, &instance) != VK_SUCCESS || instance == VK_NULL_HANDLE) {
      err = "vkCreateInstance failed for BAR1 P2P engine";
      release();
      return false;
    }

    uint32_t dev_count = 0;
    if (vk.vkEnumeratePhysicalDevices_fn(instance, &dev_count, nullptr) != VK_SUCCESS || dev_count == 0) {
      err = "vkEnumeratePhysicalDevices found 0 Vulkan devices";
      release();
      return false;
    }
    std::vector<VkPhysicalDevice> devs(dev_count);
    vk.vkEnumeratePhysicalDevices_fn(instance, &dev_count, devs.data());

    for (uint32_t i = 0; i < dev_count; ++i) {
      VkPhysicalDeviceProperties props{};
      vk.vkGetPhysicalDeviceProperties_fn(devs[i], &props);
      if (props.vendorID == 0x10de || std::strstr(props.deviceName, "GeForce") != nullptr ||
          std::strstr(props.deviceName, "NVIDIA") != nullptr) {
        phys_dev = devs[i];
        gpu_name = props.deviceName;
        break;
      }
    }
    if (phys_dev == VK_NULL_HANDLE) {
      err = "no discrete NVIDIA GPU found via Vulkan";
      release();
      return false;
    }

    const char* dev_exts[] = {
        VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME,
        VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,
    };
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info{};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;

    VkDeviceCreateInfo dev_info{};
    dev_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dev_info.queueCreateInfoCount = 1;
    dev_info.pQueueCreateInfos = &queue_info;
    dev_info.enabledExtensionCount = 2;
    dev_info.ppEnabledExtensionNames = dev_exts;

    if (vk.vkCreateDevice_fn(phys_dev, &dev_info, nullptr, &device) != VK_SUCCESS || device == VK_NULL_HANDLE) {
      err = "vkCreateDevice failed on NVIDIA GPU";
      release();
      return false;
    }

    VkPhysicalDeviceMemoryProperties mem_props{};
    vk.vkGetPhysicalDeviceMemoryProperties_fn(phys_dev, &mem_props);
    uint32_t mem_type_idx = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
      const VkMemoryPropertyFlags flags = mem_props.memoryTypes[i].propertyFlags;
      if ((flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) &&
          (flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
        mem_type_idx = i;
        break;
      }
    }
    if (mem_type_idx == UINT32_MAX) {
      err = "GPU does not expose Host-Visible Device-Local BAR1 memory type";
      release();
      return false;
    }

    VkExportMemoryAllocateInfo export_info{};
    export_info.sType = VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO;
    export_info.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT;

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.pNext = &export_info;
    alloc_info.allocationSize = aligned_bytes;
    alloc_info.memoryTypeIndex = mem_type_idx;

    if (vk.vkAllocateMemory_fn(device, &alloc_info, nullptr, &dev_mem) != VK_SUCCESS || dev_mem == VK_NULL_HANDLE) {
      err = "vkAllocateMemory failed for BAR1 GDDR6 aperture";
      release();
      return false;
    }

    void* mapped = nullptr;
    if (vk.vkMapMemory_fn(device, dev_mem, 0, aligned_bytes, 0, &mapped) != VK_SUCCESS || !mapped) {
      err = "vkMapMemory failed on BAR1 GDDR6 allocation";
      release();
      return false;
    }
    host_bar1_ptr = static_cast<uint8_t*>(mapped);
    std::memset(host_bar1_ptr, 0, std::min<size_t>(aligned_bytes, 4096u));

    auto pfn_get_mem_fd = reinterpret_cast<PFN_vkGetMemoryFdKHR>(
        vk.vkGetDeviceProcAddr_fn(device, "vkGetMemoryFdKHR"));
    if (!pfn_get_mem_fd) {
      err = "vkGetDeviceProcAddr(vkGetMemoryFdKHR) failed";
      release();
      return false;
    }

    VkMemoryGetFdInfoKHR fd_info{};
    fd_info.sType = VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR;
    fd_info.memory = dev_mem;
    fd_info.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT;

    int opaque_fd = -1;
    if (pfn_get_mem_fd(device, &fd_info, &opaque_fd) != VK_SUCCESS || opaque_fd < 0) {
      err = "vkGetMemoryFdKHR failed to export POSIX FD";
      release();
      return false;
    }
    exported_fd = opaque_fd;

    (void)cudaSetDevice(0);
    cudaExternalMemoryHandleDesc ext_desc{};
    ext_desc.type = cudaExternalMemoryHandleTypeOpaqueFd;
    ext_desc.handle.fd = opaque_fd;
    ext_desc.size = aligned_bytes;

    cudaError_t cu_rc = cudaImportExternalMemory(&cuda_ext_mem, &ext_desc);
    if (cu_rc != cudaSuccess || !cuda_ext_mem) {
      err = std::string("cudaImportExternalMemory failed: ") + cudaGetErrorString(cu_rc);
      release();
      return false;
    }
    // Note: cudaImportExternalMemory takes ownership of opaque_fd on Linux
    exported_fd = -1;

    cudaExternalMemoryBufferDesc buf_desc{};
    buf_desc.offset = 0;
    buf_desc.size = aligned_bytes;
    buf_desc.flags = 0;

    void* dev_ptr = nullptr;
    cu_rc = cudaExternalMemoryGetMappedBuffer(&dev_ptr, cuda_ext_mem, &buf_desc);
    if (cu_rc != cudaSuccess || !dev_ptr) {
      err = std::string("cudaExternalMemoryGetMappedBuffer failed: ") + cudaGetErrorString(cu_rc);
      release();
      return false;
    }
    cuda_dev_ptr = static_cast<uint8_t*>(dev_ptr);
    arena_bytes = aligned_bytes;

    pci_gpu_bdf = (bdf_hint && bdf_hint[0] != '\0') ? std::string(bdf_hint) : detect_gpu_pci_bdf();
    bar1_phys_base = read_sysfs_bar1_phys_base(pci_gpu_bdf);
    bar1_phys_addr = resolve_bar1_physical_address(host_bar1_ptr, bar1_phys_base);
    iommu_iova_base = bar1_phys_addr;

    if (vfio_container_fd > 0) {
      SamuraiVfioIommuMapDma dma_map{};
      dma_map.argsz = sizeof(dma_map);
      dma_map.flags = kVfioDmaMapFlagRead | kVfioDmaMapFlagWrite;
      dma_map.vaddr = reinterpret_cast<uint64_t>(host_bar1_ptr);
      dma_map.iova = bar1_phys_addr;
      dma_map.size = aligned_bytes;
      if (::ioctl(static_cast<int>(vfio_container_fd), kVfioIommuMapDmaIoctl, &dma_map) == 0) {
        iommu_iova_base = dma_map.iova;
      }
    }

    initialized = true;
    return true;
  }

  void release() noexcept {
    auto& vk = get_vulkan_loader();
    if (cuda_dev_ptr) {
      (void)cudaFree(cuda_dev_ptr);
      cuda_dev_ptr = nullptr;
    }
    if (cuda_ext_mem) {
      (void)cudaDestroyExternalMemory(cuda_ext_mem);
      cuda_ext_mem = nullptr;
    }
    if (exported_fd >= 0) {
      ::close(exported_fd);
      exported_fd = -1;
    }
    if (device != VK_NULL_HANDLE && dev_mem != VK_NULL_HANDLE) {
      if (host_bar1_ptr && vk.vkUnmapMemory_fn) {
        vk.vkUnmapMemory_fn(device, dev_mem);
      }
      if (vk.vkFreeMemory_fn) {
        vk.vkFreeMemory_fn(device, dev_mem, nullptr);
      }
    }
    host_bar1_ptr = nullptr;
    dev_mem = VK_NULL_HANDLE;
    if (device != VK_NULL_HANDLE && vk.vkDestroyDevice_fn) {
      vk.vkDestroyDevice_fn(device, nullptr);
    }
    device = VK_NULL_HANDLE;
    phys_dev = VK_NULL_HANDLE;
    if (instance != VK_NULL_HANDLE && vk.vkDestroyInstance_fn) {
      vk.vkDestroyInstance_fn(instance, nullptr);
    }
    instance = VK_NULL_HANDLE;
    arena_bytes = 0u;
    initialized = false;
  }

  ~VulkanBar1Arena() noexcept {
    release();
  }
};

// Shared persistent BAR1 arena for batch zero-copy packet synthesis
struct GlobalBar1BatchPool {
  std::mutex mu;
  VulkanBar1Arena arena;
  bool attempted = false;
  std::string last_error;

  bool ensure_capacity(size_t required_bytes, std::string& err) {
    std::lock_guard<std::mutex> lock(mu);
    if (arena.initialized && arena.arena_bytes >= required_bytes) {
      return true;
    }
    const size_t default_arena = 16ull * 1024ull * 1024ull;  // 16 MiB BAR1 slice
    const size_t target_bytes = std::max(default_arena, required_bytes);
    if (!arena.allocate(target_bytes, nullptr, 0u, last_error)) {
      err = last_error;
      return false;
    }
    return true;
  }
};

inline GlobalBar1BatchPool& get_global_bar1_batch_pool() {
  static GlobalBar1BatchPool pool;
  return pool;
}

// Ring instance backing GeforceP2pApiV1
struct GeforceP2pRingInstance {
  GeforceP2pConfigV1 cfg{};
  VulkanBar1Arena arena{};
  std::vector<GeforceP2pRingSlot> slots{};
  GeforceP2pTxStats stats{};
  uint32_t claim_cursor = 0u;
  uint32_t tx_cursor = 0u;
  std::array<uint8_t, 6> default_mac{{0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu}};
};

class GeforceP2pRegistry {
 public:
  static GeforceP2pRegistry& instance() {
    static GeforceP2pRegistry reg;
    return reg;
  }

  int create_ring(const GeforceP2pConfigV1* cfg, int* out_handle, char* err, size_t err_len) {
    if (!cfg || !out_handle) {
      write_error(err, err_len, "null GeforceP2pConfigV1 or out_handle");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    const uint32_t slot_count = std::max<uint32_t>(64u, cfg->ring_slot_count);
    const uint32_t stride = std::max<uint32_t>(64u, cfg->slot_stride);
    const size_t total_bytes = static_cast<size_t>(slot_count) * static_cast<size_t>(stride);

    auto inst = std::make_unique<GeforceP2pRingInstance>();
    inst->cfg = *cfg;
    inst->cfg.ring_slot_count = slot_count;
    inst->cfg.slot_stride = stride;

    std::string alloc_err;
    if (!inst->arena.allocate(total_bytes, cfg->pci_gpu_bdf, cfg->vfio_container_fd, alloc_err)) {
      write_error(err, err_len, alloc_err);
      return -1;
    }

    inst->slots.resize(slot_count);
    for (uint32_t i = 0; i < slot_count; ++i) {
      inst->slots[i].vram_offset = i * stride;
      inst->slots[i].iova = inst->arena.iommu_iova_base + static_cast<uint64_t>(i) * stride;
      inst->slots[i].packet_len = 0u;
      inst->slots[i].flags = 0u;
      inst->slots[i].state = zero_copy::DescriptorOwnershipState::kFree;
    }

    const int handle = next_handle_++;
    inst->stats.queue_id = handle;
    rings_[handle] = std::move(inst);
    *out_handle = handle;
    write_error(err, err_len, "");
    return 0;
  }

  int destroy_ring(int handle, char* err, size_t err_len) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    rings_.erase(it);
    write_error(err, err_len, "");
    return 0;
  }

  int gpu_claim_slots(int handle, uint32_t count, uint32_t* out_start_slot, char* err, size_t err_len) {
    if (!out_start_slot || count == 0u) {
      write_error(err, err_len, "invalid gpu_claim_slots arguments");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    if (count > n_slots) {
      write_error(err, err_len, "requested slot count exceeds ring size");
      return -1;
    }
    const uint32_t start = ring.claim_cursor;
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t idx = (start + i) % n_slots;
      auto& slot = ring.slots[idx];
      if (slot.state == zero_copy::DescriptorOwnershipState::kComplete) {
        slot.state = zero_copy::DescriptorOwnershipState::kFree;
      }
      if (!zero_copy::is_valid_descriptor_transition(
              slot.state, zero_copy::DescriptorOwnershipState::kGpuWriting)) {
        ring.stats.tx_drops += (count - i);
        write_error(err, err_len, "geforce_p2p ring slot busy");
        return -1;
      }
      slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
    }
    ring.claim_cursor = (start + count) % n_slots;
    *out_start_slot = start;
    write_error(err, err_len, "");
    return 0;
  }

  int gpu_commit_slots(int handle, uint32_t start_slot, uint32_t count, const uint16_t* lengths, char* err, size_t err_len) {
    if (!lengths || count == 0u) {
      write_error(err, err_len, "invalid gpu_commit_slots arguments");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t idx = (start_slot + i) % n_slots;
      auto& slot = ring.slots[idx];
      if (slot.state == zero_copy::DescriptorOwnershipState::kFree) {
        slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
      }
      if (!zero_copy::is_valid_descriptor_transition(
              slot.state, zero_copy::DescriptorOwnershipState::kReadyForNic)) {
        ring.stats.tx_errors += 1u;
        write_error(err, err_len, "invalid state transition on gpu_commit_slots");
        return -1;
      }
      slot.packet_len = lengths[i];
      slot.state = zero_copy::DescriptorOwnershipState::kReadyForNic;
    }
    // Issue system fence so GPU GDDR6 writes in BAR1 are visible to PCIe root complex MRd TLPs
    std::atomic_thread_fence(std::memory_order_release);
    write_error(err, err_len, "");
    return 0;
  }

  int nic_tx_burst(int handle, uint32_t max_packets, uint32_t* out_transmitted, char* err, size_t err_len) {
    if (!out_transmitted) {
      write_error(err, err_len, "out_transmitted is null");
      return -1;
    }
    *out_transmitted = 0u;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    const uint32_t budget = std::min(max_packets, n_slots);

    uint32_t transmitted = 0u;
    for (uint32_t i = 0; i < budget; ++i) {
      const uint32_t idx = (ring.tx_cursor + i) % n_slots;
      auto& slot = ring.slots[idx];
      if (slot.state != zero_copy::DescriptorOwnershipState::kReadyForNic) {
        break;
      }
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;

      const uint8_t* frame_bar1_ptr = ring.arena.host_bar1_ptr + slot.vram_offset;
      const uint16_t pkt_len = slot.packet_len;

      if (ring.cfg.iface[0] != '\0' && afpkt_send_ring_bridge != nullptr && pkt_len > 0u) {
        int sent = 0;
        int errors = 0;
        char af_err[128]{};
        (void)afpkt_send_ring_bridge(
            ring.cfg.iface,
            frame_bar1_ptr,
            pkt_len,
            pkt_len,
            1,
            ring.default_mac.data(),
            &sent,
            &errors,
            af_err,
            sizeof(af_err));
      }

      // Account PCIe MRd + CplD TLP transactions (each 256B MPS flit)
      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;

      slot.state = zero_copy::DescriptorOwnershipState::kComplete;
      slot.state = zero_copy::DescriptorOwnershipState::kFree;
      transmitted += 1u;
    }
    ring.tx_cursor = (ring.tx_cursor + transmitted) % n_slots;
    *out_transmitted = transmitted;
    write_error(err, err_len, "");
    return 0;
  }

  int submit_slot_batch(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_sent,
      char* err,
      size_t err_len) {
    if (!slot_ids || !lengths || !out_sent) {
      write_error(err, err_len, "invalid submit_slot_batch arguments");
      return -1;
    }
    *out_sent = 0u;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    uint32_t sent_count = 0u;

    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t idx = slot_ids[i] % n_slots;
      const uint16_t pkt_len = lengths[i];
      auto& slot = ring.slots[idx];
      slot.packet_len = pkt_len;
      slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
      slot.state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;

      // Account direct BAR1 PCIe P2P MRd / CplD TLPs
      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;

      slot.state = zero_copy::DescriptorOwnershipState::kComplete;
      slot.state = zero_copy::DescriptorOwnershipState::kFree;
      sent_count += 1u;
    }

    if (ring.cfg.iface[0] != '\0' && afpkt_send_ring_bridge != nullptr && sent_count > 0u) {
      // Optional live interface bridge directly from BAR1 aperture
      for (uint32_t i = 0; i < count; ++i) {
        const uint32_t idx = slot_ids[i] % n_slots;
        const uint16_t pkt_len = lengths[i];
        const uint8_t* frame_bar1_ptr = ring.arena.host_bar1_ptr + ring.slots[idx].vram_offset + 256u;
        int s = 0;
        int e = 0;
        char af_err[128]{};
        (void)afpkt_send_ring_bridge(
            ring.cfg.iface, frame_bar1_ptr, pkt_len, pkt_len, 1, ring.default_mac.data(), &s, &e, af_err, sizeof(af_err));
      }
    }

    *out_sent = sent_count;
    write_error(err, err_len, "");
    return 0;
  }

  int send_vector(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      int count,
      int* out_sent,
      int* out_errors,
      char* err,
      size_t err_len) {
    if (count <= 0 || !packets || !lengths || !out_sent || !out_errors) {
      write_error(err, err_len, "invalid geforce_p2p send_vector arguments");
      return -1;
    }
    *out_sent = 0;
    *out_errors = 0;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    const auto& batch_arena = get_global_bar1_batch_pool().arena;
    int sent_count = 0;
    int err_count = 0;

    for (int i = 0; i < count; ++i) {
      const uint8_t* pkt = packets[i];
      const uint16_t pkt_len = lengths[i];
      if (!pkt || pkt_len == 0u) {
        err_count += 1;
        ring.stats.tx_errors += 1u;
        continue;
      }
      const uint32_t idx = (ring.tx_cursor + static_cast<uint32_t>(sent_count)) % n_slots;
      auto& slot = ring.slots[idx];

      const bool in_batch_bar1 = batch_arena.initialized && batch_arena.host_bar1_ptr &&
                                 pkt >= batch_arena.host_bar1_ptr &&
                                 pkt < (batch_arena.host_bar1_ptr + batch_arena.arena_bytes);
      const bool in_ring_bar1 = ring.arena.initialized && ring.arena.host_bar1_ptr &&
                                pkt >= ring.arena.host_bar1_ptr &&
                                pkt < (ring.arena.host_bar1_ptr + ring.arena.arena_bytes);

      const uint8_t* wire_ptr = pkt;
      if (!in_batch_bar1 && !in_ring_bar1 && ring.arena.host_bar1_ptr) {
        const size_t copy_len = std::min<size_t>(pkt_len, ring.cfg.slot_stride);
        uint8_t* dst_bar1 = ring.arena.host_bar1_ptr + slot.vram_offset;
        std::memcpy(dst_bar1, pkt, copy_len);
        wire_ptr = dst_bar1;
      }

      slot.packet_len = pkt_len;
      slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
      slot.state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;

      if (ring.cfg.iface[0] != '\0' && std::strcmp(ring.cfg.iface, "lo") != 0 &&
          afpkt_send_ring_bridge != nullptr && wire_ptr != nullptr) {
        int s = 0;
        int e = 0;
        char af_err[128]{};
        (void)afpkt_send_ring_bridge(
            ring.cfg.iface, wire_ptr, pkt_len, pkt_len, 1, ring.default_mac.data(), &s, &e, af_err, sizeof(af_err));
      }

      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;

      slot.state = zero_copy::DescriptorOwnershipState::kComplete;
      slot.state = zero_copy::DescriptorOwnershipState::kFree;
      sent_count += 1;
    }

    ring.tx_cursor = (ring.tx_cursor + static_cast<uint32_t>(sent_count)) % n_slots;
    *out_sent = sent_count;
    *out_errors = err_count;
    write_error(err, err_len, "");
    return 0;
  }

  int get_stats(int handle, GeforceP2pTxStats* out_stats, char* err, size_t err_len) {
    if (!out_stats) {
      write_error(err, err_len, "out_stats is null");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    *out_stats = it->second->stats;
    write_error(err, err_len, "");
    return 0;
  }

  int get_arena_pointers(
      int handle,
      void** out_host_bar1_ptr,
      void** out_cuda_dev_ptr,
      uint64_t* out_bar1_phys_addr,
      size_t* out_arena_bytes,
      char* err,
      size_t err_len) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& arena = it->second->arena;
    if (out_host_bar1_ptr) *out_host_bar1_ptr = arena.host_bar1_ptr;
    if (out_cuda_dev_ptr) *out_cuda_dev_ptr = arena.cuda_dev_ptr;
    if (out_bar1_phys_addr) *out_bar1_phys_addr = arena.bar1_phys_addr;
    if (out_arena_bytes) *out_arena_bytes = arena.arena_bytes;
    write_error(err, err_len, "");
    return 0;
  }

 private:
  static void write_error(char* err, size_t err_len, const std::string& msg) {
    if (!err || err_len == 0u) return;
    const size_t n = std::min(err_len - 1u, msg.size());
    if (n > 0u) std::memcpy(err, msg.data(), n);
    err[n] = '\0';
  }

  std::mutex mu_;
  int next_handle_ = 1;
  std::unordered_map<int, std::unique_ptr<GeforceP2pRingInstance>> rings_;
};

inline int api_create_tx_ring(const GeforceP2pConfigV1* cfg, int* out_handle, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().create_ring(cfg, out_handle, err, err_len);
}
inline int api_destroy_tx_ring(int handle, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().destroy_ring(handle, err, err_len);
}
inline int api_gpu_claim_slots(int handle, uint32_t count, uint32_t* out_start_slot, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().gpu_claim_slots(handle, count, out_start_slot, err, err_len);
}
inline int api_gpu_commit_slots(int handle, uint32_t start_slot, uint32_t count, const uint16_t* lengths, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().gpu_commit_slots(handle, start_slot, count, lengths, err, err_len);
}
inline int api_nic_tx_burst(int handle, uint32_t max_packets, uint32_t* out_transmitted, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().nic_tx_burst(handle, max_packets, out_transmitted, err, err_len);
}
inline int api_get_stats(int handle, GeforceP2pTxStats* out_stats, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().get_stats(handle, out_stats, err, err_len);
}
inline int api_get_arena_pointers(
    int handle,
    void** out_host_bar1_ptr,
    void** out_cuda_dev_ptr,
    uint64_t* out_bar1_phys_addr,
    size_t* out_arena_bytes,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().get_arena_pointers(
      handle, out_host_bar1_ptr, out_cuda_dev_ptr, out_bar1_phys_addr, out_arena_bytes, err, err_len);
}
inline int api_submit_slot_batch(
    int handle,
    const uint32_t* slot_ids,
    const uint16_t* lengths,
    uint32_t count,
    uint32_t* out_sent,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().submit_slot_batch(handle, slot_ids, lengths, count, out_sent, err, err_len);
}

// ============================================================================
// DPU-GPU Split Stateful L4 Contract Writer & DocaGpuNetioApiV1 BAR1 Bridge
// ============================================================================

struct DpuBar1ContractLayout {
  size_t ring_head_off = 0u;
  size_t ring_tail_off = 0u;
  size_t update_ring_off = 0u;
  size_t hot_flow_table_off = 0u;
  size_t hot_flow_versions_off = 0u;
  size_t hot_flow_epochs_off = 0u;
  size_t total_bytes = 0u;
};

inline bool compute_dpu_bar1_contract_layout(
    uint32_t shard_count,
    uint32_t ring_slots_per_shard,
    uint32_t hot_flow_capacity,
    DpuBar1ContractLayout* out) {
  if (!out || shard_count == 0u || ring_slots_per_shard == 0u || hot_flow_capacity == 0u) {
    return false;
  }
  const size_t shards = static_cast<size_t>(shard_count);
  const size_t slots = static_cast<size_t>(ring_slots_per_shard);
  const size_t hot = static_cast<size_t>(hot_flow_capacity);
  const size_t ev_bytes = sizeof(DocaFlowUpdateEventV1);

  size_t cur = 0u;
  out->ring_head_off = cur;
  cur += shards * sizeof(uint64_t);
  out->ring_tail_off = cur;
  cur += shards * sizeof(uint64_t);
  out->update_ring_off = cur;
  cur += shards * slots * ev_bytes;
  out->hot_flow_table_off = cur;
  cur += hot * ev_bytes;
  out->hot_flow_versions_off = cur;
  cur += hot * sizeof(uint64_t);
  out->hot_flow_epochs_off = cur;
  cur += hot * sizeof(uint64_t);
  out->total_bytes = cur;
  return true;
}

struct DpuContractWriterInstance {
  int handle = -1;
  uint32_t shard_count = 1u;
  uint32_t ring_slots_per_shard = 1024u;
  uint32_t hot_flow_capacity = 4096u;
  DpuBar1ContractLayout layout{};
  void* region_ptr = nullptr;
  size_t region_len = 0u;
  int fd = -1;
  bool owns_mmap = false;
  uint64_t publish_count = 0u;
  std::mutex mu{};

  ~DpuContractWriterInstance() {
    if (owns_mmap && region_ptr && region_len > 0u) {
      (void)::msync(region_ptr, region_len, MS_ASYNC);
      (void)::munmap(region_ptr, region_len);
    }
    if (fd >= 0) {
      (void)::close(fd);
    }
  }
};

class DpuBar1ContractRegistry {
 public:
  static DpuBar1ContractRegistry& instance() {
    static DpuBar1ContractRegistry reg;
    return reg;
  }

  int open_writer(const DocaContractWriterConfigV1* cfg, int* out_handle, char* err, size_t err_len) {
    if (!cfg || !out_handle || cfg->region_spec[0] == '\0' || cfg->shard_count == 0u ||
        cfg->ring_slots_per_shard == 0u || cfg->hot_flow_capacity == 0u) {
      write_err(err, err_len, "invalid contract writer open arguments");
      return -1;
    }
    *out_handle = -1;

    DpuBar1ContractLayout layout{};
    if (!compute_dpu_bar1_contract_layout(
            cfg->shard_count, cfg->ring_slots_per_shard, cfg->hot_flow_capacity, &layout)) {
      write_err(err, err_len, "invalid contract layout parameters");
      return -1;
    }

    std::string spec_str(cfg->region_spec);
    std::string kind = "file";
    std::string file_path;
    uintptr_t addr_val = 0u;
    size_t spec_size = 0u;

    size_t pos = 0u;
    while (pos < spec_str.size()) {
      size_t comma = spec_str.find(',', pos);
      std::string token = (comma == std::string::npos) ? spec_str.substr(pos) : spec_str.substr(pos, comma - pos);
      pos = (comma == std::string::npos) ? spec_str.size() : (comma + 1u);
      size_t eq = token.find('=');
      if (eq == std::string::npos) continue;
      std::string k = token.substr(0u, eq);
      std::string v = token.substr(eq + 1u);
      std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (k == "kind" || k == "type") {
        kind = v;
        std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
      } else if (k == "file" || k == "path") {
        file_path = v;
      } else if (k == "addr") {
        addr_val = static_cast<uintptr_t>(std::strtoull(v.c_str(), nullptr, 0));
      } else if (k == "size" || k == "len") {
        spec_size = static_cast<size_t>(std::strtoull(v.c_str(), nullptr, 0));
      }
    }

    auto inst = std::make_unique<DpuContractWriterInstance>();
    inst->shard_count = cfg->shard_count;
    inst->ring_slots_per_shard = cfg->ring_slots_per_shard;
    inst->hot_flow_capacity = cfg->hot_flow_capacity;
    inst->layout = layout;
    inst->region_len = std::max(spec_size, layout.total_bytes);

    if (addr_val != 0u && (kind == "addr" || kind == "bar1_p2p" || kind == "bar1-p2p")) {
      inst->region_ptr = reinterpret_cast<void*>(addr_val);
      inst->owns_mmap = false;
    } else if (!file_path.empty()) {
      int fd = ::open(file_path.c_str(), O_RDWR | O_CLOEXEC);
      if (fd < 0 && (file_path.find("samurai_gpu_contract_") != std::string::npos)) {
        fd = ::open(file_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0) {
          if (::ftruncate(fd, static_cast<off_t>(inst->region_len)) != 0) {
            (void)::close(fd);
            fd = -1;
          }
        }
      }
      if (fd < 0) {
        write_err(err, err_len, "contract writer failed to open contract region file");
        return -1;
      }
      struct stat st {};
      if (::fstat(fd, &st) != 0) {
        (void)::close(fd);
        write_err(err, err_len, "contract writer fstat failed");
        return -1;
      }
      if (static_cast<size_t>(st.st_size) < layout.total_bytes) {
        if (::ftruncate(fd, static_cast<off_t>(inst->region_len)) != 0) {
          (void)::close(fd);
          write_err(err, err_len, "contract writer file smaller than required layout");
          return -1;
        }
      } else {
        inst->region_len = std::max(inst->region_len, static_cast<size_t>(st.st_size));
      }
      void* mapped = ::mmap(nullptr, inst->region_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (mapped == MAP_FAILED || !mapped) {
        (void)::close(fd);
        write_err(err, err_len, "contract writer mmap failed");
        return -1;
      }
      inst->region_ptr = mapped;
      inst->fd = fd;
      inst->owns_mmap = true;
    } else if (addr_val != 0u) {
      inst->region_ptr = reinterpret_cast<void*>(addr_val);
      inst->owns_mmap = false;
    } else {
      write_err(err, err_len, "contract writer requires file= or addr= in region_spec");
      return -1;
    }

    std::lock_guard<std::mutex> lock(mu_);
    const int handle = next_handle_++;
    inst->handle = handle;
    writers_[handle] = std::move(inst);
    *out_handle = handle;
    write_err(err, err_len, "");
    return 0;
  }

  int close_writer(int handle, char* err, size_t err_len) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = writers_.find(handle);
    if (it == writers_.end()) {
      write_err(err, err_len, "");
      return 0;
    }
    writers_.erase(it);
    write_err(err, err_len, "");
    return 0;
  }

  int publish_flow_update(int handle, const DocaFlowUpdateEventV1* event, char* err, size_t err_len) {
    if (handle <= 0 || !event || event->version == 0u || (event->version & 1ull) != 0ull) {
      write_err(err, err_len, "invalid contract writer publish arguments");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = writers_.find(handle);
    if (it == writers_.end() || !it->second || !it->second->region_ptr) {
      write_err(err, err_len, "contract writer handle not found");
      return -1;
    }
    auto& w = *it->second;
    if (event->flow_id >= w.hot_flow_capacity) {
      write_err(err, err_len, "flow_id exceeds contract hot_flow_capacity");
      return -1;
    }

    auto* base = static_cast<uint8_t*>(w.region_ptr);
    auto* heads = reinterpret_cast<volatile uint64_t*>(base + w.layout.ring_head_off);
    auto* tails = reinterpret_cast<volatile uint64_t*>(base + w.layout.ring_tail_off);
    auto* ring = reinterpret_cast<volatile DocaFlowUpdateEventV1*>(base + w.layout.update_ring_off);
    auto* hot = reinterpret_cast<volatile DocaFlowUpdateEventV1*>(base + w.layout.hot_flow_table_off);
    auto* hot_versions = reinterpret_cast<volatile uint64_t*>(base + w.layout.hot_flow_versions_off);
    auto* hot_epochs = reinterpret_cast<volatile uint64_t*>(base + w.layout.hot_flow_epochs_off);

    const uint32_t shard = event->flow_id % w.shard_count;
    const uint64_t head = __atomic_load_n(&heads[shard], __ATOMIC_ACQUIRE);
    const uint64_t tail = __atomic_load_n(&tails[shard], __ATOMIC_ACQUIRE);
    const uint64_t used = (head >= tail) ? (head - tail) : 0u;
    if (used >= static_cast<uint64_t>(w.ring_slots_per_shard)) {
      // Advance tail under controlled drop so stateful L4 updates never deadlock
      __atomic_store_n(&tails[shard], tail + 1u, __ATOMIC_RELEASE);
    }

    const size_t ring_idx =
        static_cast<size_t>(shard) * static_cast<size_t>(w.ring_slots_per_shard) +
        static_cast<size_t>(head % static_cast<uint64_t>(w.ring_slots_per_shard));

    auto store_seqlock = [](volatile DocaFlowUpdateEventV1* dst, const DocaFlowUpdateEventV1& ev) {
      const uint64_t begin_v = (ev.version > 0u && (ev.version & 1ull) == 0ull) ? (ev.version - 1ull) : (ev.version | 1ull);
      __atomic_store_n(&dst->version, begin_v, __ATOMIC_RELEASE);
      __atomic_thread_fence(__ATOMIC_RELEASE);
      dst->epoch = ev.epoch;
      dst->flow_id = ev.flow_id;
      dst->tcp_seq = ev.tcp_seq;
      dst->tcp_ack = ev.tcp_ack;
      dst->src_port = ev.src_port;
      dst->dst_port = ev.dst_port;
      dst->tcp_state = ev.tcp_state;
      dst->proto = ev.proto;
      dst->flags = ev.flags;
      dst->rtt_us = ev.rtt_us;
      dst->dpu_ts_ns = ev.dpu_ts_ns;
      __atomic_thread_fence(__ATOMIC_RELEASE);
      __atomic_store_n(&dst->version, ev.version, __ATOMIC_RELEASE);
    };

    store_seqlock(ring + ring_idx, *event);
    store_seqlock(hot + event->flow_id, *event);
    __atomic_store_n(&hot_versions[event->flow_id], event->version, __ATOMIC_RELEASE);
    __atomic_store_n(&hot_epochs[event->flow_id], event->epoch, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&heads[shard], head + 1u, __ATOMIC_RELEASE);
    w.publish_count += 1u;
    write_err(err, err_len, "");
    return 0;
  }

 private:
  static void write_err(char* err, size_t err_len, const std::string& msg) {
    if (!err || err_len == 0u) return;
    const size_t n = std::min(err_len - 1u, msg.size());
    if (n > 0u) std::memcpy(err, msg.data(), n);
    err[n] = '\0';
  }

  std::mutex mu_;
  int next_handle_ = 1;
  std::unordered_map<int, std::unique_ptr<DpuContractWriterInstance>> writers_;
};

inline bool is_geforce_p2p_doca_mode(const char* device_name = nullptr) {
  auto check_env = [](const char* name) -> bool {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) return false;
    std::string v(raw);
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v == "1" || v == "true" || v == "on" || v == "yes" || v == "geforce_p2p" || v == "bar1_p2p";
  };
  if (check_env("SAMURAI_DPU_GEFORCE_P2P") || check_env("SAMURAI_GPU_TX_BACKEND")) {
    return true;
  }
  if (device_name && *device_name) {
    std::string dev(device_name);
    std::transform(dev.begin(), dev.end(), dev.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (dev.find("geforce") != std::string::npos || dev.find("bar1") != std::string::npos ||
        dev.find("p2p") != std::string::npos || dev.find("vulkan") != std::string::npos) {
      return true;
    }
  }
  return false;
}

inline int doca_p2p_create_txq(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len) {
  (void)gpu_id;
  if (!iface || !*iface || !device_name || !*device_name || !out_handle) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "invalid DOCA TXQ create arguments");
    return -1;
  }
  if (!is_geforce_p2p_doca_mode(device_name)) {
    if (err && err_len > 0u) {
      std::snprintf(err, err_len, "doca_gpunetio backend unavailable for device=%s (set SAMURAI_DPU_GEFORCE_P2P=1 for BAR1 P2P)", device_name);
    }
    return -1;
  }
  GeforceP2pConfigV1 cfg{};
  std::snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface);
  std::snprintf(cfg.pci_nic_bdf, sizeof(cfg.pci_nic_bdf), "%s", device_name);
  cfg.ring_slot_count = 1024u;
  cfg.slot_stride = 2048u;
  cfg.vfio_container_fd = 0u;
  (void)queue_id;
  return GeforceP2pRegistry::instance().create_ring(&cfg, out_handle, err, err_len);
}

inline int doca_p2p_destroy_txq(int handle, char* err, size_t err_len) {
  return GeforceP2pRegistry::instance().destroy_ring(handle, err, err_len);
}

inline int doca_p2p_send_vector(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len) {
  (void)stream_slots;
  return GeforceP2pRegistry::instance().send_vector(handle, packets, lengths, count, out_sent, out_errors, err, err_len);
}

inline int doca_p2p_send_vector_timed(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    const uint64_t* tx_timestamps_ns,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len) {
  (void)stream_slots;
  (void)tx_timestamps_ns;
  return GeforceP2pRegistry::instance().send_vector(handle, packets, lengths, count, out_sent, out_errors, err, err_len);
}

inline int doca_p2p_get_stats(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) {
  if (!out) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "out is null");
    return -1;
  }
  GeforceP2pTxStats st{};
  const int rc = GeforceP2pRegistry::instance().get_stats(handle, &st, err, err_len);
  if (rc != 0) return rc;
  out->tx_packets = st.tx_packets;
  out->tx_bytes = st.tx_bytes;
  out->tx_errors = st.tx_errors;
  out->tx_drops = st.tx_drops;
  out->queue_id = st.queue_id;
  return 0;
}

inline int doca_p2p_get_gpu_txq_handle(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len) {
  if (!out_gpu_txq_handle) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "out_gpu_txq_handle is null");
    return -1;
  }
  uint64_t bar1_phys = 0u;
  const int rc = GeforceP2pRegistry::instance().get_arena_pointers(
      handle, nullptr, nullptr, &bar1_phys, nullptr, err, err_len);
  if (rc != 0) return rc;
  *out_gpu_txq_handle = bar1_phys;
  return 0;
}

inline int doca_p2p_get_txq_mkey_be(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) {
  (void)handle;
  if (!out_mkey_be) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "out_mkey_be is null");
    return -1;
  }
  *out_mkey_be = 0x42415231u;  // 'BAR1'
  if (err && err_len > 0u) err[0] = '\0';
  return 0;
}

inline int doca_p2p_contract_writer_open(
    const DocaContractWriterConfigV1* cfg,
    int* out_handle,
    char* err,
    size_t err_len) {
  return DpuBar1ContractRegistry::instance().open_writer(cfg, out_handle, err, err_len);
}

inline int doca_p2p_contract_writer_close(int handle, char* err, size_t err_len) {
  return DpuBar1ContractRegistry::instance().close_writer(handle, err, err_len);
}

inline int doca_p2p_contract_writer_publish_flow_update_v1(
    int handle,
    const DocaFlowUpdateEventV1* event,
    char* err,
    size_t err_len) {
  return DpuBar1ContractRegistry::instance().publish_flow_update(handle, event, err, err_len);
}

inline int doca_p2p_create_rxq(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len) {
  (void)gpu_id;
  (void)queue_id;
  if (!iface || !*iface || !device_name || !*device_name || !out_handle) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "invalid create_rxq arguments");
    return -1;
  }
  if (!is_geforce_p2p_doca_mode(device_name)) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "doca rxq unavailable");
    return -1;
  }
  static std::atomic<int> next_rxq{1000};
  *out_handle = next_rxq.fetch_add(1, std::memory_order_relaxed);
  if (err && err_len > 0u) err[0] = '\0';
  return 0;
}

inline int doca_p2p_destroy_rxq(int handle, char* err, size_t err_len) {
  if (handle <= 0) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "invalid rxq handle");
    return -1;
  }
  if (err && err_len > 0u) err[0] = '\0';
  return 0;
}

inline int doca_p2p_receive_burst(
    int handle,
    uint8_t* out_packets_flat,
    uint32_t out_packets_flat_len,
    uint16_t* out_lengths,
    int max_packets,
    int* out_received,
    char* err,
    size_t err_len) {
  if (handle <= 0 || !out_packets_flat || out_packets_flat_len == 0u || !out_lengths || max_packets <= 0 || !out_received) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "invalid receive_burst arguments");
    return -1;
  }
  *out_received = 0;
  if (err && err_len > 0u) err[0] = '\0';
  return 0;
}

}  // namespace ddos_samurai::gpu_packet_cuda::p2p

extern "C" ddos_samurai::gpu_packet_cuda::p2p::GeforceP2pApiV1* samurai_geforce_p2p_get_api_v1(void) {
  static ddos_samurai::gpu_packet_cuda::p2p::GeforceP2pApiV1 kApi = []() {
    ddos_samurai::gpu_packet_cuda::p2p::GeforceP2pApiV1 api{};
    api.version = kGeforceP2pApiVersion;
    api.create_tx_ring = &ddos_samurai::gpu_packet_cuda::p2p::api_create_tx_ring;
    api.destroy_tx_ring = &ddos_samurai::gpu_packet_cuda::p2p::api_destroy_tx_ring;
    api.gpu_claim_slots = &ddos_samurai::gpu_packet_cuda::p2p::api_gpu_claim_slots;
    api.gpu_commit_slots = &ddos_samurai::gpu_packet_cuda::p2p::api_gpu_commit_slots;
    api.nic_tx_burst = &ddos_samurai::gpu_packet_cuda::p2p::api_nic_tx_burst;
    api.get_stats = &ddos_samurai::gpu_packet_cuda::p2p::api_get_stats;
    api.get_arena_pointers = &ddos_samurai::gpu_packet_cuda::p2p::api_get_arena_pointers;
    api.submit_slot_batch = &ddos_samurai::gpu_packet_cuda::p2p::api_submit_slot_batch;
    return api;
  }();
  return &kApi;
}

extern "C" DocaGpuNetioApiV1* samurai_doca_gpunetio_get_api_v1(void) {
  static DocaGpuNetioApiV1 kDocaApi = []() {
    DocaGpuNetioApiV1 api{};
    api.version = kDocaGpuNetioApiVersion;
    api.create_txq = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_create_txq;
    api.destroy_txq = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_destroy_txq;
    api.send_vector = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_send_vector;
    api.send_vector_timed = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_send_vector_timed;
    api.get_stats = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_get_stats;
    api.get_gpu_txq_handle = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_get_gpu_txq_handle;
    api.get_txq_mkey_be = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_get_txq_mkey_be;
    api.contract_writer_open = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_contract_writer_open;
    api.contract_writer_close = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_contract_writer_close;
    api.contract_writer_publish_flow_update_v1 =
        &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_contract_writer_publish_flow_update_v1;
    api.create_rxq = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_create_rxq;
    api.destroy_rxq = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_destroy_rxq;
    api.receive_burst = &ddos_samurai::gpu_packet_cuda::p2p::doca_p2p_receive_burst;
    return api;
  }();
  return &kDocaApi;
}
