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
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "gpu_initiated_doorbell.cuh"
#include "tx_backend_doca_gpunetio.cuh"
#include "tx_backend_geforce_p2p.cuh"
#include "zero_copy_dataplane_contract.cuh"

namespace ddos_samurai::gpu_packet_cuda::p2p {

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

// Dynamic DPDK C-ABI symbols resolved via RTLD_DEFAULT when DPDK is loaded in-process.
using PfnDpdkP2pRegisterExtmem = int (*)(int64_t handle, void* vaddr, size_t len, uint64_t iova, uint32_t page_size);
using PfnDpdkP2pTxBurstSlots = int (*)(
    int64_t handle,
    uint16_t queue_id,
    void* bar1_base_vaddr,
    uint64_t bar1_base_iova,
    uint32_t slot_stride,
    const uint32_t* slot_indices,
    const uint16_t* pkt_lengths,
    uint16_t count,
    void (*free_cb)(void*, void*),
    void* free_cb_opaque,
    uint64_t* out_sent,
    uint64_t* out_dropped);
using PfnDpdkP2pRxBurstSlots = int (*)(
    int64_t handle,
    uint16_t queue_id,
    void* bar1_base_vaddr,
    uint32_t slot_stride,
    const uint32_t* slot_indices,
    uint16_t max_slots,
    uint16_t* out_lengths);

struct DpdkDynamicBridge {
  PfnDpdkP2pRegisterExtmem register_extmem = nullptr;
  PfnDpdkP2pTxBurstSlots tx_burst_slots = nullptr;
  PfnDpdkP2pRxBurstSlots rx_burst_slots = nullptr;
  bool resolved = false;

  void ensure_resolved() {
    if (resolved) return;
    register_extmem = reinterpret_cast<PfnDpdkP2pRegisterExtmem>(
        dlsym(RTLD_DEFAULT, "samurai_dpdk_p2p_register_extmem"));
    tx_burst_slots = reinterpret_cast<PfnDpdkP2pTxBurstSlots>(
        dlsym(RTLD_DEFAULT, "samurai_dpdk_p2p_tx_burst_slots"));
    rx_burst_slots = reinterpret_cast<PfnDpdkP2pRxBurstSlots>(
        dlsym(RTLD_DEFAULT, "samurai_dpdk_p2p_rx_burst_slots"));
    resolved = true;
  }
};

inline DpdkDynamicBridge& get_dpdk_dynamic_bridge() {
  static DpdkDynamicBridge bridge;
  bridge.ensure_resolved();
  return bridge;
}

// CUDA kernel that directly inspects and validates received Ethernet/IPv4 frames
// inside GPU BAR1 GDDR6 memory without any CPU staging copy.
__global__ void geforce_p2p_rx_verify_consume_kernel(
    const uint8_t* __restrict__ bar1_dev_base,
    uint32_t slot_stride,
    const uint32_t* __restrict__ slot_ids,
    const uint16_t* __restrict__ lengths,
    uint32_t count,
    uint32_t* __restrict__ out_valid_count,
    uint32_t* __restrict__ out_cksum_err_count) {
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= count) {
    return;
  }
  const uint32_t slot_idx = slot_ids[tid];
  const uint16_t pkt_len = lengths[tid];
  if (pkt_len < 14u || pkt_len > slot_stride) {
    atomicAdd(out_cksum_err_count, 1u);
    return;
  }
  const uint8_t* frame = bar1_dev_base + static_cast<size_t>(slot_idx) * slot_stride;
  const uint16_t eth_type = (static_cast<uint16_t>(frame[12]) << 8u) | static_cast<uint16_t>(frame[13]);
  if (eth_type == 0x0800u) {
    if (pkt_len < 34u) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
    const uint8_t* ip = frame + 14u;
    const uint8_t ver = (ip[0] >> 4u) & 0x0Fu;
    const uint8_t ihl = ip[0] & 0x0Fu;
    const uint16_t ihl_bytes = static_cast<uint16_t>(ihl) * 4u;
    if (ver != 4u || ihl < 5u || (14u + ihl_bytes) > pkt_len) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
    const uint16_t hdr_cksum = (static_cast<uint16_t>(ip[10]) << 8u) | static_cast<uint16_t>(ip[11]);
    if (hdr_cksum == 0u) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
    uint32_t sum = 0u;
    for (uint16_t b = 0u; b < ihl_bytes; b += 2u) {
      const uint16_t word = (static_cast<uint16_t>(ip[b]) << 8u) | static_cast<uint16_t>(ip[b + 1u]);
      sum += word;
    }
    while ((sum >> 16u) != 0u) {
      sum = (sum & 0xFFFFu) + (sum >> 16u);
    }
    if (static_cast<uint16_t>(~sum) != 0u) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
  } else if (eth_type == 0x86DDu) {
    if (pkt_len < 54u || ((frame[14] >> 4u) & 0x0Fu) != 6u) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
  } else if (eth_type == 0x0806u) {
    if (pkt_len < 42u) {
      atomicAdd(out_cksum_err_count, 1u);
      return;
    }
  } else {
    atomicAdd(out_cksum_err_count, 1u);
    return;
  }
  atomicAdd(out_valid_count, 1u);
}

struct VulkanDynamicLoader {
  void* lib_handle = nullptr;
  PFN_vkCreateInstance vkCreateInstance_fn = nullptr;
  PFN_vkDestroyInstance vkDestroyInstance_fn = nullptr;
  PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices_fn = nullptr;
  PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties_fn = nullptr;
  PFN_vkGetPhysicalDeviceProperties2 vkGetPhysicalDeviceProperties2_fn = nullptr;
  PFN_vkGetPhysicalDeviceExternalBufferProperties vkGetPhysicalDeviceExternalBufferProperties_fn = nullptr;
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
    vkGetPhysicalDeviceProperties2_fn =
        reinterpret_cast<PFN_vkGetPhysicalDeviceProperties2>(dlsym(lib_handle, "vkGetPhysicalDeviceProperties2"));
    if (!vkGetPhysicalDeviceProperties2_fn) {
      vkGetPhysicalDeviceProperties2_fn = reinterpret_cast<PFN_vkGetPhysicalDeviceProperties2>(
          dlsym(lib_handle, "vkGetPhysicalDeviceProperties2KHR"));
    }
    vkGetPhysicalDeviceExternalBufferProperties_fn =
        reinterpret_cast<PFN_vkGetPhysicalDeviceExternalBufferProperties>(
            dlsym(lib_handle, "vkGetPhysicalDeviceExternalBufferProperties"));
    if (!vkGetPhysicalDeviceExternalBufferProperties_fn) {
      vkGetPhysicalDeviceExternalBufferProperties_fn =
          reinterpret_cast<PFN_vkGetPhysicalDeviceExternalBufferProperties>(
              dlsym(lib_handle, "vkGetPhysicalDeviceExternalBufferPropertiesKHR"));
    }
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
        !vkGetPhysicalDeviceProperties_fn || !vkGetPhysicalDeviceProperties2_fn ||
        !vkGetPhysicalDeviceExternalBufferProperties_fn || !vkGetPhysicalDeviceMemoryProperties_fn ||
        !vkCreateDevice_fn || !vkDestroyDevice_fn || !vkAllocateMemory_fn || !vkFreeMemory_fn ||
        !vkMapMemory_fn || !vkUnmapMemory_fn || !vkGetDeviceProcAddr_fn) {
      dlclose(lib_handle);
      lib_handle = nullptr;
      err = "missing required Vulkan 1.1+ / external memory entrypoints in libvulkan";
      return false;
    }
    return true;
  }
};

inline VulkanDynamicLoader& get_vulkan_loader() {
  static VulkanDynamicLoader loader;
  return loader;
}

inline std::string normalize_pci_bdf(const std::string& raw_bdf) {
  if (raw_bdf.empty()) {
    return "";
  }
  std::string bdf = raw_bdf;
  std::transform(bdf.begin(), bdf.end(), bdf.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  unsigned int dom = 0u, bus = 0u, dev = 0u, fn = 0u;
  if (std::sscanf(bdf.c_str(), "%x:%x:%x.%x", &dom, &bus, &dev, &fn) == 4) {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04x:%02x:%02x.%x", dom & 0xFFFFu, bus & 0xFFu, dev & 0x1Fu, fn & 0x7u);
    return std::string(buf);
  }
  if (std::sscanf(bdf.c_str(), "%x:%x.%x", &bus, &dev, &fn) == 3) {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "0000:%02x:%02x.%x", bus & 0xFFu, dev & 0x1Fu, fn & 0x7u);
    return std::string(buf);
  }
  return bdf;
}

inline std::string detect_gpu_pci_bdf(int cuda_device = 0) {
  char pci_bus_id[64]{};
  if (cudaDeviceGetPCIBusId(pci_bus_id, sizeof(pci_bus_id), cuda_device) == cudaSuccess && pci_bus_id[0] != '\0') {
    return normalize_pci_bdf(pci_bus_id);
  }
  return "";
}

inline std::string detect_nic_pci_bdf_from_iface(const char* iface) {
  if (!iface || !*iface) return "";
  char link_path[128];
  std::snprintf(link_path, sizeof(link_path), "/sys/class/net/%s/device", iface);
  char target[256];
  const ssize_t len = ::readlink(link_path, target, sizeof(target) - 1);
  if (len > 0) {
    target[len] = '\0';
    const char* base = std::strrchr(target, '/');
    if (base) return normalize_pci_bdf(base + 1);
    return normalize_pci_bdf(target);
  }
  return "";
}

inline uint32_t detect_nic_driver_type(const char* nic_bdf) {
  if (!nic_bdf || !*nic_bdf) return 0u;
  const std::string norm = normalize_pci_bdf(nic_bdf);
  char link_path[160];
  std::snprintf(link_path, sizeof(link_path), "/sys/bus/pci/devices/%s/driver", norm.c_str());
  char target[256];
  const ssize_t len = ::readlink(link_path, target, sizeof(target) - 1);
  if (len > 0) {
    target[len] = '\0';
    std::string s(target);
    if (s.find("r8169") != std::string::npos || s.find("r8168") != std::string::npos) return 0u; // kRealtekR8169
    if (s.find("e1000e") != std::string::npos || s.find("e1000") != std::string::npos) return 1u; // kIntelE1000e
    if (s.find("ixgbe") != std::string::npos) return 2u; // kIntelIxgbe
    if (s.find("i40e") != std::string::npos) return 3u; // kIntelI40e
    if (s.find("mlx5") != std::string::npos) return 4u; // kMellanoxMlx5
  }
  return 0u;
}

// Reads real PCI BAR1 aperture range [start, end] from sysfs.
// Never returns a hardcoded fake address; returns false if sysfs cannot be read.
inline bool read_sysfs_bar1_aperture(const std::string& bdf_in, uint64_t* out_start, uint64_t* out_end) {
  if (out_start) *out_start = 0u;
  if (out_end) *out_end = 0u;
  const std::string bdf = normalize_pci_bdf(bdf_in.empty() ? detect_gpu_pci_bdf(0) : bdf_in);
  if (bdf.empty()) {
    return false;
  }
  const std::string path = "/sys/bus/pci/devices/" + bdf + "/resource";
  std::ifstream ifs(path);
  if (!ifs.is_open()) {
    return false;
  }
  std::string line;
  // Line 0 is BAR0, Line 1 is BAR1 (64-bit prefetchable aperture)
  if (!std::getline(ifs, line) || !std::getline(ifs, line)) {
    return false;
  }
  unsigned long long start_addr = 0ULL;
  unsigned long long end_addr = 0ULL;
  if (std::sscanf(line.c_str(), "0x%llx 0x%llx", &start_addr, &end_addr) == 2 &&
      start_addr != 0ULL && end_addr > start_addr) {
    if (out_start) *out_start = static_cast<uint64_t>(start_addr);
    if (out_end) *out_end = static_cast<uint64_t>(end_addr);
    return true;
  }
  return false;
}

inline uint64_t read_sysfs_bar1_phys_base(const std::string& bdf_in) {
  uint64_t start = 0u;
  uint64_t end = 0u;
  if (read_sysfs_bar1_aperture(bdf_in, &start, &end)) {
    return start;
  }
  return 0u;
}

// Resolves the exact physical/bus address of a host-mapped BAR1 virtual address.
// Uses /dev/nv_p2p or /proc/self/pagemap PFN verification against the BAR1 PCI aperture.
// NEVER silently falls back to the BAR1 aperture base address (BAR1 base != allocation IOVA).
inline bool resolve_bar1_allocation_phys_addr(
    void* host_mapped_ptr,
    uint64_t bar1_aperture_start,
    uint64_t bar1_aperture_end,
    uint64_t* out_phys_addr) {
  if (out_phys_addr) *out_phys_addr = 0u;
  if (!host_mapped_ptr) {
    return false;
  }
  // 1. Try kernel P2P driver (/dev/nv_p2p)
  int p2p_fd = ::open("/dev/nv_p2p", O_RDWR);
  if (p2p_fd >= 0) {
    unsigned long arg = reinterpret_cast<unsigned long>(host_mapped_ptr);
    if (::ioctl(p2p_fd, SAMURAI_IOCTL_RESOLVE_PFN, &arg) == 0 && arg != 0ul) {
      ::close(p2p_fd);
      const uint64_t phys = (static_cast<uint64_t>(arg) << 12u) |
                            (reinterpret_cast< uintptr_t >(host_mapped_ptr) & 0xFFFull);
      if (out_phys_addr) *out_phys_addr = phys;
      return true;
    }
    ::close(p2p_fd);
  }
  // 2. Try /proc/self/pagemap PFN extraction and verify it lies within [bar1_aperture_start, bar1_aperture_end]
  int pm_fd = ::open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
  if (pm_fd >= 0) {
    const uintptr_t va = reinterpret_cast<uintptr_t>(host_mapped_ptr);
    const off_t offset = static_cast<off_t>((va / 4096ull) * sizeof(uint64_t));
    uint64_t entry = 0ull;
    if (::pread(pm_fd, &entry, sizeof(entry), offset) == static_cast<ssize_t>(sizeof(entry))) {
      const bool page_present = (entry & (1ULL << 63u)) != 0ull;
      const uint64_t pfn = entry & ((1ULL << 55u) - 1ULL);
      if (page_present && pfn != 0ull) {
        const uint64_t phys = (pfn << 12u) | (va & 0xFFFull);
        if (bar1_aperture_start == 0u ||
            (phys >= bar1_aperture_start && phys <= bar1_aperture_end)) {
          ::close(pm_fd);
          if (out_phys_addr) *out_phys_addr = phys;
          return true;
        }
      }
    }
    ::close(pm_fd);
  }
  return false;
}

struct VulkanBar1Arena {
  VkInstance instance = VK_NULL_HANDLE;
  VkPhysicalDevice phys_dev = VK_NULL_HANDLE;
  VkDevice device = VK_NULL_HANDLE;
  VkDeviceMemory dev_mem = VK_NULL_HANDLE;
  cudaExternalMemory_t cuda_ext_mem = nullptr;
  int exported_fd = -1;
  int cuda_device_index = 0;
  uint8_t* host_bar1_ptr = nullptr;
  uint8_t* cuda_dev_ptr = nullptr;
  uint64_t bar1_phys_base = 0u;
  uint64_t bar1_aperture_end = 0u;
  uint64_t bar1_phys_addr = 0u;
  uint64_t iommu_iova_base = 0u;
  bool iova_verified = false;
  bool owns_memory = true;
  size_t arena_bytes = 0u;
  std::string gpu_name{};
  std::string pci_gpu_bdf{};
  bool initialized = false;

  bool allocate(
      size_t requested_bytes,
      const char* bdf_hint,
      uint32_t vfio_container_fd,
      std::string& err,
      uint64_t explicit_iova_override = 0u) {
    release();
    owns_memory = true;
    auto& vk = get_vulkan_loader();
    if (!vk.ensure_loaded(err)) {
      return false;
    }

    // Align allocation to 64 KiB boundary (minimum 1 MiB) for BAR1 MMU & IOMMU page tables
    const size_t min_bytes = 1024ull * 1024ull;
    const size_t aligned_bytes = std::max<size_t>(min_bytes, (requested_bytes + 65535ull) & ~size_t(65535ull));

    // Enumerate CUDA devices and collect their UUIDs and PCI BDFs for exact physical device matching
    int cuda_dev_count = 0;
    if (cudaGetDeviceCount(&cuda_dev_count) != cudaSuccess || cuda_dev_count <= 0) {
      err = "cudaGetDeviceCount found 0 CUDA devices for BAR1 P2P";
      return false;
    }
    struct CudaDeviceIdentity {
      int index = 0;
      uint8_t uuid[16]{};
      std::string pci_bdf{};
    };
    std::vector<CudaDeviceIdentity> cuda_devs;
    cuda_devs.reserve(static_cast<size_t>(cuda_dev_count));
    for (int c = 0; c < cuda_dev_count; ++c) {
      cudaDeviceProp cprop{};
      if (cudaGetDeviceProperties(&cprop, c) == cudaSuccess) {
        CudaDeviceIdentity cid{};
        cid.index = c;
        std::memcpy(cid.uuid, cprop.uuid.bytes, 16u);
        cid.pci_bdf = detect_gpu_pci_bdf(c);
        cuda_devs.push_back(cid);
      }
    }
    if (cuda_devs.empty()) {
      err = "failed to query CUDA device properties for BAR1 P2P";
      return false;
    }

    const std::string target_bdf = (bdf_hint && bdf_hint[0] != '\0') ? normalize_pci_bdf(bdf_hint) : "";

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

    int matched_cuda_dev = -1;
    std::string matched_bdf{};
    for (uint32_t i = 0; i < dev_count; ++i) {
      VkPhysicalDeviceIDProperties id_props{};
      id_props.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
      VkPhysicalDeviceProperties2 props2{};
      props2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
      props2.pNext = &id_props;
      vk.vkGetPhysicalDeviceProperties2_fn(devs[i], &props2);

      const auto& props = props2.properties;
      if (props.vendorID != 0x10de && std::strstr(props.deviceName, "GeForce") == nullptr &&
          std::strstr(props.deviceName, "NVIDIA") == nullptr) {
        continue;
      }

      // Match this Vulkan physical device against CUDA devices via 16-byte deviceUUID
      for (const auto& cid : cuda_devs) {
        if (!target_bdf.empty() && !cid.pci_bdf.empty() && cid.pci_bdf != target_bdf) {
          continue;
        }
        if (std::memcmp(id_props.deviceUUID, cid.uuid, 16u) == 0) {
          phys_dev = devs[i];
          gpu_name = props.deviceName;
          matched_cuda_dev = cid.index;
          matched_bdf = cid.pci_bdf;
          break;
        }
      }
      if (phys_dev != VK_NULL_HANDLE) {
        break;
      }
    }

    if (phys_dev == VK_NULL_HANDLE) {
      err = "no Vulkan NVIDIA GPU matched a CUDA device UUID" +
            (target_bdf.empty() ? std::string("") : (" for PCI BDF " + target_bdf));
      release();
      return false;
    }

    cuda_device_index = matched_cuda_dev;
    pci_gpu_bdf = !matched_bdf.empty() ? matched_bdf : (!target_bdf.empty() ? target_bdf : detect_gpu_pci_bdf(cuda_device_index));

    // Explicitly verify Vulkan external memory export capability for OPAQUE_FD
    VkPhysicalDeviceExternalBufferInfo ext_buf_info{};
    ext_buf_info.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_BUFFER_INFO;
    ext_buf_info.flags = 0;
    ext_buf_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                         VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                         VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    ext_buf_info.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT;

    VkExternalBufferProperties ext_buf_props{};
    ext_buf_props.sType = VK_STRUCTURE_TYPE_EXTERNAL_BUFFER_PROPERTIES;
    vk.vkGetPhysicalDeviceExternalBufferProperties_fn(phys_dev, &ext_buf_info, &ext_buf_props);
    if ((ext_buf_props.externalMemoryProperties.externalMemoryFeatures &
         VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT) == 0) {
      err = "Vulkan physical device does not support exportable OPAQUE_FD external memory";
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

    cudaError_t cu_rc = cudaSetDevice(cuda_device_index);
    if (cu_rc != cudaSuccess) {
      err = std::string("cudaSetDevice failed for matched GPU: ") + cudaGetErrorString(cu_rc);
      release();
      return false;
    }

    cudaExternalMemoryHandleDesc ext_desc{};
    ext_desc.type = cudaExternalMemoryHandleTypeOpaqueFd;
    ext_desc.handle.fd = opaque_fd;
    ext_desc.size = aligned_bytes;

    cu_rc = cudaImportExternalMemory(&cuda_ext_mem, &ext_desc);
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

    (void)read_sysfs_bar1_aperture(pci_gpu_bdf, &bar1_phys_base, &bar1_aperture_end);

    uint64_t resolved_phys = 0u;
    if (explicit_iova_override != 0u) {
      resolved_phys = explicit_iova_override;
      iova_verified = true;
    } else {
      const char* env_iova = std::getenv("SAMURAI_GPU_BAR1_IOVA");
      if (env_iova && *env_iova) {
        try {
          resolved_phys = std::stoull(env_iova, nullptr, 0);
          iova_verified = (resolved_phys != 0u);
        } catch (...) {}
      }
      if (!iova_verified && resolve_bar1_allocation_phys_addr(
              host_bar1_ptr, bar1_phys_base, bar1_aperture_end, &resolved_phys)) {
        iova_verified = true;
      }
    }

    bar1_phys_addr = resolved_phys;
    iommu_iova_base = resolved_phys;

    if (vfio_container_fd > 0) {
      const uint64_t candidate_iova =
          (resolved_phys != 0u) ? resolved_phys :
          ((bar1_phys_base != 0u) ? bar1_phys_base : 0x100000000ULL);
      SamuraiVfioIommuMapDma dma_map{};
      dma_map.argsz = sizeof(dma_map);
      dma_map.flags = kVfioDmaMapFlagRead | kVfioDmaMapFlagWrite;
      dma_map.vaddr = reinterpret_cast<uint64_t>(host_bar1_ptr);
      dma_map.iova = candidate_iova;
      dma_map.size = aligned_bytes;
      if (::ioctl(static_cast<int>(vfio_container_fd), kVfioIommuMapDmaIoctl, &dma_map) != 0 &&
          errno != EEXIST) {
        err = std::string("VFIO_IOMMU_MAP_DMA failed for BAR1 arena: ") + std::strerror(errno);
        release();
        return false;
      }
      iommu_iova_base = dma_map.iova;
      bar1_phys_addr = dma_map.iova;
      iova_verified = true;
    }

    initialized = true;
    return true;
  }

  bool attach_external(
      void* ext_host_ptr,
      void* ext_cuda_ptr,
      uint64_t ext_iova,
      size_t ext_bytes,
      const char* bdf_hint,
      std::string& err) {
    release();
    if (!ext_host_ptr || !ext_cuda_ptr || ext_bytes == 0u) {
      err = "invalid external BAR1 arena pointers";
      return false;
    }
    owns_memory = false;
    host_bar1_ptr = static_cast<uint8_t*>(ext_host_ptr);
    cuda_dev_ptr = static_cast<uint8_t*>(ext_cuda_ptr);
    arena_bytes = ext_bytes;
    pci_gpu_bdf = (bdf_hint && bdf_hint[0] != '\0') ? normalize_pci_bdf(bdf_hint) : detect_gpu_pci_bdf(0);
    (void)read_sysfs_bar1_aperture(pci_gpu_bdf, &bar1_phys_base, &bar1_aperture_end);
    bar1_phys_addr = ext_iova;
    iommu_iova_base = ext_iova;
    iova_verified = (ext_iova != 0u);
    initialized = true;
    return true;
  }

  void release() noexcept {
    if (!owns_memory) {
      host_bar1_ptr = nullptr;
      cuda_dev_ptr = nullptr;
      bar1_phys_base = 0u;
      bar1_aperture_end = 0u;
      bar1_phys_addr = 0u;
      iommu_iova_base = 0u;
      iova_verified = false;
      arena_bytes = 0u;
      initialized = false;
      owns_memory = true;
      return;
    }
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
    bar1_phys_base = 0u;
    bar1_aperture_end = 0u;
    bar1_phys_addr = 0u;
    iommu_iova_base = 0u;
    iova_verified = false;
    arena_bytes = 0u;
    initialized = false;
  }

  ~VulkanBar1Arena() noexcept {
    release();
  }
};

// Multi-chunk, reference-counted BAR1 batch pool.
// Prevents use-after-free on resize and prevents concurrent batches from overwriting each other.
struct Bar1PoolChunk {
  VulkanBar1Arena arena{};
  size_t write_cursor = 0u;
  uint32_t active_allocations = 0u;
};

struct Bar1ActiveSlice {
  std::shared_ptr<Bar1PoolChunk> chunk{};
  uint8_t* user_host_ptr = nullptr;
  uint8_t* user_dev_ptr = nullptr;
  size_t offset = 0u;
  size_t length = 0u;
};

struct GlobalBar1BatchPool {
  std::mutex mu;
  VulkanBar1Arena arena;  // Mirror of the latest active chunk for legacy introspection
  std::vector<std::shared_ptr<Bar1PoolChunk>> chunks;
  std::unordered_map<const void*, Bar1ActiveSlice> active_slices;
  bool attempted = false;
  std::string last_error;

  ~GlobalBar1BatchPool() {
    // Prevent double-release on mirror `arena`
    arena.owns_memory = false;
    arena.release();
  }

  void sync_mirror_locked(const VulkanBar1Arena& src) {
    arena.owns_memory = false;
    arena.host_bar1_ptr = src.host_bar1_ptr;
    arena.cuda_dev_ptr = src.cuda_dev_ptr;
    arena.bar1_phys_base = src.bar1_phys_base;
    arena.bar1_aperture_end = src.bar1_aperture_end;
    arena.bar1_phys_addr = src.bar1_phys_addr;
    arena.iommu_iova_base = src.iommu_iova_base;
    arena.iova_verified = src.iova_verified;
    arena.arena_bytes = src.arena_bytes;
    arena.gpu_name = src.gpu_name;
    arena.pci_gpu_bdf = src.pci_gpu_bdf;
    arena.initialized = src.initialized;
  }

  bool ensure_capacity(size_t required_bytes, std::string& err) {
    std::lock_guard<std::mutex> lock(mu);
    const size_t aligned_req = (required_bytes + 255ull) & ~size_t(255ull);
    for (auto& ch : chunks) {
      if (ch && ch->arena.initialized && ch->arena.arena_bytes >= aligned_req) {
        sync_mirror_locked(ch->arena);
        return true;
      }
    }
    const size_t default_arena = 16ull * 1024ull * 1024ull;  // 16 MiB BAR1 chunk
    const size_t target_bytes = std::max(default_arena, aligned_req);
    auto new_chunk = std::make_shared<Bar1PoolChunk>();
    if (!new_chunk->arena.allocate(target_bytes, nullptr, 0u, last_error)) {
      err = last_error;
      return false;
    }
    chunks.push_back(new_chunk);
    sync_mirror_locked(new_chunk->arena);
    // Reclaim idle older chunks that have zero in-flight allocations
    if (chunks.size() > 2u) {
      chunks.erase(
          std::remove_if(
              chunks.begin(),
              chunks.end() - 1,
              [](const std::shared_ptr<Bar1PoolChunk>& c) {
                return !c || c->active_allocations == 0u;
              }),
          chunks.end() - 1);
    }
    return true;
  }

  bool allocate_slice(
      size_t payload_bytes,
      size_t header_bytes,
      uint8_t** out_base_host,
      uint8_t** out_base_dev,
      uint64_t* out_slice_iova,
      std::string& err) {
    std::lock_guard<std::mutex> lock(mu);
    const size_t total_needed = ((payload_bytes + header_bytes) + 255ull) & ~size_t(255ull);
    std::shared_ptr<Bar1PoolChunk> chosen;
    size_t slice_offset = 0u;

    for (auto& ch : chunks) {
      if (!ch || !ch->arena.initialized) continue;
      if (ch->active_allocations == 0u) {
        ch->write_cursor = 0u;
      }
      if (ch->write_cursor + total_needed <= ch->arena.arena_bytes) {
        chosen = ch;
        slice_offset = ch->write_cursor;
        ch->write_cursor += total_needed;
        ch->active_allocations += 1u;
        break;
      }
    }

    if (!chosen) {
      const size_t default_arena = 16ull * 1024ull * 1024ull;
      const size_t target_bytes = std::max(default_arena, total_needed * 2u);
      auto new_chunk = std::make_shared<Bar1PoolChunk>();
      if (!new_chunk->arena.allocate(target_bytes, nullptr, 0u, last_error)) {
        err = last_error;
        return false;
      }
      slice_offset = 0u;
      new_chunk->write_cursor = total_needed;
      new_chunk->active_allocations = 1u;
      chunks.push_back(new_chunk);
      chosen = new_chunk;
      sync_mirror_locked(chosen->arena);
    }

    uint8_t* base_h = chosen->arena.host_bar1_ptr + slice_offset;
    uint8_t* base_d = chosen->arena.cuda_dev_ptr + slice_offset;
    uint8_t* user_h = base_h + header_bytes;
    uint8_t* user_d = base_d + header_bytes;

    Bar1ActiveSlice slice{};
    slice.chunk = chosen;
    slice.user_host_ptr = user_h;
    slice.user_dev_ptr = user_d;
    slice.offset = slice_offset;
    slice.length = total_needed;
    active_slices[user_h] = slice;
    active_slices[user_d] = slice;

    if (out_base_host) *out_base_host = base_h;
    if (out_base_dev) *out_base_dev = base_d;
    if (out_slice_iova) {
      *out_slice_iova = (chosen->arena.iommu_iova_base != 0u)
                            ? (chosen->arena.iommu_iova_base + slice_offset)
                            : 0u;
    }
    return true;
  }

  bool release_slice(const void* user_ptr) {
    if (!user_ptr) return false;
    std::lock_guard<std::mutex> lock(mu);
    auto it = active_slices.find(user_ptr);
    if (it == active_slices.end()) {
      return false;
    }
    Bar1ActiveSlice slice = it->second;
    active_slices.erase(slice.user_host_ptr);
    active_slices.erase(slice.user_dev_ptr);
    if (slice.chunk && slice.chunk->active_allocations > 0u) {
      slice.chunk->active_allocations -= 1u;
      if (slice.chunk->active_allocations == 0u) {
        slice.chunk->write_cursor = 0u;
      }
    }
    if (chunks.size() > 1u) {
      chunks.erase(
          std::remove_if(
              chunks.begin(),
              chunks.end() - 1,
              [](const std::shared_ptr<Bar1PoolChunk>& c) {
                return !c || c->active_allocations == 0u;
              }),
          chunks.end() - 1);
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
  uint32_t rx_cursor = 0u;
  GeforceP2pNicTransportOpsV1 transport_ops{};
  bool has_transport = false;
  cudaStream_t verify_stream = nullptr;
  uint32_t* d_rx_slot_ids = nullptr;
  uint16_t* d_rx_lengths = nullptr;
  uint32_t* d_rx_counts = nullptr;
  uint32_t rx_scratch_cap = 0u;

  // GPU-Initiated Doorbell state
  GeforceP2pDoorbellConfigV1 doorbell_cfg{};
  bool has_gpu_doorbell = false;
  bool owns_tx_desc_ring = false;
  bool owns_nic_mmio_mmap = false;
  bool registered_nic_mmio_cuda = false;
  int nic_mmio_fd = -1;
  void* host_tx_desc_ring = nullptr;
  void* dev_tx_desc_ring = nullptr;
  void* host_nic_mmio_base = nullptr;
  volatile uint8_t* dev_nic_mmio_base = nullptr;
  size_t nic_mmio_bytes = 0u;
  uint32_t gpu_tx_desc_head = 0u;
  uint32_t gpu_tx_producer_seq = 0u;
  cudaStream_t doorbell_stream = nullptr;
  uint32_t* d_db_slot_ids = nullptr;
  uint16_t* d_db_lengths = nullptr;
  uint32_t* d_db_counters = nullptr;
  uint32_t db_scratch_cap = 0u;
  doorbell::GeforceP2pGpuDeviceTxq* host_device_txq = nullptr;
  doorbell::GeforceP2pGpuDeviceTxq* dev_device_txq = nullptr;
  uint64_t synced_dev_txq_descs = 0u;
  uint64_t synced_dev_txq_kicks = 0u;
  uint64_t synced_dev_txq_drops = 0u;
  uint64_t synced_dev_txq_reaped = 0u;
  uint64_t synced_dev_txq_bytes = 0u;

  void cleanup_gpu_doorbell() {
    if (d_db_slot_ids) { (void)cudaFree(d_db_slot_ids); d_db_slot_ids = nullptr; }
    if (d_db_lengths) { (void)cudaFree(d_db_lengths); d_db_lengths = nullptr; }
    if (d_db_counters) { (void)cudaFree(d_db_counters); d_db_counters = nullptr; }
    db_scratch_cap = 0u;
    if (doorbell_stream) { (void)cudaStreamDestroy(doorbell_stream); doorbell_stream = nullptr; }
    if (host_device_txq) {
      (void)cudaFreeHost(host_device_txq);
      host_device_txq = nullptr;
      dev_device_txq = nullptr;
    }
    synced_dev_txq_descs = 0u;
    synced_dev_txq_kicks = 0u;
    synced_dev_txq_drops = 0u;
    synced_dev_txq_reaped = 0u;
    synced_dev_txq_bytes = 0u;
    if (owns_tx_desc_ring && host_tx_desc_ring) {
      (void)cudaFreeHost(host_tx_desc_ring);
    }
    if (registered_nic_mmio_cuda && host_nic_mmio_base) {
      (void)cudaHostUnregister(host_nic_mmio_base);
    }
    if (owns_nic_mmio_mmap && host_nic_mmio_base && nic_mmio_bytes > 0u) {
      (void)munmap(host_nic_mmio_base, nic_mmio_bytes);
    }
    if (nic_mmio_fd >= 0) {
      (void)close(nic_mmio_fd);
      nic_mmio_fd = -1;
    }
    host_tx_desc_ring = nullptr;
    dev_tx_desc_ring = nullptr;
    host_nic_mmio_base = nullptr;
    dev_nic_mmio_base = nullptr;
    nic_mmio_bytes = 0u;
    owns_tx_desc_ring = false;
    owns_nic_mmio_mmap = false;
    registered_nic_mmio_cuda = false;
    has_gpu_doorbell = false;
  }

  ~GeforceP2pRingInstance() {
    cleanup_gpu_doorbell();
    if (d_rx_slot_ids) (void)cudaFree(d_rx_slot_ids);
    if (d_rx_lengths) (void)cudaFree(d_rx_lengths);
    if (d_rx_counts) (void)cudaFree(d_rx_counts);
    if (verify_stream) (void)cudaStreamDestroy(verify_stream);
  }
};

// DPDK C-ABI adapter callbacks for GeforceP2pNicTransportOpsV1
inline int dpdk_transport_dma_map_cb(
    void* user_ctx,
    void* bar1_host_va,
    uint64_t bar1_iova,
    size_t region_bytes,
    uint32_t page_size) {
  auto* ring = static_cast<GeforceP2pRingInstance*>(user_ctx);
  if (!ring || ring->cfg.dpdk_port_handle < 0 || bar1_iova == 0u) {
    return -1;
  }
  auto& br = get_dpdk_dynamic_bridge();
  if (!br.register_extmem) {
    return -1;
  }
  return br.register_extmem(ring->cfg.dpdk_port_handle, bar1_host_va, region_bytes, bar1_iova, page_size);
}

inline int dpdk_transport_tx_burst_cb(
    void* user_ctx,
    void* bar1_host_va,
    uint64_t bar1_iova,
    uint32_t slot_stride,
    const uint32_t* slot_indices,
    const uint16_t* pkt_lengths,
    uint32_t count) {
  auto* ring = static_cast<GeforceP2pRingInstance*>(user_ctx);
  if (!ring || ring->cfg.dpdk_port_handle < 0 || bar1_iova == 0u) {
    return -1;
  }
  auto& br = get_dpdk_dynamic_bridge();
  if (!br.tx_burst_slots) {
    return -1;
  }
  uint64_t sent = 0u;
  uint64_t dropped = 0u;
  return br.tx_burst_slots(
      ring->cfg.dpdk_port_handle,
      ring->cfg.dpdk_queue_id,
      bar1_host_va,
      bar1_iova,
      slot_stride,
      slot_indices,
      pkt_lengths,
      static_cast<uint16_t>(std::min<uint32_t>(count, 65535u)),
      nullptr,
      nullptr,
      &sent,
      &dropped);
}

inline int dpdk_transport_rx_burst_cb(
    void* user_ctx,
    void* bar1_host_va,
    uint64_t bar1_iova,
    uint32_t slot_stride,
    const uint32_t* slot_indices,
    uint32_t max_slots,
    uint16_t* out_lengths) {
  (void)bar1_iova;
  auto* ring = static_cast<GeforceP2pRingInstance*>(user_ctx);
  if (!ring || ring->cfg.dpdk_port_handle < 0) {
    return -1;
  }
  auto& br = get_dpdk_dynamic_bridge();
  if (!br.rx_burst_slots) {
    return -1;
  }
  return br.rx_burst_slots(
      ring->cfg.dpdk_port_handle,
      ring->cfg.dpdk_queue_id,
      bar1_host_va,
      slot_stride,
      slot_indices,
      static_cast<uint16_t>(std::min<uint32_t>(max_slots, 65535u)),
      out_lengths);
}

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
    if (cfg->external_host_bar1_ptr != nullptr && cfg->external_cuda_dev_ptr != nullptr &&
        cfg->external_arena_bytes >= total_bytes) {
      uint64_t ext_iova = (cfg->external_bar1_iova != 0u) ? cfg->external_bar1_iova : cfg->bar1_phys_base;
      if (ext_iova == 0u && default_bar1_iova_override_ != 0u) {
        ext_iova = default_bar1_iova_override_ + (static_cast<uint64_t>(cfg->dpdk_queue_id) * total_bytes);
      }
      if (!inst->arena.attach_external(
              cfg->external_host_bar1_ptr,
              cfg->external_cuda_dev_ptr,
              ext_iova,
              cfg->external_arena_bytes,
              cfg->pci_gpu_bdf,
              alloc_err)) {
        write_error(err, err_len, alloc_err);
        return -1;
      }
    } else {
      const uint64_t iova_override =
          (cfg->bar1_phys_base != 0u) ? cfg->bar1_phys_base : default_bar1_iova_override_;
      if (!inst->arena.allocate(
              total_bytes, cfg->pci_gpu_bdf, cfg->vfio_container_fd, alloc_err, iova_override)) {
        write_error(err, err_len, alloc_err);
        return -1;
      }
    }

    inst->slots.resize(slot_count);
    for (uint32_t i = 0; i < slot_count; ++i) {
      inst->slots[i].vram_offset = i * stride;
      inst->slots[i].iova = (inst->arena.iommu_iova_base != 0u)
                                ? (inst->arena.iommu_iova_base + static_cast<uint64_t>(i) * stride)
                                : 0u;
      inst->slots[i].packet_len = 0u;
      inst->slots[i].flags = 0u;
      inst->slots[i].state = zero_copy::DescriptorOwnershipState::kFree;
    }

    if (has_default_doorbell_cfg_) {
      GeforceP2pDoorbellConfigV1 auto_db = default_doorbell_cfg_;
      if (auto_db.queue_id == 0u && cfg->dpdk_queue_id > 0u) {
        auto_db.queue_id = cfg->dpdk_queue_id;
      }
      if (bind_gpu_doorbell_locked(*inst, &auto_db, err, err_len) != 0) {
        return -1;
      }
    }

    // Auto-bind DPDK zero-copy transport if dpdk_port_handle >= 0 is configured
    if (cfg->dpdk_port_handle >= 0) {
      if (inst->arena.iommu_iova_base == 0u || !inst->arena.iova_verified) {
        write_error(
            err,
            err_len,
            "geforce_p2p: unverified BAR1 IOVA; refusing to bind DPDK DMA without verified IOVA/IOMMU mapping");
        return -1;
      }
      GeforceP2pNicTransportOpsV1 dpdk_ops{};
      dpdk_ops.user_ctx = inst.get();
      dpdk_ops.dma_map_region = &dpdk_transport_dma_map_cb;
      dpdk_ops.tx_burst_slots = &dpdk_transport_tx_burst_cb;
      dpdk_ops.rx_burst_slots = &dpdk_transport_rx_burst_cb;
      if (dpdk_ops.dma_map_region(
              dpdk_ops.user_ctx,
              inst->arena.host_bar1_ptr,
              inst->arena.iommu_iova_base,
              inst->arena.arena_bytes,
              65536u) != 0) {
        write_error(err, err_len, "geforce_p2p: DPDK rte_extmem_register / rte_dev_dma_map failed for BAR1 arena");
        return -1;
      }
      inst->transport_ops = dpdk_ops;
      inst->has_transport = true;
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

  int bind_nic_transport(int handle, const GeforceP2pNicTransportOpsV1* ops, char* err, size_t err_len) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    if (!ops || !ops->tx_burst_slots) {
      ring.transport_ops = GeforceP2pNicTransportOpsV1{};
      ring.has_transport = false;
      write_error(err, err_len, "geforce_p2p: cleared or invalid NIC transport ops");
      return ops ? -1 : 0;
    }
    const uint64_t dma_iova = (ring.arena.iommu_iova_base != 0u)
                                  ? ring.arena.iommu_iova_base
                                  : ring.arena.bar1_phys_base;
    if (ops->dma_map_region != nullptr) {
      if (ops->dma_map_region(
              ops->user_ctx,
              ring.arena.host_bar1_ptr,
              dma_iova,
              ring.arena.arena_bytes,
              65536u) != 0) {
        write_error(err, err_len, "geforce_p2p: NIC transport dma_map_region failed");
        return -1;
      }
      if (ring.arena.iommu_iova_base == 0u && dma_iova != 0u) {
        ring.arena.iommu_iova_base = dma_iova;
        ring.arena.bar1_phys_addr = dma_iova;
        ring.arena.iova_verified = true;
        for (uint32_t i = 0; i < ring.slots.size(); ++i) {
          ring.slots[i].iova = dma_iova + static_cast<uint64_t>(ring.slots[i].vram_offset);
        }
      }
    }
    ring.transport_ops = *ops;
    ring.has_transport = true;
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
    if ((!ring.has_transport || !ring.transport_ops.tx_burst_slots) && !ring.has_gpu_doorbell) {
      ring.stats.tx_errors += 1u;
      write_error(
          err,
          err_len,
          "geforce_p2p: no NIC DMA transport or GPU doorbell bound (DPDK/VFIO or GPU doorbell required; AF_PACKET fallback disabled)");
      return -1;
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    const uint32_t budget = std::min(max_packets, n_slots);

    std::vector<uint32_t> ready_indices;
    std::vector<uint16_t> ready_lengths;
    ready_indices.reserve(budget);
    ready_lengths.reserve(budget);

    for (uint32_t i = 0; i < budget; ++i) {
      const uint32_t idx = (ring.tx_cursor + i) % n_slots;
      auto& slot = ring.slots[idx];
      if (slot.state != zero_copy::DescriptorOwnershipState::kReadyForNic) {
        break;
      }
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;
      ready_indices.push_back(idx);
      ready_lengths.push_back(slot.packet_len);
    }

    if (ready_indices.empty()) {
      write_error(err, err_len, "");
      return 0;
    }

    if (ring.has_gpu_doorbell && (!ring.has_transport || !ring.transport_ops.tx_burst_slots)) {
      uint32_t db_sent = 0u;
      const int db_rc = gpu_doorbell_tx_burst_locked(
          ring,
          ready_indices.data(),
          ready_lengths.data(),
          static_cast<uint32_t>(ready_indices.size()),
          &db_sent,
          err,
          err_len);
      if (db_rc != 0) {
        for (uint32_t idx : ready_indices) {
          ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kReadyForNic;
        }
        return -1;
      }
      for (uint32_t i = db_sent; i < ready_indices.size(); ++i) {
        ring.slots[ready_indices[i]].state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      }
      ring.tx_cursor = (ring.tx_cursor + db_sent) % n_slots;
      *out_transmitted = db_sent;
      return 0;
    }

    const uint64_t dma_iova = (ring.arena.iommu_iova_base != 0u)
                                  ? ring.arena.iommu_iova_base
                                  : ring.arena.bar1_phys_base;
    const int tx_rc = ring.transport_ops.tx_burst_slots(
        ring.transport_ops.user_ctx,
        ring.arena.host_bar1_ptr,
        dma_iova,
        ring.cfg.slot_stride,
        ready_indices.data(),
        ready_lengths.data(),
        static_cast<uint32_t>(ready_indices.size()));

    if (tx_rc < 0) {
      for (uint32_t idx : ready_indices) {
        ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      }
      ring.stats.tx_errors += static_cast<uint64_t>(ready_indices.size());
      write_error(err, err_len, "geforce_p2p: NIC DMA tx_burst_slots transport returned failure");
      return -1;
    }

    const uint32_t transmitted = std::min<uint32_t>(
        static_cast<uint32_t>(tx_rc), static_cast<uint32_t>(ready_indices.size()));
    for (uint32_t i = 0; i < transmitted; ++i) {
      const uint32_t idx = ready_indices[i];
      const uint16_t pkt_len = ready_lengths[i];
      auto& slot = ring.slots[idx];
      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;
      slot.state = zero_copy::DescriptorOwnershipState::kComplete;
      slot.state = zero_copy::DescriptorOwnershipState::kFree;
    }
    for (uint32_t i = transmitted; i < ready_indices.size(); ++i) {
      const uint32_t idx = ready_indices[i];
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      ring.stats.tx_drops += 1u;
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
    if (count == 0u) {
      write_error(err, err_len, "");
      return 0;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    if ((!ring.has_transport || !ring.transport_ops.tx_burst_slots) && !ring.has_gpu_doorbell) {
      ring.stats.tx_errors += count;
      ring.stats.tx_drops += count;
      write_error(
          err,
          err_len,
          "geforce_p2p: submit_slot_batch failed (no NIC DMA transport or GPU doorbell bound; AF_PACKET fallback disabled)");
      return -1;
    }

    if (ring.has_gpu_doorbell && (!ring.has_transport || !ring.transport_ops.tx_burst_slots)) {
      return gpu_doorbell_tx_burst_locked(ring, slot_ids, lengths, count, out_sent, err, err_len);
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    std::vector<uint32_t> norm_slots(count);
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t idx = slot_ids[i] % n_slots;
      norm_slots[i] = idx;
      auto& slot = ring.slots[idx];
      slot.packet_len = lengths[i];
      slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
      slot.state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;
    }

    const uint64_t dma_iova = (ring.arena.iommu_iova_base != 0u)
                                  ? ring.arena.iommu_iova_base
                                  : ring.arena.bar1_phys_base;
    const int tx_rc = ring.transport_ops.tx_burst_slots(
        ring.transport_ops.user_ctx,
        ring.arena.host_bar1_ptr,
        dma_iova,
        ring.cfg.slot_stride,
        norm_slots.data(),
        lengths,
        count);

    if (tx_rc < 0) {
      for (uint32_t idx : norm_slots) {
        ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
      }
      ring.stats.tx_errors += count;
      ring.stats.tx_drops += count;
      write_error(err, err_len, "geforce_p2p: NIC DMA tx_burst_slots failed in submit_slot_batch");
      return -1;
    }

    const uint32_t sent_count = std::min<uint32_t>(static_cast<uint32_t>(tx_rc), count);
    for (uint32_t i = 0; i < sent_count; ++i) {
      const uint32_t idx = norm_slots[i];
      const uint16_t pkt_len = lengths[i];
      auto& slot = ring.slots[idx];
      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;
      slot.state = zero_copy::DescriptorOwnershipState::kComplete;
      slot.state = zero_copy::DescriptorOwnershipState::kFree;
    }
    for (uint32_t i = sent_count; i < count; ++i) {
      const uint32_t idx = norm_slots[i];
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
      ring.stats.tx_drops += 1u;
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
    if (!ring.has_transport || !ring.transport_ops.tx_burst_slots) {
      *out_errors = count;
      ring.stats.tx_errors += static_cast<uint64_t>(count);
      ring.stats.tx_drops += static_cast<uint64_t>(count);
      write_error(
          err,
          err_len,
          "geforce_p2p: send_vector failed (no NIC DMA transport bound; AF_PACKET fallback disabled)");
      return -1;
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    std::vector<uint32_t> batch_slots;
    std::vector<uint16_t> batch_lengths;
    batch_slots.reserve(static_cast<size_t>(count));
    batch_lengths.reserve(static_cast<size_t>(count));
    int err_count = 0;

    for (int i = 0; i < count; ++i) {
      const uint8_t* pkt = packets[i];
      const uint16_t pkt_len = lengths[i];
      if (!pkt || pkt_len == 0u) {
        err_count += 1;
        ring.stats.tx_errors += 1u;
        continue;
      }
      const uint32_t idx = (ring.tx_cursor + static_cast<uint32_t>(batch_slots.size())) % n_slots;
      auto& slot = ring.slots[idx];

      const bool in_ring_bar1 = ring.arena.initialized && ring.arena.host_bar1_ptr &&
                                pkt >= ring.arena.host_bar1_ptr &&
                                pkt < (ring.arena.host_bar1_ptr + ring.arena.arena_bytes);
      if (!in_ring_bar1 && ring.arena.host_bar1_ptr) {
        const size_t copy_len = std::min<size_t>(pkt_len, ring.cfg.slot_stride);
        uint8_t* dst_bar1 = ring.arena.host_bar1_ptr + slot.vram_offset;
        std::memcpy(dst_bar1, pkt, copy_len);
      }

      slot.packet_len = pkt_len;
      slot.state = zero_copy::DescriptorOwnershipState::kGpuWriting;
      slot.state = zero_copy::DescriptorOwnershipState::kReadyForNic;
      slot.state = zero_copy::DescriptorOwnershipState::kNicOwned;
      batch_slots.push_back(idx);
      batch_lengths.push_back(pkt_len);
    }

    if (batch_slots.empty()) {
      *out_errors = err_count;
      write_error(err, err_len, "no valid packets in send_vector");
      return -1;
    }

    const uint64_t dma_iova = (ring.arena.iommu_iova_base != 0u)
                                  ? ring.arena.iommu_iova_base
                                  : ring.arena.bar1_phys_base;
    const int tx_rc = ring.transport_ops.tx_burst_slots(
        ring.transport_ops.user_ctx,
        ring.arena.host_bar1_ptr,
        dma_iova,
        ring.cfg.slot_stride,
        batch_slots.data(),
        batch_lengths.data(),
        static_cast<uint32_t>(batch_slots.size()));

    if (tx_rc < 0) {
      for (uint32_t idx : batch_slots) {
        ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
      }
      err_count += static_cast<int>(batch_slots.size());
      ring.stats.tx_errors += static_cast<uint64_t>(batch_slots.size());
      *out_errors = err_count;
      write_error(err, err_len, "geforce_p2p: NIC DMA tx_burst_slots failed in send_vector");
      return -1;
    }

    const uint32_t sent_count = std::min<uint32_t>(
        static_cast<uint32_t>(tx_rc), static_cast<uint32_t>(batch_slots.size()));
    for (uint32_t i = 0; i < sent_count; ++i) {
      const uint32_t idx = batch_slots[i];
      const uint16_t pkt_len = batch_lengths[i];
      const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
      ring.stats.mrd_tlp_requests += 1u;
      ring.stats.cpld_tlp_responses += tlp_flits;
      ring.stats.tx_packets += 1u;
      ring.stats.tx_bytes += pkt_len;
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kComplete;
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
    }
    for (uint32_t i = sent_count; i < batch_slots.size(); ++i) {
      const uint32_t idx = batch_slots[i];
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
      ring.stats.tx_drops += 1u;
      err_count += 1;
    }

    ring.tx_cursor = (ring.tx_cursor + sent_count) % n_slots;
    *out_sent = static_cast<int>(sent_count);
    *out_errors = err_count;
    write_error(err, err_len, "");
    return 0;
  }

  int nic_rx_burst(
      int handle,
      uint32_t max_packets,
      uint32_t* out_received,
      uint32_t* out_slot_ids,
      uint16_t* out_lengths,
      char* err,
      size_t err_len) {
    if (!out_received || !out_slot_ids || !out_lengths || max_packets == 0u) {
      write_error(err, err_len, "invalid nic_rx_burst arguments");
      return -1;
    }
    *out_received = 0u;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    if (!ring.has_transport || !ring.transport_ops.rx_burst_slots) {
      ring.stats.rx_errors += 1u;
      write_error(err, err_len, "geforce_p2p: no NIC RX DMA transport bound");
      return -1;
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    const uint32_t budget = std::min(max_packets, n_slots);
    std::vector<uint32_t> rx_slots;
    rx_slots.reserve(budget);

    for (uint32_t i = 0; i < n_slots && rx_slots.size() < budget; ++i) {
      const uint32_t idx = (ring.rx_cursor + i) % n_slots;
      if (ring.slots[idx].state == zero_copy::DescriptorOwnershipState::kFree ||
          ring.slots[idx].state == zero_copy::DescriptorOwnershipState::kComplete) {
        ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kNicOwned;
        rx_slots.push_back(idx);
      }
    }
    if (rx_slots.empty()) {
      ring.stats.rx_drops += 1u;
      write_error(err, err_len, "geforce_p2p: no free BAR1 slots available for RX burst");
      return -1;
    }

    const uint64_t dma_iova = (ring.arena.iommu_iova_base != 0u)
                                  ? ring.arena.iommu_iova_base
                                  : ring.arena.bar1_phys_base;
    const int rx_rc = ring.transport_ops.rx_burst_slots(
        ring.transport_ops.user_ctx,
        ring.arena.host_bar1_ptr,
        dma_iova,
        ring.cfg.slot_stride,
        rx_slots.data(),
        static_cast<uint32_t>(rx_slots.size()),
        out_lengths);

    if (rx_rc < 0) {
      for (uint32_t idx : rx_slots) {
        ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
      }
      ring.stats.rx_errors += 1u;
      write_error(err, err_len, "geforce_p2p: NIC RX DMA transport failed");
      return -1;
    }

    const uint32_t received = std::min<uint32_t>(
        static_cast<uint32_t>(rx_rc), static_cast<uint32_t>(rx_slots.size()));
    for (uint32_t i = 0; i < received; ++i) {
      const uint32_t idx = rx_slots[i];
      out_slot_ids[i] = idx;
      ring.slots[idx].packet_len = out_lengths[i];
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kComplete;
      ring.stats.rx_packets += 1u;
      ring.stats.rx_bytes += out_lengths[i];
    }
    for (uint32_t i = received; i < rx_slots.size(); ++i) {
      ring.slots[rx_slots[i]].state = zero_copy::DescriptorOwnershipState::kFree;
    }

    ring.rx_cursor = (ring.rx_cursor + received) % n_slots;
    std::atomic_thread_fence(std::memory_order_release);
    *out_received = received;
    write_error(err, err_len, "");
    return 0;
  }

  int gpu_verify_rx_slots(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_valid_packets,
      char* err,
      size_t err_len) {
    if (!slot_ids || !lengths || !out_valid_packets) {
      write_error(err, err_len, "invalid gpu_verify_rx_slots arguments");
      return -1;
    }
    *out_valid_packets = 0u;
    if (count == 0u) {
      write_error(err, err_len, "");
      return 0;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    if (!ring.arena.initialized || !ring.arena.cuda_dev_ptr) {
      write_error(err, err_len, "geforce_p2p BAR1 CUDA pointer not initialized");
      return -1;
    }

    (void)cudaSetDevice(ring.arena.cuda_device_index);
    if (!ring.verify_stream) {
      if (cudaStreamCreateWithFlags(&ring.verify_stream, cudaStreamNonBlocking) != cudaSuccess) {
        write_error(err, err_len, "cudaStreamCreateWithFlags failed for RX verification");
        return -1;
      }
    }
    if (ring.rx_scratch_cap < count) {
      if (ring.d_rx_slot_ids) (void)cudaFree(ring.d_rx_slot_ids);
      if (ring.d_rx_lengths) (void)cudaFree(ring.d_rx_lengths);
      if (!ring.d_rx_counts) {
        if (cudaMalloc(reinterpret_cast<void**>(&ring.d_rx_counts), 2u * sizeof(uint32_t)) != cudaSuccess) {
          write_error(err, err_len, "cudaMalloc failed for d_rx_counts");
          return -1;
        }
      }
      const uint32_t new_cap = std::max<uint32_t>(count, 1024u);
      if (cudaMalloc(reinterpret_cast<void**>(&ring.d_rx_slot_ids), new_cap * sizeof(uint32_t)) != cudaSuccess ||
          cudaMalloc(reinterpret_cast<void**>(&ring.d_rx_lengths), new_cap * sizeof(uint16_t)) != cudaSuccess) {
        write_error(err, err_len, "cudaMalloc failed for RX verification scratch buffers");
        return -1;
      }
      ring.rx_scratch_cap = new_cap;
    }

    (void)cudaMemsetAsync(ring.d_rx_counts, 0, 2u * sizeof(uint32_t), ring.verify_stream);
    (void)cudaMemcpyAsync(
        ring.d_rx_slot_ids, slot_ids, count * sizeof(uint32_t), cudaMemcpyHostToDevice, ring.verify_stream);
    (void)cudaMemcpyAsync(
        ring.d_rx_lengths, lengths, count * sizeof(uint16_t), cudaMemcpyHostToDevice, ring.verify_stream);

    const uint32_t threads = 128u;
    const uint32_t blocks = (count + threads - 1u) / threads;
    geforce_p2p_rx_verify_consume_kernel<<<blocks, threads, 0, ring.verify_stream>>>(
        ring.arena.cuda_dev_ptr,
        ring.cfg.slot_stride,
        ring.d_rx_slot_ids,
        ring.d_rx_lengths,
        count,
        ring.d_rx_counts,
        ring.d_rx_counts + 1);

    uint32_t host_counts[2]{0u, 0u};
    (void)cudaMemcpyAsync(
        host_counts, ring.d_rx_counts, 2u * sizeof(uint32_t), cudaMemcpyDeviceToHost, ring.verify_stream);
    const cudaError_t sync_rc = cudaStreamSynchronize(ring.verify_stream);
    if (sync_rc != cudaSuccess) {
      write_error(err, err_len, std::string("gpu_verify_rx_slots kernel failed: ") + cudaGetErrorString(sync_rc));
      return -1;
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t idx = slot_ids[i] % n_slots;
      ring.slots[idx].state = zero_copy::DescriptorOwnershipState::kFree;
    }

    ring.stats.gpu_rx_verified_packets += host_counts[0];
    ring.stats.gpu_rx_checksum_errors += host_counts[1];
    *out_valid_packets = host_counts[0];
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
    sync_device_txq_stats_locked(*it->second);
    *out_stats = it->second->stats;
    write_error(err, err_len, "");
    return 0;
  }

  void configure_persistent_doorbell(
      const GeforceP2pDoorbellConfigV1* db_cfg,
      uint64_t explicit_bar1_iova_override = 0u) {
    std::lock_guard<std::mutex> lock(mu_);
    default_bar1_iova_override_ = explicit_bar1_iova_override;
    if (db_cfg) {
      default_doorbell_cfg_ = *db_cfg;
      has_default_doorbell_cfg_ = true;
    } else {
      default_doorbell_cfg_ = GeforceP2pDoorbellConfigV1{};
      has_default_doorbell_cfg_ = false;
    }
  }

  uint64_t get_default_bar1_iova_override() {
    std::lock_guard<std::mutex> lock(mu_);
    return default_bar1_iova_override_;
  }

  int get_gpu_txq_handle(
      int handle,
      uint64_t* out_gpu_txq_handle,
      uint32_t* out_mkey_be,
      char* err,
      size_t err_len) {
    if (!out_gpu_txq_handle) {
      write_error(err, err_len, "out_gpu_txq_handle is null");
      return -1;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    auto& ring = *it->second;
    if (ring.has_gpu_doorbell && ring.dev_device_txq != nullptr) {
      *out_gpu_txq_handle = reinterpret_cast<uint64_t>(ring.dev_device_txq);
      if (out_mkey_be) {
        *out_mkey_be = doorbell::kGeforceP2pDoorbellMkeyBe;
      }
      write_error(err, err_len, "");
      return 0;
    }
    *out_gpu_txq_handle =
        (ring.arena.bar1_phys_addr != 0u) ? ring.arena.bar1_phys_addr : ring.arena.bar1_phys_base;
    if (out_mkey_be) {
      *out_mkey_be = 0x42415231u;  // 'BAR1'
    }
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
    if (out_bar1_phys_addr) {
      *out_bar1_phys_addr = (arena.bar1_phys_addr != 0u) ? arena.bar1_phys_addr : arena.bar1_phys_base;
    }
    if (out_arena_bytes) *out_arena_bytes = arena.arena_bytes;
    write_error(err, err_len, "");
    return 0;
  }

  int bind_gpu_doorbell(
      int handle,
      const GeforceP2pDoorbellConfigV1* db_cfg,
      char* err,
      size_t err_len) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    return bind_gpu_doorbell_locked(*it->second, db_cfg, err, err_len);
  }

 private:
  void sync_device_txq_stats_locked(GeforceP2pRingInstance& ring) {
    if (!ring.host_device_txq || ring.host_device_txq->magic != doorbell::kGeforceP2pDeviceTxqMagic) {
      return;
    }
    const uint64_t descs =
        static_cast<uint64_t>(__atomic_load_n(&ring.host_device_txq->descriptors_written, __ATOMIC_ACQUIRE));
    const uint64_t kicks =
        static_cast<uint64_t>(__atomic_load_n(&ring.host_device_txq->doorbell_kicks, __ATOMIC_ACQUIRE));
    const uint64_t drops =
        static_cast<uint64_t>(__atomic_load_n(&ring.host_device_txq->backpressure_drops, __ATOMIC_ACQUIRE));
    const uint64_t reaped =
        static_cast<uint64_t>(__atomic_load_n(&ring.host_device_txq->reaped_completions, __ATOMIC_ACQUIRE));
    const uint64_t bytes =
        static_cast<uint64_t>(__atomic_load_n(&ring.host_device_txq->tx_bytes, __ATOMIC_ACQUIRE));

    if (descs > ring.synced_dev_txq_descs) {
      const uint64_t d = descs - ring.synced_dev_txq_descs;
      ring.stats.gpu_descriptors_written += d;
      ring.stats.tx_packets += d;
      ring.stats.mrd_tlp_requests += d;
      ring.stats.cpld_tlp_responses += d;
      ring.synced_dev_txq_descs = descs;
    }
    if (kicks > ring.synced_dev_txq_kicks) {
      ring.stats.gpu_doorbell_kicks += (kicks - ring.synced_dev_txq_kicks);
      ring.synced_dev_txq_kicks = kicks;
    }
    if (drops > ring.synced_dev_txq_drops) {
      const uint64_t d = drops - ring.synced_dev_txq_drops;
      ring.stats.gpu_ring_full_backpressure += d;
      ring.stats.tx_drops += d;
      ring.synced_dev_txq_drops = drops;
    }
    if (reaped > ring.synced_dev_txq_reaped) {
      ring.stats.gpu_reaped_completions += (reaped - ring.synced_dev_txq_reaped);
      ring.synced_dev_txq_reaped = reaped;
    }
    if (bytes > ring.synced_dev_txq_bytes) {
      ring.stats.tx_bytes += (bytes - ring.synced_dev_txq_bytes);
      ring.synced_dev_txq_bytes = bytes;
    }
  }

  int bind_gpu_doorbell_locked(
      GeforceP2pRingInstance& ring,
      const GeforceP2pDoorbellConfigV1* db_cfg,
      char* err,
      size_t err_len) {
    ring.cleanup_gpu_doorbell();

    if (!db_cfg) {
      write_error(err, err_len, "");
      return 0;
    }
    if (db_cfg->nic_driver_type > static_cast<uint32_t>(doorbell::NicHardwareDriverType::kMellanoxMlx5)) {
      write_error(err, err_len, "geforce_p2p: unsupported nic_driver_type in GeforceP2pDoorbellConfigV1");
      return -1;
    }
    const uint32_t ring_sz = db_cfg->tx_ring_size;
    if (ring_sz < 16u || (ring_sz & (ring_sz - 1u)) != 0u) {
      write_error(err, err_len, "geforce_p2p: tx_ring_size must be a power of 2 >= 16");
      return -1;
    }
    if (ring.arena.iommu_iova_base == 0u || !ring.arena.iova_verified) {
      write_error(
          err,
          err_len,
          "geforce_p2p: refusing to bind GPU-initiated doorbell without verified BAR1 DMA IOVA");
      return -1;
    }

    (void)cudaSetDevice(ring.arena.cuda_device_index);
    const size_t desc_bytes =
        (db_cfg->nic_driver_type == static_cast<uint32_t>(doorbell::NicHardwareDriverType::kMellanoxMlx5))
            ? sizeof(doorbell::Mlx5TxWqe)
            : 16u;
    const size_t total_ring_bytes = static_cast<size_t>(ring_sz) * desc_bytes;

    // 1. Setup GPU-mapped NIC TX descriptor ring
    if (db_cfg->host_tx_desc_ring != nullptr && db_cfg->dev_tx_desc_ring != nullptr) {
      ring.host_tx_desc_ring = db_cfg->host_tx_desc_ring;
      ring.dev_tx_desc_ring = db_cfg->dev_tx_desc_ring;
      ring.owns_tx_desc_ring = false;
    } else if (db_cfg->host_tx_desc_ring != nullptr) {
      ring.host_tx_desc_ring = db_cfg->host_tx_desc_ring;
      void* dev_ptr = nullptr;
      if (cudaHostGetDevicePointer(&dev_ptr, ring.host_tx_desc_ring, 0) != cudaSuccess || !dev_ptr) {
        write_error(err, err_len, "geforce_p2p: cudaHostGetDevicePointer failed for host_tx_desc_ring");
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      ring.dev_tx_desc_ring = dev_ptr;
      ring.owns_tx_desc_ring = false;
    } else {
      void* host_ring = nullptr;
      void* dev_ring = nullptr;
      if (cudaHostAlloc(&host_ring, total_ring_bytes, cudaHostAllocMapped) != cudaSuccess || !host_ring ||
          cudaHostGetDevicePointer(&dev_ring, host_ring, 0) != cudaSuccess || !dev_ring) {
        write_error(err, err_len, "geforce_p2p: cudaHostAlloc(cudaHostAllocMapped) failed for TX descriptor ring");
        if (host_ring) (void)cudaFreeHost(host_ring);
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      std::memset(host_ring, 0, total_ring_bytes);
      if (db_cfg->nic_driver_type == static_cast<uint32_t>(doorbell::NicHardwareDriverType::kRealtekR8169)) {
        auto* rtl_ring = static_cast<doorbell::Rtl8169TxDesc*>(host_ring);
        rtl_ring[ring_sz - 1u].opts1 = doorbell::kRtlRingEnd;
      }
      ring.host_tx_desc_ring = host_ring;
      ring.dev_tx_desc_ring = dev_ring;
      ring.owns_tx_desc_ring = true;
    }

    // 2. Setup GPU-mapped NIC MMIO Doorbell BAR region
    const size_t mmio_len = (db_cfg->nic_mmio_bytes >= 4096u) ? db_cfg->nic_mmio_bytes : 4096u;
    if (db_cfg->host_nic_mmio_base != nullptr && db_cfg->dev_nic_mmio_base != nullptr) {
      ring.host_nic_mmio_base = db_cfg->host_nic_mmio_base;
      ring.dev_nic_mmio_base = static_cast<volatile uint8_t*>(db_cfg->dev_nic_mmio_base);
      ring.nic_mmio_bytes = mmio_len;
      ring.owns_nic_mmio_mmap = false;
      ring.registered_nic_mmio_cuda = false;
    } else if (db_cfg->host_nic_mmio_base != nullptr) {
      ring.host_nic_mmio_base = db_cfg->host_nic_mmio_base;
      ring.nic_mmio_bytes = mmio_len;
      void* dev_mmio = nullptr;
      if (cudaHostGetDevicePointer(&dev_mmio, ring.host_nic_mmio_base, 0) != cudaSuccess || !dev_mmio) {
        if (cudaHostRegister(
                ring.host_nic_mmio_base,
                mmio_len,
                cudaHostRegisterIoMemory | cudaHostRegisterMapped) != cudaSuccess ||
            cudaHostGetDevicePointer(&dev_mmio, ring.host_nic_mmio_base, 0) != cudaSuccess || !dev_mmio) {
          write_error(err, err_len, "geforce_p2p: failed to map host_nic_mmio_base into CUDA device address space");
          ring.cleanup_gpu_doorbell();
          return -1;
        }
        ring.registered_nic_mmio_cuda = true;
      }
      ring.dev_nic_mmio_base = static_cast<volatile uint8_t*>(dev_mmio);
    } else if (ring.cfg.pci_nic_bdf[0] != '\0') {
      char res_path[160]{};
      std::snprintf(
          res_path,
          sizeof(res_path),
          "/sys/bus/pci/devices/%s/resource%u",
          ring.cfg.pci_nic_bdf,
          db_cfg->pci_mmio_bar_index);
      const int fd = open(res_path, O_RDWR | O_SYNC);
      if (fd < 0) {
        write_error(err, err_len, std::string("geforce_p2p: cannot open NIC MMIO BAR ") + res_path);
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      void* mmio_ptr = mmap(nullptr, mmio_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (mmio_ptr == MAP_FAILED || !mmio_ptr) {
        (void)close(fd);
        write_error(err, err_len, std::string("geforce_p2p: mmap failed on NIC MMIO BAR ") + res_path);
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      // Fault in the PFN mapping before cudaHostRegisterIoMemory
      volatile uint8_t touch = *static_cast<volatile uint8_t*>(mmio_ptr);
      (void)touch;
      ring.nic_mmio_fd = fd;
      ring.host_nic_mmio_base = mmio_ptr;
      ring.nic_mmio_bytes = mmio_len;
      ring.owns_nic_mmio_mmap = true;

      const cudaError_t reg_rc = cudaHostRegister(
          mmio_ptr, mmio_len, cudaHostRegisterIoMemory | cudaHostRegisterMapped);
      if (reg_rc != cudaSuccess) {
        write_error(
            err,
            err_len,
            std::string("geforce_p2p: cudaHostRegisterIoMemory failed on ") + res_path + ": " +
                cudaGetErrorString(reg_rc));
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      ring.registered_nic_mmio_cuda = true;
      void* dev_mmio = nullptr;
      if (cudaHostGetDevicePointer(&dev_mmio, mmio_ptr, 0) != cudaSuccess || !dev_mmio) {
        write_error(err, err_len, "geforce_p2p: cudaHostGetDevicePointer failed for NIC MMIO BAR");
        ring.cleanup_gpu_doorbell();
        return -1;
      }
      ring.dev_nic_mmio_base = static_cast<volatile uint8_t*>(dev_mmio);
    } else {
      write_error(err, err_len, "geforce_p2p: bind_gpu_doorbell requires host_nic_mmio_base or pci_nic_bdf");
      ring.cleanup_gpu_doorbell();
      return -1;
    }

    uint64_t ring_iova = db_cfg->tx_desc_ring_iova;
    if (ring_iova == 0u && ring.host_tx_desc_ring != nullptr) {
      uint64_t phys_addr = 0u;
      if (resolve_bar1_allocation_phys_addr(ring.host_tx_desc_ring, 0u, ~0ull, &phys_addr)) {
        ring_iova = phys_addr;
      }
    }

    if ((db_cfg->flags & doorbell::kDoorbellFlagInitPmdRegs) != 0u && ring.host_nic_mmio_base != nullptr) {
      if (!doorbell::host_init_nic_pmd_tx_ring_mmio(
              ring.host_nic_mmio_base,
              ring.nic_mmio_bytes,
              static_cast<doorbell::NicHardwareDriverType>(db_cfg->nic_driver_type),
              db_cfg->queue_id,
              ring_iova,
              ring_sz)) {
        write_error(err, err_len, "geforce_p2p: host_init_nic_pmd_tx_ring_mmio failed (MMIO BAR size too small)");
        ring.cleanup_gpu_doorbell();
        return -1;
      }
    }

    void* host_txq_raw = nullptr;
    void* dev_txq_raw = nullptr;
    if (cudaHostAlloc(
            &host_txq_raw,
            sizeof(doorbell::GeforceP2pGpuDeviceTxq),
            cudaHostAllocPortable | cudaHostAllocMapped) != cudaSuccess ||
        !host_txq_raw ||
        cudaHostGetDevicePointer(&dev_txq_raw, host_txq_raw, 0) != cudaSuccess ||
        !dev_txq_raw) {
      if (host_txq_raw) (void)cudaFreeHost(host_txq_raw);
      write_error(err, err_len, "geforce_p2p: cudaHostAlloc failed for GeforceP2pGpuDeviceTxq");
      ring.cleanup_gpu_doorbell();
      return -1;
    }
    ring.host_device_txq = static_cast<doorbell::GeforceP2pGpuDeviceTxq*>(host_txq_raw);
    ring.dev_device_txq = static_cast<doorbell::GeforceP2pGpuDeviceTxq*>(dev_txq_raw);
    std::memset(ring.host_device_txq, 0, sizeof(doorbell::GeforceP2pGpuDeviceTxq));
    ring.host_device_txq->magic = doorbell::kGeforceP2pDeviceTxqMagic;
    ring.host_device_txq->dev_tx_desc_ring = ring.dev_tx_desc_ring;
    ring.host_device_txq->dev_nic_mmio_base = ring.dev_nic_mmio_base;
    ring.host_device_txq->bar1_dev_base = reinterpret_cast<uint64_t>(ring.arena.cuda_dev_ptr);
    ring.host_device_txq->bar1_host_base = reinterpret_cast<uint64_t>(ring.arena.host_bar1_ptr);
    ring.host_device_txq->bar1_iova_base = ring.arena.iommu_iova_base;
    ring.host_device_txq->arena_bytes = ring.arena.arena_bytes;
    ring.host_device_txq->tx_ring_size = ring_sz;
    ring.host_device_txq->tx_ring_mask = ring_sz - 1u;
    ring.host_device_txq->nic_driver_type = db_cfg->nic_driver_type;
    ring.host_device_txq->queue_id = db_cfg->queue_id;
    ring.host_device_txq->mlx5_qpn = db_cfg->mlx5_qpn;
    ring.host_device_txq->mlx5_lkey = db_cfg->mlx5_lkey;
    ring.host_device_txq->doorbell_reg_offset = db_cfg->doorbell_reg_offset;
    ring.host_device_txq->slot_stride = ring.cfg.slot_stride;
    ring.host_device_txq->flags = db_cfg->flags;

    if (cudaStreamCreateWithFlags(&ring.doorbell_stream, cudaStreamNonBlocking) != cudaSuccess) {
      write_error(err, err_len, "geforce_p2p: cudaStreamCreateWithFlags failed for doorbell_stream");
      ring.cleanup_gpu_doorbell();
      return -1;
    }

    ring.doorbell_cfg = *db_cfg;
    ring.gpu_tx_desc_head = 0u;
    ring.gpu_tx_producer_seq = 0u;
    ring.has_gpu_doorbell = true;
    write_error(err, err_len, "");
    return 0;
  }

 public:
  int gpu_doorbell_tx_burst(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_submitted,
      char* err,
      size_t err_len) {
    if (!slot_ids || !lengths || !out_submitted) {
      write_error(err, err_len, "invalid gpu_doorbell_tx_burst arguments");
      return -1;
    }
    *out_submitted = 0u;
    if (count == 0u) {
      write_error(err, err_len, "");
      return 0;
    }
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rings_.find(handle);
    if (it == rings_.end()) {
      write_error(err, err_len, "geforce_p2p invalid ring handle");
      return -1;
    }
    return gpu_doorbell_tx_burst_locked(*it->second, slot_ids, lengths, count, out_submitted, err, err_len);
  }

 private:
  int gpu_doorbell_tx_burst_locked(
      GeforceP2pRingInstance& ring,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_submitted,
      char* err,
      size_t err_len) {
    if (!ring.has_gpu_doorbell || !ring.dev_tx_desc_ring || !ring.dev_nic_mmio_base) {
      ring.stats.tx_errors += count;
      write_error(err, err_len, "geforce_p2p: GPU-initiated doorbell not bound on this ring");
      return -1;
    }
    if (ring.arena.iommu_iova_base == 0u || !ring.arena.iova_verified) {
      ring.stats.tx_errors += count;
      write_error(err, err_len, "geforce_p2p: unverified BAR1 IOVA in gpu_doorbell_tx_burst");
      return -1;
    }

    (void)cudaSetDevice(ring.arena.cuda_device_index);
    const uint32_t max_chunk = 256u;
    if (ring.db_scratch_cap < max_chunk) {
      if (ring.d_db_slot_ids) (void)cudaFree(ring.d_db_slot_ids);
      if (ring.d_db_lengths) (void)cudaFree(ring.d_db_lengths);
      if (ring.d_db_counters) (void)cudaFree(ring.d_db_counters);
      if (cudaMalloc(reinterpret_cast<void**>(&ring.d_db_slot_ids), max_chunk * sizeof(uint32_t)) != cudaSuccess ||
          cudaMalloc(reinterpret_cast<void**>(&ring.d_db_lengths), max_chunk * sizeof(uint16_t)) != cudaSuccess ||
          cudaMalloc(reinterpret_cast<void**>(&ring.d_db_counters), 4u * sizeof(uint32_t)) != cudaSuccess) {
        write_error(err, err_len, "geforce_p2p: cudaMalloc failed for GPU doorbell scratch buffers");
        return -1;
      }
      ring.db_scratch_cap = max_chunk;
    }

    const uint32_t n_slots = static_cast<uint32_t>(ring.slots.size());
    const uint32_t desc_ring_sz = ring.doorbell_cfg.tx_ring_size;
    uint32_t total_submitted = 0u;
    uint32_t offset = 0u;

    while (offset < count) {
      const uint32_t chunk = std::min<uint32_t>(count - offset, max_chunk);
      uint32_t norm_slots[256];
      for (uint32_t i = 0u; i < chunk; ++i) {
        norm_slots[i] = slot_ids[offset + i] % n_slots;
      }

      (void)cudaMemsetAsync(ring.d_db_counters, 0, 4u * sizeof(uint32_t), ring.doorbell_stream);
      (void)cudaMemcpyAsync(
          ring.d_db_slot_ids, norm_slots, chunk * sizeof(uint32_t), cudaMemcpyHostToDevice, ring.doorbell_stream);
      (void)cudaMemcpyAsync(
          ring.d_db_lengths,
          lengths + offset,
          chunk * sizeof(uint16_t),
          cudaMemcpyHostToDevice,
          ring.doorbell_stream);

      doorbell::geforce_p2p_gpu_doorbell_tx_burst_kernel<<<1, 256, 0, ring.doorbell_stream>>>(
          ring.arena.iommu_iova_base,
          ring.cfg.slot_stride,
          ring.d_db_slot_ids,
          ring.d_db_lengths,
          chunk,
          ring.dev_tx_desc_ring,
          desc_ring_sz,
          ring.gpu_tx_desc_head,
          ring.gpu_tx_producer_seq,
          ring.dev_nic_mmio_base,
          ring.doorbell_cfg.nic_driver_type,
          ring.doorbell_cfg.queue_id,
          ring.doorbell_cfg.mlx5_qpn,
          ring.doorbell_cfg.mlx5_lkey,
          ring.doorbell_cfg.doorbell_reg_offset,
          ring.doorbell_cfg.flags,
          ring.d_db_counters,
          ring.d_db_counters + 1,
          ring.d_db_counters + 2,
          ring.d_db_counters + 3);

      uint32_t host_counters[4]{0u, 0u, 0u, 0u};
      (void)cudaMemcpyAsync(
          host_counters,
          ring.d_db_counters,
          4u * sizeof(uint32_t),
          cudaMemcpyDeviceToHost,
          ring.doorbell_stream);
      const cudaError_t sync_rc = cudaStreamSynchronize(ring.doorbell_stream);
      if (sync_rc != cudaSuccess) {
        ring.stats.tx_errors += (count - offset);
        write_error(
            err,
            err_len,
            std::string("geforce_p2p_gpu_doorbell_tx_burst_kernel failed: ") + cudaGetErrorString(sync_rc));
        return -1;
      }

      const uint32_t submitted = std::min<uint32_t>(host_counters[0], chunk);
      const uint32_t drops = host_counters[1];
      const uint32_t kicks = host_counters[2];
      const uint32_t reaped = host_counters[3];

      ring.gpu_tx_desc_head = (ring.gpu_tx_desc_head + submitted) & (desc_ring_sz - 1u);
      ring.gpu_tx_producer_seq += submitted;
      ring.stats.gpu_descriptors_written += submitted;
      ring.stats.gpu_ring_full_backpressure += drops;
      ring.stats.gpu_doorbell_kicks += kicks;
      ring.stats.gpu_reaped_completions += reaped;

      for (uint32_t i = 0u; i < submitted; ++i) {
        const uint32_t s_idx = norm_slots[i];
        const uint16_t pkt_len = lengths[offset + i];
        const uint64_t tlp_flits = std::max<uint64_t>(1u, (static_cast<uint64_t>(pkt_len) + 255u) / 256u);
        ring.stats.mrd_tlp_requests += 1u;
        ring.stats.cpld_tlp_responses += tlp_flits;
        ring.stats.tx_packets += 1u;
        ring.stats.tx_bytes += pkt_len;
        ring.slots[s_idx].state = zero_copy::DescriptorOwnershipState::kComplete;
        ring.slots[s_idx].state = zero_copy::DescriptorOwnershipState::kFree;
      }
      if (drops > 0u) {
        ring.stats.tx_drops += drops;
      }

      total_submitted += submitted;
      if (submitted < chunk) {
        break;  // Hardware TX descriptor ring backpressure encountered
      }
      offset += chunk;
    }

    *out_submitted = total_submitted;
    write_error(err, err_len, "");
    return 0;
  }
  static void write_error(char* err, size_t err_len, const std::string& msg) {
    if (!err || err_len == 0u) return;
    const size_t n = std::min(err_len - 1u, msg.size());
    if (n > 0u) std::memcpy(err, msg.data(), n);
    err[n] = '\0';
  }

  std::mutex mu_;
  int next_handle_ = 1;
  std::unordered_map<int, std::unique_ptr<GeforceP2pRingInstance>> rings_;
  GeforceP2pDoorbellConfigV1 default_doorbell_cfg_{};
  bool has_default_doorbell_cfg_ = false;
  uint64_t default_bar1_iova_override_ = 0u;
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
inline int api_bind_nic_transport(
    int handle,
    const GeforceP2pNicTransportOpsV1* ops,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().bind_nic_transport(handle, ops, err, err_len);
}
inline int api_nic_rx_burst(
    int handle,
    uint32_t max_packets,
    uint32_t* out_received,
    uint32_t* out_slot_ids,
    uint16_t* out_lengths,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().nic_rx_burst(
      handle, max_packets, out_received, out_slot_ids, out_lengths, err, err_len);
}
inline int api_gpu_verify_rx_slots(
    int handle,
    const uint32_t* slot_ids,
    const uint16_t* lengths,
    uint32_t count,
    uint32_t* out_valid_packets,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().gpu_verify_rx_slots(
      handle, slot_ids, lengths, count, out_valid_packets, err, err_len);
}
inline int api_bind_gpu_doorbell(
    int handle,
    const GeforceP2pDoorbellConfigV1* db_cfg,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().bind_gpu_doorbell(handle, db_cfg, err, err_len);
}
inline int api_gpu_doorbell_tx_burst(
    int handle,
    const uint32_t* slot_ids,
    const uint16_t* lengths,
    uint32_t count,
    uint32_t* out_submitted,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().gpu_doorbell_tx_burst(
      handle, slot_ids, lengths, count, out_submitted, err, err_len);
}
inline int api_get_gpu_txq_handle(
    int handle,
    uint64_t* out_gpu_txq_handle,
    uint32_t* out_mkey_be,
    char* err,
    size_t err_len) {
  return GeforceP2pRegistry::instance().get_gpu_txq_handle(
      handle, out_gpu_txq_handle, out_mkey_be, err, err_len);
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
  return GeforceP2pRegistry::instance().get_gpu_txq_handle(handle, out_gpu_txq_handle, nullptr, err, err_len);
}

inline int doca_p2p_get_txq_mkey_be(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) {
  if (!out_mkey_be) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "out_mkey_be is null");
    return -1;
  }
  uint64_t dummy_txq = 0u;
  return GeforceP2pRegistry::instance().get_gpu_txq_handle(handle, &dummy_txq, out_mkey_be, err, err_len);
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
  GeforceP2pConfigV1 cfg{};
  std::snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface);
  std::snprintf(cfg.pci_nic_bdf, sizeof(cfg.pci_nic_bdf), "%s", device_name);
  cfg.ring_slot_count = 1024u;
  cfg.slot_stride = 2048u;
  cfg.vfio_container_fd = 0u;
  return GeforceP2pRegistry::instance().create_ring(&cfg, out_handle, err, err_len);
}

inline int doca_p2p_destroy_rxq(int handle, char* err, size_t err_len) {
  if (handle <= 0) {
    if (err && err_len > 0u) std::snprintf(err, err_len, "invalid rxq handle");
    return -1;
  }
  return GeforceP2pRegistry::instance().destroy_ring(handle, err, err_len);
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
  std::vector<uint32_t> slot_ids(static_cast<size_t>(max_packets), 0u);
  uint32_t received = 0u;
  const int rc = GeforceP2pRegistry::instance().nic_rx_burst(
      handle,
      static_cast<uint32_t>(max_packets),
      &received,
      slot_ids.data(),
      out_lengths,
      err,
      err_len);
  if (rc != 0) {
    return rc;
  }
  if (received > 0u) {
    void* host_bar1_ptr = nullptr;
    size_t arena_bytes = 0u;
    if (GeforceP2pRegistry::instance().get_arena_pointers(
            handle, &host_bar1_ptr, nullptr, nullptr, &arena_bytes, err, err_len) == 0 &&
        host_bar1_ptr != nullptr) {
      const uint32_t stride = out_packets_flat_len / static_cast<uint32_t>(max_packets);
      for (uint32_t i = 0; i < received && stride > 0u; ++i) {
        const size_t src_off = static_cast<size_t>(slot_ids[i]) * 2048u;
        const size_t copy_len = std::min<size_t>(out_lengths[i], stride);
        if (src_off + copy_len <= arena_bytes) {
          std::memcpy(
              out_packets_flat + static_cast<size_t>(i) * stride,
              static_cast<const uint8_t*>(host_bar1_ptr) + src_off,
              copy_len);
        }
      }
    }
    uint32_t valid_pkts = 0u;
    (void)GeforceP2pRegistry::instance().gpu_verify_rx_slots(
        handle, slot_ids.data(), out_lengths, received, &valid_pkts, err, err_len);
  }
  *out_received = static_cast<int>(received);
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
    api.bind_nic_transport = &ddos_samurai::gpu_packet_cuda::p2p::api_bind_nic_transport;
    api.nic_rx_burst = &ddos_samurai::gpu_packet_cuda::p2p::api_nic_rx_burst;
    api.gpu_verify_rx_slots = &ddos_samurai::gpu_packet_cuda::p2p::api_gpu_verify_rx_slots;
    api.bind_gpu_doorbell = &ddos_samurai::gpu_packet_cuda::p2p::api_bind_gpu_doorbell;
    api.gpu_doorbell_tx_burst = &ddos_samurai::gpu_packet_cuda::p2p::api_gpu_doorbell_tx_burst;
    api.get_gpu_txq_handle = &ddos_samurai::gpu_packet_cuda::p2p::api_get_gpu_txq_handle;
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
