#pragma once

#include <cstddef>
#include <cstdint>
#include "zero_copy_dataplane_contract.cuh"

/**
 * @file tx_backend_geforce_p2p.cuh
 * @brief Open-Standard P2P DMA Zero-Copy Packet Engine for Consumer NVIDIA GPUs (GeForce GTX/RTX).
 *
 * Designed as a vendor-unlocked alternative to NVIDIA DOCA GPUNetIO (which is locked to
 * enterprise BlueField DPUs and A100/H100 GPUs).
 *
 * Architecture:
 *   1. Compute: CUDA SMs construct packets in parallel directly into Vulkan Host-Visible
 *      GDDR6 VRAM arena (BAR1).
 *   2. Bus Mapping: BAR1 physical pages are mapped into DPDK's IOMMU domain via Linux VFIO
 *      (VFIO_IOMMU_MAP_DMA) or direct IOVA allocation.
 *   3. Direct Egress: DPDK Poll Mode Drivers (PMD) or NIC DMA controllers issue PCIe Memory
 *      Read (MRd) TLPs directly to the GPU BAR1 window. GPU BAR1 controller answers with
 *      Completion with Data (CplD) TLPs directly to the NIC TX FIFO.
 *   4. Zero-Copy: Zero CPU memory copies, zero host RAM overhead.
 *
 * For full theoretical limits and experimental validation, see:
 *   docs/45-commodity-gpu-nic-p2p-packet-engine-report.md
 */

#define SAMURAI_GEFORCE_P2P_API_DECLS 1

constexpr int kGeforceP2pApiVersion = 1;

namespace ddos_samurai::gpu_packet_cuda::p2p {

struct alignas(64) GeforceP2pTxStats {
  uint64_t tx_packets = 0u;
  uint64_t tx_bytes = 0u;
  uint64_t tx_errors = 0u;
  uint64_t tx_drops = 0u;
  uint64_t mrd_tlp_requests = 0u;
  uint64_t cpld_tlp_responses = 0u;
  int queue_id = 0;
};

struct alignas(64) GeforceP2pRingSlot {
  uint64_t iova = 0u;              // IOVA address mapped in NIC IOMMU domain
  uint32_t vram_offset = 0u;      // Offset within BAR1 VRAM arena
  uint16_t packet_len = 0u;       // Wire length including Ethernet header
  uint16_t flags = 0u;            // Checksum / offload flags
  zero_copy::DescriptorOwnershipState state = zero_copy::DescriptorOwnershipState::kFree;
};

struct GeforceP2pConfigV1 {
  char pci_gpu_bdf[32]{};         // e.g. "0000:01:00.0"
  char pci_nic_bdf[32]{};         // e.g. "0000:02:00.0"
  char iface[32]{};               // e.g. "enp2s0" or "veth0"
  uint64_t bar1_phys_base = 0u;   // e.g. 0xfcc0000000 (detected via sysfs)
  uint32_t ring_slot_count = 1024u;
  uint32_t slot_stride = 2048u;   // 2KB per packet slot
  uint32_t vfio_container_fd = 0u;
  uint32_t flags = 0u;
};

struct GeforceP2pApiV1 {
  int version = 0;

  // Lifecycle
  int (*create_tx_ring)(
      const GeforceP2pConfigV1* cfg,
      int* out_handle,
      char* err,
      size_t err_len) = nullptr;

  int (*destroy_tx_ring)(
      int handle,
      char* err,
      size_t err_len) = nullptr;

  // GPU Side: Claim slots in VRAM for CUDA kernel packet generation
  int (*gpu_claim_slots)(
      int handle,
      uint32_t count,
      uint32_t* out_start_slot,
      char* err,
      size_t err_len) = nullptr;

  // GPU Side: Mark generated packets ready for NIC PCIe MRd fetch
  int (*gpu_commit_slots)(
      int handle,
      uint32_t start_slot,
      uint32_t count,
      const uint16_t* lengths,
      char* err,
      size_t err_len) = nullptr;

  // DPDK / NIC Side: Ring doorbell and transmit via PCIe P2P MRd
  int (*nic_tx_burst)(
      int handle,
      uint32_t max_packets,
      uint32_t* out_transmitted,
      char* err,
      size_t err_len) = nullptr;

  // Telemetry
  int (*get_stats)(
      int handle,
      GeforceP2pTxStats* out_stats,
      char* err,
      size_t err_len) = nullptr;

  // Direct BAR1 Arena introspection (Host BAR1 VA, CUDA GDDR6 VA, Physical BAR1 Bus Address)
  int (*get_arena_pointers)(
      int handle,
      void** out_host_bar1_ptr,
      void** out_cuda_dev_ptr,
      uint64_t* out_bar1_phys_addr,
      size_t* out_arena_bytes,
      char* err,
      size_t err_len) = nullptr;

  // Batch slot submission for persistent GPU runtime queues
  int (*submit_slot_batch)(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_sent,
      char* err,
      size_t err_len) = nullptr;
};

}  // namespace ddos_samurai::gpu_packet_cuda::p2p

extern "C" __attribute__((weak))
ddos_samurai::gpu_packet_cuda::p2p::GeforceP2pApiV1* samurai_geforce_p2p_get_api_v1(void);
