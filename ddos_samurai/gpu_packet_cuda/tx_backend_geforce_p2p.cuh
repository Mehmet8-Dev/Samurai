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
  uint64_t rx_packets = 0u;
  uint64_t rx_bytes = 0u;
  uint64_t rx_errors = 0u;
  uint64_t rx_drops = 0u;
  uint64_t gpu_rx_verified_packets = 0u;
  uint64_t gpu_rx_checksum_errors = 0u;
  uint64_t gpu_doorbell_kicks = 0u;
  uint64_t gpu_descriptors_written = 0u;
  uint64_t gpu_ring_full_backpressure = 0u;
  uint64_t gpu_reaped_completions = 0u;
  int queue_id = 0;
};

struct alignas(64) GeforceP2pRingSlot {
  uint64_t iova = 0u;              // IOVA address mapped in NIC IOMMU domain
  uint32_t vram_offset = 0u;      // Offset within BAR1 VRAM arena
  uint16_t packet_len = 0u;       // Wire length including Ethernet header
  uint16_t flags = 0u;            // Checksum / offload flags
  zero_copy::DescriptorOwnershipState state = zero_copy::DescriptorOwnershipState::kFree;
};

struct GeforceP2pNicTransportOpsV1 {
  void* user_ctx = nullptr;
  // Map BAR1 VA + IOVA into NIC DMA/IOMMU domain. Returns 0 on success, <0 on failure.
  int (*dma_map_region)(
      void* user_ctx,
      void* bar1_host_va,
      uint64_t bar1_iova,
      size_t region_bytes,
      uint32_t page_size) = nullptr;
  // Transmit slot batch directly from BAR1 arena via NIC DMA (e.g. DPDK extbuf).
  // Returns number of transmitted packets (>=0), or <0 on transport failure.
  int (*tx_burst_slots)(
      void* user_ctx,
      void* bar1_host_va,
      uint64_t bar1_iova,
      uint32_t slot_stride,
      const uint32_t* slot_indices,
      const uint16_t* pkt_lengths,
      uint32_t count) = nullptr;
  // Receive packet burst from NIC DMA into BAR1 RX slots.
  // Returns number of received packets (>=0), or <0 on transport failure.
  int (*rx_burst_slots)(
      void* user_ctx,
      void* bar1_host_va,
      uint64_t bar1_iova,
      uint32_t slot_stride,
      const uint32_t* slot_indices,
      uint32_t max_slots,
      uint16_t* out_lengths) = nullptr;
};

struct GeforceP2pConfigV1 {
  char pci_gpu_bdf[32]{};         // e.g. "0000:01:00.0"
  char pci_nic_bdf[32]{};         // e.g. "0000:02:00.0"
  char iface[32]{};               // e.g. "enp2s0" or "veth0"
  uint64_t bar1_phys_base = 0u;   // Verified DMA IOVA override (0 = auto-resolve)
  uint32_t ring_slot_count = 1024u;
  uint32_t slot_stride = 2048u;   // 2KB per packet slot
  uint32_t vfio_container_fd = 0u;
  uint32_t flags = 0u;
  int64_t dpdk_port_handle = -1;
  uint16_t dpdk_queue_id = 0u;
  uint16_t reserved_pad = 0u;
  void* external_host_bar1_ptr = nullptr;
  void* external_cuda_dev_ptr = nullptr;
  uint64_t external_bar1_iova = 0u;
  size_t external_arena_bytes = 0u;
};

struct GeforceP2pDoorbellConfigV1 {
  uint32_t nic_driver_type = 0u;     // 0=r8169, 1=e1000e, 2=ixgbe, 3=i40e, 4=mlx5
  uint32_t queue_id = 0u;
  uint32_t tx_ring_size = 256u;      // Power of 2 hardware TX descriptor ring capacity
  uint32_t doorbell_reg_offset = 0u; // 0 = use hardware default (0x38, 0x3818, 0x6018, 0x100000, 0x800)
  uint32_t mlx5_qpn = 0u;
  uint32_t mlx5_lkey = 0u;
  uint32_t pci_mmio_bar_index = 2u;  // BAR2 (r8169) or BAR0 (Intel/Mellanox)
  uint32_t flags = 0u;
  void* host_tx_desc_ring = nullptr;
  void* dev_tx_desc_ring = nullptr;
  uint64_t tx_desc_ring_iova = 0u;
  void* host_nic_mmio_base = nullptr;
  void* dev_nic_mmio_base = nullptr;
  size_t nic_mmio_bytes = 4096u;
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

  // Bind an explicit NIC DMA / DPDK zero-copy transport to this P2P ring
  int (*bind_nic_transport)(
      int handle,
      const GeforceP2pNicTransportOpsV1* ops,
      char* err,
      size_t err_len) = nullptr;

  // NIC RX -> GPU BAR1 slot burst (receives wire frames directly into BAR1 RX slots)
  int (*nic_rx_burst)(
      int handle,
      uint32_t max_packets,
      uint32_t* out_received,
      uint32_t* out_slot_ids,
      uint16_t* out_lengths,
      char* err,
      size_t err_len) = nullptr;

  // GPU CUDA kernel verification & consumption of received BAR1 RX slots
  int (*gpu_verify_rx_slots)(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_valid_packets,
      char* err,
      size_t err_len) = nullptr;

  // Bind GPU-Initiated NIC TX Descriptor Ring & PCIe MMIO Doorbell to this P2P ring
  int (*bind_gpu_doorbell)(
      int handle,
      const GeforceP2pDoorbellConfigV1* db_cfg,
      char* err,
      size_t err_len) = nullptr;

  // Execute 100% GPU-Initiated TX Descriptor Write + PCIe MMIO Doorbell Kick (Zero-CPU Burst)
  int (*gpu_doorbell_tx_burst)(
      int handle,
      const uint32_t* slot_ids,
      const uint16_t* lengths,
      uint32_t count,
      uint32_t* out_submitted,
      char* err,
      size_t err_len) = nullptr;

  // Retrieve device-resident GPU-PMD TXQ context pointer & MKey for Persistent Kernel Direct TX
  int (*get_gpu_txq_handle)(
      int handle,
      uint64_t* out_gpu_txq_handle,
      uint32_t* out_mkey_be,
      char* err,
      size_t err_len) = nullptr;
};

}  // namespace ddos_samurai::gpu_packet_cuda::p2p

extern "C" __attribute__((weak))
ddos_samurai::gpu_packet_cuda::p2p::GeforceP2pApiV1* samurai_geforce_p2p_get_api_v1(void);
