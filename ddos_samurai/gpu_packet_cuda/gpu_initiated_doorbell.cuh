#pragma once

#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>

/**
 * @file gpu_initiated_doorbell.cuh
 * @brief GPU-Initiated NIC TX Descriptor, Completion Reaper & PCIe MMIO Doorbell Engine (GPU-PMD)
 *        for Consumer GeForce GPUs.
 *
 * Eliminates the CPU lcore doorbell bottleneck (`rte_eth_tx_burst`) and proprietary DOCA GPUNetIO
 * hardware locks by allowing CUDA kernels (both burst and persistent kernels) on consumer NVIDIA
 * GeForce GPUs (GTX/RTX) to:
 *   1. Reap completed hardware TX descriptors (`DescOwn == 0` / `DD == 1`) directly on the GPU.
 *   2. Write 64-bit BAR1 physical/IOVA addresses directly into the NIC's hardware TX descriptor
 *      ring (`r8169`, `e1000e`, `ixgbe`, `i40e`, `mlx5`).
 *   3. Enforce system-wide PCIe memory ordering via `__threadfence_system()`.
 *   4. Emit a single batched Posted PCIe Memory Write (`MWr`) TLP from the warp/block leader
 *      directly to the NIC's MMIO Doorbell register (`TPPoll`, `TDT`, `QTX_TAIL`, or `BlueFlame`).
 */

namespace ddos_samurai::gpu_packet_cuda::p2p::doorbell {

enum class NicHardwareDriverType : uint32_t {
  kRealtekR8169 = 0u,
  kIntelE1000e  = 1u,
  kIntelIxgbe   = 2u,
  kIntelI40e    = 3u,
  kMellanoxMlx5 = 4u,
};

// Magic tag & MKey identifying a GeForce BAR1 GPU-PMD Device TXQ handle inside persistent kernels
constexpr uint64_t kGeforceP2pDeviceTxqMagic = 0x4746503250545851ULL;  // "GFP2PTXQ"
constexpr uint32_t kGeforceP2pDoorbellMkeyBe = 0x47504442u;            // 'GPDB'

//GeforceP2pDoorbellConfigV1 flags
constexpr uint32_t kDoorbellFlagInitPmdRegs    = (1u << 0);  // Initialize NIC TX ring MMIO registers on bind
constexpr uint32_t kDoorbellFlagAutoReapOnWrap = (1u << 1);  // Auto-reap descriptors on ring wrap (autonomous PMD)

#pragma pack(push, 4)

// 1. Realtek RTL8169 / RTL8168 (1GbE/2.5GbE) 16-Byte Hardware TX Descriptor
struct Rtl8169TxDesc {
  uint32_t opts1;  // +0x00: DescOwn(31) | RingEnd(30) | FirstFrag(29) | LastFrag(28) | Len(0..13)
  uint32_t opts2;  // +0x04: VLAN / Checksum Offload flags
  uint64_t addr;   // +0x08: 64-bit PCIe DMA IOVA (GPU BAR1 VRAM slot address)
};

// 2. Intel e1000e (82574L / I217 / I219 1GbE) 16-Byte Hardware TX Descriptor
struct E1000eTxDesc {
  uint64_t buffer_addr;  // +0x00: 64-bit PCIe DMA IOVA (GPU BAR1 VRAM slot address)
  union {
    uint32_t data;
    struct {
      uint16_t length;
      uint8_t  cso;
      uint8_t  cmd;
    } flags;
  } lower;
  union {
    uint32_t data;
    struct {
      uint8_t  status;
      uint8_t  css;
      uint16_t special;
    } fields;
  } upper;
};

// 3. Intel ixgbe (82599ES / X540 / X550 10GbE) 16-Byte Advanced TX Descriptor
union IxgbeAdvTxDesc {
  struct {
    uint64_t buffer_addr;    // +0x00: 64-bit PCIe DMA IOVA (GPU BAR1 VRAM slot address)
    uint32_t cmd_type_len;   // +0x08: DCMD_EOP | DCMD_IFCS | DCMD_RS | DTYP_DATA | len
    uint32_t olinfo_status;  // +0x0c: Paylen << 14
  } read;
  struct {
    uint64_t rsvd;
    uint32_t nxtseq_seed;
    uint32_t status;         // IXGBE_TXD_STAT_DD (bit 0)
  } wb;
};

// 4. Intel i40e (XL710 / X710 25GbE/40GbE) 16-Byte Hardware TX Descriptor
struct I40eTxDesc {
  uint64_t buffer_addr;          // +0x00: 64-bit PCIe DMA IOVA (GPU BAR1 VRAM slot address)
  uint64_t cmd_type_offset_bsz;  // +0x08: DTYPE_DATA | CMD_(EOP|RS|ICRC) | (len << 34)
};

// 5. Mellanox ConnectX-4/5/6 (mlx5 100GbE/200GbE) 64-Byte TX WQE
struct Mlx5WqeCtrlSeg {
  uint32_t opmod_idx_opcode;  // Big-endian: [23:8] WQE index, [7:0] opcode (0x0A = SEND)
  uint32_t qpn_ds;            // Big-endian: [31:8] QPN, [7:0] DS (4 = 64B)
  uint8_t  signature;
  uint8_t  rsvd[2];
  uint8_t  fm_ce_se;
  uint32_t imm;
};

struct Mlx5WqeEthSeg {
  uint32_t rsvd0;
  uint8_t  cs_flags;          // L3/L4 checksum flags
  uint8_t  rsvd1;
  uint16_t mss;
  uint16_t rsvd2;
  uint16_t inline_hdr_sz;
  uint8_t  inline_hdr_start[2];
};

struct Mlx5WqeDataSeg {
  uint32_t byte_count;        // Big-endian: packet byte length
  uint32_t lkey;              // Big-endian: UMR/MR LKey for GPU BAR1 region
  uint64_t addr;              // Big-endian: 64-bit GPU BAR1 VRAM DMA IOVA
};

struct Mlx5TxWqe {
  Mlx5WqeCtrlSeg ctrl;
  Mlx5WqeEthSeg  eth;
  Mlx5WqeDataSeg data;
  uint8_t        pad[16];
};

#pragma pack(pop)

/**
 * @brief Device-accessible GPU-PMD TX Queue Context for Persistent & Burst Kernels.
 * Allocated in CUDA mapped memory (`cudaHostAllocMapped`) so both the persistent CUDA
 * dataplane kernel and host telemetry readers can access it without stopping the GPU.
 */
struct alignas(128) GeforceP2pGpuDeviceTxq {
  uint64_t magic;                      // Must be kGeforceP2pDeviceTxqMagic
  void* dev_tx_desc_ring;              // Device pointer to hardware TX descriptor ring
  volatile uint8_t* dev_nic_mmio_base; // Device pointer to NIC MMIO BAR
  uint64_t bar1_dev_base;              // CUDA device VA base of BAR1 payload arena
  uint64_t bar1_host_base;             // Host VA base of BAR1 payload arena
  uint64_t bar1_iova_base;             // Verified 64-bit PCIe DMA IOVA base of BAR1 arena
  uint64_t arena_bytes;                // Total byte size of BAR1 payload arena
  uint32_t tx_ring_size;               // Power-of-2 hardware TX descriptor ring size
  uint32_t tx_ring_mask;               // tx_ring_size - 1
  uint32_t nic_driver_type;            // NicHardwareDriverType
  uint32_t queue_id;                   // Hardware TX queue index
  uint32_t mlx5_qpn;                   // Mellanox SQ number
  uint32_t mlx5_lkey;                  // Mellanox UMR/MR LKey
  uint32_t doorbell_reg_offset;        // Custom doorbell offset (0 = hardware default)
  uint32_t slot_stride;                // BAR1 slot stride in bytes
  uint32_t flags;                      // kDoorbellFlagInitPmdRegs | kDoorbellFlagAutoReapOnWrap
  // Mutable GPU-PMD runtime state (updated atomically on device)
  uint32_t reserve_cursor;             // Monotonic packet/descriptor sequence number
  uint32_t commit_tail;                // Latest contiguous tail index published to descriptor ring
  uint32_t last_pushed_tail;           // Last tail index kicked to NIC MMIO Doorbell
  uint32_t published_cursor;           // Contiguous published sequence cursor (all seq < published_cursor ready)
  uint32_t last_pushed_seq;            // Last monotonic published_cursor kicked to NIC MMIO Doorbell
  uint32_t pad0;
  uint32_t* dev_slot_published_seq;    // Optional external per-slot published tag array (for rings > 4096)
  unsigned long long descriptors_written;
  unsigned long long doorbell_kicks;
  unsigned long long backpressure_drops;
  unsigned long long reaped_completions;
  unsigned long long tx_bytes;
  uint32_t inline_slot_published_seq[4096]; // Zero-init safe inline per-slot published sequence tags
};

// Realtek r8169 constants & PMD MMIO registers
constexpr uint32_t kRtlDescOwn       = 0x80000000u;
constexpr uint32_t kRtlRingEnd       = 0x40000000u;
constexpr uint32_t kRtlFirstFrag     = 0x20000000u;
constexpr uint32_t kRtlLastFrag      = 0x10000000u;
constexpr uint32_t kRtlPktLenMask    = 0x00003FFFu;
constexpr uint32_t kRtlRegTnpdsLow   = 0x0020u;  // TxDescStartAddrLow (32-bit)
constexpr uint32_t kRtlRegTnpdsHigh  = 0x0024u;  // TxDescStartAddrHigh (32-bit)
constexpr uint32_t kRtlRegCmd        = 0x0037u;  // Command register (8-bit)
constexpr uint8_t  kRtlCmdTxEnb      = 0x04u;    // Enable Transmitter
constexpr uint32_t kRtlRegTpPoll     = 0x0038u;  // Transmit Priority Polling (Doorbell)
constexpr uint8_t  kRtlTpPollNpq     = 0x40u;    // Normal Priority Queue Poll bit

// Intel e1000e constants & PMD MMIO registers
constexpr uint8_t  kE1000TxdCmdEop          = 0x01u;
constexpr uint8_t  kE1000TxdCmdIfcs         = 0x02u;
constexpr uint8_t  kE1000TxdCmdRs           = 0x08u;
constexpr uint8_t  kE1000TxdStatDd          = 0x01u;
constexpr uint32_t kE1000RegTdbal           = 0x03800u;
constexpr uint32_t kE1000RegTdbah           = 0x03804u;
constexpr uint32_t kE1000RegTdlen           = 0x03808u;
constexpr uint32_t kE1000RegTdh             = 0x03810u;
constexpr uint32_t kE1000RegTdt             = 0x03818u;
constexpr uint32_t kE1000RegTxdctl          = 0x03828u;
constexpr uint32_t kE1000TxdctlQueueEnable  = (1u << 22);

// Intel ixgbe constants & PMD MMIO registers
constexpr uint32_t kIxgbeAdvTxdDtypData    = 0x00300000u;
constexpr uint32_t kIxgbeAdvTxdDcmdEop     = 0x01000000u;
constexpr uint32_t kIxgbeAdvTxdDcmdIfcs    = 0x02000000u;
constexpr uint32_t kIxgbeAdvTxdDcmdRs      = 0x08000000u;
constexpr uint32_t kIxgbeAdvTxdDcmdDext    = 0x20000000u;
constexpr uint32_t kIxgbeTxdStatDd         = 0x00000001u;
constexpr uint32_t kIxgbeAdvTxdPaylenShift = 14u;
constexpr uint32_t kIxgbeTxdctlEnable      = (1u << 25);

__host__ __device__ __forceinline__ uint32_t ixgbe_reg_tdbal(uint32_t queue_id) {
  return 0x06000u + (queue_id * 0x40u);
}
__host__ __device__ __forceinline__ uint32_t ixgbe_reg_tdbah(uint32_t queue_id) {
  return 0x06004u + (queue_id * 0x40u);
}
__host__ __device__ __forceinline__ uint32_t ixgbe_reg_tdlen(uint32_t queue_id) {
  return 0x06008u + (queue_id * 0x40u);
}
__host__ __device__ __forceinline__ uint32_t ixgbe_reg_tdh(uint32_t queue_id) {
  return 0x06010u + (queue_id * 0x40u);
}
__host__ __device__ __forceinline__ uint32_t ixgbe_reg_tdt(uint32_t queue_id) {
  return 0x06018u + (queue_id * 0x40u);
}
__host__ __device__ __forceinline__ uint32_t ixgbe_reg_txdctl(uint32_t queue_id) {
  return 0x06028u + (queue_id * 0x40u);
}

// Intel i40e constants
constexpr uint64_t kI40eTxDescDtypeData = 0x0ULL;
constexpr uint64_t kI40eTxDescDtypeDone = 0xFULL;
constexpr uint64_t kI40eTxDescDtypeMask = 0xFULL;
constexpr uint64_t kI40eTxDescCmdShift  = 4ULL;
constexpr uint64_t kI40eTxDescCmdEop    = (0x0001ULL << kI40eTxDescCmdShift);
constexpr uint64_t kI40eTxDescCmdRs     = (0x0002ULL << kI40eTxDescCmdShift);
constexpr uint64_t kI40eTxDescCmdIcrc   = (0x0004ULL << kI40eTxDescCmdShift);
constexpr uint32_t kMaxInlinePublishedSlots = 4096u;

__host__ __device__ __forceinline__ uint32_t i40e_reg_qtx_tail(uint32_t queue_id) {
  return 0x00100000u + (queue_id * 0x1000u);
}

// Mellanox mlx5 constants
constexpr uint32_t kMlx5OpcodeSend    = 0x0Au;
constexpr uint8_t  kMlx5EthWqeL3Csum  = (1u << 6);
constexpr uint8_t  kMlx5EthWqeL4Csum  = (1u << 7);
constexpr uint32_t kMlx5DefaultBfOff  = 0x0800u;

__host__ __device__ __forceinline__ uint32_t bswap32_dev(uint32_t v) {
#if defined(__CUDA_ARCH__)
  return __byte_perm(v, 0u, 0x0123u);
#else
  return __builtin_bswap32(v);
#endif
}

__host__ __device__ __forceinline__ uint64_t bswap64_dev(uint64_t v) {
  const uint32_t hi = bswap32_dev(static_cast<uint32_t>(v >> 32));
  const uint32_t lo = bswap32_dev(static_cast<uint32_t>(v & 0xFFFFFFFFULL));
  return (static_cast<uint64_t>(lo) << 32) | static_cast<uint64_t>(hi);
}

/**
 * @brief Initializes NIC hardware TX descriptor ring registers directly via MMIO (Bare-Metal PMD).
 * Programs the descriptor ring base IOVA, byte length, head/tail pointers, and queue enable bit.
 */
__host__ inline bool host_init_nic_pmd_tx_ring_mmio(
    void* host_nic_mmio_base,
    size_t mmio_bytes,
    NicHardwareDriverType nic_type,
    uint32_t queue_id,
    uint64_t tx_desc_ring_iova,
    uint32_t ring_size) {
  if (!host_nic_mmio_base || ring_size == 0u) {
    return false;
  }
  auto* mmio = static_cast<volatile uint8_t*>(host_nic_mmio_base);
  const uint32_t iova_lo = static_cast<uint32_t>(tx_desc_ring_iova & 0xFFFFFFFFULL);
  const uint32_t iova_hi = static_cast<uint32_t>(tx_desc_ring_iova >> 32);
  const uint32_t ring_bytes = ring_size * 16u;

  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169: {
      if (mmio_bytes < 0x40u) return false;
      *(volatile uint32_t*)(mmio + kRtlRegTnpdsLow)  = iova_lo;
      *(volatile uint32_t*)(mmio + kRtlRegTnpdsHigh) = iova_hi;
      const uint8_t cmd = *(volatile uint8_t*)(mmio + kRtlRegCmd);
      *(volatile uint8_t*)(mmio + kRtlRegCmd) = static_cast<uint8_t>(cmd | kRtlCmdTxEnb);
      __sync_synchronize();
      return true;
    }
    case NicHardwareDriverType::kIntelE1000e: {
      if (mmio_bytes < (kE1000RegTxdctl + 4u)) return false;
      *(volatile uint32_t*)(mmio + kE1000RegTdbal) = iova_lo;
      *(volatile uint32_t*)(mmio + kE1000RegTdbah) = iova_hi;
      *(volatile uint32_t*)(mmio + kE1000RegTdlen) = ring_bytes;
      *(volatile uint32_t*)(mmio + kE1000RegTdh)   = 0u;
      *(volatile uint32_t*)(mmio + kE1000RegTdt)   = 0u;
      const uint32_t txdctl = *(volatile uint32_t*)(mmio + kE1000RegTxdctl);
      *(volatile uint32_t*)(mmio + kE1000RegTxdctl) = txdctl | kE1000TxdctlQueueEnable;
      __sync_synchronize();
      return true;
    }
    case NicHardwareDriverType::kIntelIxgbe: {
      const uint32_t max_off = ixgbe_reg_txdctl(queue_id) + 4u;
      if (mmio_bytes < max_off) return false;
      *(volatile uint32_t*)(mmio + ixgbe_reg_tdbal(queue_id)) = iova_lo;
      *(volatile uint32_t*)(mmio + ixgbe_reg_tdbah(queue_id)) = iova_hi;
      *(volatile uint32_t*)(mmio + ixgbe_reg_tdlen(queue_id)) = ring_bytes;
      *(volatile uint32_t*)(mmio + ixgbe_reg_tdh(queue_id))   = 0u;
      *(volatile uint32_t*)(mmio + ixgbe_reg_tdt(queue_id))   = 0u;
      const uint32_t txdctl = *(volatile uint32_t*)(mmio + ixgbe_reg_txdctl(queue_id));
      *(volatile uint32_t*)(mmio + ixgbe_reg_txdctl(queue_id)) = txdctl | kIxgbeTxdctlEnable;
      __sync_synchronize();
      return true;
    }
    case NicHardwareDriverType::kIntelI40e: {
      const uint32_t tail_off = i40e_reg_qtx_tail(queue_id);
      if (mmio_bytes < (tail_off + 4u)) return false;
      *(volatile uint32_t*)(mmio + tail_off) = 0u;
      __sync_synchronize();
      return true;
    }
    case NicHardwareDriverType::kMellanoxMlx5: {
      return true;
    }
  }
  return false;
}

#if defined(__CUDACC__)

/**
 * @brief GPU-PMD hardware TX descriptor completion reaper.
 * Checks if descriptor `desc_idx` previously held an in-flight packet that has now completed
 * (either via NIC DMA writeback clearing `DescOwn` / setting `DD`, or via `kDoorbellFlagAutoReapOnWrap`),
 * resets its completion state for reuse, and returns true if a completion was reaped.
 */
__device__ __forceinline__ bool device_reap_nic_tx_descriptor(
    void* dev_tx_desc_ring,
    uint32_t desc_idx,
    uint32_t ring_size,
    NicHardwareDriverType nic_type,
    uint32_t flags) {
  if (!dev_tx_desc_ring || ring_size == 0u) {
    return false;
  }
  const bool auto_reap = (flags & kDoorbellFlagAutoReapOnWrap) != 0u;

  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169: {
      auto* ring = static_cast<volatile Rtl8169TxDesc*>(dev_tx_desc_ring);
      volatile Rtl8169TxDesc& desc = ring[desc_idx];
      const uint32_t opts1 = desc.opts1;
      if ((opts1 & kRtlDescOwn) != 0u) {
        if (auto_reap) {
          desc.opts1 = (desc_idx == (ring_size - 1u)) ? kRtlRingEnd : 0u;
          __threadfence_system();
          return true;
        }
        return false;
      }
      if (desc.addr != 0u) {
        // NIC hardware cleared DescOwn after completing DMA fetch from BAR1
        return true;
      }
      return false;
    }

    case NicHardwareDriverType::kIntelE1000e: {
      auto* ring = static_cast<volatile E1000eTxDesc*>(dev_tx_desc_ring);
      volatile E1000eTxDesc& desc = ring[desc_idx];
      if (desc.lower.data != 0u) {
        if ((desc.upper.data & kE1000TxdStatDd) != 0u || auto_reap) {
          desc.lower.data = 0u;
          desc.upper.data = 0u;
          __threadfence_system();
          return true;
        }
      }
      return false;
    }

    case NicHardwareDriverType::kIntelIxgbe: {
      auto* ring = static_cast<volatile IxgbeAdvTxDesc*>(dev_tx_desc_ring);
      volatile IxgbeAdvTxDesc& desc = ring[desc_idx];
      if (desc.read.cmd_type_len != 0u) {
        if ((desc.wb.status & kIxgbeTxdStatDd) != 0u || auto_reap) {
          desc.read.cmd_type_len = 0u;
          desc.wb.status = 0u;
          __threadfence_system();
          return true;
        }
      }
      return false;
    }

    case NicHardwareDriverType::kIntelI40e: {
      auto* ring = static_cast<volatile I40eTxDesc*>(dev_tx_desc_ring);
      volatile I40eTxDesc& desc = ring[desc_idx];
      if (desc.buffer_addr != 0ULL || desc.cmd_type_offset_bsz != 0ULL) {
        const bool dd_done = (desc.cmd_type_offset_bsz & kI40eTxDescDtypeMask) == kI40eTxDescDtypeDone;
        if (dd_done || auto_reap) {
          desc.cmd_type_offset_bsz = 0ULL;
          desc.buffer_addr = 0ULL;
          __threadfence_system();
          return true;
        }
      }
      return false;
    }

    case NicHardwareDriverType::kMellanoxMlx5: {
      auto* ring = static_cast<volatile Mlx5TxWqe*>(dev_tx_desc_ring);
      volatile Mlx5TxWqe& wqe = ring[desc_idx];
      if (wqe.data.addr != 0ULL) {
        if (wqe.ctrl.signature == 0xFFu || auto_reap) {
          wqe.data.addr = 0ULL;
          wqe.ctrl.opmod_idx_opcode = 0u;
          wqe.ctrl.signature = 0u;
          __threadfence_system();
          return true;
        }
      }
      return false;
    }
  }
  return false;
}

/**
 * @brief Non-destructive check whether hardware TX descriptor slot `desc_idx` is free or reapable.
 * Used before advancing `reserve_cursor` so backpressure never creates holes or overruns `TDT`.
 */
__device__ __forceinline__ bool device_is_nic_tx_slot_available(
    const void* dev_tx_desc_ring,
    uint32_t desc_idx,
    NicHardwareDriverType nic_type,
    uint32_t flags) {
  if (!dev_tx_desc_ring) {
    return false;
  }
  const bool auto_reap = (flags & kDoorbellFlagAutoReapOnWrap) != 0u;
  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169: {
      const auto* ring = static_cast<const volatile Rtl8169TxDesc*>(dev_tx_desc_ring);
      return ((ring[desc_idx].opts1 & kRtlDescOwn) == 0u) || auto_reap;
    }
    case NicHardwareDriverType::kIntelE1000e: {
      const auto* ring = static_cast<const volatile E1000eTxDesc*>(dev_tx_desc_ring);
      const volatile E1000eTxDesc& d = ring[desc_idx];
      return (d.lower.data == 0u) || ((d.upper.data & kE1000TxdStatDd) != 0u) || auto_reap;
    }
    case NicHardwareDriverType::kIntelIxgbe: {
      const auto* ring = static_cast<const volatile IxgbeAdvTxDesc*>(dev_tx_desc_ring);
      const volatile IxgbeAdvTxDesc& d = ring[desc_idx];
      return (d.read.cmd_type_len == 0u) || ((d.wb.status & kIxgbeTxdStatDd) != 0u) || auto_reap;
    }
    case NicHardwareDriverType::kIntelI40e: {
      const auto* ring = static_cast<const volatile I40eTxDesc*>(dev_tx_desc_ring);
      const volatile I40eTxDesc& d = ring[desc_idx];
      return (d.buffer_addr == 0ULL && d.cmd_type_offset_bsz == 0ULL) ||
             ((d.cmd_type_offset_bsz & kI40eTxDescDtypeMask) == kI40eTxDescDtypeDone) ||
             auto_reap;
    }
    case NicHardwareDriverType::kMellanoxMlx5: {
      const auto* ring = static_cast<const volatile Mlx5TxWqe*>(dev_tx_desc_ring);
      const volatile Mlx5TxWqe& wqe = ring[desc_idx];
      return (wqe.data.addr == 0ULL) || (wqe.ctrl.signature == 0xFFu) || auto_reap;
    }
  }
  return false;
}

__device__ __forceinline__ uint32_t device_p2p_published_seq_tag(uint32_t seq) {
  const uint32_t tag = seq + 1u;
  return (tag == 0u) ? 1u : tag;
}

__device__ __forceinline__ uint32_t* device_p2p_published_slot_ptr(
    GeforceP2pGpuDeviceTxq* txq,
    uint32_t desc_idx) {
  if (txq->dev_slot_published_seq != nullptr) {
    return &txq->dev_slot_published_seq[desc_idx];
  }
  if (desc_idx < 4096u) {
    return &txq->inline_slot_published_seq[desc_idx];
  }
  return nullptr;
}

/**
 * @brief Writes a single hardware TX descriptor directly from a CUDA thread.
 * @return true if descriptor was written, false if ring slot is still owned by NIC hardware.
 */
__device__ __forceinline__ bool device_write_nic_tx_descriptor(
    void* dev_tx_desc_ring,
    uint32_t desc_idx,
    uint32_t ring_size,
    uint64_t bar1_slot_iova,
    uint16_t pkt_len,
    NicHardwareDriverType nic_type,
    uint32_t producer_seq,
    uint32_t mlx5_qpn,
    uint32_t mlx5_lkey) {
  if (!dev_tx_desc_ring || pkt_len == 0u || ring_size == 0u) {
    return false;
  }
  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169: {
      auto* ring = static_cast<volatile Rtl8169TxDesc*>(dev_tx_desc_ring);
      volatile Rtl8169TxDesc& desc = ring[desc_idx];
      if ((desc.opts1 & kRtlDescOwn) != 0u) {
        return false;  // NIC hardware still owns this descriptor (backpressure)
      }
      desc.addr  = bar1_slot_iova;
      desc.opts2 = 0u;
      // Ensure 64-bit BAR1 address is visible before handing ownership (DescOwn) to NIC
      __threadfence_system();
      uint32_t opts1 = kRtlFirstFrag | kRtlLastFrag | (static_cast<uint32_t>(pkt_len) & kRtlPktLenMask);
      if (desc_idx == (ring_size - 1u)) {
        opts1 |= kRtlRingEnd;
      }
      desc.opts1 = opts1 | kRtlDescOwn;
      return true;
    }

    case NicHardwareDriverType::kIntelE1000e: {
      auto* ring = static_cast<volatile E1000eTxDesc*>(dev_tx_desc_ring);
      volatile E1000eTxDesc& desc = ring[desc_idx];
      const uint32_t prev_lower = desc.lower.data;
      const uint32_t prev_upper = desc.upper.data;
      if (prev_lower != 0u && ((prev_upper & kE1000TxdStatDd) == 0u)) {
        return false;  // Previous packet not yet completed by Intel e1000e DMA engine
      }
      desc.buffer_addr = bar1_slot_iova;
      desc.upper.data  = 0u;
      // Ensure 64-bit BAR1 address is visible before publishing command/length to NIC DMA
      __threadfence_system();
      const uint32_t cmd = static_cast<uint32_t>(kE1000TxdCmdEop | kE1000TxdCmdIfcs | kE1000TxdCmdRs);
      desc.lower.data  = static_cast<uint32_t>(pkt_len) | (cmd << 24);
      return true;
    }

    case NicHardwareDriverType::kIntelIxgbe: {
      auto* ring = static_cast<volatile IxgbeAdvTxDesc*>(dev_tx_desc_ring);
      volatile IxgbeAdvTxDesc& desc = ring[desc_idx];
      if (desc.read.cmd_type_len != 0u && ((desc.wb.status & kIxgbeTxdStatDd) == 0u)) {
        return false;  // Previous packet not yet completed by Intel ixgbe DMA engine
      }
      desc.read.buffer_addr   = bar1_slot_iova;
      desc.read.olinfo_status = static_cast<uint32_t>(pkt_len) << kIxgbeAdvTxdPaylenShift;
      __threadfence_system();
      desc.read.cmd_type_len  = kIxgbeAdvTxdDtypData |
                                kIxgbeAdvTxdDcmdDext |
                                kIxgbeAdvTxdDcmdEop  |
                                kIxgbeAdvTxdDcmdIfcs |
                                kIxgbeAdvTxdDcmdRs   |
                                static_cast<uint32_t>(pkt_len);
      return true;
    }

    case NicHardwareDriverType::kIntelI40e: {
      auto* ring = static_cast<volatile I40eTxDesc*>(dev_tx_desc_ring);
      volatile I40eTxDesc& desc = ring[desc_idx];
      if ((desc.buffer_addr != 0ULL || desc.cmd_type_offset_bsz != 0ULL) &&
          ((desc.cmd_type_offset_bsz & kI40eTxDescDtypeMask) != kI40eTxDescDtypeDone)) {
        return false;  // Previous packet not yet completed by Intel i40e DMA engine
      }
      const uint64_t cmd = kI40eTxDescDtypeData |
                           kI40eTxDescCmdEop    |
                           kI40eTxDescCmdRs     |
                           kI40eTxDescCmdIcrc;
      const uint64_t bsz = (static_cast<uint64_t>(pkt_len) & 0x3FFFULL) << 34;
      desc.buffer_addr = bar1_slot_iova;
      __threadfence_system();
      desc.cmd_type_offset_bsz = cmd | bsz;
      return true;
    }

    case NicHardwareDriverType::kMellanoxMlx5: {
      auto* ring = static_cast<volatile Mlx5TxWqe*>(dev_tx_desc_ring);
      volatile Mlx5TxWqe& wqe = ring[desc_idx];
      if (wqe.data.addr != 0ULL && wqe.ctrl.signature != 0xFFu) {
        return false;  // Previous WQE not yet completed
      }
      const uint32_t opmod_idx_opcode = kMlx5OpcodeSend | ((producer_seq & 0xFFFFu) << 8);
      const uint32_t qpn_ds = (mlx5_qpn << 8) | 4u;
      wqe.ctrl.signature        = 0u;
      wqe.ctrl.fm_ce_se         = 0u;
      wqe.ctrl.imm              = 0u;
      wqe.eth.cs_flags          = kMlx5EthWqeL3Csum | kMlx5EthWqeL4Csum;
      wqe.eth.inline_hdr_sz     = 0u;
      wqe.data.byte_count       = bswap32_dev(static_cast<uint32_t>(pkt_len));
      wqe.data.lkey             = bswap32_dev(mlx5_lkey);
      wqe.data.addr             = bswap64_dev(bar1_slot_iova);
      __threadfence_system();
      wqe.ctrl.qpn_ds           = bswap32_dev(qpn_ds);
      wqe.ctrl.opmod_idx_opcode = bswap32_dev(opmod_idx_opcode);
      return true;
    }
  }
  return false;
}

/**
 * @brief Rings the NIC hardware MMIO Doorbell directly from the GPU (single elected thread).
 * Emits a Posted PCIe Memory Write (MWr) TLP from GPU across Root Complex to NIC BAR.
 */
__device__ __forceinline__ void device_ring_nic_doorbell(
    volatile uint8_t* dev_nic_mmio_base,
    NicHardwareDriverType nic_type,
    uint32_t queue_id,
    uint32_t new_tail_idx,
    uint32_t producer_seq,
    uint32_t mlx5_qpn,
    uint32_t custom_doorbell_offset) {
  if (!dev_nic_mmio_base) {
    return;
  }
  // System-wide PCIe memory fence: guarantee all BAR1 payloads and TX descriptors
  // are visible to the Root Complex and NIC DMA engine before the Doorbell MWr TLP arrives.
  __threadfence_system();

  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169: {
      const uint32_t off = (custom_doorbell_offset != 0u) ? custom_doorbell_offset : kRtlRegTpPoll;
      *(volatile uint8_t*)(dev_nic_mmio_base + off) = kRtlTpPollNpq;
      break;
    }
    case NicHardwareDriverType::kIntelE1000e: {
      const uint32_t off = (custom_doorbell_offset != 0u) ? custom_doorbell_offset : kE1000RegTdt;
      *(volatile uint32_t*)(dev_nic_mmio_base + off) = new_tail_idx;
      break;
    }
    case NicHardwareDriverType::kIntelIxgbe: {
      const uint32_t off = (custom_doorbell_offset != 0u) ? custom_doorbell_offset : ixgbe_reg_tdt(queue_id);
      *(volatile uint32_t*)(dev_nic_mmio_base + off) = new_tail_idx;
      break;
    }
    case NicHardwareDriverType::kIntelI40e: {
      const uint32_t off = (custom_doorbell_offset != 0u) ? custom_doorbell_offset : i40e_reg_qtx_tail(queue_id);
      *(volatile uint32_t*)(dev_nic_mmio_base + off) = new_tail_idx;
      break;
    }
    case NicHardwareDriverType::kMellanoxMlx5: {
      const uint32_t off = (custom_doorbell_offset != 0u) ? custom_doorbell_offset : kMlx5DefaultBfOff;
      const uint64_t db_val = (static_cast<uint64_t>(mlx5_qpn) << 32) |
                              static_cast<uint64_t>(producer_seq & 0xFFFFu);
      *(volatile uint64_t*)(dev_nic_mmio_base + off) = db_val;
      break;
    }
  }
  __threadfence_system();
}

__device__ __forceinline__ bool device_is_valid_nic_driver_type(NicHardwareDriverType nic_type) {
  switch (nic_type) {
    case NicHardwareDriverType::kRealtekR8169:
    case NicHardwareDriverType::kIntelE1000e:
    case NicHardwareDriverType::kIntelIxgbe:
    case NicHardwareDriverType::kIntelI40e:
    case NicHardwareDriverType::kMellanoxMlx5:
      return true;
  }
  return false;
}

/**
 * @brief Persistent Kernel Direct Enqueue Hook for Consumer GeForce BAR1 GPU-PMD.
 * Called per-lane inside `persistent_dataplane_kernel` without any CPU bridge thread.
 */
__device__ __forceinline__ bool device_p2p_txq_try_enqueue(
    GeforceP2pGpuDeviceTxq* txq,
    const uint8_t* packet_ptr,
    uint32_t packet_len) {
  if (!txq || txq->magic != kGeforceP2pDeviceTxqMagic || !txq->dev_tx_desc_ring ||
      !packet_ptr || packet_len == 0u || txq->tx_ring_size < 2u) {
    return false;
  }

  const auto nic_type = static_cast<NicHardwareDriverType>(txq->nic_driver_type);
  if (!device_is_valid_nic_driver_type(nic_type)) {
    atomicAdd(&txq->backpressure_drops, 1ULL);
    return false;
  }

  const uint32_t max_usable = txq->tx_ring_size - 1u;
  uint32_t seq = 0u;
  uint32_t desc_idx = 0u;

  while (true) {
    const uint32_t cur = atomicAdd(&txq->reserve_cursor, 0u);
    const uint32_t pub_floor = atomicAdd(&txq->published_cursor, 0u);
    if ((cur - pub_floor) >= max_usable) {
      atomicAdd(&txq->backpressure_drops, 1ULL);
      return false;
    }
    const uint32_t cand_idx = cur & txq->tx_ring_mask;
    if (!device_is_nic_tx_slot_available(txq->dev_tx_desc_ring, cand_idx, nic_type, txq->flags)) {
      atomicAdd(&txq->backpressure_drops, 1ULL);
      return false;
    }
    if (atomicCAS(&txq->reserve_cursor, cur, cur + 1u) == cur) {
      seq = cur;
      desc_idx = cand_idx;
      break;
    }
  }

  if (device_reap_nic_tx_descriptor(
          txq->dev_tx_desc_ring, desc_idx, txq->tx_ring_size, nic_type, txq->flags)) {
    atomicAdd(&txq->reaped_completions, 1ULL);
  }

  const uint64_t pkt_va = reinterpret_cast<uint64_t>(packet_ptr);
  uint64_t offset = 0u;
  if (txq->bar1_dev_base != 0u && pkt_va >= txq->bar1_dev_base &&
      pkt_va < (txq->bar1_dev_base + txq->arena_bytes)) {
    offset = pkt_va - txq->bar1_dev_base;
  } else if (txq->bar1_host_base != 0u && pkt_va >= txq->bar1_host_base &&
             pkt_va < (txq->bar1_host_base + txq->arena_bytes)) {
    offset = pkt_va - txq->bar1_host_base;
  } else if (txq->arena_bytes > 0u) {
    const uint64_t stride = (txq->slot_stride > 0u) ? txq->slot_stride : 2048ULL;
    offset = (static_cast<uint64_t>(seq) * stride) % txq->arena_bytes;
  }
  const uint64_t slot_iova = txq->bar1_iova_base + offset;
  const uint16_t clamped_len =
      (packet_len > 0xFFFFu) ? static_cast<uint16_t>(0xFFFFu) : static_cast<uint16_t>(packet_len);

  const bool ok = device_write_nic_tx_descriptor(
      txq->dev_tx_desc_ring,
      desc_idx,
      txq->tx_ring_size,
      slot_iova,
      clamped_len,
      nic_type,
      seq,
      txq->mlx5_qpn,
      txq->mlx5_lkey);

  if (!ok) {
    atomicAdd(&txq->backpressure_drops, 1ULL);
    return false;
  }

  __threadfence_system();
  if (uint32_t* pub_slot = device_p2p_published_slot_ptr(txq, desc_idx)) {
    atomicExch(pub_slot, device_p2p_published_seq_tag(seq));
  }

  atomicAdd(&txq->descriptors_written, 1ULL);
  atomicAdd(&txq->tx_bytes, static_cast<unsigned long long>(clamped_len));
  return true;
}

/**
 * @brief Persistent Kernel Direct Commit & Doorbell Push Hook for Consumer GeForce BAR1 GPU-PMD.
 * Advances `published_cursor` strictly across contiguous completed descriptor writes so out-of-order
 * warps never kick NIC `TDT` past an unwritten descriptor. Returns true both when this warp rings
 * the doorbell and when doorbell ringing was safely coalesced or deferred to an earlier in-flight warp.
 */
__device__ __forceinline__ bool device_p2p_txq_try_commit_push(GeforceP2pGpuDeviceTxq* txq) {
  if (!txq || txq->magic != kGeforceP2pDeviceTxqMagic || !txq->dev_nic_mmio_base ||
      txq->tx_ring_size < 2u) {
    return false;
  }

  uint32_t pub = atomicAdd(&txq->published_cursor, 0u);
  while (true) {
    const uint32_t idx = pub & txq->tx_ring_mask;
    uint32_t* pub_slot = device_p2p_published_slot_ptr(txq, idx);
    if (!pub_slot) {
      pub = atomicAdd(&txq->reserve_cursor, 0u);
      break;
    }
    const uint32_t have_tag = atomicAdd(pub_slot, 0u);
    if (have_tag != device_p2p_published_seq_tag(pub)) {
      break;
    }
    const uint32_t prev = atomicCAS(&txq->published_cursor, pub, pub + 1u);
    if (prev == pub) {
      pub += 1u;
    } else {
      pub = prev;
    }
  }

  const uint32_t new_tail = pub & txq->tx_ring_mask;
  atomicExch(&txq->commit_tail, new_tail);

  uint32_t prev_pushed = atomicAdd(&txq->last_pushed_seq, 0u);
  while (static_cast<int32_t>(pub - prev_pushed) > 0) {
    const uint32_t seen = atomicCAS(&txq->last_pushed_seq, prev_pushed, pub);
    if (seen == prev_pushed) {
      const auto nic_type = static_cast<NicHardwareDriverType>(txq->nic_driver_type);
      device_ring_nic_doorbell(
          txq->dev_nic_mmio_base,
          nic_type,
          txq->queue_id,
          new_tail,
          pub,
          txq->mlx5_qpn,
          txq->doorbell_reg_offset);
      atomicExch(&txq->last_pushed_tail, new_tail);
      atomicAdd(&txq->doorbell_kicks, 1ULL);
      return true;
    }
    prev_pushed = seen;
  }
  return true;
}

/**
 * @brief CUDA kernel that reaps completed descriptors, populates NIC hardware TX descriptors
 *        for an arbitrary-length batch of BAR1 slots, and rings the NIC MMIO Doorbell once.
 *        Uses two-phase availability check per chunk so descriptors past a busy ring entry are
 *        never prematurely written, and enforces `usable_ring_cap = desc_ring_size - 1` (`TDT != TDH`).
 */
__global__ void geforce_p2p_gpu_doorbell_tx_burst_kernel(
    uint64_t bar1_iova_base,
    uint32_t slot_stride,
    const uint32_t* __restrict__ slot_indices,
    const uint16_t* __restrict__ pkt_lengths,
    uint32_t count,
    void* dev_tx_desc_ring,
    uint32_t desc_ring_size,
    uint32_t start_tx_head,
    uint32_t start_producer_seq,
    volatile uint8_t* dev_nic_mmio_base,
    uint32_t nic_driver_type_raw,
    uint32_t queue_id,
    uint32_t mlx5_qpn,
    uint32_t mlx5_lkey,
    uint32_t custom_doorbell_offset,
    uint32_t doorbell_flags,
    uint32_t* out_submitted_count,
    uint32_t* out_backpressure_drops,
    uint32_t* out_doorbell_kicks,
    uint32_t* out_reaped_completions) {
  __shared__ uint32_t s_slot_avail[256];
  __shared__ uint32_t s_slot_ok[256];
  __shared__ uint32_t s_slot_reaped[256];
  __shared__ uint32_t s_chunk_valid_n;
  __shared__ uint32_t s_contiguous_ok;
  __shared__ uint32_t s_total_reaped;
  __shared__ uint32_t s_stop;

  const uint32_t tid = threadIdx.x;
  const auto nic_type = static_cast<NicHardwareDriverType>(nic_driver_type_raw);
  const uint32_t usable_ring_cap = (desc_ring_size > 1u) ? (desc_ring_size - 1u) : 0u;
  const uint32_t ring_mask = (desc_ring_size > 0u) ? (desc_ring_size - 1u) : 0u;
  const bool valid_cfg = (dev_tx_desc_ring != nullptr) &&
                         (slot_indices != nullptr) &&
                         (pkt_lengths != nullptr) &&
                         (usable_ring_cap > 0u) &&
                         device_is_valid_nic_driver_type(nic_type);

  if (tid == 0u) {
    s_chunk_valid_n = 0u;
    s_contiguous_ok = 0u;
    s_total_reaped = 0u;
    s_stop = valid_cfg ? 0u : 1u;
  }
  __syncthreads();

  for (uint32_t base = 0u; s_stop == 0u && base < count && base < usable_ring_cap; base += 256u) {
    const uint32_t rem = count - base;
    const uint32_t max_rem = usable_ring_cap - base;
    const uint32_t eff_rem = (rem < max_rem) ? rem : max_rem;
    const uint32_t chunk_n = (eff_rem <= 256u) ? eff_rem : 256u;

    // Phase 1: Non-destructive contiguous slot availability check
    if (tid < chunk_n) {
      const uint32_t idx = base + tid;
      const uint16_t pkt_len = pkt_lengths[idx];
      const uint32_t desc_idx = (start_tx_head + idx) & ring_mask;
      const bool avail = (pkt_len > 0u) &&
          device_is_nic_tx_slot_available(dev_tx_desc_ring, desc_idx, nic_type, doorbell_flags);
      s_slot_avail[tid] = avail ? 1u : 0u;
    } else if (tid < 256u) {
      s_slot_avail[tid] = 0u;
    }
    __syncthreads();

    if (tid == 0u) {
      uint32_t valid_n = 0u;
      for (uint32_t i = 0u; i < chunk_n; ++i) {
        if (s_slot_avail[i] == 0u) {
          s_stop = 1u;
          break;
        }
        valid_n += 1u;
      }
      s_chunk_valid_n = valid_n;
    }
    __syncthreads();

    // Phase 2: Write descriptors strictly within the verified contiguous prefix [0, s_chunk_valid_n)
    const uint32_t valid_n = s_chunk_valid_n;
    if (tid < valid_n) {
      const uint32_t idx = base + tid;
      const uint32_t bar1_slot = slot_indices[idx];
      const uint16_t pkt_len = pkt_lengths[idx];
      const uint64_t slot_iova = bar1_iova_base + static_cast<uint64_t>(bar1_slot) * slot_stride;
      const uint32_t desc_idx = (start_tx_head + idx) & ring_mask;
      const uint32_t prod_seq = start_producer_seq + idx;

      const bool reaped = device_reap_nic_tx_descriptor(
          dev_tx_desc_ring, desc_idx, desc_ring_size, nic_type, doorbell_flags);
      s_slot_reaped[tid] = reaped ? 1u : 0u;

      const bool ok = device_write_nic_tx_descriptor(
          dev_tx_desc_ring,
          desc_idx,
          desc_ring_size,
          slot_iova,
          pkt_len,
          nic_type,
          prod_seq,
          mlx5_qpn,
          mlx5_lkey);
      s_slot_ok[tid] = ok ? 1u : 0u;
    } else if (tid < 256u) {
      s_slot_ok[tid] = 0u;
      s_slot_reaped[tid] = 0u;
    }

    __syncthreads();

    if (tid == 0u) {
      for (uint32_t i = 0u; i < valid_n; ++i) {
        if (s_slot_ok[i] == 0u) {
          s_stop = 1u;
          break;
        }
        s_contiguous_ok += 1u;
        s_total_reaped += s_slot_reaped[i];
      }
    }
    __syncthreads();
    if (s_stop != 0u) {
      break;
    }
  }

  if (tid == 0u) {
    const uint32_t contiguous_ok = s_contiguous_ok;
    const uint32_t total_reaped = s_total_reaped;
    const uint32_t drops = count - contiguous_ok;
    if (out_submitted_count) {
      *out_submitted_count = contiguous_ok;
    }
    if (out_backpressure_drops && drops > 0u) {
      atomicAdd(out_backpressure_drops, drops);
    }
    if (out_reaped_completions && total_reaped > 0u) {
      atomicAdd(out_reaped_completions, total_reaped);
    }
    if (contiguous_ok > 0u && dev_nic_mmio_base != nullptr) {
      const uint32_t new_tail = (start_tx_head + contiguous_ok) & ring_mask;
      const uint32_t new_prod_seq = start_producer_seq + contiguous_ok;
      device_ring_nic_doorbell(
          dev_nic_mmio_base,
          nic_type,
          queue_id,
          new_tail,
          new_prod_seq,
          mlx5_qpn,
          custom_doorbell_offset);
      if (out_doorbell_kicks) {
        atomicAdd(out_doorbell_kicks, 1u);
      }
    }
  }
}

#endif  // defined(__CUDACC__)

}  // namespace ddos_samurai::gpu_packet_cuda::p2p::doorbell
