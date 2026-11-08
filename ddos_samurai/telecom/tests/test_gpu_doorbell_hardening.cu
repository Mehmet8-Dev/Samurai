#include <cuda_runtime.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ddos_samurai/gpu_packet_cuda/gpu_initiated_doorbell.cuh"

using namespace ddos_samurai::gpu_packet_cuda::p2p::doorbell;

namespace {

// Kernel 1: Multi-warp race & backpressure test on GeforceP2pGpuDeviceTxq.
// Warp 0 holds an occupied/uncompleted descriptor at slot 0 or delays writing while Warp 1 tries to commit.
__global__ void test_multiwarp_backpressure_kernel(
    GeforceP2pGpuDeviceTxq* txq,
    const uint8_t* dummy_pkt,
    uint32_t* out_ok_count) {
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < 64u) {
    if (device_p2p_txq_try_enqueue(txq, dummy_pkt, 128u)) {
      atomicAdd(out_ok_count, 1u);
    }
    __syncthreads();
    if ((threadIdx.x & 31u) == 0u) {
      device_p2p_txq_try_commit_push(txq);
    }
  }
}


void CheckCuda(cudaError_t err, const char* what) {
  if (err != cudaSuccess) {
    std::fprintf(stderr, "CUDA error in %s: %s\n", what, cudaGetErrorString(err));
    std::exit(2);
  }
}

// Test A: Burst kernel >256 packet support (512 descriptors in one launch).
void TestBurstKernelOver256() {
  constexpr uint32_t kRingSize = 1024u;
  constexpr uint32_t kBurstCount = 512u;

  E1000eTxDesc* h_ring = nullptr;
  E1000eTxDesc* d_ring = nullptr;
  uint8_t* h_mmio = nullptr;
  uint8_t* d_mmio = nullptr;
  CheckCuda(cudaHostAlloc(&h_ring, kRingSize * sizeof(E1000eTxDesc), cudaHostAllocMapped), "alloc ring");
  CheckCuda(cudaHostGetDevicePointer(&d_ring, h_ring, 0), "dev ring");
  std::memset(h_ring, 0, kRingSize * sizeof(E1000eTxDesc));

  CheckCuda(cudaHostAlloc(&h_mmio, 0x10000, cudaHostAllocMapped), "alloc mmio");
  CheckCuda(cudaHostGetDevicePointer(&d_mmio, h_mmio, 0), "dev mmio");
  std::memset(h_mmio, 0, 0x10000);

  std::vector<uint32_t> h_slots(kBurstCount);
  std::vector<uint16_t> h_lens(kBurstCount, 128u);
  for (uint32_t i = 0; i < kBurstCount; ++i) h_slots[i] = i;

  uint32_t* d_slots = nullptr;
  uint16_t* d_lens = nullptr;
  uint32_t* d_counters = nullptr;
  CheckCuda(cudaMalloc(&d_slots, kBurstCount * sizeof(uint32_t)), "d_slots");
  CheckCuda(cudaMalloc(&d_lens, kBurstCount * sizeof(uint16_t)), "d_lens");
  CheckCuda(cudaMalloc(&d_counters, 4 * sizeof(uint32_t)), "d_counters");
  CheckCuda(cudaMemset(d_counters, 0, 4 * sizeof(uint32_t)), "zero counters");
  CheckCuda(cudaMemcpy(d_slots, h_slots.data(), kBurstCount * sizeof(uint32_t), cudaMemcpyHostToDevice), "copy slots");
  CheckCuda(cudaMemcpy(d_lens, h_lens.data(), kBurstCount * sizeof(uint16_t), cudaMemcpyHostToDevice), "copy lens");

  geforce_p2p_gpu_doorbell_tx_burst_kernel<<<1, 256>>>(
      0x100000000ULL,
      2048u,
      d_slots,
      d_lens,
      kBurstCount,
      d_ring,
      kRingSize,
      0u,
      0u,
      d_mmio,
      static_cast<uint32_t>(NicHardwareDriverType::kIntelE1000e),
      0u,
      0u,
      0u,
      0u,
      0u,
      d_counters,
      d_counters + 1,
      d_counters + 2,
      d_counters + 3);
  CheckCuda(cudaDeviceSynchronize(), "sync burst >256");

  uint32_t h_counters[4]{};
  CheckCuda(cudaMemcpy(h_counters, d_counters, sizeof(h_counters), cudaMemcpyDeviceToHost), "read counters");
  const uint32_t mmio_tdt = *reinterpret_cast<volatile uint32_t*>(h_mmio + kE1000RegTdt);

  assert(h_counters[0] == kBurstCount && "Expected all 512 descriptors submitted in a single burst launch");
  assert(h_counters[1] == 0u && "Expected 0 backpressure drops");
  assert(h_counters[2] == 1u && "Expected exactly 1 batched MMIO doorbell kick");
  assert(mmio_tdt == kBurstCount && "Expected E1000e TDT == 512");

  cudaFree(d_slots);
  cudaFree(d_lens);
  cudaFree(d_counters);
  cudaFreeHost(h_ring);
  cudaFreeHost(h_mmio);
}

// Test B: Intel i40e backpressure when previous descriptor is still in-flight (DTYPE != 0xF).
void TestI40eInFlightBackpressure() {
  constexpr uint32_t kRingSize = 64u;
  I40eTxDesc* h_ring = nullptr;
  I40eTxDesc* d_ring = nullptr;
  uint8_t* h_mmio = nullptr;
  uint8_t* d_mmio = nullptr;
  CheckCuda(cudaHostAlloc(&h_ring, kRingSize * sizeof(I40eTxDesc), cudaHostAllocMapped), "alloc i40e ring");
  CheckCuda(cudaHostGetDevicePointer(&d_ring, h_ring, 0), "dev i40e ring");
  std::memset(h_ring, 0, kRingSize * sizeof(I40eTxDesc));

  // Slot 0 has an in-flight Data Descriptor (buffer_addr != 0, DTYPE == 0x0, NOT 0xF Done).
  h_ring[0].buffer_addr = 0xDEAD0000ULL;
  h_ring[0].cmd_type_offset_bsz = kI40eTxDescCmdEop | kI40eTxDescCmdRs | (128ULL << 34);

  CheckCuda(cudaHostAlloc(&h_mmio, 0x110000, cudaHostAllocMapped), "alloc i40e mmio");
  CheckCuda(cudaHostGetDevicePointer(&d_mmio, h_mmio, 0), "dev i40e mmio");
  std::memset(h_mmio, 0, 0x110000);

  uint32_t slot0 = 0u;
  uint16_t len0 = 128u;
  uint32_t* d_slots = nullptr;
  uint16_t* d_lens = nullptr;
  uint32_t* d_counters = nullptr;
  CheckCuda(cudaMalloc(&d_slots, sizeof(uint32_t)), "i40e d_slots");
  CheckCuda(cudaMalloc(&d_lens, sizeof(uint16_t)), "i40e d_lens");
  CheckCuda(cudaMalloc(&d_counters, 4 * sizeof(uint32_t)), "i40e d_counters");
  CheckCuda(cudaMemset(d_counters, 0, 4 * sizeof(uint32_t)), "i40e zero");
  CheckCuda(cudaMemcpy(d_slots, &slot0, sizeof(uint32_t), cudaMemcpyHostToDevice), "i40e slot");
  CheckCuda(cudaMemcpy(d_lens, &len0, sizeof(uint16_t), cudaMemcpyHostToDevice), "i40e len");

  geforce_p2p_gpu_doorbell_tx_burst_kernel<<<1, 256>>>(
      0x200000000ULL,
      2048u,
      d_slots,
      d_lens,
      1u,
      d_ring,
      kRingSize,
      0u,
      0u,
      d_mmio,
      static_cast<uint32_t>(NicHardwareDriverType::kIntelI40e),
      0u,
      0u,
      0u,
      0u,
      0u,  // auto_reap OFF -> must backpressure on uncompleted DTYPE != 0xF!
      d_counters,
      d_counters + 1,
      d_counters + 2,
      d_counters + 3);
  CheckCuda(cudaDeviceSynchronize(), "sync i40e backpressure");

  uint32_t h_counters[4]{};
  CheckCuda(cudaMemcpy(h_counters, d_counters, sizeof(h_counters), cudaMemcpyDeviceToHost), "i40e read");
  assert(h_counters[0] == 0u && "In-flight i40e descriptor (DTYPE != 0xF) must NOT be overwritten");
  assert(h_counters[1] == 1u && "Expected 1 backpressure drop on busy i40e descriptor");
  assert(h_ring[0].buffer_addr == 0xDEAD0000ULL && "Busy i40e descriptor address must remain intact");

  // Now simulate hardware completion (DTYPE = 0xF) and verify reap + overwrite succeeds!
  h_ring[0].cmd_type_offset_bsz = 0xFULL;
  CheckCuda(cudaMemset(d_counters, 0, 4 * sizeof(uint32_t)), "i40e reset");
  geforce_p2p_gpu_doorbell_tx_burst_kernel<<<1, 256>>>(
      0x200000000ULL,
      2048u,
      d_slots,
      d_lens,
      1u,
      d_ring,
      kRingSize,
      0u,
      0u,
      d_mmio,
      static_cast<uint32_t>(NicHardwareDriverType::kIntelI40e),
      0u,
      0u,
      0u,
      0u,
      0u,
      d_counters,
      d_counters + 1,
      d_counters + 2,
      d_counters + 3);
  CheckCuda(cudaDeviceSynchronize(), "sync i40e completed");
  CheckCuda(cudaMemcpy(h_counters, d_counters, sizeof(h_counters), cudaMemcpyDeviceToHost), "i40e read2");
  assert(h_counters[0] == 1u && "Completed i40e descriptor (DTYPE == 0xF) must be reaped and reused");
  assert(h_counters[3] == 1u && "Expected 1 reaped completion on i40e");

  cudaFree(d_slots);
  cudaFree(d_lens);
  cudaFree(d_counters);
  cudaFreeHost(h_ring);
  cudaFreeHost(h_mmio);
}

// Test C: Multi-warp backpressure must NOT advance reserve_cursor / doorbell TDT past busy descriptor!
void TestMultiWarpBackpressureCursorIntegrity() {
  constexpr uint32_t kRingSize = 64u;
  E1000eTxDesc* h_ring = nullptr;
  E1000eTxDesc* d_ring = nullptr;
  uint8_t* h_mmio = nullptr;
  uint8_t* d_mmio = nullptr;
  GeforceP2pGpuDeviceTxq* h_txq = nullptr;
  GeforceP2pGpuDeviceTxq* d_txq = nullptr;

  CheckCuda(cudaHostAlloc(&h_ring, kRingSize * sizeof(E1000eTxDesc), cudaHostAllocMapped), "alloc c ring");
  CheckCuda(cudaHostGetDevicePointer(&d_ring, h_ring, 0), "dev c ring");
  std::memset(h_ring, 0, kRingSize * sizeof(E1000eTxDesc));

  // Slots 0..7 are free, Slot 8 is busy (owned by NIC, DD == 0)!
  h_ring[8].buffer_addr = 0xBEEF0000ULL;
  h_ring[8].lower.data = 128u | (static_cast<uint32_t>(kE1000TxdCmdEop | kE1000TxdCmdRs) << 24);
  h_ring[8].upper.data = 0u;  // DD == 0 (busy!)

  CheckCuda(cudaHostAlloc(&h_mmio, 0x10000, cudaHostAllocMapped), "alloc c mmio");
  CheckCuda(cudaHostGetDevicePointer(&d_mmio, h_mmio, 0), "dev c mmio");
  std::memset(h_mmio, 0, 0x10000);

  CheckCuda(cudaHostAlloc(&h_txq, sizeof(GeforceP2pGpuDeviceTxq), cudaHostAllocMapped), "alloc txq");
  CheckCuda(cudaHostGetDevicePointer(&d_txq, h_txq, 0), "dev txq");
  std::memset(h_txq, 0, sizeof(GeforceP2pGpuDeviceTxq));

  uint8_t* d_dummy_pkt = nullptr;
  uint32_t* d_ok_count = nullptr;
  CheckCuda(cudaMalloc(&d_dummy_pkt, 64 * 2048u), "dummy pkt");
  CheckCuda(cudaMalloc(&d_ok_count, sizeof(uint32_t)), "ok count");
  CheckCuda(cudaMemset(d_ok_count, 0, sizeof(uint32_t)), "zero ok");

  h_txq->magic = kGeforceP2pDeviceTxqMagic;
  h_txq->dev_tx_desc_ring = d_ring;
  h_txq->dev_nic_mmio_base = d_mmio;
  h_txq->bar1_dev_base = reinterpret_cast<uint64_t>(d_dummy_pkt);
  h_txq->bar1_iova_base = 0x300000000ULL;
  h_txq->arena_bytes = 64 * 2048u;
  h_txq->tx_ring_size = kRingSize;
  h_txq->tx_ring_mask = kRingSize - 1u;
  h_txq->nic_driver_type = static_cast<uint32_t>(NicHardwareDriverType::kIntelE1000e);
  h_txq->slot_stride = 2048u;

  // Launch 64 threads (2 warps) trying to enqueue simultaneously when slot 8 is busy!
  test_multiwarp_backpressure_kernel<<<1, 64>>>(d_txq, d_dummy_pkt, d_ok_count);
  CheckCuda(cudaDeviceSynchronize(), "sync multiwarp");

  uint32_t h_ok = 0u;
  CheckCuda(cudaMemcpy(&h_ok, d_ok_count, sizeof(uint32_t), cudaMemcpyDeviceToHost), "read ok");
  const uint32_t mmio_tdt = *reinterpret_cast<volatile uint32_t*>(h_mmio + kE1000RegTdt);

  // Hardware invariant: ONLY slots 0..7 before busy slot 8 may be written and committed to TDT!
  // No thread may skip over busy slot 8 to write slots 9..63 or kick TDT past 8!
  assert(h_ok == 8u && "Exactly 8 descriptors before busy slot 8 must be written without ring holes");
  assert(mmio_tdt == 8u && "MMIO Doorbell TDT must stop cleanly at busy slot 8 (never overrun to 64)");
  assert(h_ring[9].buffer_addr == 0u && "Slot 9 after busy slot 8 must not have a ring hole write");

  cudaFree(d_dummy_pkt);
  cudaFree(d_ok_count);
  cudaFreeHost(h_txq);
  cudaFreeHost(h_ring);
  cudaFreeHost(h_mmio);
}

}  // namespace

int main() {
  int dev_count = 0;
  if (cudaGetDeviceCount(&dev_count) != cudaSuccess || dev_count <= 0) {
    std::printf("[SKIP] No CUDA GPU available.\n");
    return 0;
  }
  TestBurstKernelOver256();
  TestI40eInFlightBackpressure();
  TestMultiWarpBackpressureCursorIntegrity();
  std::printf("[PASS] test_gpu_doorbell_hardening: all 3 GPU-PMD hardware invariants verified.\n");
  return 0;
}
