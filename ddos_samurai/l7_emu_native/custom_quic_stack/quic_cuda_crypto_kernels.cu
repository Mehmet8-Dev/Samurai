#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>
#include <mutex>

#include "quic_crypto_primitives.cuh"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

__global__ void k_derive_quic_initial_keys_batch(
    const uint8_t* __restrict__ dcids_8b,
    const uint8_t* __restrict__ scids_8b,
    std::size_t count,
    QuicInitialKeyMaterial* __restrict__ out_materials) {
  const std::size_t idx = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }
  const uint8_t* dcid = dcids_8b + idx * 8u;
  const uint8_t* scid = (scids_8b != nullptr) ? (scids_8b + idx * 8u) : nullptr;
  primitives::derive_quic_v1_initial_keys_8b(dcid, scid, &out_materials[idx]);
}

__global__ void k_aes128_hp_mask_batch(
    const uint8_t* __restrict__ hp_keys_16b,
    const uint8_t* __restrict__ samples_16b,
    std::size_t count,
    uint8_t* __restrict__ masks_5b_out) {
  const std::size_t idx = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }
  uint8_t rk[176];
  primitives::aes128_expand_key(hp_keys_16b + idx * 16u, rk);
  uint8_t out_block[16];
  primitives::aes128_encrypt_block(rk, samples_16b + idx * 16u, out_block);
  uint8_t* dst = masks_5b_out + idx * 5u;
  for (int i = 0; i < 5; ++i) {
    dst[i] = out_block[i];
  }
}

__global__ void k_chacha20_poly1305_encrypt_batch(
    QuicAeadBatchItem* __restrict__ items,
    uint8_t* __restrict__ packet_buffers,
    std::size_t packet_stride,
    std::size_t count) {
  const std::size_t idx = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }
  primitives::quic_chacha20_poly1305_encrypt_and_hp(
      &items[idx],
      packet_buffers + idx * packet_stride);
}

__global__ void k_aes128_gcm_encrypt_batch(
    QuicAeadBatchItem* __restrict__ items,
    uint8_t* __restrict__ packet_buffers,
    std::size_t packet_stride,
    std::size_t count) {
  const std::size_t idx = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }
  primitives::quic_aes128_gcm_encrypt_and_hp(
      &items[idx],
      packet_buffers + idx * packet_stride);
}

struct PersistentQuicCudaWorkspace {
  std::mutex mtx;
  bool initialized{false};
  bool available{false};
  int device_id{-1};
  cudaStream_t stream{nullptr};

  uint8_t* d_dcids{nullptr};
  uint8_t* d_scids{nullptr};
  QuicInitialKeyMaterial* d_materials{nullptr};
  std::size_t key_cap{0};

  uint8_t* d_hp_keys{nullptr};
  uint8_t* d_samples{nullptr};
  uint8_t* d_masks{nullptr};
  std::size_t hp_cap{0};

  QuicAeadBatchItem* d_items{nullptr};
  uint8_t* d_pkt_bufs{nullptr};
  std::size_t aead_item_cap{0};
  std::size_t aead_buf_cap{0};

  void init_once() {
    if (initialized) {
      return;
    }
    initialized = true;
    int dev_count = 0;
    if (cudaGetDeviceCount(&dev_count) != cudaSuccess || dev_count <= 0) {
      available = false;
      return;
    }
    if (cudaSetDevice(0) != cudaSuccess) {
      available = false;
      return;
    }
    if (cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking) != cudaSuccess) {
      available = false;
      return;
    }
    device_id = 0;
    available = true;
  }

  bool ensure_key_cap(std::size_t count) {
    if (count <= key_cap) {
      return true;
    }
    const std::size_t new_cap = (count < 4096u) ? 4096u : count;
    if (d_dcids) cudaFree(d_dcids);
    if (d_scids) cudaFree(d_scids);
    if (d_materials) cudaFree(d_materials);
    d_dcids = nullptr;
    d_scids = nullptr;
    d_materials = nullptr;
    if (cudaMalloc(&d_dcids, new_cap * 8u) != cudaSuccess ||
        cudaMalloc(&d_scids, new_cap * 8u) != cudaSuccess ||
        cudaMalloc(&d_materials, new_cap * sizeof(QuicInitialKeyMaterial)) != cudaSuccess) {
      key_cap = 0;
      return false;
    }
    key_cap = new_cap;
    return true;
  }

  bool ensure_hp_cap(std::size_t count) {
    if (count <= hp_cap) {
      return true;
    }
    const std::size_t new_cap = (count < 4096u) ? 4096u : count;
    if (d_hp_keys) cudaFree(d_hp_keys);
    if (d_samples) cudaFree(d_samples);
    if (d_masks) cudaFree(d_masks);
    d_hp_keys = nullptr;
    d_samples = nullptr;
    d_masks = nullptr;
    if (cudaMalloc(&d_hp_keys, new_cap * 16u) != cudaSuccess ||
        cudaMalloc(&d_samples, new_cap * 16u) != cudaSuccess ||
        cudaMalloc(&d_masks, new_cap * 5u) != cudaSuccess) {
      hp_cap = 0;
      return false;
    }
    hp_cap = new_cap;
    return true;
  }

  bool ensure_aead_cap(std::size_t count, std::size_t total_buf_bytes) {
    if (count > aead_item_cap) {
      const std::size_t new_cap = (count < 1024u) ? 1024u : count;
      if (d_items) cudaFree(d_items);
      d_items = nullptr;
      if (cudaMalloc(&d_items, new_cap * sizeof(QuicAeadBatchItem)) != cudaSuccess) {
        aead_item_cap = 0;
        return false;
      }
      aead_item_cap = new_cap;
    }
    if (total_buf_bytes > aead_buf_cap) {
      const std::size_t new_bcap = (total_buf_bytes < (2u << 20)) ? (2u << 20) : total_buf_bytes;
      if (d_pkt_bufs) cudaFree(d_pkt_bufs);
      d_pkt_bufs = nullptr;
      if (cudaMalloc(&d_pkt_bufs, new_bcap) != cudaSuccess) {
        aead_buf_cap = 0;
        return false;
      }
      aead_buf_cap = new_bcap;
    }
    return true;
  }
};

PersistentQuicCudaWorkspace& ws() {
  static PersistentQuicCudaWorkspace instance;
  return instance;
}

}  // namespace

extern "C" bool samurai_quic_cuda_probe_device(int* device_id_out) {
  auto& w = ws();
  std::lock_guard<std::mutex> lock(w.mtx);
  w.init_once();
  if (device_id_out != nullptr) {
    *device_id_out = w.device_id;
  }
  return w.available;
}

extern "C" bool samurai_quic_cuda_derive_initial_keys(
    const uint8_t* dcids_8b,
    const uint8_t* scids_8b,
    std::size_t count,
    QuicInitialKeyMaterial* out_materials) {
  if (dcids_8b == nullptr || out_materials == nullptr || count == 0) {
    return false;
  }
  auto& w = ws();
  std::lock_guard<std::mutex> lock(w.mtx);
  w.init_once();
  if (!w.available || !w.ensure_key_cap(count)) {
    return false;
  }
  if (cudaMemcpyAsync(w.d_dcids, dcids_8b, count * 8u, cudaMemcpyHostToDevice, w.stream) != cudaSuccess) {
    return false;
  }
  if (scids_8b != nullptr) {
    if (cudaMemcpyAsync(w.d_scids, scids_8b, count * 8u, cudaMemcpyHostToDevice, w.stream) != cudaSuccess) {
      return false;
    }
  } else {
    if (cudaMemsetAsync(w.d_scids, 0, count * 8u, w.stream) != cudaSuccess) {
      return false;
    }
  }

  const unsigned int threads = 128u;
  const unsigned int blocks = static_cast<unsigned int>((count + threads - 1u) / threads);
  k_derive_quic_initial_keys_batch<<<blocks, threads, 0, w.stream>>>(
      w.d_dcids, w.d_scids, count, w.d_materials);

  if (cudaMemcpyAsync(
          out_materials,
          w.d_materials,
          count * sizeof(QuicInitialKeyMaterial),
          cudaMemcpyDeviceToHost,
          w.stream) != cudaSuccess) {
    return false;
  }
  return cudaStreamSynchronize(w.stream) == cudaSuccess;
}

extern "C" bool samurai_quic_cuda_aes128_hp_mask(
    const uint8_t* hp_keys_16b,
    const uint8_t* samples_16b,
    std::size_t count,
    uint8_t* masks_5b_out) {
  if (hp_keys_16b == nullptr || samples_16b == nullptr || masks_5b_out == nullptr || count == 0) {
    return false;
  }
  auto& w = ws();
  std::lock_guard<std::mutex> lock(w.mtx);
  w.init_once();
  if (!w.available || !w.ensure_hp_cap(count)) {
    return false;
  }
  if (cudaMemcpyAsync(w.d_hp_keys, hp_keys_16b, count * 16u, cudaMemcpyHostToDevice, w.stream) != cudaSuccess ||
      cudaMemcpyAsync(w.d_samples, samples_16b, count * 16u, cudaMemcpyHostToDevice, w.stream) != cudaSuccess) {
    return false;
  }

  const unsigned int threads = 128u;
  const unsigned int blocks = static_cast<unsigned int>((count + threads - 1u) / threads);
  k_aes128_hp_mask_batch<<<blocks, threads, 0, w.stream>>>(
      w.d_hp_keys, w.d_samples, count, w.d_masks);

  if (cudaMemcpyAsync(masks_5b_out, w.d_masks, count * 5u, cudaMemcpyDeviceToHost, w.stream) != cudaSuccess) {
    return false;
  }
  return cudaStreamSynchronize(w.stream) == cudaSuccess;
}

extern "C" bool samurai_quic_cuda_aead_encrypt(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    bool use_chacha20) {
  if (items == nullptr || packet_buffers == nullptr || packet_stride == 0 || count == 0) {
    return false;
  }
  const std::size_t total_bytes = count * packet_stride;
  auto& w = ws();
  std::lock_guard<std::mutex> lock(w.mtx);
  w.init_once();
  if (!w.available || !w.ensure_aead_cap(count, total_bytes)) {
    return false;
  }
  if (cudaMemcpyAsync(w.d_items, items, count * sizeof(QuicAeadBatchItem), cudaMemcpyHostToDevice, w.stream) != cudaSuccess ||
      cudaMemcpyAsync(w.d_pkt_bufs, packet_buffers, total_bytes, cudaMemcpyHostToDevice, w.stream) != cudaSuccess) {
    return false;
  }

  const unsigned int threads = 128u;
  const unsigned int blocks = static_cast<unsigned int>((count + threads - 1u) / threads);
  if (use_chacha20) {
    k_chacha20_poly1305_encrypt_batch<<<blocks, threads, 0, w.stream>>>(
        w.d_items, w.d_pkt_bufs, packet_stride, count);
  } else {
    k_aes128_gcm_encrypt_batch<<<blocks, threads, 0, w.stream>>>(
        w.d_items, w.d_pkt_bufs, packet_stride, count);
  }

  if (cudaMemcpyAsync(items, w.d_items, count * sizeof(QuicAeadBatchItem), cudaMemcpyDeviceToHost, w.stream) != cudaSuccess ||
      cudaMemcpyAsync(packet_buffers, w.d_pkt_bufs, total_bytes, cudaMemcpyDeviceToHost, w.stream) != cudaSuccess) {
    return false;
  }
  return cudaStreamSynchronize(w.stream) == cudaSuccess;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
