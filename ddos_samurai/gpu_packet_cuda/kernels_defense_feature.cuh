#pragma once

#include <cstddef>
#include <cstdint>
#include <cuda_runtime_api.h>

namespace ddos_samurai::gpu_packet_cuda::defense {

struct PacketView {
  const uint8_t* data = nullptr;
  size_t len = 0;
};

inline uint8_t packet_seed_byte(const uint8_t* data, size_t len) {
  if (data == nullptr || len == 0u) {
    return 0u;
  }
  cudaPointerAttributes attr{};
  const cudaError_t attr_rc = cudaPointerGetAttributes(&attr, data);
  if (attr_rc == cudaSuccess) {
#if CUDART_VERSION >= 10000
    const bool is_device_ptr = (attr.type == cudaMemoryTypeDevice || attr.type == cudaMemoryTypeManaged);
#else
    const bool is_device_ptr = (attr.memoryType == cudaMemoryTypeDevice);
#endif
    if (is_device_ptr) {
      uint8_t b = 0u;
      const cudaError_t cp_rc = cudaMemcpy(&b, data, sizeof(uint8_t), cudaMemcpyDeviceToHost);
      if (cp_rc == cudaSuccess) {
        return b;
      }
      (void)cudaGetLastError();
      return 0u;
    }
  } else {
    (void)cudaGetLastError();
  }
  return data[0];
}

// Deterministic placeholder extractor used by the isolated defense module.
inline void extract_features_stub(const PacketView* packets, size_t packet_count, float* out_features, size_t feature_dim) {
  if (packets == nullptr || out_features == nullptr || feature_dim == 0) {
    return;
  }
  for (size_t i = 0; i < packet_count; ++i) {
    const PacketView& p = packets[i];
    const float lenf = static_cast<float>(p.len);
    const float seed = static_cast<float>(packet_seed_byte(p.data, p.len));
    for (size_t j = 0; j < feature_dim; ++j) {
      out_features[(i * feature_dim) + j] = (lenf * 0.001f) + (seed * 0.0001f) + static_cast<float>(j) * 0.00001f;
    }
  }
}

}  // namespace ddos_samurai::gpu_packet_cuda::defense
