#pragma once

#include <cstddef>
#include <cstdint>

namespace ddos_samurai::gpu_packet_cuda::defense {

struct PacketView {
  const uint8_t* data = nullptr;
  size_t len = 0;
};

// Deterministic placeholder extractor used by the isolated defense module.
inline void extract_features_stub(const PacketView* packets, size_t packet_count, float* out_features, size_t feature_dim) {
  if (packets == nullptr || out_features == nullptr || feature_dim == 0) {
    return;
  }
  for (size_t i = 0; i < packet_count; ++i) {
    const PacketView& p = packets[i];
    const float lenf = static_cast<float>(p.len);
    const float seed = (p.len > 0 && p.data != nullptr) ? static_cast<float>(p.data[0]) : 0.0f;
    for (size_t j = 0; j < feature_dim; ++j) {
      out_features[(i * feature_dim) + j] = (lenf * 0.001f) + (seed * 0.0001f) + static_cast<float>(j) * 0.00001f;
    }
  }
}

}  // namespace ddos_samurai::gpu_packet_cuda::defense
