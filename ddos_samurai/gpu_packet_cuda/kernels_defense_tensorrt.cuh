#pragma once

#include <cstddef>
#include <cstdint>

namespace ddos_samurai::gpu_packet_cuda::defense {

#if defined(SAMURAI_WITH_TENSORRT)
constexpr bool kTensorRtEnabled = true;
#else
constexpr bool kTensorRtEnabled = false;
#endif

inline int enqueue_inference_stub(const float* features, size_t batch, size_t feature_dim, int32_t* labels, float* confidences) {
  if (features == nullptr || labels == nullptr || confidences == nullptr) {
    return -1;
  }
  for (size_t i = 0; i < batch; ++i) {
    const float score = features[(i * feature_dim) + 0];
    labels[i] = (score > 0.2f) ? 1 : 0;
    confidences[i] = (score > 0.2f) ? 0.9f : 0.6f;
  }
  return 0;
}

}  // namespace ddos_samurai::gpu_packet_cuda::defense
