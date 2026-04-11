#include <cuda_runtime.h>

__constant__ unsigned int k_polymorphic_masks[8] = {
    0x00000001U, 0x00000003U, 0x00000007U, 0x0000000FU,
    0x0000001FU, 0x0000003FU, 0x0000007FU, 0x000000FFU,
};

__device__ __forceinline__ unsigned long long rotl64(unsigned long long x, int k) {
  return (x << k) | (x >> (64 - k));
}

__device__ __forceinline__ unsigned long long splitmix64_dev(unsigned long long& x) {
  x += 0x9E3779B97F4A7C15ULL;
  unsigned long long z = x;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

__device__ __forceinline__ unsigned int xoroshiro128p_next_u32(unsigned long long& s0, unsigned long long& s1) {
  const unsigned long long out = s0 + s1;
  unsigned long long x = s0;
  unsigned long long y = s1;
  y ^= x;
  s0 = rotl64(x, 55) ^ y ^ (y << 14);
  s1 = rotl64(y, 36);
  return static_cast<unsigned int>(out & 0xFFFFFFFFULL);
}

extern "C" __global__ void samurai_gpu_cuda_payload_planner_kernel(
    unsigned short* method_idx,
    unsigned short* path_idx,
    unsigned short* header_profile_idx,
    unsigned char* body_kind,
    unsigned char* step_id,
    unsigned short* think_time_ms,
    unsigned int* flags,
    unsigned int count,
    unsigned int max_steps,
    unsigned int method_count,
    unsigned int path_count,
    unsigned int header_count,
    unsigned int body_count,
    unsigned int seed) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) {
    return;
  }

  __shared__ unsigned long long s_s0[256];
  __shared__ unsigned long long s_s1[256];
  const unsigned int lane = threadIdx.x & 0xFFU;
  unsigned long long sm = (static_cast<unsigned long long>(seed) << 32) ^ static_cast<unsigned long long>(i);
  s_s0[lane] = splitmix64_dev(sm);
  s_s1[lane] = splitmix64_dev(sm);
  __syncthreads();

  unsigned long long s0 = s_s0[lane];
  unsigned long long s1 = s_s1[lane];
  const unsigned int r0 = xoroshiro128p_next_u32(s0, s1);
  const unsigned int r1 = xoroshiro128p_next_u32(s0, s1);
  const unsigned int r2 = xoroshiro128p_next_u32(s0, s1);

  method_idx[i] = static_cast<unsigned short>(method_count ? (r0 % method_count) : 0U);
  path_idx[i] = static_cast<unsigned short>(path_count ? (r1 % path_count) : 0U);
  header_profile_idx[i] = static_cast<unsigned short>(header_count ? (r2 % header_count) : 0U);
  body_kind[i] = static_cast<unsigned char>(body_count ? (xoroshiro128p_next_u32(s0, s1) % body_count) : 0U);
  step_id[i] = static_cast<unsigned char>(max_steps ? (xoroshiro128p_next_u32(s0, s1) % max_steps) : 0U);
  think_time_ms[i] = static_cast<unsigned short>(
      step_id[i] == 0 ? 1000U + (xoroshiro128p_next_u32(s0, s1) % 6000U)
                      : 10U + (xoroshiro128p_next_u32(s0, s1) % 240U));
  const unsigned int poly = k_polymorphic_masks[(r0 >> 5U) & 0x7U];
  flags[i] = (xoroshiro128p_next_u32(s0, s1) & poly) | (((r1 >> 3U) & 0x1FFU) << 8U);
}
