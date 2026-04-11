#include <cuda_runtime.h>

__device__ __forceinline__ unsigned long long rotl64_rng(unsigned long long x, int k) {
  return (x << k) | (x >> (64 - k));
}

__device__ __forceinline__ unsigned long long splitmix64_rng(unsigned long long& x) {
  x += 0x9E3779B97F4A7C15ULL;
  unsigned long long z = x;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

__device__ __forceinline__ unsigned int xoroshiro128p_u32(unsigned long long& s0, unsigned long long& s1) {
  const unsigned long long out = s0 + s1;
  unsigned long long x = s0;
  unsigned long long y = s1;
  y ^= x;
  s0 = rotl64_rng(x, 55) ^ y ^ (y << 14);
  s1 = rotl64_rng(y, 36);
  return static_cast<unsigned int>(out & 0xFFFFFFFFULL);
}

extern "C" __global__ void samurai_gpu_cuda_payload_rng_seed_kernel(
    unsigned int* out_seed_words,
    unsigned int count,
    unsigned int seed) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) {
    return;
  }
  __shared__ unsigned long long s0_blk[256];
  __shared__ unsigned long long s1_blk[256];
  const unsigned int lane = threadIdx.x & 0xFFU;
  unsigned long long sm = (static_cast<unsigned long long>(seed) << 32) ^ static_cast<unsigned long long>(i);
  s0_blk[lane] = splitmix64_rng(sm);
  s1_blk[lane] = splitmix64_rng(sm);
  __syncthreads();
  unsigned long long s0 = s0_blk[lane];
  unsigned long long s1 = s1_blk[lane];
  out_seed_words[i] = xoroshiro128p_u32(s0, s1);
}
