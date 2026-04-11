#include <cuda_runtime.h>

__constant__ unsigned int k_template_flag_base[4] = {0x10U, 0x20U, 0x40U, 0x80U};

extern "C" __global__ void samurai_gpu_cuda_payload_template_expand_kernel(
    const unsigned short* path_idx,
    unsigned int* template_flags,
    unsigned int count) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) {
    return;
  }
  __shared__ unsigned short s_paths[256];
  const unsigned int lane = threadIdx.x & 0xFFU;
  s_paths[lane] = path_idx[i];
  __syncthreads();
  const unsigned int p = static_cast<unsigned int>(s_paths[lane] & 0x3ffU);
  template_flags[i] = p | k_template_flag_base[(p >> 2U) & 0x3U];
}
