__global__ void create_tcp_packets_kernel_spoof(
    uint8_t* packets_buffer,
    int64_t count,
    uint32_t target_ip_int,
    int64_t target_port,
    int64_t tcp_flags_int,
    int64_t has_ethernet,
    int64_t user_tcp_window,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac,
    uint32_t spoof_base_ip,
    uint32_t spoof_mask) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t transport_len = TCP_HEADER_LEN_WITH_OPT;
  int64_t packet_size = (has_ethernet ? 14 : 0) + 20 + transport_len;
  int64_t packet_offset = idx * packet_size;

  uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
  uint32_t src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  uint8_t ip_ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));
  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  uint32_t tcp_seq = static_cast<uint32_t>(rng_uniform(local_state) * 4294967295.0f);

  uint16_t tcp_window = static_cast<uint16_t>(select_tcp_window(user_tcp_window, local_state));
  write_l2_l3_ipv4_header(
      packets_buffer,
      packet_offset,
      has_ethernet,
      gateway_mac,
      static_cast<uint16_t>(20 + transport_len),
      ip_id,
      ip_ttl,
      TCP_PROTOCOL,
      src_ip_int,
      target_ip_int);

  int64_t transport_offset = packet_offset + (has_ethernet ? 14 : 0) + 20;
  uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));

  write_uint16_be(packets_buffer, transport_offset, src_port);
  write_uint16_be(packets_buffer, transport_offset + 2, static_cast<uint16_t>(target_port));
  write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq);
  write_uint32_be(packets_buffer, transport_offset + 8, 0u);
  packets_buffer[transport_offset + 12] = 0xA0;
  packets_buffer[transport_offset + 13] = static_cast<uint8_t>(tcp_flags_int);
  write_uint16_be(packets_buffer, transport_offset + 14, tcp_window);
  write_uint16_be(packets_buffer, transport_offset + 16, 0);
  write_uint16_be(packets_buffer, transport_offset + 18, 0);

  int64_t opt_offset = transport_offset + 20;
  uint16_t mss_val = static_cast<uint16_t>(1380 + (idx % 81));
  packets_buffer[opt_offset] = 2;
  packets_buffer[opt_offset + 1] = 4;
  write_uint16_be(packets_buffer, opt_offset + 2, mss_val);
  packets_buffer[opt_offset + 4] = 4;
  packets_buffer[opt_offset + 5] = 2;
  uint32_t ts_val = static_cast<uint32_t>(rng_uniform(local_state) * 4294967295.0f);
  packets_buffer[opt_offset + 6] = 8;
  packets_buffer[opt_offset + 7] = 10;
  write_uint32_be(packets_buffer, opt_offset + 8, ts_val);
  write_uint32_be(packets_buffer, opt_offset + 12, 0u);
  packets_buffer[opt_offset + 16] = 1;
  packets_buffer[opt_offset + 17] = 3;
  packets_buffer[opt_offset + 18] = 3;
  packets_buffer[opt_offset + 19] = 7;

  uint16_t tcp_csum = calculate_tcp_checksum_optimized(
      packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int);
  write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum);

  rng_states[idx] = local_state;
}

__global__ void create_tcp_packets_kernel_nospoof(
    uint8_t* packets_buffer,
    int64_t count,
    uint32_t target_ip_int,
    int64_t target_port,
    uint32_t real_src_ip_int,
    int64_t tcp_flags_int,
    int64_t has_ethernet,
    int64_t user_tcp_window,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t transport_len = TCP_HEADER_LEN_WITH_OPT;
  int64_t packet_size = (has_ethernet ? 14 : 0) + 20 + transport_len;
  int64_t packet_offset = idx * packet_size;

  uint8_t ip_ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));
  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  uint32_t tcp_seq = static_cast<uint32_t>(rng_uniform(local_state) * 4294967295.0f);

  uint16_t tcp_window = static_cast<uint16_t>(select_tcp_window(user_tcp_window, local_state));
  write_l2_l3_ipv4_header(
      packets_buffer,
      packet_offset,
      has_ethernet,
      gateway_mac,
      static_cast<uint16_t>(20 + transport_len),
      ip_id,
      ip_ttl,
      TCP_PROTOCOL,
      real_src_ip_int,
      target_ip_int);

  int64_t transport_offset = packet_offset + (has_ethernet ? 14 : 0) + 20;
  uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));

  write_uint16_be(packets_buffer, transport_offset, src_port);
  write_uint16_be(packets_buffer, transport_offset + 2, static_cast<uint16_t>(target_port));
  write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq);
  write_uint32_be(packets_buffer, transport_offset + 8, 0u);
  packets_buffer[transport_offset + 12] = 0xA0;
  packets_buffer[transport_offset + 13] = static_cast<uint8_t>(tcp_flags_int);
  write_uint16_be(packets_buffer, transport_offset + 14, tcp_window);
  write_uint16_be(packets_buffer, transport_offset + 16, 0);
  write_uint16_be(packets_buffer, transport_offset + 18, 0);

  int64_t opt_offset = transport_offset + 20;
  uint16_t mss_val = static_cast<uint16_t>(1380 + (idx % 81));
  packets_buffer[opt_offset] = 2;
  packets_buffer[opt_offset + 1] = 4;
  write_uint16_be(packets_buffer, opt_offset + 2, mss_val);
  packets_buffer[opt_offset + 4] = 4;
  packets_buffer[opt_offset + 5] = 2;
  uint32_t ts_val = static_cast<uint32_t>(rng_uniform(local_state) * 4294967295.0f);
  packets_buffer[opt_offset + 6] = 8;
  packets_buffer[opt_offset + 7] = 10;
  write_uint32_be(packets_buffer, opt_offset + 8, ts_val);
  write_uint32_be(packets_buffer, opt_offset + 12, 0u);
  packets_buffer[opt_offset + 16] = 1;
  packets_buffer[opt_offset + 17] = 3;
  packets_buffer[opt_offset + 18] = 3;
  packets_buffer[opt_offset + 19] = 7;

  uint16_t tcp_csum = calculate_tcp_checksum_optimized(
      packets_buffer, transport_offset, transport_len, real_src_ip_int, target_ip_int);
  write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum);

  rng_states[idx] = local_state;
}

__global__ void create_udp_packets_kernel_spoof(
    uint8_t* packets_buffer,
    int64_t count,
    uint32_t target_ip_int,
    int64_t target_port,
    int64_t has_ethernet,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac,
    uint32_t spoof_base_ip,
    uint32_t spoof_mask) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t transport_len = UDP_HEADER_LEN;
  int64_t packet_size = (has_ethernet ? 14 : 0) + 20 + transport_len;
  int64_t packet_offset = idx * packet_size;

  uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
  uint32_t src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  uint8_t ip_ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));
  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);

  write_l2_l3_ipv4_header(
      packets_buffer,
      packet_offset,
      has_ethernet,
      gateway_mac,
      static_cast<uint16_t>(20 + transport_len),
      ip_id,
      ip_ttl,
      UDP_PROTOCOL,
      src_ip_int,
      target_ip_int);

  int64_t transport_offset = packet_offset + (has_ethernet ? 14 : 0) + 20;
  uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));
  write_uint16_be(packets_buffer, transport_offset, src_port);
  write_uint16_be(packets_buffer, transport_offset + 2, static_cast<uint16_t>(target_port));
  write_uint16_be(packets_buffer, transport_offset + 4, static_cast<uint16_t>(transport_len));
  write_uint16_be(packets_buffer, transport_offset + 6, 0);

  uint16_t udp_csum = calculate_udp_checksum_optimized(
      packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int);
  write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);

  rng_states[idx] = local_state;
}

__global__ void create_udp_packets_kernel_nospoof(
    uint8_t* packets_buffer,
    int64_t count,
    uint32_t target_ip_int,
    int64_t target_port,
    uint32_t real_src_ip_int,
    int64_t has_ethernet,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t transport_len = UDP_HEADER_LEN;
  int64_t packet_size = (has_ethernet ? 14 : 0) + 20 + transport_len;
  int64_t packet_offset = idx * packet_size;

  uint8_t ip_ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));
  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);

  write_l2_l3_ipv4_header(
      packets_buffer,
      packet_offset,
      has_ethernet,
      gateway_mac,
      static_cast<uint16_t>(20 + transport_len),
      ip_id,
      ip_ttl,
      UDP_PROTOCOL,
      real_src_ip_int,
      target_ip_int);

  int64_t transport_offset = packet_offset + (has_ethernet ? 14 : 0) + 20;
  uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));
  write_uint16_be(packets_buffer, transport_offset, src_port);
  write_uint16_be(packets_buffer, transport_offset + 2, static_cast<uint16_t>(target_port));
  write_uint16_be(packets_buffer, transport_offset + 4, static_cast<uint16_t>(transport_len));
  write_uint16_be(packets_buffer, transport_offset + 6, 0);

  uint16_t udp_csum = calculate_udp_checksum_optimized(
      packets_buffer, transport_offset, transport_len, real_src_ip_int, target_ip_int);
  write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);

  rng_states[idx] = local_state;
}

