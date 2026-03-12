__global__ void template_kernel(
    uint8_t* packets_buffer,
    const uint8_t* template_global,
    int64_t use_constant,
    int64_t count,
    int64_t packet_size,
    uint32_t real_src_ip_int,
    int64_t spoof_enabled,
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
  int64_t offset = idx * packet_size;

  for (int64_t i = 0; i < packet_size; ++i) {
    if (use_constant == 1 && i < TEMPLATE_CONST_MAX) {
      packets_buffer[offset + i] = TEMPLATE_CONST_DEV[i];
    } else {
      packets_buffer[offset + i] = template_global[i];
    }
  }

  int64_t ip_offset = 0;
  if (has_ethernet == 1) {
    packets_buffer[offset] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[offset + 5] = gateway_mac & 0xFF;
    ip_offset = ETHERNET_HEADER_LEN;
  }

  uint16_t old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10);
  uint32_t old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12);
  uint16_t old_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8);
  uint16_t old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4);

  uint32_t src_ip_int;
  if (spoof_enabled == 1) {
    uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
    src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  } else {
    src_ip_int = real_src_ip_int;
  }
  write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int);

  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id);

  packets_buffer[offset + ip_offset + 8] = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));

  uint8_t ver_ihl = packets_buffer[offset + ip_offset];
  uint8_t ihl = ver_ihl & 0x0F;
  int64_t ip_header_len = static_cast<int64_t>(ihl) * 4;

  uint16_t new_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8);
  uint16_t ip_csum = old_ip_csum;
  ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id);
  ip_csum = rfc1624_update_word(ip_csum, old_ttl_proto, new_ttl_proto);
  write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum);

  int64_t transport_offset = offset + ip_offset + ip_header_len;
  uint16_t old_src_port = read_uint16_be(packets_buffer, transport_offset);
  uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));
  write_uint16_be(packets_buffer, transport_offset, src_port);

  uint8_t protocol = packets_buffer[offset + ip_offset + 9];

  if (protocol == TCP_PROTOCOL) {
    uint16_t old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16);
    uint16_t tcp_csum = old_tcp_csum;
    tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int);
    tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port);
    write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum);
  } else if (protocol == UDP_PROTOCOL) {
    uint16_t old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6);
    uint16_t udp_csum = old_udp_csum;
    udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int);
    udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port);
    if (udp_csum == 0) {
      udp_csum = 0xFFFF;
    }
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);
  }

  rng_states[idx] = local_state;
}

__global__ void pool_kernel(
    uint8_t* packets_buffer,
    const uint8_t* templates_global,
    int64_t templates_global_len,
    int64_t use_constant,
    int64_t count,
    int64_t packet_size,
    int64_t num_templates,
    uint32_t target_ip_int,
    uint32_t real_src_ip_int,
    int64_t spoof_enabled,
    int64_t specific_src_port,
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
  int64_t offset = idx * packet_size;
  int64_t template_idx = idx % num_templates;
  int64_t template_offset = template_idx * packet_size;

  if (use_constant == 1 && template_offset + packet_size <= POOL_CONST_MAX) {
    for (int64_t i = 0; i < packet_size; ++i) {
      packets_buffer[offset + i] = POOL_CONST_DEV[template_offset + i];
    }
  } else {
    if (template_offset + packet_size > templates_global_len) {
      return;
    }
    for (int64_t i = 0; i < packet_size; ++i) {
      packets_buffer[offset + i] = templates_global[template_offset + i];
    }
  }

  int64_t ip_offset = 0;
  if (has_ethernet) {
    packets_buffer[offset] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[offset + 5] = gateway_mac & 0xFF;
    ip_offset = ETHERNET_HEADER_LEN;
  }

  uint16_t old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10);
  uint32_t old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12);
  uint32_t old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16);
  uint16_t old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4);
  uint16_t old_ip_total_len = read_uint16_be(packets_buffer, offset + ip_offset + 2);

  uint32_t src_ip_int;
  if (spoof_enabled) {
    uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
    src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  } else {
    src_ip_int = real_src_ip_int;
  }
  write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int);

  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id);

  uint16_t src_port;
  if (specific_src_port > 0) {
    src_port = static_cast<uint16_t>(specific_src_port);
  } else {
    src_port = static_cast<uint16_t>(1024 + static_cast<int>(rng_uniform(local_state) * 64511.0f));
  }

  uint8_t ver_ihl = packets_buffer[offset + ip_offset];
  uint8_t ihl = ver_ihl & 0x0F;
  int64_t ip_header_len = static_cast<int64_t>(ihl) * 4;

  uint16_t ip_total_len = has_ethernet ? static_cast<uint16_t>(packet_size - ETHERNET_HEADER_LEN)
                                       : static_cast<uint16_t>(packet_size);

  write_uint16_be(packets_buffer, offset + ip_offset + 2, ip_total_len);
  write_uint32_be(packets_buffer, offset + ip_offset + 16, target_ip_int);

  uint16_t ip_csum = old_ip_csum;
  ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id);
  ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, target_ip_int);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_total_len, ip_total_len);
  write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum);

  int64_t transport_offset = offset + ip_offset + ip_header_len;
  uint16_t old_src_port = read_uint16_be(packets_buffer, transport_offset);
  write_uint16_be(packets_buffer, transport_offset, src_port);

  uint8_t protocol = packets_buffer[offset + ip_offset + 9];
  if (protocol == TCP_PROTOCOL) {
    uint16_t old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16);
    uint32_t old_tcp_seq = read_uint32_be(packets_buffer, transport_offset + 4);
    uint32_t tcp_seq = static_cast<uint32_t>((idx * 1664525ull + 1013904223ull) & 0xFFFFFFFFull);
    write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq);

    uint16_t tcp_csum = old_tcp_csum;
    tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int);
    tcp_csum = rfc1624_update_dword(tcp_csum, old_dst_ip_int, target_ip_int);
    tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port);
    tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_seq, tcp_seq);
    write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum);
  } else if (protocol == UDP_PROTOCOL) {
    uint16_t old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6);
    uint16_t old_udp_len = read_uint16_be(packets_buffer, transport_offset + 4);
    uint16_t udp_len = static_cast<uint16_t>(ip_total_len - ip_header_len);
    write_uint16_be(packets_buffer, transport_offset + 4, udp_len);

    uint16_t udp_csum = old_udp_csum;
    udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int);
    udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, target_ip_int);
    udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port);
    udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len);
    udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len);
    if (udp_csum == 0) {
      udp_csum = 0xFFFF;
    }
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);
  }

  rng_states[idx] = local_state;
}

__global__ void stateful_pool_kernel(
    uint8_t* packets_buffer,
    const uint8_t* templates_global,
    int64_t templates_global_len,
    int64_t use_constant,
    int64_t count,
    int64_t packet_size,
    int64_t num_templates,
    uint32_t target_ip_int,
    uint32_t real_src_ip_int,
    int64_t spoof_enabled,
    int64_t specific_src_port,
    int64_t has_ethernet,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac,
    uint32_t spoof_base_ip,
    uint32_t spoof_mask,
    const uint32_t* seq_array,
    const uint32_t* ack_array,
    const uint8_t* state_array,
    const uint32_t* actual_lengths,
    const uint16_t* window_sizes,
    const uint16_t* mss_values,
    const uint8_t* ttls) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t offset = idx * packet_size;
  int64_t template_idx = idx % num_templates;
  int64_t template_offset = template_idx * packet_size;

  if (use_constant == 1 && template_offset + packet_size <= POOL_CONST_MAX) {
    for (int64_t i = 0; i < packet_size; ++i) {
      packets_buffer[offset + i] = POOL_CONST_DEV[template_offset + i];
    }
  } else {
    if (template_offset + packet_size > templates_global_len) {
      return;
    }
    for (int64_t i = 0; i < packet_size; ++i) {
      packets_buffer[offset + i] = templates_global[template_offset + i];
    }
  }

  int64_t ip_offset;
  uint16_t ip_total_len;
  if (has_ethernet) {
    ip_offset = ETHERNET_HEADER_LEN;
    uint32_t current_actual_len = actual_lengths[template_idx];
    ip_total_len = static_cast<uint16_t>(current_actual_len - ETHERNET_HEADER_LEN);

    packets_buffer[offset] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[offset + 5] = gateway_mac & 0xFF;
  } else {
    ip_offset = 0;
    ip_total_len = static_cast<uint16_t>(actual_lengths[template_idx]);
  }

  uint16_t win_size = window_sizes[idx] > 0 ? window_sizes[idx] : 64240;
  uint16_t mss = mss_values[idx] > 0 ? mss_values[idx] : 1460;
  uint8_t ttl_val = ttls[idx] > 0 ? ttls[idx] : 64;

  uint8_t ver_ihl = packets_buffer[offset + ip_offset];
  uint8_t ihl = ver_ihl & 0x0F;
  int64_t ip_header_len = static_cast<int64_t>(ihl) * 4;

  uint16_t old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10);
  uint32_t old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12);
  uint32_t old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16);
  uint16_t old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4);
  uint16_t old_ip_total_len = read_uint16_be(packets_buffer, offset + ip_offset + 2);
  uint16_t old_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8);

  uint32_t src_ip_int;
  if (spoof_enabled) {
    uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
    src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  } else {
    src_ip_int = real_src_ip_int;
  }
  write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int);

  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id);

  packets_buffer[offset + ip_offset + 8] = ttl_val;

  uint16_t src_port;
  if (specific_src_port > 0) {
    src_port = static_cast<uint16_t>(specific_src_port + idx);
  } else {
    src_port = static_cast<uint16_t>(1024 + (idx % 64512));
  }

  write_uint16_be(packets_buffer, offset + ip_offset + 2, ip_total_len);
  write_uint32_be(packets_buffer, offset + ip_offset + 16, target_ip_int);

  uint16_t new_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8);
  uint16_t ip_csum = old_ip_csum;
  ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int);
  ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, target_ip_int);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_total_len, ip_total_len);
  ip_csum = rfc1624_update_word(ip_csum, old_ttl_proto, new_ttl_proto);
  write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum);

  int64_t transport_offset = offset + ip_offset + ip_header_len;
  uint16_t old_src_port = read_uint16_be(packets_buffer, transport_offset);
  write_uint16_be(packets_buffer, transport_offset, src_port);

  uint8_t protocol = packets_buffer[offset + ip_offset + 9];

  if (protocol == TCP_PROTOCOL) {
    uint16_t old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16);
    uint32_t old_tcp_seq = read_uint32_be(packets_buffer, transport_offset + 4);
    uint32_t old_tcp_ack = read_uint32_be(packets_buffer, transport_offset + 8);
    uint16_t old_doff_flags = read_uint16_be(packets_buffer, transport_offset + 12);
    uint16_t old_window = read_uint16_be(packets_buffer, transport_offset + 14);
    uint16_t old_mss = 0;

    uint32_t tcp_seq;
    uint32_t tcp_ack;
    if (state_array[idx] == 2) {
      tcp_seq = seq_array[idx];
      tcp_ack = ack_array[idx];
      packets_buffer[transport_offset + 13] = 0x18;
    } else {
      tcp_seq = static_cast<uint32_t>((idx * 1664525ull + 1013904223ull) & 0xFFFFFFFFull);
      tcp_ack = 0;
      packets_buffer[transport_offset + 13] = 0x02;
    }

    write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq);
    write_uint32_be(packets_buffer, transport_offset + 8, tcp_ack);
    write_uint16_be(packets_buffer, transport_offset + 14, win_size);

    int mss_patched = 0;
    if (ip_header_len + 20 <= ip_total_len) {
      if (packets_buffer[transport_offset + 20] == 2) {
        old_mss = read_uint16_be(packets_buffer, transport_offset + 22);
        write_uint16_be(packets_buffer, transport_offset + 22, mss);
        mss_patched = 1;
      }
    }

    uint16_t new_doff_flags = read_uint16_be(packets_buffer, transport_offset + 12);

    uint16_t tcp_csum = old_tcp_csum;
    tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int);
    tcp_csum = rfc1624_update_dword(tcp_csum, old_dst_ip_int, target_ip_int);
    tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port);
    tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_seq, tcp_seq);
    tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_ack, tcp_ack);
    tcp_csum = rfc1624_update_word(tcp_csum, old_doff_flags, new_doff_flags);
    tcp_csum = rfc1624_update_word(tcp_csum, old_window, win_size);
    if (mss_patched == 1) {
      tcp_csum = rfc1624_update_word(tcp_csum, old_mss, mss);
    }
    write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum);
  } else if (protocol == UDP_PROTOCOL) {
    uint16_t old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6);
    uint16_t old_udp_len = read_uint16_be(packets_buffer, transport_offset + 4);
    uint16_t udp_len = static_cast<uint16_t>(ip_total_len - ip_header_len);
    write_uint16_be(packets_buffer, transport_offset + 4, udp_len);

    uint16_t udp_csum = old_udp_csum;
    udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int);
    udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, target_ip_int);
    udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port);
    udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len);
    udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len);
    if (udp_csum == 0) {
      udp_csum = 0xFFFF;
    }
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);
  }

  rng_states[idx] = local_state;
}

