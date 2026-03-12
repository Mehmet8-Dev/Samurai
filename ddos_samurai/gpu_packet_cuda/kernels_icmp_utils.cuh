__global__ void create_icmp_packets_kernel(
    uint8_t* packets_buffer,
    int64_t count,
    uint32_t target_ip_int,
    uint32_t real_src_ip_int,
    int64_t spoof_enabled,
    int64_t has_ethernet,
    int64_t icmp_type,
    int64_t icmp_code,
    curandStatePhilox4_32_10_t* rng_states,
    uint64_t gateway_mac,
    uint32_t spoof_base_ip,
    uint32_t spoof_mask,
    int64_t payload_size) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  curandStatePhilox4_32_10_t local_state = rng_states[idx];

  int64_t eth_len = has_ethernet ? ETHERNET_HEADER_LEN : 0;
  int64_t icmp_len = ICMP_HEADER_LEN + payload_size;
  int64_t ip_total_len = IP_HEADER_LEN + icmp_len;
  int64_t packet_size = eth_len + ip_total_len;

  int64_t offset = idx * packet_size;
  int64_t current = offset;

  uint32_t src_ip_int;
  if (spoof_enabled) {
    uint32_t num_hosts = (spoof_mask >= 32) ? 1u : (1u << (32u - spoof_mask));
    src_ip_int = spoof_base_ip + static_cast<uint32_t>(rng_uniform(local_state) * static_cast<float>(num_hosts - 1));
  } else {
    src_ip_int = real_src_ip_int;
  }

  uint16_t ip_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  uint8_t ttl = static_cast<uint8_t>(48 + static_cast<int>(rng_uniform(local_state) * 81.0f));
  uint16_t icmp_id = static_cast<uint16_t>(rng_uniform(local_state) * 65535.0f);
  uint16_t icmp_seq = static_cast<uint16_t>(idx & 0xFFFF);

  if (has_ethernet) {
    packets_buffer[current] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[current + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[current + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[current + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[current + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[current + 5] = gateway_mac & 0xFF;
    write_uint32_be(packets_buffer, current + 6, 0x00000000u);
    write_uint16_be(packets_buffer, current + 10, 0x0000u);
    write_uint16_be(packets_buffer, current + 12, 0x0800u);
    current += ETHERNET_HEADER_LEN;
  }

  int64_t ip_offset = current;
  write_uint16_be(packets_buffer, ip_offset, 0x4500u);
  write_uint16_be(packets_buffer, ip_offset + 2, static_cast<uint16_t>(ip_total_len));
  write_uint16_be(packets_buffer, ip_offset + 4, ip_id);
  write_uint16_be(packets_buffer, ip_offset + 6, 0);
  packets_buffer[ip_offset + 8] = ttl;
  packets_buffer[ip_offset + 9] = ICMP_PROTOCOL;
  write_uint16_be(packets_buffer, ip_offset + 10, 0);
  write_uint32_be(packets_buffer, ip_offset + 12, src_ip_int);
  write_uint32_be(packets_buffer, ip_offset + 16, target_ip_int);
  uint16_t ip_csum = calculate_checksum(packets_buffer, ip_offset, IP_HEADER_LEN);
  write_uint16_be(packets_buffer, ip_offset + 10, ip_csum);
  current += IP_HEADER_LEN;

  int64_t icmp_offset = current;
  packets_buffer[icmp_offset] = static_cast<uint8_t>(icmp_type);
  packets_buffer[icmp_offset + 1] = static_cast<uint8_t>(icmp_code);
  write_uint16_be(packets_buffer, icmp_offset + 2, 0);

  if (icmp_type == 8 || icmp_type == 0) {
    write_uint16_be(packets_buffer, icmp_offset + 4, icmp_id);
    write_uint16_be(packets_buffer, icmp_offset + 6, icmp_seq);
  } else {
    write_uint32_be(packets_buffer, icmp_offset + 4, 0);
  }
  current += ICMP_HEADER_LEN;

  for (int64_t i = 0; i < payload_size; ++i) {
    packets_buffer[current + i] = static_cast<uint8_t>(rng_uniform(local_state) * 256.0f) & 0xFF;
  }

  uint16_t icmp_csum = calculate_icmp_checksum(packets_buffer, icmp_offset, icmp_len);
  write_uint16_be(packets_buffer, icmp_offset + 2, icmp_csum);

  rng_states[idx] = local_state;
}

template <typename T>
struct DeviceArray {
  T* ptr = nullptr;
  size_t count = 0;

  DeviceArray() = default;
  explicit DeviceArray(const std::vector<T>& data, cudaStream_t stream = nullptr) {
    if (data.empty()) {
      return;
    }
    count = data.size();
    throw_if_cuda(cudaMalloc(&ptr, sizeof(T) * count), "cudaMalloc DeviceArray failed");
    throw_if_cuda(cudaMemcpyAsync(ptr, data.data(), sizeof(T) * count, cudaMemcpyHostToDevice, stream),
                  "cudaMemcpyAsync DeviceArray failed");
  }

  DeviceArray(const DeviceArray&) = delete;
  DeviceArray& operator=(const DeviceArray&) = delete;

  DeviceArray(DeviceArray&& o) noexcept : ptr(o.ptr), count(o.count) {
    o.ptr = nullptr;
    o.count = 0;
  }

  DeviceArray& operator=(DeviceArray&& o) noexcept {
    if (this != &o) {
      if (ptr) {
        cudaFree(ptr);
      }
      ptr = o.ptr;
      count = o.count;
      o.ptr = nullptr;
      o.count = 0;
    }
    return *this;
  }

  ~DeviceArray() {
    if (ptr) {
      cudaFree(ptr);
    }
  }
};

std::vector<uint8_t> to_bytes_flat(const std::vector<std::vector<uint8_t>>& chunks) {
  size_t total = 0;
  for (const auto& c : chunks) {
    total += c.size();
  }
  std::vector<uint8_t> out;
  out.reserve(total);
  for (const auto& c : chunks) {
    out.insert(out.end(), c.begin(), c.end());
  }
  return out;
}

int blocks_for_count(int64_t count) {
  return static_cast<int>((count + kThreadsPerBlock - 1) / kThreadsPerBlock);
}

BenchmarkPathResult telemetry_delta_to_path(const GenerationTelemetry& before,
                                            const GenerationTelemetry& after,
                                            int count,
                                            double total_seconds,
                                            int iterations) {
  BenchmarkPathResult out;
  double avg_sec = total_seconds / static_cast<double>(std::max(1, iterations));
  out.avg_ms = avg_sec * 1000.0;
  out.pps = (avg_sec > 0.0) ? (static_cast<double>(count) / avg_sec) : 0.0;
  out.cache_hit = (after.gpu_template_cache_hit_count >= before.gpu_template_cache_hit_count)
                      ? after.gpu_template_cache_hit_count - before.gpu_template_cache_hit_count
                      : 0;
  out.cache_miss = (after.gpu_template_cache_miss_count >= before.gpu_template_cache_miss_count)
                       ? after.gpu_template_cache_miss_count - before.gpu_template_cache_miss_count
                       : 0;
  out.h2d_copy_count = (after.gpu_template_h2d_copy_count >= before.gpu_template_h2d_copy_count)
                           ? after.gpu_template_h2d_copy_count - before.gpu_template_h2d_copy_count
                           : 0;
  out.h2d_copy_bytes = (after.gpu_template_h2d_copy_bytes >= before.gpu_template_h2d_copy_bytes)
                           ? after.gpu_template_h2d_copy_bytes - before.gpu_template_h2d_copy_bytes
                           : 0;
  out.rng_alloc = (after.gpu_rng_state_alloc_count >= before.gpu_rng_state_alloc_count)
                      ? after.gpu_rng_state_alloc_count - before.gpu_rng_state_alloc_count
                      : 0;
  out.rng_reuse = (after.gpu_rng_state_reuse_count >= before.gpu_rng_state_reuse_count)
                      ? after.gpu_rng_state_reuse_count - before.gpu_rng_state_reuse_count
                      : 0;
  return out;
}

}  // namespace

DeviceBuffer::DeviceBuffer(DeviceBuffer&& other) noexcept {
  ptr = other.ptr;
  size = other.size;
  other.ptr = nullptr;
  other.size = 0;
}

DeviceBuffer& DeviceBuffer::operator=(DeviceBuffer&& other) noexcept {
  if (this != &other) {
    reset();
    ptr = other.ptr;
    size = other.size;
    other.ptr = nullptr;
    other.size = 0;
  }
  return *this;
}

DeviceBuffer::~DeviceBuffer() {
  reset();
}

void DeviceBuffer::reset() {
  if (ptr) {
    cudaFree(ptr);
    ptr = nullptr;
    size = 0;
  }
}

void safe_kernel_launch(
    const std::string& kernel_name,
    cudaError_t launch_status,
    cudaStream_t stream,
    bool synchronize) {
  if (launch_status != cudaSuccess) {
    throw GPUKernelError("Kernel '" + kernel_name + "' launch failed: " + cudaGetErrorString(launch_status));
  }
  if (synchronize) {
    cudaError_t st = stream ? cudaStreamSynchronize(stream) : cudaDeviceSynchronize();
    if (st != cudaSuccess) {
      throw GPUKernelError("Kernel '" + kernel_name + "' execution failed: " + std::string(cudaGetErrorString(st)));
    }
  }
}

bool init_gpu() {
  auto [ok, msg] = check_gpu_available();
  (void)msg;
  return ok;
}

std::pair<bool, std::string> check_gpu_available() {
  int device_count = 0;
  if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
    return {false, "CUDA not available"};
  }

  int dev = 0;
  throw_if_cuda(cudaGetDevice(&dev), "cudaGetDevice failed");
  cudaDeviceProp prop{};
  if (cudaGetDeviceProperties(&prop, dev) != cudaSuccess) {
    return {false, "cudaGetDeviceProperties failed"};
  }
  if (prop.major < 3) {
    return {false, "GPU compute capability too low (need 3.0+)"};
  }

  size_t free_b = 0;
  size_t total_b = 0;
  if (cudaMemGetInfo(&free_b, &total_b) != cudaSuccess) {
    return {false, "cudaMemGetInfo failed"};
  }

  double free_mb = static_cast<double>(free_b) / (1024.0 * 1024.0);
  if (free_mb < 64.0) {
    std::ostringstream oss;
    oss << "Low GPU memory: " << std::fixed << std::setprecision(1) << free_mb << " MB free";
    return {false, oss.str()};
  }

  std::ostringstream ok;
  ok << "GPU ready: " << prop.name << ", " << std::fixed << std::setprecision(0)
     << free_mb << " MB free, CC " << prop.major << "." << prop.minor;
  return {true, ok.str()};
}

GPUInfo get_gpu_info() {
  GPUInfo out;
  auto [ok, msg] = check_gpu_available();
  out.available = ok;
  if (!ok) {
    out.error = msg;
    return out;
  }

  int dev = 0;
  if (cudaGetDevice(&dev) != cudaSuccess) {
    out.available = false;
    out.error = "cudaGetDevice failed";
    return out;
  }

  cudaDeviceProp prop{};
  if (cudaGetDeviceProperties(&prop, dev) != cudaSuccess) {
    out.available = false;
    out.error = "cudaGetDeviceProperties failed";
    return out;
  }

  size_t free_b = 0;
  size_t total_b = 0;
  if (cudaMemGetInfo(&free_b, &total_b) != cudaSuccess) {
    out.available = false;
    out.error = "cudaMemGetInfo failed";
    return out;
  }

  out.name = prop.name;
  out.compute_capability = std::to_string(prop.major) + "." + std::to_string(prop.minor);
  out.total_memory_mb = static_cast<double>(total_b) / (1024.0 * 1024.0);
  out.free_memory_mb = static_cast<double>(free_b) / (1024.0 * 1024.0);
  out.max_threads_per_block = prop.maxThreadsPerBlock;
  out.max_shared_memory_per_block = static_cast<int>(prop.sharedMemPerBlock);
  out.warp_size = prop.warpSize;
  return out;
}

bool is_gpu_available() {
  return check_gpu_available().first;
}

GenerationTelemetry get_generation_telemetry() {
  std::lock_guard<std::mutex> lock(g_generation_lock);
  GenerationTelemetry out = g_generation_telemetry;
  out.template_cache_entries = static_cast<int>(g_template_cache.size());
  out.rng_pool_entries = static_cast<int>(g_rng_state_pool.size());
  out.template_cache_limit = gpu_cache_limit();
  out.rng_pool_limit = rng_pool_limit();
  return out;
}

void reset_generation_telemetry() {
  std::lock_guard<std::mutex> lock(g_generation_lock);
  g_generation_telemetry = GenerationTelemetry{};
}

void clear_generation_caches() {
  std::lock_guard<std::mutex> lock(g_generation_lock);
  for (auto& kv : g_template_cache) {
    if (kv.second.first) {
      cudaFree(kv.second.first);
    }
  }
  g_template_cache.clear();
  g_template_lru.clear();
  g_template_lru_idx.clear();

  for (auto& kv : g_rng_state_pool) {
    if (kv.second) {
      cudaFree(kv.second);
    }
  }
  g_rng_state_pool.clear();
  g_rng_lru.clear();
  g_rng_lru_idx.clear();
}

PoolTelemetry get_pool_telemetry() {
  PoolTelemetry out;
  out.d2h_transfer_count = g_d2h_transfer_count.load();
  out.d2h_transfer_bytes = g_d2h_transfer_bytes.load();
  out.gpu_pool = get_memory_pool_impl().stats();
  out.pinned_host_pool = get_pinned_pool_impl().stats();
  return out;
}

void configure_pinned_host_pool(std::optional<int> max_mb, std::optional<int> max_bytes) {
  size_t bytes = 0;
  if (max_bytes.has_value()) {
    bytes = static_cast<size_t>(std::max(1, *max_bytes));
  } else if (max_mb.has_value()) {
    bytes = static_cast<size_t>(std::max(1, *max_mb)) * 1024ull * 1024ull;
  } else {
    return;
  }
  get_pinned_pool_impl().configure(bytes);
}

std::vector<uint8_t> copy_gpu_to_host_pinned(
    const DeviceBuffer& gpu_arr,
    const std::string& key,
    cudaStream_t stream,
    bool blocking) {
  if (!gpu_arr.valid()) {
    return {};
  }
  HostBuffer hb = get_pinned_pool_impl().acquire(gpu_arr.size, key);
  throw_if_cuda(cudaMemcpyAsync(hb.ptr, gpu_arr.ptr, gpu_arr.size, cudaMemcpyDeviceToHost, stream),
                "cudaMemcpyAsync D2H failed");
  if (blocking) {
    throw_if_cuda(stream ? cudaStreamSynchronize(stream) : cudaDeviceSynchronize(),
                  "D2H synchronize failed");
  }
  g_d2h_transfer_count.fetch_add(1);
  g_d2h_transfer_bytes.fetch_add(gpu_arr.size);
  return std::vector<uint8_t>(hb.ptr, hb.ptr + gpu_arr.size);
}

uint32_t ip_to_int(const std::string& ip_str) {
  std::array<int, 4> parts{0, 0, 0, 0};
  char dot = 0;
  std::istringstream iss(ip_str);
  if (!(iss >> parts[0] >> dot) || dot != '.' ||
      !(iss >> parts[1] >> dot) || dot != '.' ||
      !(iss >> parts[2] >> dot) || dot != '.' ||
      !(iss >> parts[3])) {
    throw std::invalid_argument("Invalid IPv4 string: " + ip_str);
  }
  for (int p : parts) {
    if (p < 0 || p > 255) {
      throw std::invalid_argument("Invalid IPv4 octet in: " + ip_str);
    }
  }

  return (static_cast<uint32_t>(parts[0]) << 24) |
         (static_cast<uint32_t>(parts[1]) << 16) |
         (static_cast<uint32_t>(parts[2]) << 8) |
         static_cast<uint32_t>(parts[3]);
}

std::string int_to_ip(uint32_t ip_int) {
  std::ostringstream oss;
  oss << ((ip_int >> 24) & 0xFF) << "."
      << ((ip_int >> 16) & 0xFF) << "."
      << ((ip_int >> 8) & 0xFF) << "."
      << (ip_int & 0xFF);
  return oss.str();
}

uint64_t mac_to_int(const std::string& mac_str) {
  std::string s = mac_str;
  for (char& c : s) {
    if (c == '-') {
      c = ':';
    }
  }

  std::array<int, 6> parts{0, 0, 0, 0, 0, 0};
  std::istringstream iss(s);
  std::string token;
  for (int i = 0; i < 6; ++i) {
    if (!std::getline(iss, token, ':')) {
      throw std::invalid_argument("Invalid MAC string: " + mac_str);
    }
    int v = std::stoi(token, nullptr, 16);
    if (v < 0 || v > 255) {
      throw std::invalid_argument("Invalid MAC byte in: " + mac_str);
    }
    parts[i] = v;
  }

  uint64_t out = 0;
  for (int i = 0; i < 6; ++i) {
    out |= (static_cast<uint64_t>(parts[i]) << (40 - i * 8));
  }
  return out;
}

std::string int_to_mac(uint64_t mac_int) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (int i = 0; i < 6; ++i) {
    if (i > 0) {
      oss << ":";
    }
    oss << std::setw(2) << ((mac_int >> (40 - i * 8)) & 0xFF);
  }
  return oss.str();
}

std::pair<uint32_t, uint32_t> parse_subnet(const std::string& subnet) {
  std::string s = subnet;
  if (s.empty()) {
    throw std::invalid_argument("Subnet must not be empty");
  }

  size_t slash = s.find('/');
  if (slash == std::string::npos) {
    throw std::invalid_argument("Invalid subnet format: " + s);
  }

  std::string ip_part = s.substr(0, slash);
  std::string mask_part = s.substr(slash + 1);

  uint32_t mask_bits = 0;
  try {
    mask_bits = static_cast<uint32_t>(std::stoul(mask_part));
  } catch (...) {
    throw std::invalid_argument("Invalid subnet mask: " + mask_part);
  }
  if (mask_bits > 32) {
    throw std::invalid_argument("Invalid subnet mask (must be <= 32): " + mask_part);
  }

  uint32_t ip = ip_to_int(ip_part);
  uint32_t mask = (mask_bits == 0) ? 0 : (0xFFFFFFFFu << (32 - mask_bits));
  uint32_t base = ip & mask;
  return {base, mask_bits};
}

