#pragma once

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ddos_samurai::gpu_packet_cuda {

constexpr int ETHERNET_HEADER_LEN = 14;
constexpr int MIN_ETHERNET_FRAME = 64;
constexpr int IP_HEADER_LEN = 20;
constexpr int IP_HEADER_MAX_LEN = 60;
constexpr int IPV6_HEADER_LEN = 40;

constexpr int TCP_HEADER_LEN_NO_OPT = 20;
constexpr int TCP_OPTIONS_LEN = 20;
constexpr int TCP_HEADER_LEN_WITH_OPT = 40;
constexpr int UDP_HEADER_LEN = 8;
constexpr int ICMP_HEADER_LEN = 8;

constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr uint8_t ICMP_ECHO_REPLY = 0;

constexpr uint8_t TCP_PROTOCOL = 6;
constexpr uint8_t UDP_PROTOCOL = 17;
constexpr uint8_t ICMP_PROTOCOL = 1;

constexpr int TEMPLATE_CONST_MAX = 4096;
constexpr int POOL_CONST_MAX = 32768;

struct GenerationTelemetry {
  uint64_t gpu_template_h2d_copy_count = 0;
  uint64_t gpu_template_h2d_copy_bytes = 0;
  uint64_t gpu_rng_state_alloc_count = 0;
  uint64_t gpu_rng_state_reuse_count = 0;
  uint64_t gpu_template_cache_hit_count = 0;
  uint64_t gpu_template_cache_miss_count = 0;
  int template_cache_entries = 0;
  int rng_pool_entries = 0;
  int template_cache_limit = 0;
  int rng_pool_limit = 0;
};

struct GPUPoolTelemetry {
  uint64_t total_bytes = 0;
  uint64_t used_bytes = 0;
  uint64_t peak_used_bytes = 0;
  uint64_t buffers_allocated = 0;
  uint64_t buffers_in_use = 0;
  uint64_t pool_hits = 0;
  uint64_t pool_misses = 0;
  uint64_t oom_recoveries = 0;
  double hit_rate_pct = 0.0;
};

struct PinnedPoolTelemetry {
  uint64_t buffers_allocated = 0;
  uint64_t total_nbytes = 0;
  uint64_t max_bytes = 0;
  uint64_t high_watermark_bytes = 0;
  uint64_t pinned_enabled = 0;
  uint64_t pool_hits = 0;
  uint64_t pool_misses = 0;
  uint64_t pool_evictions = 0;
  uint64_t alloc_fallbacks = 0;
  uint64_t oversize_bypass = 0;
  double hit_rate_pct = 0.0;
};

struct PoolTelemetry {
  uint64_t d2h_transfer_count = 0;
  uint64_t d2h_transfer_bytes = 0;
  GPUPoolTelemetry gpu_pool;
  PinnedPoolTelemetry pinned_host_pool;
};

struct DeviceBuffer {
  uint8_t* ptr = nullptr;
  size_t size = 0;

  DeviceBuffer() = default;
  DeviceBuffer(uint8_t* p, size_t n) : ptr(p), size(n) {}

  DeviceBuffer(const DeviceBuffer&) = delete;
  DeviceBuffer& operator=(const DeviceBuffer&) = delete;

  DeviceBuffer(DeviceBuffer&& other) noexcept;
  DeviceBuffer& operator=(DeviceBuffer&& other) noexcept;

  ~DeviceBuffer();

  bool valid() const { return ptr != nullptr && size > 0; }
  void reset();
};

struct PacketResult {
  DeviceBuffer packets_gpu;
  int packet_size = 0;
};

struct BenchmarkPathResult {
  double avg_ms = 0.0;
  double pps = 0.0;
  uint64_t cache_hit = 0;
  uint64_t cache_miss = 0;
  uint64_t h2d_copy_count = 0;
  uint64_t h2d_copy_bytes = 0;
  uint64_t rng_alloc = 0;
  uint64_t rng_reuse = 0;
};

struct BenchmarkResult {
  int count = 0;
  int iterations = 0;
  int template_size = 0;
  BenchmarkPathResult constant;
  BenchmarkPathResult global;
  BenchmarkPathResult auto_path;
  BenchmarkPathResult forced_global_fallback;
  GenerationTelemetry generation_telemetry;
};

struct GPUInfo {
  bool available = false;
  std::string name;
  std::string compute_capability;
  double total_memory_mb = 0.0;
  double free_memory_mb = 0.0;
  int max_threads_per_block = 0;
  int max_shared_memory_per_block = 0;
  int warp_size = 0;
  std::string error;
};

class GPUPacketError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class GPUMemoryError : public GPUPacketError {
 public:
  using GPUPacketError::GPUPacketError;
};

class GPUKernelError : public GPUPacketError {
 public:
  using GPUPacketError::GPUPacketError;
};

class GPUPacketGenerator {
 public:
  explicit GPUPacketGenerator(
      int max_batch_size = 100000,
      std::string real_src_ip = "192.168.1.100",
      bool spoof_ip = true,
      bool has_ethernet = false,
      std::string spoof_subnet = "1.0.0.0/8");

  std::vector<std::vector<uint8_t>> generate_batch(
      const std::vector<uint8_t>& template_bytes,
      int batch_size,
      cudaStream_t stream = nullptr,
      uint64_t gateway_mac = 0xFFFFFFFFFFFFull);

 private:
  int max_batch_size_;
  std::string real_src_ip_;
  bool spoof_ip_;
  bool has_ethernet_;
  std::string spoof_subnet_;
};

bool init_gpu();
bool is_gpu_available();
std::pair<bool, std::string> check_gpu_available();
GPUInfo get_gpu_info();

GenerationTelemetry get_generation_telemetry();
void reset_generation_telemetry();
void clear_generation_caches();

PoolTelemetry get_pool_telemetry();
void configure_pinned_host_pool(
    std::optional<int> max_mb = std::nullopt,
    std::optional<int> max_bytes = std::nullopt);

std::vector<uint8_t> copy_gpu_to_host_pinned(
    const DeviceBuffer& gpu_arr,
    const std::string& key = "default",
    cudaStream_t stream = nullptr,
    bool blocking = true);

PacketResult generate_packets(
    int64_t count,
    const std::string& target_ip,
    int64_t target_port,
    const std::string& protocol = "tcp",
    bool spoof_ip = true,
    const std::string& real_src_ip = "192.168.1.100",
    int64_t tcp_flags = 0x02,
    bool has_ethernet = true,
    int64_t window = -1,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8");

PacketResult generate_packets_from_template(
    const std::vector<uint8_t>& template_bytes,
    int64_t count,
    const std::string& real_src_ip = "192.168.1.100",
    bool spoof_ip = true,
    bool has_ethernet = true,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8",
    bool force_global_fallback = false);

PacketResult generate_packets_from_template_pool(
    const std::vector<std::vector<uint8_t>>& templates_bytes_list,
    int64_t count,
    const std::string& target_ip,
    const std::string& real_src_ip = "192.168.1.100",
    bool spoof_ip = true,
    int64_t specific_src_port = -1,
    bool has_ethernet = true,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8",
    bool force_global_fallback = false);

PacketResult generate_stateful_packets(
    const std::vector<std::vector<uint8_t>>& templates_bytes_list,
    int64_t count,
    const std::string& target_ip,
    bool spoof_ip = true,
    const std::string& real_src_ip = "192.168.1.100",
    int64_t specific_src_port = -1,
    bool has_ethernet = true,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8",
    const std::vector<uint32_t>& seq_list = {},
    const std::vector<uint32_t>& ack_list = {},
    const std::vector<uint8_t>& state_list = {},
    const std::vector<uint32_t>& actual_lengths = {},
    const std::vector<uint16_t>& window_sizes = {},
    const std::vector<uint16_t>& mss_values = {},
    const std::vector<uint8_t>& ttls = {},
    bool force_global_fallback = false);

PacketResult generate_fragmented_packets(
    const std::vector<uint8_t>& payload_bytes,
    int64_t count,
    const std::string& target_ip,
    int64_t target_port,
    const std::string& protocol = "udp",
    bool spoof_ip = true,
    const std::string& real_src_ip = "192.168.1.100",
    bool has_ethernet = true,
    int64_t frag1_size = 1500,
    int64_t frag2_size = 1500,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8");

PacketResult generate_amplification_packets(
    const std::vector<uint8_t>& template_bytes,
    const std::vector<std::string>& reflectors_ips,
    const std::string& victim_ip,
    int64_t count,
    bool has_ethernet = true,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull);

PacketResult generate_icmp_packets(
    int64_t count,
    const std::string& target_ip,
    const std::string& real_src_ip = "192.168.1.100",
    bool spoof_ip = true,
    bool has_ethernet = true,
    int64_t icmp_type = 8,
    int64_t icmp_code = 0,
    int64_t payload_size = 56,
    cudaStream_t stream = nullptr,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8");

BenchmarkResult benchmark_template_generation_paths(
    const std::vector<uint8_t>& template_bytes,
    int count = 200000,
    int iterations = 5,
    const std::string& real_src_ip = "192.168.1.100",
    bool spoof_ip = true,
    bool has_ethernet = true,
    uint64_t gateway_mac = 0xFFFFFFFFFFFFull,
    const std::string& spoof_subnet = "1.0.0.0/8");

uint32_t ip_to_int(const std::string& ip_str);
std::string int_to_ip(uint32_t ip_int);
uint64_t mac_to_int(const std::string& mac_str);
std::string int_to_mac(uint64_t mac_int);
std::pair<uint32_t, uint32_t> parse_subnet(const std::string& subnet);

void safe_kernel_launch(
    const std::string& kernel_name,
    cudaError_t launch_status,
    cudaStream_t stream = nullptr,
    bool synchronize = false);

}  // namespace ddos_samurai::gpu_packet_cuda

extern "C" {

// C ABI bridge used by Python backend glue.
int samurai_gpu_packet_generate_packets(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_packets_from_template(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_packets_from_template_pool(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_stateful_packets(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_fragmented_packets(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_amplification_packets(
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
    int* out_packet_size);

int samurai_gpu_packet_generate_icmp_packets(
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
    int* out_packet_size);

void samurai_gpu_packet_free(void* ptr);
const char* samurai_gpu_packet_last_error();

}
