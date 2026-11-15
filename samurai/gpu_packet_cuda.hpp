#pragma once

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace samurai::gpu_packet_cuda {

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
  enum class AllocKind : uint8_t {
    kDevice = 0,
    kMappedHost = 1,
    kVulkanBar1P2p = 2,
  };

  uint8_t* ptr = nullptr;
  uint8_t* host_ptr = nullptr;
  uint8_t* host_base_ptr = nullptr;
  size_t size = 0;
  AllocKind alloc_kind = AllocKind::kDevice;

  DeviceBuffer() = default;
  DeviceBuffer(uint8_t* p, size_t n)
      : ptr(p), host_ptr(nullptr), host_base_ptr(nullptr), size(n), alloc_kind(AllocKind::kDevice) {}

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

}  // namespace samurai::gpu_packet_cuda

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

typedef struct samurai_gpu_packet_flow_affinity_v1 {
  int64_t global_tid;
  int32_t global_warp_id;
  int32_t lane;
  int64_t flow_start;
  int64_t flow_id;
} samurai_gpu_packet_flow_affinity_v1;

typedef struct samurai_gpu_packet_flow_update_event_v1 {
  uint64_t version;
  uint64_t epoch;
  uint32_t flow_id;
  uint32_t tcp_seq;
  uint32_t tcp_ack;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t tcp_state;
  uint8_t proto;
  uint16_t flags;
  uint32_t rtt_us;
  uint64_t dpu_ts_ns;
} samurai_gpu_packet_flow_update_event_v1;

int samurai_gpu_packet_publication_budget_us(uint32_t rtt_us, uint32_t* out_budget_us);
int samurai_gpu_packet_seqlock_next_versions(
    uint64_t current_version,
    uint64_t* out_write_begin,
    uint64_t* out_write_commit);
int samurai_gpu_packet_descriptor_transition_valid(
    int32_t from_state,
    int32_t to_state,
    int32_t* out_valid);
int samurai_gpu_packet_compute_flow_affinity_v1(
    int32_t block_idx,
    int32_t block_dim,
    int32_t thread_idx,
    int32_t flows_per_warp,
    int32_t warp_size,
    samurai_gpu_packet_flow_affinity_v1* out);
int samurai_gpu_packet_contract_publish_flow_update_v1(
    const samurai_gpu_packet_flow_update_event_v1* event);
int samurai_gpu_packet_contract_read_hot_flow_v1(
    uint32_t flow_id,
    samurai_gpu_packet_flow_update_event_v1* out_event);
int samurai_gpu_packet_contract_export_region_v1(char* out_spec, size_t out_spec_len);

int samurai_gpu_packet_set_kernel_mode(int mode);
int samurai_gpu_packet_get_kernel_mode();
int samurai_gpu_packet_start_stream(const char* profile_json, int64_t* out_stream_id);
int samurai_gpu_packet_update_stream(int64_t stream_id, const char* update_json);
int samurai_gpu_packet_stop_stream(int64_t stream_id);
const char* samurai_gpu_packet_read_stream_stats(int64_t stream_id);
typedef struct samurai_gpu_packet_stream_stats_snapshot {
  int64_t stream_id;
  int32_t kernel_mode;
  int32_t runtime_active;
  uint64_t submitted;
  uint64_t completed;
  uint64_t quota_left;
  uint64_t persistent_tx_bridge_sent;
  uint64_t persistent_produced;
  uint64_t queue_pressure;
  uint64_t ring_drop_events;
  double scheduler_fairness_cv_pct;
  uint64_t no_progress_events;
  uint64_t persistent_runtime_restarts;
  uint64_t quota_stall;
  uint64_t bridge_drain_batches;
  uint64_t bridge_drain_packets;
  uint64_t ring_occupancy_peak;
  uint64_t compat_fallback_count;
  uint64_t persistent_bridge_ipg_ns;
  uint64_t max_packet_bytes;
} samurai_gpu_packet_stream_stats_snapshot;
int samurai_gpu_packet_read_stream_stats_snapshot(
    int64_t stream_id,
    samurai_gpu_packet_stream_stats_snapshot* out_stats);
int samurai_gpu_packet_shutdown_runtime();

void samurai_gpu_packet_free(void* ptr);
const char* samurai_gpu_packet_last_error();

// Consumer GeForce BAR1 Zero-Copy P2P DMA Arena introspection C ABI.
int samurai_gpu_packet_p2p_bar1_available(void);
int samurai_gpu_packet_p2p_get_arena_info(
    uint64_t* out_bar1_phys,
    void** out_host_ptr,
    void** out_dev_ptr,
    size_t* out_size);

// Telecom GTP-U 4G/5G Hardware Data Plane C ABI.
int samurai_gpu_packet_generate_gtpu_packets(
    const char* config_json,
    int count,
    void** out_packets_ptr,
    size_t* out_total_bytes,
    int* out_packet_size);
int samurai_gpu_packet_telco_upsert_tunnels_v1(
    const void* entries,
    uint32_t count);
int samurai_gpu_packet_telco_clear_tunnels_v1(void);
int samurai_gpu_packet_telco_verify_rx_batch_v1(
    const void* rx_base_ptr,
    uint32_t slot_stride,
    uint32_t count,
    void* out_stats);
int samurai_gpu_packet_telco_read_rx_stats_v1(
    void* out_stats);
int samurai_gpu_packet_p2p_tx_bar1_batch_v1(
    const uint32_t* slot_indices,
    const uint16_t* pkt_lengths,
    uint32_t count,
    uint32_t* out_submitted_count);
int samurai_gpu_packet_p2p_set_active_ring_v1(int ring_handle);
int samurai_gpu_packet_p2p_get_active_ring_v1(void);
int samurai_gpu_packet_telco_attach_cups_shm_v1(
    const char* shm_path,
    uint32_t max_tunnels);
int samurai_gpu_packet_telco_detach_cups_shm_v1(void);

// Isolated defense/classifier C ABI.
int samurai_gpu_packet_defense_init(
    const char* runtime,
    const char* engine_path,
    const char* rdma_mode,
    int rdma_strict,
    int64_t max_batch_size,
    int64_t flush_timeout_ms);
int samurai_gpu_packet_classify_batch(
    const uint8_t* packets_flat,
    const int32_t* packet_lengths,
    int64_t packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason);
int samurai_gpu_packet_classify_from_ingress(
    int32_t max_packets,
    int32_t max_packet_size,
    int32_t* out_packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason);
const char* samurai_gpu_packet_read_classifier_stats();
int samurai_gpu_packet_defense_get_doca_rx_gpu_handle(uint64_t* out_gpu_rxq_handle);
int samurai_gpu_packet_defense_shutdown();
const char* samurai_gpu_packet_defense_last_error();

}
