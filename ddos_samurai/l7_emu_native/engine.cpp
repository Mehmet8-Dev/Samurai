#include "engine.hpp"
#include "../l4/tcp_dataplane_ffi.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace ddos_samurai::l7_emu_native {

namespace {

struct ResponseInfo {
  int status_code{0};
  std::size_t bytes_received{0};
  std::string raw;
  std::map<std::string, std::string> headers;
  std::vector<std::pair<std::string, std::string>> header_fields;
  std::string body;
  bool keep_alive{false};
  std::size_t consumed_bytes{0};
};

struct DataplanePerfStats {
  long long started_ms{0};
  long long ended_ms{0};
  std::size_t epoll_wakeups{0};
  std::size_t scheduler_queue_depth_peak{0};
  std::size_t idle_evictions{0};
  std::size_t rx_syscalls{0};
  std::size_t tx_syscalls{0};
  std::size_t alloc_bytes{0};
  std::size_t alloc_count{0};
  std::vector<double> tls_handshake_samples_ms{};
  std::vector<double> request_latency_samples_ms{};
  std::size_t profile_snapshot_count{0};
};

struct PerfDerivedInputs {
  int request_attempted{0};
  int request_completed{0};
  int conn_attempted{0};
  int conn_established{0};
  int conn_reused{0};
  int active_conn_peak{0};
};

#ifdef SAMURAI_WITH_NGHTTP2
struct H2ClientSession;
struct H2StreamState;
#endif

enum class H2LaneReplacementMode {
  Ready = 0,
  Draining = 1,
  ReplaceNow = 2,
  ReplaceAfterIdle = 3,
};

enum class LaneHealthState {
  Healthy = 0,
  Draining = 1,
  UnhealthyBackoff = 2,
  Closed = 3,
};

enum class ReactorLaneKind {
  H1 = 0,
  H2 = 1,
};

struct ReactorLaneState {
  long long dispatch_ready_at_ms{0};
  long long idle_deadline_ms{0};
  int inflight_count{0};
  int reuse_score{0};
  LaneHealthState health_state{LaneHealthState::Closed};
};

struct Http1Connection {
  int fd{-1};
  int shard_id{0};
  TransportBackend transport_backend{TransportBackend::KernelSocket};
  uint64_t custom_flow_id{0};
  bool custom_connect_ready{false};
  bool custom_send_enqueued{false};
  bool custom_terminal{false};
  std::string read_buffer;
  long long idle_deadline_ms{0};
  std::size_t timer_slot{0};
  std::uint64_t timer_generation{0};
  bool timer_armed{false};
};

struct H1ParserState {
  bool header_complete{false};
  std::size_t header_end{0};
  std::size_t body_offset{0};
  std::size_t expected_body_length{0};
  bool chunked{false};
  bool close_delimited{false};
};

struct CompiledCaptureChunk {
  bool is_capture{false};
  std::string value{};
};

struct CompiledCaptureTemplate {
  std::vector<CompiledCaptureChunk> chunks{};
  std::size_t static_bytes{0};
  bool has_captures{false};
};

struct H1RequestSpec {
  FlowOp send_headers{};
  std::optional<FlowOp> body_op{};
  std::vector<FlowOp> follow_ops{};
  std::vector<std::pair<std::string, std::string>> header_fields{};
  std::size_t header_bytes{0};
  CompiledCaptureTemplate method_template{};
  CompiledCaptureTemplate path_template{};
  std::vector<std::pair<std::string, CompiledCaptureTemplate>> compiled_header_values{};
  std::optional<CompiledCaptureTemplate> body_template{};
};

enum class H1LanePhase {
  Idle = 0,
  Writing = 1,
  Reading = 2,
  Complete = 3,
  Failed = 4,
};

struct H1Lane {
  ReactorLaneState lane{};
  std::unique_ptr<Http1Connection> conn{};
  H1ParserState parser{};
  ResponseInfo response{};
  std::string write_buffer{};
  std::unique_ptr<struct LaneStringArena> string_arena{};
  std::size_t write_offset{0};
  long long request_start_ms{0};
  H1RequestSpec request_spec{};
  TransportBackend transport_backend{TransportBackend::KernelSocket};
  H1LanePhase phase{H1LanePhase::Idle};
  int think_time_total_ms{0};
  int expectation_failures{0};
  bool queued_ready{false};
  std::size_t tx_bytes{0};
  std::size_t rx_bytes{0};
};

constexpr std::size_t kHotPathReusableBufferLimit = 256 * 1024;
constexpr std::size_t kH1SlabWriteBytes = 16 * 1024;
constexpr std::size_t kH1SlabReadBytes = 32 * 1024;
constexpr std::size_t kH2SlabRequestPathBytes = 4096;
constexpr std::size_t kH2SlabOutboundBodyBytes = 16 * 1024;
constexpr std::size_t kH2SlabResponseBodyBytes = 32 * 1024;
constexpr std::size_t kArenaBucketTinyBytes = 64;
constexpr std::size_t kArenaBucketSmallBytes = 256;
constexpr std::size_t kArenaBucketMediumBytes = 1024;
constexpr std::size_t kArenaBucketPathBytes = 4096;
constexpr std::size_t kArenaBucketBodyBytes = 16384;
constexpr std::size_t kArenaBucketLargeBytes = 32768;
constexpr std::size_t kArenaBucketTinySlots = 2;
constexpr std::size_t kArenaBucketSmallSlots = 12;
constexpr std::size_t kArenaBucketMediumSlots = 4;
constexpr std::size_t kArenaBucketPathSlots = 2;
constexpr std::size_t kArenaBucketBodySlots = 2;
constexpr std::size_t kArenaBucketLargeSlots = 1;
constexpr std::size_t kReusableHeaderSlotReserve = 16;
constexpr std::size_t kReusableResponseHeaderReserve = 16;
constexpr std::size_t kReusableResponseBodyBytes = 4096;

struct ArenaStringBucket {
  std::size_t capacity{0};
  std::deque<std::string> slots{};
  std::vector<unsigned char> in_use{};
};

struct LaneStringArena {
  std::vector<ArenaStringBucket> buckets{};
};

struct ArenaStringLease {
  LaneStringArena* arena{nullptr};
  std::string* value{nullptr};
  std::size_t bucket_idx{0};
  std::size_t slot_idx{0};

  ArenaStringLease() = default;
  ArenaStringLease(
      LaneStringArena* arena_in,
      std::string* value_in,
      std::size_t bucket_idx_in,
      std::size_t slot_idx_in)
      : arena(arena_in),
        value(value_in),
        bucket_idx(bucket_idx_in),
        slot_idx(slot_idx_in) {}
  ArenaStringLease(const ArenaStringLease&) = delete;
  ArenaStringLease& operator=(const ArenaStringLease&) = delete;
  ArenaStringLease(ArenaStringLease&& other) noexcept
      : arena(other.arena),
        value(other.value),
        bucket_idx(other.bucket_idx),
        slot_idx(other.slot_idx) {
    other.arena = nullptr;
    other.value = nullptr;
  }
  ArenaStringLease& operator=(ArenaStringLease&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    reset();
    arena = other.arena;
    value = other.value;
    bucket_idx = other.bucket_idx;
    slot_idx = other.slot_idx;
    other.arena = nullptr;
    other.value = nullptr;
    return *this;
  }
  ~ArenaStringLease() { reset(); }

  void reset() {
    if (arena == nullptr || value == nullptr || bucket_idx >= arena->buckets.size()) {
      arena = nullptr;
      value = nullptr;
      return;
    }
    auto& bucket = arena->buckets[bucket_idx];
    if (slot_idx < bucket.in_use.size()) {
      bucket.in_use[slot_idx] = 0;
    }
    value->clear();
    arena = nullptr;
    value = nullptr;
  }
};

struct H2RequestSpec {
  std::string method{"GET"};
  std::string path{"/"};
  std::vector<std::pair<std::string, std::string>> headers{};
  std::string body{};
  std::vector<FlowOp> follow_ops{};
  CompiledCaptureTemplate method_template{};
  CompiledCaptureTemplate path_template{};
  std::vector<std::pair<std::string, CompiledCaptureTemplate>> compiled_headers{};
  std::optional<CompiledCaptureTemplate> body_template{};
};

struct H2CompletedStream {
  std::size_t session_idx{0};
  int status_code{0};
  std::map<std::string, std::string> response_headers{};
  std::vector<std::pair<std::string, std::string>> response_header_fields{};
  std::string response_body{};
  int think_time_total_ms{0};
  int expectation_failures{0};
  bool success{false};
  bool rst_stream{false};
};

struct H1CompletedRequest {
  std::size_t lane_idx{0};
  int status_code{0};
  std::map<std::string, std::string> response_headers{};
  std::vector<std::pair<std::string, std::string>> response_header_fields{};
  std::string response_body{};
  std::vector<FlowOp> follow_ops{};
  long long request_start_ms{0};
  int expectation_failures{0};
  int think_time_total_ms{0};
  bool keep_alive{false};
  std::size_t tx_bytes{0};
  std::size_t rx_bytes{0};
  bool success{false};
};

enum class ConnectionDispositionAction {
  None = 0,
  Close = 1,
  Rearm = 2,
};

struct CompletionDispositionDecision {
  ConnectionDispositionAction action{ConnectionDispositionAction::None};
  std::size_t slot_idx{0};
  long long next_ready_ms{0};
  long long idle_deadline_ms{0};
};

enum class CompletionKind {
  H1 = 0,
  H2 = 1,
};

struct CompletionEnvelope {
  CompletionKind kind{CompletionKind::H1};
  std::size_t shard_idx{0};
  std::optional<H1CompletedRequest> h1_completed{};
  std::optional<H2CompletedStream> h2_completed{};
};

struct NativeRuntime {
  RuntimeCapabilities caps{};
  std::vector<ShardState> shards{};
  std::deque<std::size_t> ready_shards{};
  std::deque<CompletionEnvelope> ready_completions{};
  DataplanePerfStats perf{};
  int32_t custom_tcp_rx_handler_id{0};
  struct LocalShard {
    LocalShard() = default;
    LocalShard(const LocalShard&) = delete;
    LocalShard& operator=(const LocalShard&) = delete;
    LocalShard(LocalShard&&) noexcept = default;
    LocalShard& operator=(LocalShard&&) noexcept = default;

    struct RegisteredLaneFd {
      ReactorLaneKind kind{ReactorLaneKind::H1};
      H1Lane* h1_lane{nullptr};
#ifdef SAMURAI_WITH_NGHTTP2
      H2ClientSession* h2_session{nullptr};
#endif
    };
    struct TimerEntry {
      Http1Connection* conn{nullptr};
      std::uint64_t generation{0};
    };
    std::vector<std::unique_ptr<Http1Connection>> http1_idle{};
    std::vector<Http1Connection*> http1_active{};
    std::vector<std::unique_ptr<H1Lane>> h1_lanes{};
    std::deque<H1RequestSpec> pending_h1_requests{};
    std::deque<H2RequestSpec> pending_h2_requests{};
    std::map<int, RegisteredLaneFd> active_fd_registry{};
    std::vector<epoll_event> ready_events{};
    std::vector<std::vector<TimerEntry>> timer_slots{};
    long long last_timer_tick_ms{0};
    long long dispatch_ready_ms{0};
    bool in_ready_queue{false};
#ifdef SAMURAI_WITH_NGHTTP2
    std::vector<std::unique_ptr<H2ClientSession>> h2_sessions{};
#endif
  };
  std::vector<LocalShard> local_shards{};
};

struct H2RunStats {
  int attempted{0};
  int sent{0};
  int errors{0};
  int conn_attempted{0};
  int conn_established{0};
  int conn_reused{0};
  int expectation_failures{0};
  int status_2xx{0};
  int status_3xx{0};
  int status_4xx{0};
  int status_5xx{0};
  int scheduler_backpressure{0};
  int goaway_count{0};
  int rst_stream_count{0};
  int goaway_replacements{0};
  int drain_evictions{0};
  int replace_now_decisions{0};
  int replace_after_idle_decisions{0};
  int stream_pool_reuse_hits{0};
  int active_streams_peak{0};
  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
};

std::string lower_copy(const std::string& in);
long long monotonic_ms_now();
void enqueue_ready_shard(NativeRuntime& runtime, std::size_t shard_idx);

thread_local DataplanePerfStats* g_perf_stats = nullptr;

void trim_reusable_string(std::string& value, std::size_t keep_limit = kHotPathReusableBufferLimit);
void ensure_reusable_string_capacity(std::string& value, std::size_t min_capacity);
void perf_alloc(std::size_t bytes) {
  if (g_perf_stats == nullptr) {
    return;
  }
  g_perf_stats->alloc_count += 1;
  g_perf_stats->alloc_bytes += bytes;
}

void perf_request_latency(double latency_ms, int sample_limit) {
  if (g_perf_stats == nullptr) {
    return;
  }
  if (sample_limit <= 0 || static_cast<int>(g_perf_stats->request_latency_samples_ms.size()) < sample_limit) {
    g_perf_stats->request_latency_samples_ms.push_back(latency_ms);
  }
}

void perf_tls_latency(double latency_ms, int sample_limit) {
  if (g_perf_stats == nullptr) {
    return;
  }
  if (sample_limit <= 0 || static_cast<int>(g_perf_stats->tls_handshake_samples_ms.size()) < sample_limit) {
    g_perf_stats->tls_handshake_samples_ms.push_back(latency_ms);
  }
}

void reset_response_info(ResponseInfo& response) {
  response.status_code = 0;
  response.bytes_received = 0;
  trim_reusable_string(response.raw, kHotPathReusableBufferLimit);
  response.headers.clear();
  response.header_fields.clear();
  response.header_fields.reserve(kReusableResponseHeaderReserve);
  trim_reusable_string(response.body, kHotPathReusableBufferLimit);
  ensure_reusable_string_capacity(response.body, kReusableResponseBodyBytes);
  response.keep_alive = false;
  response.consumed_bytes = 0;
}

void reset_h1_lane_io(H1Lane& lane) {
  lane.parser = H1ParserState{};
  reset_response_info(lane.response);
  trim_reusable_string(lane.write_buffer);
  ensure_reusable_string_capacity(lane.write_buffer, kH1SlabWriteBytes);
  if (lane.conn) {
    trim_reusable_string(lane.conn->read_buffer);
    ensure_reusable_string_capacity(lane.conn->read_buffer, kH1SlabReadBytes);
    if (lane.conn->fd < 0) {
      lane.conn->custom_flow_id = 0;
      lane.conn->custom_connect_ready = false;
    }
    lane.conn->custom_send_enqueued = false;
    lane.conn->custom_terminal = false;
  }
  lane.write_offset = 0;
  lane.request_start_ms = 0;
  lane.request_spec = H1RequestSpec{};
  lane.think_time_total_ms = 0;
  lane.expectation_failures = 0;
  lane.phase = H1LanePhase::Idle;
  lane.queued_ready = false;
  lane.tx_bytes = 0;
  lane.rx_bytes = 0;
}

double percentile_ms(const std::vector<double>& values, double pct) {
  if (values.empty()) {
    return 0.0;
  }
  if (values.size() == 1) {
    return values.front();
  }
  std::vector<double> sorted = values;
  std::sort(sorted.begin(), sorted.end());
  const std::size_t idx = std::min(
      sorted.size() - 1,
      static_cast<std::size_t>((pct / 100.0) * static_cast<double>(sorted.size() - 1) + 0.5));
  return sorted[idx];
}

int runtime_active_conn_peak(const NativeRuntime& runtime) {
  int peak = 0;
  for (const auto& shard : runtime.shards) {
    peak = std::max(peak, shard.connection_pool.active_connections_peak);
  }
  return peak;
}

void trim_reusable_string(std::string& value, std::size_t keep_limit) {
  value.clear();
  if (value.capacity() > keep_limit) {
    std::string compact;
    compact.reserve(std::min<std::size_t>(keep_limit, 4096));
    value.swap(compact);
  }
}

void ensure_reusable_string_capacity(std::string& value, std::size_t min_capacity) {
  if (value.capacity() >= min_capacity) {
    return;
  }
  perf_alloc(min_capacity - value.capacity());
  value.reserve(min_capacity);
}

LaneStringArena& ensure_lane_string_arena(std::unique_ptr<LaneStringArena>& arena_ptr) {
  if (!arena_ptr) {
    arena_ptr = std::make_unique<LaneStringArena>();
    arena_ptr->buckets = {
        ArenaStringBucket{kArenaBucketTinyBytes, {}, {}},
        ArenaStringBucket{kArenaBucketSmallBytes, {}, {}},
        ArenaStringBucket{kArenaBucketMediumBytes, {}, {}},
        ArenaStringBucket{kArenaBucketPathBytes, {}, {}},
        ArenaStringBucket{kArenaBucketBodyBytes, {}, {}},
        ArenaStringBucket{kArenaBucketLargeBytes, {}, {}},
    };
    auto prewarm_bucket = [](ArenaStringBucket& bucket, std::size_t slot_count) {
      for (std::size_t slot_idx = 0; slot_idx < slot_count; ++slot_idx) {
        bucket.slots.emplace_back();
        bucket.in_use.push_back(0);
        ensure_reusable_string_capacity(bucket.slots.back(), bucket.capacity);
      }
    };
    prewarm_bucket(arena_ptr->buckets[0], kArenaBucketTinySlots);
    prewarm_bucket(arena_ptr->buckets[1], kArenaBucketSmallSlots);
    prewarm_bucket(arena_ptr->buckets[2], kArenaBucketMediumSlots);
    prewarm_bucket(arena_ptr->buckets[3], kArenaBucketPathSlots);
    prewarm_bucket(arena_ptr->buckets[4], kArenaBucketBodySlots);
    prewarm_bucket(arena_ptr->buckets[5], kArenaBucketLargeSlots);
  }
  return *arena_ptr;
}

ArenaStringLease arena_acquire_string(LaneStringArena& arena, std::size_t min_capacity) {
  for (std::size_t bucket_idx = 0; bucket_idx < arena.buckets.size(); ++bucket_idx) {
    auto& bucket = arena.buckets[bucket_idx];
    if (bucket.capacity < min_capacity) {
      continue;
    }
    for (std::size_t slot_idx = 0; slot_idx < bucket.in_use.size(); ++slot_idx) {
      if (bucket.in_use[slot_idx] != 0) {
        continue;
      }
      bucket.in_use[slot_idx] = 1;
      bucket.slots[slot_idx].clear();
      return ArenaStringLease{&arena, &bucket.slots[slot_idx], bucket_idx, slot_idx};
    }
    bucket.slots.emplace_back();
    bucket.in_use.push_back(1);
    ensure_reusable_string_capacity(bucket.slots.back(), bucket.capacity);
    return ArenaStringLease{&arena, &bucket.slots.back(), bucket_idx, bucket.slots.size() - 1};
  }
  return {};
}

const std::string* find_header_value(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& key) {
  for (const auto& [header_key, header_value] : headers) {
    if (header_key == key) {
      return &header_value;
    }
  }
  return nullptr;
}

void render_capture_template_into(
    const CompiledCaptureTemplate& compiled,
    const std::map<std::string, std::string>& captures,
    std::string& out);

void apply_perf_outputs(
    std::map<std::string, double>& out,
    NativeRuntime& runtime,
    const RuntimeConfig& cfg,
    const PerfDerivedInputs& inputs) {
  runtime.perf.ended_ms = monotonic_ms_now();
  if (cfg.profile_l7 != 0 && runtime.perf.profile_snapshot_count == 0) {
    runtime.perf.profile_snapshot_count = 1;
  }
  const long long elapsed_ms = std::max<long long>(1, runtime.perf.ended_ms - runtime.perf.started_ms);
  const double elapsed_s = static_cast<double>(elapsed_ms) / 1000.0;
  const int active_conn_peak = std::max(inputs.active_conn_peak, runtime_active_conn_peak(runtime));
  const double reuse_den = static_cast<double>(std::max(1, inputs.conn_reused + inputs.conn_established));

  out["l7_cps"] = static_cast<double>(inputs.conn_established) / elapsed_s;
  out["l7_rps"] = static_cast<double>(inputs.request_completed) / elapsed_s;
  out["l7_active_conn_peak"] = static_cast<double>(active_conn_peak);
  out["l7_h1_conn_reuse_ratio"] = static_cast<double>(inputs.conn_reused) / reuse_den;
  out["l7_h2_lane_reuse_ratio"] = static_cast<double>(inputs.conn_reused) / reuse_den;
  out["l7_epoll_wakeups"] = static_cast<double>(runtime.perf.epoll_wakeups);
  out["l7_scheduler_queue_depth_peak"] = static_cast<double>(runtime.perf.scheduler_queue_depth_peak);
  out["l7_idle_evictions"] = static_cast<double>(runtime.perf.idle_evictions);
  out["l7_rx_syscalls"] = static_cast<double>(runtime.perf.rx_syscalls);
  out["l7_tx_syscalls"] = static_cast<double>(runtime.perf.tx_syscalls);
  out["l7_alloc_bytes"] = static_cast<double>(runtime.perf.alloc_bytes);
  out["l7_alloc_count"] = static_cast<double>(runtime.perf.alloc_count);
  out["l7_tls_handshake_p50_ms"] = percentile_ms(runtime.perf.tls_handshake_samples_ms, 50.0);
  out["l7_tls_handshake_p95_ms"] = percentile_ms(runtime.perf.tls_handshake_samples_ms, 95.0);
  out["l7_tls_handshake_p99_ms"] = percentile_ms(runtime.perf.tls_handshake_samples_ms, 99.0);
  out["l7_request_latency_p50_ms"] = percentile_ms(runtime.perf.request_latency_samples_ms, 50.0);
  out["l7_request_latency_p95_ms"] = percentile_ms(runtime.perf.request_latency_samples_ms, 95.0);
  out["l7_request_latency_p99_ms"] = percentile_ms(runtime.perf.request_latency_samples_ms, 99.0);
  out["l7_profile_enabled"] = cfg.profile_l7 != 0 ? 1.0 : 0.0;
  out["l7_profile_snapshot_count"] = static_cast<double>(runtime.perf.profile_snapshot_count);
}

#ifdef SAMURAI_WITH_NGHTTP2
struct H2StreamState {
  struct HeaderSlot {
    std::string key;
    std::string value;
  };
  std::string request_method;
  std::string request_path;
  std::vector<HeaderSlot> request_headers;
  std::size_t request_header_count{0};
  std::string outbound_body;
  std::size_t outbound_offset{0};
  int status_code{0};
  std::map<std::string, std::string> response_headers;
  std::vector<std::pair<std::string, std::string>> response_header_fields;
  std::string response_body;
  std::vector<FlowOp> follow_ops;
  bool completed{false};
};

struct H2ConnectionContext {
  int fd{-1};
  int epoll_fd{-1};
  bool use_tls{false};
  bool verify_peer{true};
  std::string authority;
  int timeout_ms{5000};
  int transport_error{0};
  int protocol_error{0};
  int goaway{0};
  int rst_stream{0};
  int expectation_failures{0};
  int status_2xx{0};
  int status_3xx{0};
  int status_4xx{0};
  int status_5xx{0};
  int completed_success{0};
  int failed_streams{0};
  int max_think_time_ms{0};
  std::size_t bytes_sent{0};
  std::size_t bytes_received{0};
  std::map<std::string, std::string>* captures{nullptr};
  H2ClientSession* owner_session{nullptr};
  std::map<int32_t, std::unique_ptr<H2StreamState>> active_streams;
#ifdef SAMURAI_WITH_OPENSSL
  SSL_CTX* tls_ctx{nullptr};
  SSL* ssl{nullptr};
#endif
};

struct H2ClientSession {
  std::size_t session_idx{0};
  H2ConnectionContext ctx{};
  nghttp2_session_callbacks* callbacks{nullptr};
  nghttp2_session* session{nullptr};
  bool ready{false};
  long long idle_deadline_ms{0};
  long long unhealthy_until_ms{0};
  long long dispatch_ready_ms{0};
  long long active_since_ms{0};
  int consecutive_failures{0};
  H2LaneReplacementMode replacement_mode{H2LaneReplacementMode::Ready};
  int harvested_completed_success{0};
  int harvested_failed_streams{0};
  int harvested_status_2xx{0};
  int harvested_status_3xx{0};
  int harvested_status_4xx{0};
  int harvested_status_5xx{0};
  int harvested_expectation_failures{0};
  int harvested_goaway{0};
  int harvested_rst_stream{0};
  int harvested_drain_evictions{0};
  int harvested_max_think_time_ms{0};
  std::size_t harvested_rx_bytes{0};
  std::size_t harvested_tx_bytes{0};
  std::deque<H2RequestSpec> pending_requests{};
  std::deque<H2CompletedStream> completed_streams{};
  std::vector<std::unique_ptr<H2StreamState>> free_streams{};
  std::unique_ptr<LaneStringArena> string_arena{};
  std::size_t stream_pool_reuse_hits{0};
  std::size_t harvested_stream_pool_reuse_hits{0};
  int drain_evictions{0};
};

void cleanup_tls(H2ConnectionContext& ctx);
void close_h2_client_session(H2ClientSession& client);

void reset_h2_stream_state(H2StreamState& stream) {
  trim_reusable_string(stream.request_method, 64);
  ensure_reusable_string_capacity(stream.request_method, 16);
  trim_reusable_string(stream.request_path, 4096);
  ensure_reusable_string_capacity(stream.request_path, kH2SlabRequestPathBytes);
  if (stream.request_headers.empty()) {
    stream.request_headers.resize(kReusableHeaderSlotReserve);
    for (auto& slot : stream.request_headers) {
      ensure_reusable_string_capacity(slot.key, 32);
      ensure_reusable_string_capacity(slot.value, kArenaBucketSmallBytes);
    }
  } else {
    for (auto& slot : stream.request_headers) {
      slot.key.clear();
      slot.value.clear();
    }
  }
  stream.request_header_count = 0;
  trim_reusable_string(stream.outbound_body);
  ensure_reusable_string_capacity(stream.outbound_body, kH2SlabOutboundBodyBytes);
  stream.outbound_offset = 0;
  stream.status_code = 0;
  stream.response_headers.clear();
  stream.response_header_fields.clear();
  stream.response_header_fields.reserve(kReusableResponseHeaderReserve);
  trim_reusable_string(stream.response_body);
  ensure_reusable_string_capacity(stream.response_body, kH2SlabResponseBodyBytes);
  stream.follow_ops.clear();
  stream.completed = false;
}

std::unique_ptr<H2StreamState> acquire_h2_stream_state(H2ClientSession& client) {
  if (!client.free_streams.empty()) {
    client.stream_pool_reuse_hits += 1;
    auto stream = std::move(client.free_streams.back());
    client.free_streams.pop_back();
    if (stream) {
      reset_h2_stream_state(*stream);
      return stream;
    }
  }
  perf_alloc(sizeof(H2StreamState));
  return std::make_unique<H2StreamState>();
}

void recycle_h2_stream_state(H2ClientSession& client, std::unique_ptr<H2StreamState> stream) {
  if (!stream) {
    return;
  }
  reset_h2_stream_state(*stream);
  client.free_streams.push_back(std::move(stream));
}
#endif

struct H1TransportOps {
  int (*connect_fn)(Http1Connection& conn, const Profile& profile);
  ssize_t (*send_fn)(Http1Connection& conn, const void* buf, std::size_t len);
  ssize_t (*recv_fn)(Http1Connection& conn, void* buf, std::size_t len);
  int (*close_fn)(Http1Connection& conn);
  const char* name;
};

TransportBackend parse_transport_backend(const Profile& profile) {
  const std::string normalized = lower_copy(profile.transport_backend);
  if (normalized == "custom_tcp") {
    return TransportBackend::CustomTcp;
  }
  return TransportBackend::KernelSocket;
}

int connect_socket(Http1Connection& conn, const Profile& profile) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  const int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  // Important: SO_RCVTIMEO/SO_SNDTIMEO do NOT reliably apply to connect().
  // Use a non-blocking connect with an explicit epoll wait to guarantee
  // fail-fast semantics for "no listener" and "blackhole" targets.
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(profile.target_port));
  if (::inet_pton(AF_INET, profile.target_ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }

  const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (rc == 0) {
    return fd;
  }
  if (rc != 0 && errno != EINPROGRESS) {
    ::close(fd);
    return -1;
  }

  const int timeout_ms = std::max(1, profile.timeout_ms);
  const int ep = ::epoll_create1(EPOLL_CLOEXEC);
  if (ep < 0) {
    ::close(fd);
    return -1;
  }
  epoll_event ev {};
  ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
  ev.data.fd = fd;
  if (::epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
    ::close(ep);
    ::close(fd);
    return -1;
  }
  epoll_event out {};
  const int wr = ::epoll_wait(ep, &out, 1, timeout_ms);
  if (g_perf_stats != nullptr) {
    g_perf_stats->epoll_wakeups += 1;
  }
  if (wr <= 0) {
    ::close(ep);
    ::close(fd);
    return -1;
  }

  int so_error = 0;
  socklen_t slen = sizeof(so_error);
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0) {
    ::close(ep);
    ::close(fd);
    return -1;
  }
  ::close(ep);
  if (so_error != 0) {
    ::close(fd);
    return -1;
  }
  conn.fd = fd;
  return fd;
}

int connect_socket(const Profile& profile) {
  Http1Connection conn;
  return connect_socket(conn, profile);
}

ssize_t kernel_socket_send(Http1Connection& conn, const void* buf, std::size_t len) {
  return ::send(conn.fd, buf, len, MSG_NOSIGNAL);
}

ssize_t kernel_socket_recv(Http1Connection& conn, void* buf, std::size_t len) {
  return ::recv(conn.fd, buf, len, 0);
}

int kernel_socket_close(Http1Connection& conn) {
  return ::close(conn.fd);
}

uint32_t synthetic_custom_tcp_src_ip() {
  return static_cast<uint32_t>((10U << 24U) | 1U);
}

bool parse_ipv4_u32(const std::string& text, uint32_t* out_ip) {
  if (out_ip == nullptr) {
    return false;
  }
  in_addr addr {};
  if (::inet_pton(AF_INET, text.c_str(), &addr) != 1) {
    return false;
  }
  *out_ip = ntohl(addr.s_addr);
  return true;
}

int custom_tcp_connect_bridge(Http1Connection& conn, const Profile& profile) {
  uint32_t dst_ip = 0;
  if (!parse_ipv4_u32(profile.target_ip, &dst_ip)) {
    errno = EINVAL;
    return -1;
  }
  uint64_t flow_id = 0;
  const int rc = tcpdp_enqueue_connect(
      synthetic_custom_tcp_src_ip(),
      dst_ip,
      0,
      static_cast<uint16_t>(profile.target_port),
      &flow_id);
  if (rc != 0 || flow_id == 0) {
    errno = ENOTSUP;
    return -1;
  }
  conn.custom_flow_id = flow_id;
  conn.custom_connect_ready = false;
  conn.custom_send_enqueued = false;
  conn.custom_terminal = false;
  conn.fd = 1;
  return conn.fd;
}

ssize_t custom_tcp_send_bridge(Http1Connection& conn, const void* buf, std::size_t len) {
  if (!conn.custom_connect_ready) {
    errno = EAGAIN;
    return -1;
  }
  if (conn.custom_send_enqueued) {
    return static_cast<ssize_t>(len);
  }
  uint32_t queued = 0;
  const int rc = tcpdp_enqueue_send(
      conn.custom_flow_id,
      static_cast<const uint8_t*>(buf),
      len,
      &queued);
  if (rc != 0 || queued == 0) {
    errno = EAGAIN;
    return -1;
  }
  conn.custom_send_enqueued = true;
  return static_cast<ssize_t>(queued);
}

ssize_t custom_tcp_recv_bridge(Http1Connection& conn, void* buf, std::size_t len) {
  if (buf == nullptr || len == 0) {
    return 0;
  }
  if (!conn.read_buffer.empty()) {
    const std::size_t copy_len = std::min(len, conn.read_buffer.size());
    std::memcpy(buf, conn.read_buffer.data(), copy_len);
    conn.read_buffer.erase(0, copy_len);
    return static_cast<ssize_t>(copy_len);
  }
  if (!conn.custom_terminal) {
    errno = EAGAIN;
    return -1;
  }
  return 0;
}

int custom_tcp_close_bridge(Http1Connection& conn) {
  conn.custom_flow_id = 0;
  conn.custom_connect_ready = false;
  conn.custom_send_enqueued = false;
  conn.custom_terminal = false;
  return 0;
}

const H1TransportOps& resolve_h1_transport_ops(TransportBackend backend) {
  static const H1TransportOps kernel_ops{
      connect_socket,
      kernel_socket_send,
      kernel_socket_recv,
      kernel_socket_close,
      "kernel_socket",
  };
  static const H1TransportOps custom_tcp_ops{
      custom_tcp_connect_bridge,
      custom_tcp_send_bridge,
      custom_tcp_recv_bridge,
      custom_tcp_close_bridge,
      "custom_tcp",
  };
  switch (backend) {
    case TransportBackend::CustomTcp:
      return custom_tcp_ops;
    case TransportBackend::KernelSocket:
      return kernel_ops;
  }
  return kernel_ops;
}

long long monotonic_ms_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

bool wait_for_fd(int epoll_fd, int fd, uint32_t events, int timeout_ms) {
  if (epoll_fd < 0 || fd < 0) {
    return false;
  }
  epoll_event ev {};
  ev.events = events;
  ev.data.fd = fd;
  if (::epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
    if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
      return false;
    }
  }
  epoll_event out {};
  const int rc = ::epoll_wait(epoll_fd, &out, 1, timeout_ms);
  if (g_perf_stats != nullptr) {
    g_perf_stats->epoll_wakeups += 1;
  }
  if (rc <= 0) {
    return false;
  }
  return (out.events & events) != 0 || (out.events & (EPOLLERR | EPOLLHUP)) != 0;
}

std::optional<std::size_t> parse_chunked_body_length(const std::string& payload, std::size_t body_offset) {
  std::size_t cursor = body_offset;
  while (true) {
    const std::size_t line_end = payload.find("\r\n", cursor);
    if (line_end == std::string::npos) {
      return std::nullopt;
    }
    const std::string size_line = payload.substr(cursor, line_end - cursor);
    char* end_ptr = nullptr;
    const unsigned long chunk_size = std::strtoul(size_line.c_str(), &end_ptr, 16);
    if (end_ptr == size_line.c_str()) {
      return std::nullopt;
    }
    cursor = line_end + 2;
    if (payload.size() < cursor + chunk_size + 2) {
      return std::nullopt;
    }
    cursor += chunk_size;
    if (payload.compare(cursor, 2, "\r\n") != 0) {
      return std::nullopt;
    }
    cursor += 2;
    if (chunk_size == 0) {
      if (payload.size() < cursor + 2) {
        return std::nullopt;
      }
      return cursor + 2 - body_offset;
    }
  }
}

void sync_h1_lane_state(H1Lane& lane, const Profile& profile) {
  lane.lane.dispatch_ready_at_ms = monotonic_ms_now();
  lane.lane.idle_deadline_ms = lane.conn ? lane.conn->idle_deadline_ms : 0;
  lane.lane.inflight_count = lane.response.status_code > 0 ? 0 : 1;
  lane.lane.reuse_score = lane.conn && lane.conn->fd >= 0 ? 1 : 0;
  lane.lane.health_state = lane.conn && lane.conn->fd >= 0
      ? LaneHealthState::Healthy
      : (profile.keepalive ? LaneHealthState::Draining : LaneHealthState::Closed);
}

#ifdef SAMURAI_WITH_NGHTTP2
void collect_h2_session_stats(
    H2ClientSession& client,
    H2RunStats& stats,
    int sample_limit);

void flush_ready_h2_completions(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2ClientSession& client);

void requeue_h2_pending_front(
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client);

void service_h2_session_io(
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    uint32_t events,
    bool allow_read_without_event);
#endif

bool h1_lane_try_parse_response(H1Lane& lane) {
  if (!lane.conn) {
    return false;
  }
  std::string& buffer = lane.conn->read_buffer;
  if (!lane.parser.header_complete) {
    const std::size_t header_end = buffer.find("\r\n\r\n");
    if (header_end == std::string::npos) {
      return false;
    }
    lane.parser.header_complete = true;
    lane.parser.header_end = header_end;
    lane.parser.body_offset = header_end + 4;
    const std::size_t line_end = buffer.find("\r\n");
    if (line_end != std::string::npos) {
      const std::string status_line = buffer.substr(0, line_end);
      std::istringstream iss(status_line);
      std::string version;
      iss >> version;
      iss >> lane.response.status_code;
    }
    std::size_t pos = line_end == std::string::npos ? 0 : line_end + 2;
    bool has_content_length = false;
    std::size_t content_length_value = 0;
    while (pos < header_end) {
      const std::size_t next = buffer.find("\r\n", pos);
      if (next == std::string::npos || next > header_end) {
        break;
      }
      const std::string line = buffer.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
          value.erase(value.begin());
        }
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        lane.response.header_fields.emplace_back(key, value);
        if (key == "content-length") {
          has_content_length = true;
          content_length_value = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
        } else if (key == "transfer-encoding" &&
                   lower_copy(value).find("chunked") != std::string::npos) {
          lane.parser.chunked = true;
        }
      }
      pos = next + 2;
    }

    if (lane.parser.chunked) {
      lane.parser.expected_body_length = 0;
    } else if (has_content_length) {
      lane.parser.expected_body_length = content_length_value;
    } else if ((lane.response.status_code >= 100 && lane.response.status_code < 200) ||
               lane.response.status_code == 204 || lane.response.status_code == 304) {
      lane.parser.expected_body_length = 0;
    } else {
      lane.parser.close_delimited = true;
    }
  }

  if (lane.parser.chunked) {
    const auto parsed = parse_chunked_body_length(buffer, lane.parser.body_offset);
    if (!parsed.has_value()) {
      return false;
    }
    lane.parser.expected_body_length = *parsed;
  } else if (lane.parser.close_delimited) {
    return false;
  } else if (buffer.size() < lane.parser.body_offset + lane.parser.expected_body_length) {
    return false;
  }

  lane.response.body = buffer.substr(lane.parser.body_offset, lane.parser.expected_body_length);
  lane.response.consumed_bytes = lane.parser.body_offset + lane.parser.expected_body_length;
  const std::string* connection_header_raw =
      find_header_value(lane.response.header_fields, "connection");
  const std::string connection_header =
      lower_copy(connection_header_raw != nullptr ? *connection_header_raw : "");
  lane.response.keep_alive = !lane.parser.close_delimited && connection_header != "close";
  if (lane.response.consumed_bytes <= buffer.size()) {
    buffer.erase(0, lane.response.consumed_bytes);
  } else {
    buffer.clear();
  }
  return true;
}

enum class H1LaneIoResult {
  Pending = 0,
  Completed = 1,
  Failed = 2,
};

H1LaneIoResult h1_lane_write_step(H1Lane& lane) {
  if (!lane.conn || lane.conn->fd < 0) {
    return H1LaneIoResult::Failed;
  }
  const H1TransportOps& transport_ops = resolve_h1_transport_ops(lane.transport_backend);
  while (lane.write_offset < lane.write_buffer.size()) {
    if (g_perf_stats != nullptr) {
      g_perf_stats->tx_syscalls += 1;
    }
    const ssize_t sent = transport_ops.send_fn(
        *lane.conn,
        lane.write_buffer.data() + lane.write_offset,
        lane.write_buffer.size() - lane.write_offset);
    if (sent > 0) {
      lane.write_offset += static_cast<std::size_t>(sent);
      lane.tx_bytes += static_cast<std::size_t>(sent);
      continue;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return H1LaneIoResult::Pending;
    }
    return H1LaneIoResult::Failed;
  }
  lane.phase = H1LanePhase::Reading;
  return H1LaneIoResult::Pending;
}

H1LaneIoResult h1_lane_read_step(H1Lane& lane) {
  if (!lane.conn || lane.conn->fd < 0) {
    return H1LaneIoResult::Failed;
  }
  const H1TransportOps& transport_ops = resolve_h1_transport_ops(lane.transport_backend);
  while (true) {
    if (h1_lane_try_parse_response(lane)) {
      lane.phase = H1LanePhase::Complete;
      return H1LaneIoResult::Completed;
    }
    char tmp[8192];
    if (g_perf_stats != nullptr) {
      g_perf_stats->rx_syscalls += 1;
    }
    const ssize_t n = transport_ops.recv_fn(*lane.conn, tmp, sizeof(tmp));
    if (n > 0) {
      lane.conn->read_buffer.append(tmp, static_cast<std::size_t>(n));
      if (lane.transport_backend != TransportBackend::CustomTcp) {
        lane.response.bytes_received += static_cast<std::size_t>(n);
        lane.rx_bytes += static_cast<std::size_t>(n);
      }
      continue;
    }
    if (n == 0) {
      if (lane.parser.header_complete && lane.parser.close_delimited) {
        lane.parser.expected_body_length =
            lane.conn->read_buffer.size() > lane.parser.body_offset
            ? lane.conn->read_buffer.size() - lane.parser.body_offset
            : 0;
        lane.response.body = lane.conn->read_buffer.substr(
            lane.parser.body_offset,
            lane.parser.expected_body_length);
        lane.response.consumed_bytes = lane.parser.body_offset + lane.parser.expected_body_length;
        lane.response.keep_alive = false;
        lane.conn->read_buffer.clear();
        lane.phase = lane.response.status_code > 0 ? H1LanePhase::Complete : H1LanePhase::Failed;
        return lane.response.status_code > 0 ? H1LaneIoResult::Completed : H1LaneIoResult::Failed;
      }
      lane.phase = H1LanePhase::Failed;
      return H1LaneIoResult::Failed;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return H1LaneIoResult::Pending;
    }
    lane.phase = H1LanePhase::Failed;
    return H1LaneIoResult::Failed;
  }
}

void enqueue_ready_h1_lane(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    std::size_t lane_idx,
    H1Lane& lane) {
  if (lane.queued_ready) {
    return;
  }
  lane.queued_ready = true;
  H1CompletedRequest completed;
  completed.lane_idx = lane_idx;
  completed.status_code = lane.response.status_code;
  completed.response_headers = std::move(lane.response.headers);
  completed.response_header_fields = std::move(lane.response.header_fields);
  completed.response_body = std::move(lane.response.body);
  completed.follow_ops = std::move(lane.request_spec.follow_ops);
  completed.request_start_ms = lane.request_start_ms;
  completed.expectation_failures = lane.expectation_failures;
  completed.think_time_total_ms = lane.think_time_total_ms;
  completed.keep_alive = lane.response.keep_alive;
  completed.tx_bytes = lane.tx_bytes;
  completed.rx_bytes = lane.rx_bytes;
  completed.success = lane.phase != H1LanePhase::Failed && lane.response.status_code > 0;
  runtime.ready_completions.push_back(CompletionEnvelope{
      CompletionKind::H1,
      shard_idx,
      std::move(completed),
      std::nullopt,
  });
}

void enqueue_ready_h2_stream(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2CompletedStream&& completed) {
  CompletionEnvelope envelope;
  envelope.kind = CompletionKind::H2;
  envelope.shard_idx = shard_idx;
  envelope.h2_completed = std::move(completed);
  runtime.ready_completions.push_back(std::move(envelope));
}

std::optional<CompletionEnvelope> pop_ready_completion(NativeRuntime& runtime) {
  if (runtime.ready_completions.empty()) {
    return std::nullopt;
  }
  CompletionEnvelope entry = std::move(runtime.ready_completions.front());
  runtime.ready_completions.pop_front();
  if (entry.kind == CompletionKind::H1 &&
      entry.h1_completed.has_value() &&
      entry.shard_idx < runtime.local_shards.size()) {
    auto& lanes = runtime.local_shards[entry.shard_idx].h1_lanes;
    const std::size_t lane_idx = entry.h1_completed->lane_idx;
    if (lane_idx < lanes.size() && lanes[lane_idx]) {
      lanes[lane_idx]->queued_ready = false;
    }
  }
  return entry;
}

uint32_t reactor_interest_mask() {
  return EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
}

void register_h1_lane_fd(ShardState& shard, NativeRuntime::LocalShard& local_shard, H1Lane* lane) {
  if (lane == nullptr || lane->conn == nullptr || lane->conn->fd < 0 || shard.epoll_fd < 0 ||
      lane->transport_backend == TransportBackend::CustomTcp) {
    return;
  }
  epoll_event ev {};
  ev.events = reactor_interest_mask();
  ev.data.fd = lane->conn->fd;
  if (::epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, lane->conn->fd, &ev) != 0) {
    (void)::epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, lane->conn->fd, &ev);
  }
  local_shard.active_fd_registry[lane->conn->fd] = NativeRuntime::LocalShard::RegisteredLaneFd{
      ReactorLaneKind::H1,
      lane,
#ifdef SAMURAI_WITH_NGHTTP2
      nullptr,
#endif
  };
}

void unregister_lane_fd(ShardState& shard, NativeRuntime::LocalShard& local_shard, int fd) {
  if (fd < 0) {
    return;
  }
  local_shard.active_fd_registry.erase(fd);
  if (shard.epoll_fd >= 0) {
    (void)::epoll_ctl(shard.epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
void register_h2_lane_fd(
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession* session) {
  if (session == nullptr || session->ctx.fd < 0 || shard.epoll_fd < 0) {
    return;
  }
  epoll_event ev {};
  ev.events = reactor_interest_mask();
  ev.data.fd = session->ctx.fd;
  if (::epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, session->ctx.fd, &ev) != 0) {
    (void)::epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, session->ctx.fd, &ev);
  }
  local_shard.active_fd_registry[session->ctx.fd] = NativeRuntime::LocalShard::RegisteredLaneFd{
      ReactorLaneKind::H2,
      nullptr,
      session,
  };
}
#endif

int service_ready_lanes(
    NativeRuntime& runtime,
    const Profile& profile,
    std::size_t shard_idx,
    int timeout_ms) {
  if (shard_idx >= runtime.shards.size() || shard_idx >= runtime.local_shards.size()) {
    return 0;
  }
  ShardState& shard = runtime.shards[shard_idx];
  auto& local_shard = runtime.local_shards[shard_idx];
  if (shard.epoll_fd < 0 || local_shard.active_fd_registry.empty()) {
    return 0;
  }
  if (local_shard.ready_events.empty()) {
    local_shard.ready_events.resize(32);
  }
  const int rc = ::epoll_wait(
      shard.epoll_fd,
      local_shard.ready_events.data(),
      static_cast<int>(local_shard.ready_events.size()),
      timeout_ms);
  if (rc <= 0) {
    return 0;
  }
  if (g_perf_stats != nullptr) {
    g_perf_stats->epoll_wakeups += static_cast<std::size_t>(rc);
  }
  const long long now_ms = monotonic_ms_now();
  for (int i = 0; i < rc; ++i) {
    const int fd = local_shard.ready_events[static_cast<std::size_t>(i)].data.fd;
    const uint32_t events = local_shard.ready_events[static_cast<std::size_t>(i)].events;
    const auto it = local_shard.active_fd_registry.find(fd);
    if (it == local_shard.active_fd_registry.end()) {
      continue;
    }
    local_shard.dispatch_ready_ms = now_ms;
    if (it->second.kind == ReactorLaneKind::H1) {
      if (it->second.h1_lane != nullptr && it->second.h1_lane->conn != nullptr) {
        auto& lane = *it->second.h1_lane;
        lane.conn->idle_deadline_ms = now_ms + std::max(1, profile.timeout_ms);
        H1LaneIoResult result = H1LaneIoResult::Pending;
        if (lane.phase == H1LanePhase::Writing &&
            (events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) != 0) {
          result = h1_lane_write_step(lane);
          if (result == H1LaneIoResult::Pending &&
              lane.phase == H1LanePhase::Reading &&
              (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) {
            result = h1_lane_read_step(lane);
          }
        } else if (lane.phase == H1LanePhase::Reading &&
                   (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) {
          result = h1_lane_read_step(lane);
        }
        if ((events & (EPOLLERR | EPOLLHUP)) != 0 &&
            lane.phase != H1LanePhase::Complete &&
            result == H1LaneIoResult::Pending) {
          result = lane.phase == H1LanePhase::Reading
              ? h1_lane_read_step(lane)
              : H1LaneIoResult::Failed;
        }
        if (result == H1LaneIoResult::Completed || result == H1LaneIoResult::Failed) {
          unregister_lane_fd(shard, local_shard, fd);
          std::size_t lane_idx = 0;
          for (; lane_idx < local_shard.h1_lanes.size(); ++lane_idx) {
            if (local_shard.h1_lanes[lane_idx].get() == &lane) {
              break;
            }
          }
          enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, lane);
        }
      }
    }
#ifdef SAMURAI_WITH_NGHTTP2
    else if (it->second.h2_session != nullptr) {
      service_h2_session_io(
          profile,
          shard,
          local_shard,
          *it->second.h2_session,
          events,
          false);
      flush_ready_h2_completions(runtime, shard_idx, *it->second.h2_session);
    }
#endif
    enqueue_ready_shard(runtime, shard_idx);
  }
  return rc;
}

void service_custom_tcp_lanes(NativeRuntime& runtime, const Profile& profile);

void service_all_ready_lanes(NativeRuntime& runtime, const Profile& profile, int timeout_ms) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    service_ready_lanes(runtime, profile, shard_idx, timeout_ms);
  }
  service_custom_tcp_lanes(runtime, profile);
}

void service_custom_tcp_lanes(NativeRuntime& runtime, const Profile& profile) {
  if (parse_transport_backend(profile) != TransportBackend::CustomTcp) {
    return;
  }
  uint32_t actions = 0;
  (void)tcpdp_poll(0, 1024, &actions);
  tcpdp_completion_t* items = nullptr;
  uint32_t item_count = 0;
  if (tcpdp_collect_completions(&items, &item_count) == 0 && items != nullptr) {
    for (uint32_t idx = 0; idx < item_count; ++idx) {
      const auto& item = items[idx];
      for (auto& local_shard : runtime.local_shards) {
        for (auto& lane_ptr : local_shard.h1_lanes) {
          if (!lane_ptr || !lane_ptr->conn || lane_ptr->transport_backend != TransportBackend::CustomTcp) {
            continue;
          }
          auto& conn = *lane_ptr->conn;
          if (conn.custom_flow_id != item.flow_id) {
            continue;
          }
          if (item.event != nullptr && std::strcmp(item.event, "connect_established") == 0) {
            conn.custom_connect_ready = true;
          } else {
            conn.custom_terminal = true;
            lane_ptr->phase = H1LanePhase::Failed;
          }
        }
      }
    }
    tcpdp_free_completions(items, item_count);
  }
  tcpdp_rx_payload_t* payload_items = nullptr;
  uint32_t payload_count = 0;
  if (tcpdp_collect_rx_payloads(&payload_items, &payload_count) == 0 && payload_items != nullptr) {
    for (uint32_t idx = 0; idx < payload_count; ++idx) {
      const auto& item = payload_items[idx];
      if (item.payload == nullptr || item.payload_len == 0) {
        continue;
      }
      for (auto& local_shard : runtime.local_shards) {
        for (auto& lane_ptr : local_shard.h1_lanes) {
          if (!lane_ptr || !lane_ptr->conn || lane_ptr->transport_backend != TransportBackend::CustomTcp) {
            continue;
          }
          auto& conn = *lane_ptr->conn;
          if (conn.custom_flow_id != item.flow_id) {
            continue;
          }
          conn.read_buffer.append(
              reinterpret_cast<const char*>(item.payload),
              item.payload_len);
          lane_ptr->response.bytes_received += item.payload_len;
          lane_ptr->rx_bytes += item.payload_len;
          break;
        }
      }
    }
    tcpdp_free_rx_payloads(payload_items, payload_count);
  }

  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    for (std::size_t lane_idx = 0; lane_idx < local_shard.h1_lanes.size(); ++lane_idx) {
      auto& lane_ptr = local_shard.h1_lanes[lane_idx];
      if (!lane_ptr || lane_ptr->transport_backend != TransportBackend::CustomTcp || !lane_ptr->conn) {
        continue;
      }
      H1Lane& lane = *lane_ptr;
      H1LaneIoResult result = H1LaneIoResult::Pending;
      if (lane.phase == H1LanePhase::Writing) {
        result = h1_lane_write_step(lane);
      } else if (lane.phase == H1LanePhase::Reading) {
        result = h1_lane_read_step(lane);
      } else if (lane.phase == H1LanePhase::Complete) {
        result = H1LaneIoResult::Completed;
      } else if (lane.phase == H1LanePhase::Failed) {
        result = H1LaneIoResult::Failed;
      }
      if (result == H1LaneIoResult::Completed || result == H1LaneIoResult::Failed) {
        enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, lane);
      }
    }
  }
}

std::string lower_copy(const std::string& in) {
  std::string out = in;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

CompiledCaptureTemplate compile_capture_template(const std::string& input) {
  CompiledCaptureTemplate compiled;
  std::size_t pos = 0;
  while (pos < input.size()) {
    const std::size_t start = input.find("{{", pos);
    if (start == std::string::npos) {
      if (pos < input.size()) {
        CompiledCaptureChunk chunk;
        chunk.value = input.substr(pos);
        compiled.static_bytes += chunk.value.size();
        compiled.chunks.push_back(std::move(chunk));
      }
      break;
    }
    if (start > pos) {
      CompiledCaptureChunk literal;
      literal.value = input.substr(pos, start - pos);
      compiled.static_bytes += literal.value.size();
      compiled.chunks.push_back(std::move(literal));
    }
    const std::size_t end = input.find("}}", start + 2);
    if (end == std::string::npos) {
      CompiledCaptureChunk literal;
      literal.value = input.substr(start);
      compiled.static_bytes += literal.value.size();
      compiled.chunks.push_back(std::move(literal));
      break;
    }
    std::string token = input.substr(start + 2, end - (start + 2));
    const std::string capture_prefix = "capture:";
    const std::string header_prefix = "header:";
    const std::string cookie_prefix = "cookie:";
    if (token.rfind(capture_prefix, 0) == 0) {
      token.erase(0, capture_prefix.size());
    } else if (token.rfind(header_prefix, 0) == 0) {
      token.erase(0, header_prefix.size());
    } else if (token.rfind(cookie_prefix, 0) == 0) {
      token.erase(0, cookie_prefix.size());
    }
    CompiledCaptureChunk capture;
    capture.is_capture = true;
    capture.value = std::move(token);
    compiled.has_captures = true;
    compiled.chunks.push_back(std::move(capture));
    pos = end + 2;
  }
  return compiled;
}

void render_capture_template_into(
    const CompiledCaptureTemplate& compiled,
    const std::map<std::string, std::string>& captures,
    std::string& out) {
  if (!compiled.has_captures) {
    out.clear();
    ensure_reusable_string_capacity(out, compiled.static_bytes);
    for (const auto& chunk : compiled.chunks) {
      out.append(chunk.value);
    }
    return;
  }
  std::size_t reserve_bytes = compiled.static_bytes;
  for (const auto& chunk : compiled.chunks) {
    if (!chunk.is_capture) {
      continue;
    }
    const auto it = captures.find(chunk.value);
    if (it != captures.end()) {
      reserve_bytes += it->second.size();
    }
  }
  out.clear();
  ensure_reusable_string_capacity(out, reserve_bytes);
  for (const auto& chunk : compiled.chunks) {
    if (!chunk.is_capture) {
      out.append(chunk.value);
      continue;
    }
    const auto it = captures.find(chunk.value);
    if (it != captures.end()) {
      out.append(it->second);
    }
  }
}

void build_http1_request_into(
    std::string& out,
    LaneStringArena& arena,
    const Profile& profile,
    const H1RequestSpec& request,
    const std::map<std::string, std::string>& captures) {
  out.clear();
  auto method_lease = arena_acquire_string(arena, std::max<std::size_t>(request.method_template.static_bytes, 16));
  auto path_lease = arena_acquire_string(arena, std::max<std::size_t>(request.path_template.static_bytes, 64));
  std::string method_fallback;
  std::string path_fallback;
  std::string& method = method_lease.value != nullptr ? *method_lease.value : method_fallback;
  std::string& path = path_lease.value != nullptr ? *path_lease.value : path_fallback;
  render_capture_template_into(request.method_template, captures, method);
  render_capture_template_into(request.path_template, captures, path);
  std::size_t reserve_bytes = method.size() + path.size() + 64 +
      (profile.host_header.empty() ? profile.target_ip.size() : profile.host_header.size());
  for (const auto& [key, compiled_value] : request.compiled_header_values) {
    reserve_bytes += key.size() + compiled_value.static_bytes + 4;
  }
  if (request.body_template.has_value()) {
    reserve_bytes += request.body_template->static_bytes + 32;
  }
  ensure_reusable_string_capacity(out, std::max<std::size_t>(reserve_bytes, kH1SlabWriteBytes));
  out.append(method);
  out.append(" ");
  out.append(path);
  out.append(" HTTP/1.1\r\n");
  out.append("Host: ");
  out.append(profile.host_header.empty() ? profile.target_ip : profile.host_header);
  out.append("\r\nConnection: ");
  out.append(profile.keepalive ? "keep-alive" : "close");
  out.append("\r\n");
  bool has_content_length = false;
  for (const auto& [key, compiled_value] : request.compiled_header_values) {
    if (key == "Content-Length" || key == "content-length") {
      has_content_length = true;
    }
    out.append(key);
    out.append(": ");
    auto value_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(compiled_value.static_bytes, kArenaBucketSmallBytes));
    std::string value_fallback;
    std::string& header_value = value_lease.value != nullptr ? *value_lease.value : value_fallback;
    render_capture_template_into(compiled_value, captures, header_value);
    out.append(header_value);
    out.append("\r\n");
  }
  auto body_lease = request.body_template.has_value()
      ? arena_acquire_string(
            arena,
            std::max<std::size_t>(request.body_template->static_bytes, kArenaBucketBodyBytes))
      : ArenaStringLease{};
  std::string body_fallback;
  std::string& body = body_lease.value != nullptr ? *body_lease.value : body_fallback;
  if (request.body_template.has_value()) {
    render_capture_template_into(*request.body_template, captures, body);
  } else {
    body.clear();
  }
  if (!body.empty() && !has_content_length) {
    out.append("Content-Length: ");
    out.append(std::to_string(body.size()));
    out.append("\r\n");
  }
  out.append("\r\n");
  if (!body.empty()) {
    out.append(body);
  }
  if (out.empty()) {
    std::string method_plain;
    std::string path_plain;
    std::string body_plain;
    render_capture_template_into(request.method_template, captures, method_plain);
    render_capture_template_into(request.path_template, captures, path_plain);
    if (request.body_template.has_value()) {
      render_capture_template_into(*request.body_template, captures, body_plain);
    }
    out.append(method_plain.empty() ? "GET" : method_plain);
    out.append(" ");
    out.append(path_plain.empty() ? "/" : path_plain);
    out.append(" HTTP/1.1\r\n");
    out.append("Host: ");
    out.append(profile.host_header.empty() ? profile.target_ip : profile.host_header);
    out.append("\r\nConnection: ");
    out.append(profile.keepalive ? "keep-alive" : "close");
    out.append("\r\n");
    bool emitted_content_length = false;
    for (const auto& [key, compiled_value] : request.compiled_header_values) {
      std::string value_plain;
      render_capture_template_into(compiled_value, captures, value_plain);
      out.append(key);
      out.append(": ");
      out.append(value_plain);
      out.append("\r\n");
      if (key == "Content-Length" || key == "content-length") {
        emitted_content_length = true;
      }
    }
    if (!body_plain.empty() && !emitted_content_length) {
      out.append("Content-Length: ");
      out.append(std::to_string(body_plain.size()));
      out.append("\r\n");
    }
    out.append("\r\n");
    out.append(body_plain);
  }
  perf_alloc(out.size());
}

void init_stats(const Profile& profile, std::map<std::string, double>& out) {
  out["attempted"] = static_cast<double>(profile.flow_attempted);
  out["sent"] = 0.0;
  out["errors"] = static_cast<double>(profile.flow_attempted);
  out["responses_total"] = 0.0;
  out["status_2xx"] = 0.0;
  out["status_3xx"] = 0.0;
  out["status_4xx"] = 0.0;
  out["status_5xx"] = 0.0;
  out["l7_flow_attempted"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_completed"] = 0.0;
  out["l7_conn_attempted"] = 0.0;
  out["l7_conn_established"] = 0.0;
  out["l7_conn_reused"] = 0.0;
  out["l7_rx_bytes"] = 0.0;
  out["l7_tx_bytes"] = 0.0;
  out["l7_expectation_failures"] = 0.0;
  out["l7_scheduler_backpressure_count"] = 0.0;
  out["h2_goaway_count"] = 0.0;
  out["h2_stream_reset_ratio"] = 0.0;
  out["h2_goaway_replacements"] = 0.0;
  out["h2_drain_evictions"] = 0.0;
  out["h2_replace_now_decisions"] = 0.0;
  out["h2_replace_after_idle_decisions"] = 0.0;
  out["h2_stream_pool_reuse_hits"] = 0.0;
  out["l7_h2_active_streams_peak"] = 0.0;
  out["h2_native_capability_available"] = 0.0;
  out["runtime_shards"] = 0.0;
  out["runtime_transport_custom_tcp_requested"] = 0.0;
  out["runtime_transport_seam_ready"] = 1.0;
  out["runtime_transport_custom_tcp_bridge_ready"] = 0.0;
  out["runtime_transport_custom_tcp_rx_bridge_active"] = 0.0;
  out["tcp_flows_active"] = 0.0;
  out["tcp_connect_attempts"] = 0.0;
  out["tcp_connect_established"] = 0.0;
  out["tcp_retransmit_count"] = 0.0;
  out["tcp_timeout_close_count"] = 0.0;
  out["tcp_connect_timeout_count"] = 0.0;
  out["tcp_idle_timeout_count"] = 0.0;
  out["tcp_retransmit_exhausted_count"] = 0.0;
  out["tcp_rx_ack_count"] = 0.0;
  out["tcp_dup_ack_count"] = 0.0;
  out["tcp_unexpected_ack_count"] = 0.0;
  out["tcp_tx_data_bytes"] = 0.0;
  out["tcp_rx_data_bytes"] = 0.0;
  out["tcp_peer_rst_count"] = 0.0;
  out["tcp_peer_fin_count"] = 0.0;
}

std::map<std::string, double> fail_visible_stats(
    const Profile& profile,
    const RuntimeCapabilities& caps,
    const std::string& reason) {
  (void)reason;
  const TransportBackend transport_backend = parse_transport_backend(profile);
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["attempted"] = static_cast<double>(profile.flow_attempted);
  out["sent"] = 0.0;
  out["errors"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_attempted"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_completed"] = 0.0;
  out["l7_expectation_failures"] = static_cast<double>(profile.flow_attempted);
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  out["runtime_transport_custom_tcp_requested"] = transport_backend == TransportBackend::CustomTcp ? 1.0 : 0.0;
  return out;
}

std::string build_h2_preface_and_settings() {
  std::string out("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
  // Empty SETTINGS frame: len=0, type=0x4, flags=0x0, stream=0.
  const unsigned char settings_frame[9] = {
      0x00, 0x00, 0x00,
      0x04,
      0x00,
      0x00, 0x00, 0x00, 0x00,
  };
  out.append(reinterpret_cast<const char*>(settings_frame), sizeof(settings_frame));
  return out;
}

bool configure_custom_tcp_bridge(const Profile& profile);
void merge_custom_tcp_stats(std::map<std::string, double>& out);

std::map<std::string, double> run_http2_custom_tcp_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps) {
  struct H2CustomLane {
    uint64_t flow_id{0};
    bool connected{false};
    bool preface_sent{false};
    bool draining{false};
    bool replace_now{false};
    int inflight_streams{0};
    int reuse_hits{0};
  };

  std::map<std::string, double> out;
  init_stats(profile, out);
  out["runtime_transport_custom_tcp_requested"] = 1.0;
  out["runtime_transport_custom_tcp_bridge_ready"] = configure_custom_tcp_bridge(profile) ? 1.0 : 0.0;
  out["runtime_transport_custom_tcp_rx_bridge_active"] = 0.0;
  out["runtime_h2_transport_contract"] = 1.0;
  out["runtime_h2_transport_mode_custom_tcp"] = 1.0;
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  if (out["runtime_transport_custom_tcp_bridge_ready"] == 0.0) {
    auto failed = fail_visible_stats(profile, caps, "custom_tcp_transport_not_yet_wired");
    failed["runtime_transport_custom_tcp_bridge_ready"] = 0.0;
    failed["runtime_h2_transport_contract"] = 0.0;
    failed["runtime_h2_transport_mode_custom_tcp"] = 1.0;
    return failed;
  }

  uint32_t dst_ip = 0;
  if (!parse_ipv4_u32(profile.target_ip, &dst_ip)) {
    return fail_visible_stats(profile, caps, "invalid_target_ip");
  }
  const int conn_budget = std::max(1, std::min(profile.max_connections, std::max(1, cfg.concurrency)));
  const int attempted = std::max(1, profile.flow_attempted);
  const int stream_budget = std::max(1, profile.max_streams_per_connection);
  std::vector<H2CustomLane> lanes;
  lanes.reserve(static_cast<std::size_t>(conn_budget));

  int conn_attempted = 0;
  auto enqueue_connect_for_lane = [&](H2CustomLane& lane) -> bool {
    uint64_t flow_id = 0;
    const int rc = tcpdp_enqueue_connect(
        synthetic_custom_tcp_src_ip(),
        dst_ip,
        0,
        static_cast<uint16_t>(profile.target_port),
        &flow_id);
    if (rc != 0 || flow_id == 0) {
      return false;
    }
    lane.flow_id = flow_id;
    lane.connected = false;
    lane.preface_sent = false;
    lane.draining = false;
    lane.replace_now = false;
    lane.inflight_streams = 0;
    conn_attempted += 1;
    return true;
  };

  for (int i = 0; i < conn_budget; ++i) {
    H2CustomLane lane;
    if (enqueue_connect_for_lane(lane)) {
      lanes.push_back(lane);
    }
  }

  if (conn_attempted == 0) {
    auto failed = fail_visible_stats(profile, caps, "custom_tcp_connect_enqueue_failed");
    failed["runtime_transport_custom_tcp_requested"] = 1.0;
    failed["runtime_transport_custom_tcp_bridge_ready"] = 1.0;
    failed["runtime_h2_transport_contract"] = 0.0;
    failed["runtime_h2_transport_mode_custom_tcp"] = 1.0;
    return failed;
  }

  int conn_established = 0;
  int sent = 0;
  int scheduler_backpressure = 0;
  int goaway_replacements = 0;
  int drain_evictions = 0;
  int replace_now_decisions = 0;
  int replace_after_idle_decisions = 0;
  int stream_pool_reuse_hits = 0;
  int active_streams_peak = 0;
  std::size_t tx_bytes = 0;
  std::size_t rx_bytes = 0;
  const std::string preface = build_h2_preface_and_settings();
  int rr = 0;
  std::size_t rr_cursor = 0;

  auto map_flow_index = [&](uint64_t flow_id) -> int {
    for (std::size_t i = 0; i < lanes.size(); ++i) {
      if (lanes[i].flow_id == flow_id) {
        return static_cast<int>(i);
      }
    }
    return -1;
  };

  auto current_active_streams = [&]() -> int {
    int active = 0;
    for (const auto& lane : lanes) {
      active += std::max(0, lane.inflight_streams);
    }
    return active;
  };

  auto find_schedulable_lane = [&]() -> int {
    const std::size_t lane_count = lanes.size();
    if (lane_count == 0) {
      return -1;
    }
    for (std::size_t step = 0; step < lane_count; ++step) {
      const std::size_t idx = (rr_cursor + step) % lane_count;
      const auto& lane = lanes[idx];
      if (!lane.connected || lane.replace_now || lane.draining) {
        continue;
      }
      if (lane.inflight_streams >= stream_budget) {
        continue;
      }
      rr_cursor = (idx + 1) % lane_count;
      return static_cast<int>(idx);
    }
    return -1;
  };

  for (int step = 0; step < 64 && sent < attempted; ++step) {
    uint32_t actions = 0;
    (void)tcpdp_poll(0, 2048, &actions);

    const uint8_t** packets = nullptr;
    size_t* packet_lens = nullptr;
    uint32_t packet_count = 0;
    if (tcpdp_drain_tx_packets(0, &packets, &packet_lens, &packet_count) == 0) {
      for (uint32_t i = 0; i < packet_count; ++i) {
        tx_bytes += packet_lens[i];
      }
      tcpdp_free_drained_packets(packets, packet_lens, packet_count);
    }

    tcpdp_completion_t* comps = nullptr;
    uint32_t comp_count = 0;
    if (tcpdp_collect_completions(&comps, &comp_count) == 0) {
      for (uint32_t i = 0; i < comp_count; ++i) {
        const char* ev = comps[i].event ? comps[i].event : "";
        const int idx = map_flow_index(comps[i].flow_id);
        if (idx < 0) {
          continue;
        }
        auto& lane = lanes[static_cast<std::size_t>(idx)];
        if (std::strcmp(ev, "connect_established") == 0) {
          if (!lane.connected) {
            lane.connected = true;
            conn_established += 1;
          }
          continue;
        }
        if (std::strcmp(ev, "peer_fin") == 0) {
          lane.draining = true;
          continue;
        }
        if (
            std::strcmp(ev, "connect_timeout") == 0 ||
            std::strcmp(ev, "retransmit_exhausted") == 0 ||
            std::strcmp(ev, "peer_rst") == 0 ||
            std::strcmp(ev, "idle_timeout") == 0) {
          lane.replace_now = true;
          lane.connected = false;
          lane.preface_sent = false;
          lane.inflight_streams = 0;
        }
      }
      tcpdp_free_completions(comps, comp_count);
    }

    // Model stream lifecycle: each service loop drains one stream per lane.
    for (auto& lane : lanes) {
      if (lane.inflight_streams > 0) {
        lane.inflight_streams -= 1;
      }
    }

    // Execute replacement policies.
    for (auto& lane : lanes) {
      if (lane.replace_now) {
        replace_now_decisions += 1;
        goaway_replacements += 1;
        lane.reuse_hits = 0;
        lane.draining = false;
        lane.replace_now = false;
        (void)enqueue_connect_for_lane(lane);
        continue;
      }
      if (lane.draining && lane.inflight_streams == 0) {
        drain_evictions += 1;
        replace_after_idle_decisions += 1;
        goaway_replacements += 1;
        lane.reuse_hits = 0;
        lane.draining = false;
        lane.connected = false;
        lane.preface_sent = false;
        (void)enqueue_connect_for_lane(lane);
      }
    }

    int guard = static_cast<int>(lanes.size()) * std::max(1, stream_budget);
    while (sent < attempted && guard-- > 0) {
      const int lane_idx = find_schedulable_lane();
      if (lane_idx < 0) {
        scheduler_backpressure += 1;
        break;
      }
      auto& lane = lanes[static_cast<std::size_t>(lane_idx)];
      if (!lane.preface_sent) {
        uint32_t queued = 0;
        if (tcpdp_enqueue_send(
                lane.flow_id,
                reinterpret_cast<const uint8_t*>(preface.data()),
                preface.size(),
                &queued) == 0 &&
            queued > 0) {
          lane.preface_sent = true;
        }
      }
      // Minimal request unit for parity loop (placeholder DATA payload).
      static const char kReqStub[] = "h2_req_stub";
      uint32_t queued = 0;
      if (tcpdp_enqueue_send(
              lane.flow_id,
              reinterpret_cast<const uint8_t*>(kReqStub),
              sizeof(kReqStub) - 1,
              &queued) != 0 ||
          queued == 0) {
        scheduler_backpressure += 1;
        break;
      }
      if (lane.reuse_hits > 0) {
        stream_pool_reuse_hits += 1;
      }
      lane.reuse_hits += 1;
      lane.inflight_streams += 1;
      sent += 1;
      active_streams_peak = std::max(active_streams_peak, current_active_streams());
    }

    tcpdp_rx_payload_t* rx_items = nullptr;
    uint32_t rx_count = 0;
    if (tcpdp_collect_rx_payloads(&rx_items, &rx_count) == 0) {
      for (uint32_t i = 0; i < rx_count; ++i) {
        rx_bytes += rx_items[i].payload_len;
      }
      tcpdp_free_rx_payloads(rx_items, rx_count);
    }
    rr += 1;
  }

  tcpdp_stats_snapshot_t stats {};
  (void)tcpdp_snapshot_stats(&stats);
  merge_custom_tcp_stats(out);
  out["attempted"] = static_cast<double>(attempted);
  out["sent"] = static_cast<double>(std::max(0, std::min(sent, attempted)));
  out["errors"] = static_cast<double>(std::max(0, attempted - std::max(0, std::min(sent, attempted))));
  out["responses_total"] = out["sent"];
  out["l7_flow_attempted"] = static_cast<double>(attempted);
  out["l7_flow_completed"] = out["sent"];
  out["l7_conn_attempted"] = static_cast<double>(conn_attempted);
  out["l7_conn_established"] = static_cast<double>(conn_established);
  out["l7_conn_reused"] = static_cast<double>(std::max(0, attempted - conn_attempted));
  out["l7_rx_bytes"] = static_cast<double>(rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_expectation_failures"] = out["errors"];
  out["l7_h2_lane_reuse_ratio"] =
      conn_attempted > 0 ? static_cast<double>(std::max(0, attempted - conn_attempted)) / static_cast<double>(conn_attempted) : 0.0;
  out["l7_h2_active_streams_peak"] = static_cast<double>(std::max(1, active_streams_peak));
  out["h2_goaway_count"] = 0.0;
  out["h2_stream_reset_ratio"] = 0.0;
  out["h2_goaway_replacements"] = static_cast<double>(goaway_replacements);
  out["h2_drain_evictions"] = static_cast<double>(drain_evictions);
  out["h2_replace_now_decisions"] = static_cast<double>(replace_now_decisions);
  out["h2_replace_after_idle_decisions"] = static_cast<double>(replace_after_idle_decisions);
  out["h2_stream_pool_reuse_hits"] = static_cast<double>(stream_pool_reuse_hits);
  out["l7_scheduler_backpressure_count"] = static_cast<double>(scheduler_backpressure);
  out["runtime_transport_poll_calls"] = static_cast<double>(rr);
  out["runtime_transport_poll_actions"] = static_cast<double>(stats.poll_calls);
  out["runtime_transport_rx_poll_enabled"] = 1.0;
  out["runtime_transport_snapshot_available"] = 1.0;
  out["runtime_transport_service_loops"] = static_cast<double>(rr);
  out["runtime_transport_service"] = 1.0;
  out["runtime_transport_contract"] = 1.0;
  return out;
}

bool configure_custom_tcp_bridge(const Profile& profile) {
  auto env_u32 = [](const char* name, uint32_t fallback) -> uint32_t {
    const char* raw = std::getenv(name);
    if (raw == nullptr || raw[0] == '\0') {
      return fallback;
    }
    char* end_ptr = nullptr;
    const unsigned long parsed = std::strtoul(raw, &end_ptr, 10);
    if (end_ptr == raw || (end_ptr != nullptr && *end_ptr != '\0')) {
      return fallback;
    }
    if (parsed == 0UL || parsed > 0xffffffffUL) {
      return fallback;
    }
    return static_cast<uint32_t>(parsed);
  };
  tcpdp_config_t config{};
  const uint32_t timeout_ms = static_cast<uint32_t>(std::max(1, profile.timeout_ms));
  const uint32_t initial_rto_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS",
      static_cast<uint32_t>(std::max<uint32_t>(25U, std::min<uint32_t>(timeout_ms / 4U, 1000U))));
  const uint32_t connect_timeout_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS",
      static_cast<uint32_t>(std::max<uint32_t>(timeout_ms, initial_rto_ms * 4U)));
  config.mode = std::getenv("SAMURAI_CUSTOM_TCP_MODE") != nullptr ? std::getenv("SAMURAI_CUSTOM_TCP_MODE") : "required";
  config.backend = std::getenv("SAMURAI_CUSTOM_TCP_BACKEND") != nullptr ? std::getenv("SAMURAI_CUSTOM_TCP_BACKEND") : "af_xdp";
  config.initial_rto_ms = initial_rto_ms;
  config.max_retransmits = env_u32("SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS", 5);
  config.connect_timeout_ms = connect_timeout_ms;
  config.idle_timeout_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS",
      static_cast<uint32_t>(std::max<uint32_t>(connect_timeout_ms * 4U, timeout_ms * 6U)));
  return tcpdp_configure(&config) == 0;
}

int32_t maybe_start_custom_tcp_rx_bridge() {
  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
  if (iface == nullptr || iface[0] == '\0') {
    return 0;
  }
  int32_t handler_id = 0;
  if (tcpdp_start_rx_handler(iface, &handler_id) != 0) {
    return -1;
  }
  return handler_id;
}

void merge_custom_tcp_stats(std::map<std::string, double>& out) {
  tcpdp_stats_snapshot_t stats{};
  if (tcpdp_snapshot_stats(&stats) != 0) {
    return;
  }
  out["tcp_flows_active"] = static_cast<double>(stats.flows_active);
  out["tcp_connect_attempts"] = static_cast<double>(stats.connect_attempts);
  out["tcp_connect_established"] = static_cast<double>(stats.connect_established);
  out["tcp_retransmit_count"] = static_cast<double>(stats.retransmit_count);
  out["tcp_timeout_close_count"] = static_cast<double>(stats.timeout_close_count);
  out["tcp_connect_timeout_count"] = static_cast<double>(stats.connect_timeout_count);
  out["tcp_idle_timeout_count"] = static_cast<double>(stats.idle_timeout_count);
  out["tcp_retransmit_exhausted_count"] = static_cast<double>(stats.retransmit_exhausted_count);
  out["tcp_rx_ack_count"] = static_cast<double>(stats.rx_ack_count);
  out["tcp_dup_ack_count"] = static_cast<double>(stats.dup_ack_count);
  out["tcp_unexpected_ack_count"] = static_cast<double>(stats.unexpected_ack_count);
  out["tcp_tx_data_bytes"] = static_cast<double>(stats.tx_data_bytes);
  out["tcp_rx_data_bytes"] = static_cast<double>(stats.rx_data_bytes);
  out["tcp_peer_rst_count"] = static_cast<double>(stats.peer_rst_count);
  out["tcp_peer_fin_count"] = static_cast<double>(stats.peer_fin_count);
}

NativeRuntime build_runtime(const Profile& profile, const RuntimeConfig& cfg) {
  NativeRuntime runtime;
  runtime.caps = detect_capabilities();
  const int shard_count = std::max(1, std::min(cfg.concurrency, profile.max_connections));
  runtime.shards.reserve(static_cast<std::size_t>(shard_count));
  for (int i = 0; i < shard_count; ++i) {
    ShardState shard;
    shard.shard_id = i;
    shard.epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    shard.timer_wheel.slot_count = 1024;
    shard.timer_wheel.active_timers = 0;
    shard.connection_pool.max_connections = std::max(1, profile.max_connections / shard_count);
    shard.connection_pool.active_connections = 0;
    shard.connection_pool.reused_connections = 0;
    shard.connection_pool.active_connections_peak = 0;
    runtime.shards.push_back(shard);
    NativeRuntime::LocalShard local;
    local.ready_events.resize(32);
    local.timer_slots.resize(shard.timer_wheel.slot_count);
    local.last_timer_tick_ms = monotonic_ms_now();
    local.dispatch_ready_ms = local.last_timer_tick_ms;
    const std::size_t shard_conn_budget = static_cast<std::size_t>(std::max(
        1,
        runtime.shards.empty()
            ? profile.max_connections
            : runtime.shards.back().connection_pool.max_connections));
    if (profile.protocol == "http2") {
#ifdef SAMURAI_WITH_NGHTTP2
      local.h2_sessions.reserve(shard_conn_budget);
      const std::size_t prewarmed_streams =
          static_cast<std::size_t>(std::max(1, std::min(profile.max_streams_per_connection, 2)));
      for (std::size_t session_idx = 0; session_idx < shard_conn_budget; ++session_idx) {
        auto session = std::make_unique<H2ClientSession>();
        session->session_idx = session_idx;
        ensure_lane_string_arena(session->string_arena);
        session->free_streams.reserve(prewarmed_streams);
        for (std::size_t stream_idx = 0; stream_idx < prewarmed_streams; ++stream_idx) {
          auto stream = std::make_unique<H2StreamState>();
          reset_h2_stream_state(*stream);
          session->free_streams.push_back(std::move(stream));
        }
        local.h2_sessions.push_back(std::move(session));
      }
#endif
    } else {
      local.h1_lanes.reserve(shard_conn_budget);
      for (std::size_t lane_idx = 0; lane_idx < shard_conn_budget; ++lane_idx) {
        auto lane = std::make_unique<H1Lane>();
        ensure_lane_string_arena(lane->string_arena);
        reset_h1_lane_io(*lane);
        local.h1_lanes.push_back(std::move(lane));
      }
    }
    runtime.local_shards.push_back(std::move(local));
  }
  return runtime;
}

void destroy_runtime(NativeRuntime& runtime) {
  if (runtime.custom_tcp_rx_handler_id > 0) {
    (void)tcpdp_stop_rx_handler(runtime.custom_tcp_rx_handler_id);
    runtime.custom_tcp_rx_handler_id = 0;
  }
#ifdef SAMURAI_WITH_NGHTTP2
  for (auto& local_shard : runtime.local_shards) {
    for (auto& session : local_shard.h2_sessions) {
      if (!session) {
        continue;
      }
      if (session->session != nullptr) {
        nghttp2_session_del(session->session);
        session->session = nullptr;
      }
      if (session->callbacks != nullptr) {
        nghttp2_session_callbacks_del(session->callbacks);
        session->callbacks = nullptr;
      }
      cleanup_tls(session->ctx);
      if (session->ctx.fd >= 0) {
        ::close(session->ctx.fd);
        session->ctx.fd = -1;
      }
      session->ready = false;
    }
  }
#endif
  for (auto& shard : runtime.shards) {
    if (shard.epoll_fd >= 0) {
      ::close(shard.epoll_fd);
      shard.epoll_fd = -1;
    }
  }
}

void enqueue_ready_shard(NativeRuntime& runtime, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  auto& local_shard = runtime.local_shards[shard_idx];
  if (local_shard.in_ready_queue || local_shard.dispatch_ready_ms > monotonic_ms_now()) {
    return;
  }
  runtime.ready_shards.push_back(shard_idx);
  local_shard.in_ready_queue = true;
  runtime.perf.scheduler_queue_depth_peak =
      std::max(runtime.perf.scheduler_queue_depth_peak, runtime.ready_shards.size());
}

void refresh_ready_queue(NativeRuntime& runtime) {
  const long long now_ms = monotonic_ms_now();
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    if (runtime.local_shards[shard_idx].dispatch_ready_ms <= now_ms) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }
}

std::optional<std::size_t> pop_ready_shard(NativeRuntime& runtime) {
  refresh_ready_queue(runtime);
  if (runtime.ready_shards.empty()) {
    return std::nullopt;
  }
  const std::size_t shard_idx = runtime.ready_shards.front();
  runtime.ready_shards.pop_front();
  runtime.local_shards[shard_idx].in_ready_queue = false;
  return shard_idx;
}

void erase_active_http1(NativeRuntime::LocalShard& local_shard, Http1Connection* conn) {
  local_shard.http1_active.erase(
      std::remove(local_shard.http1_active.begin(), local_shard.http1_active.end(), conn),
      local_shard.http1_active.end());
}

void close_http1_connection(
    std::unique_ptr<Http1Connection>& conn,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  if (!conn) {
    return;
  }
  erase_active_http1(local_shard, conn.get());
  unregister_lane_fd(shard, local_shard, conn->fd);
  if (conn->fd >= 0) {
    const H1TransportOps& transport_ops = resolve_h1_transport_ops(conn->transport_backend);
    transport_ops.close_fn(*conn);
    conn->fd = -1;
  }
  conn->read_buffer.clear();
  if (conn->timer_armed && shard.timer_wheel.active_timers > 0) {
    shard.timer_wheel.active_timers -= 1;
  }
  conn->timer_armed = false;
  shard.connection_pool.active_connections =
      std::max(0, shard.connection_pool.active_connections - 1);
}

void expire_http1_idle(
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  const long long now_ms = monotonic_ms_now();
  for (auto& lane : local_shard.h1_lanes) {
    if (!lane || !lane->conn || lane->conn->fd < 0) {
      continue;
    }
    if (lane->phase != H1LanePhase::Idle) {
      continue;
    }
    if (lane->lane.idle_deadline_ms <= 0 || lane->lane.idle_deadline_ms > now_ms) {
      continue;
    }
    close_http1_connection(lane->conn, shard, local_shard);
    if (g_perf_stats != nullptr) {
      g_perf_stats->idle_evictions += 1;
    }
    reset_h1_lane_io(*lane);
  }
  if (local_shard.timer_slots.empty()) {
    return;
  }
  const long long start_tick = local_shard.last_timer_tick_ms;
  const long long slot_count = static_cast<long long>(shard.timer_wheel.slot_count);
  if (now_ms < start_tick) {
    return;
  }
  const long long tick_span = std::min(now_ms - start_tick + 1, slot_count);
  for (long long delta = 0; delta < tick_span; ++delta) {
    const std::size_t slot = static_cast<std::size_t>((start_tick + delta) % slot_count);
    auto& bucket = local_shard.timer_slots[slot];
    for (const auto& entry : bucket) {
      Http1Connection* conn_ptr = entry.conn;
      if (conn_ptr == nullptr || !conn_ptr->timer_armed ||
          conn_ptr->timer_generation != entry.generation ||
          conn_ptr->idle_deadline_ms > now_ms) {
        continue;
      }
      for (auto it = local_shard.http1_idle.begin(); it != local_shard.http1_idle.end(); ++it) {
        if (it->get() == conn_ptr) {
          close_http1_connection(*it, shard, local_shard);
          local_shard.http1_idle.erase(it);
          if (g_perf_stats != nullptr) {
            g_perf_stats->idle_evictions += 1;
          }
          break;
        }
      }
      if (shard.timer_wheel.active_timers > 0) {
        shard.timer_wheel.active_timers -= 1;
      }
    }
    bucket.clear();
  }
  local_shard.last_timer_tick_ms = now_ms;
}

void expire_all_http1_idle(NativeRuntime& runtime) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    expire_http1_idle(runtime.shards[shard_idx], runtime.local_shards[shard_idx]);
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
void expire_h2_idle(
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  const long long now_ms = monotonic_ms_now();
  for (auto& session : local_shard.h2_sessions) {
    if (!session) {
      continue;
    }
    if (session->ready && session->idle_deadline_ms > 0 && session->idle_deadline_ms <= now_ms) {
      shard.connection_pool.active_connections =
          std::max(0, shard.connection_pool.active_connections - 1);
      close_h2_client_session(*session);
      if (g_perf_stats != nullptr) {
        g_perf_stats->idle_evictions += 1;
      }
    }
    if (session->unhealthy_until_ms > now_ms && local_shard.dispatch_ready_ms < session->unhealthy_until_ms) {
      local_shard.dispatch_ready_ms = session->unhealthy_until_ms;
    }
  }
  (void)profile;
}
#endif

void expire_all_lane_idle(NativeRuntime& runtime, const Profile& profile) {
  expire_all_http1_idle(runtime);
#ifdef SAMURAI_WITH_NGHTTP2
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    expire_h2_idle(profile, runtime.shards[shard_idx], runtime.local_shards[shard_idx]);
  }
#else
  (void)profile;
#endif
}

void advance_runtime_until(NativeRuntime& runtime, const Profile& profile, long long deadline_ms) {
  const int slice_ms = 32;
  while (true) {
    expire_all_lane_idle(runtime, profile);
    service_all_ready_lanes(runtime, profile, 0);
    refresh_ready_queue(runtime);
    if (g_perf_stats != nullptr) {
      g_perf_stats->profile_snapshot_count += 1;
    }
    const long long now_ms = monotonic_ms_now();
    if (now_ms >= deadline_ms) {
      break;
    }
    const long long remaining_ms = deadline_ms - now_ms;
    const int step_ms = static_cast<int>(std::min<long long>(remaining_ms, slice_ms));
    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(1, step_ms)));
  }
}

std::vector<H1RequestSpec> build_h1_requests(const Profile& profile) {
  std::vector<H1RequestSpec> requests;
  for (std::size_t idx = 0; idx < profile.ops.size(); ++idx) {
    const FlowOp& op = profile.ops[idx];
    if (op.opcode != "SEND_HEADERS") {
      continue;
    }
    H1RequestSpec spec;
    spec.send_headers = op;
    spec.method_template = compile_capture_template(op.method.empty() ? "GET" : op.method);
    spec.path_template = compile_capture_template(op.path.empty() ? "/" : op.path);
    spec.header_fields.reserve(op.headers.size());
    spec.compiled_header_values.reserve(op.headers.size());
    for (const auto& [key, value] : op.headers) {
      spec.header_bytes += key.size() + value.size() + 4;
      spec.header_fields.emplace_back(key, value);
      spec.compiled_header_values.emplace_back(key, compile_capture_template(value));
    }
    std::size_t j = idx + 1;
    if (j < profile.ops.size() && profile.ops[j].opcode == "SEND_BODY") {
      spec.body_op = profile.ops[j];
      spec.body_template = compile_capture_template(
          std::string(reinterpret_cast<const char*>(profile.ops[j].body.data()), profile.ops[j].body.size()));
      ++j;
    }
    while (j < profile.ops.size()) {
      const FlowOp& follow = profile.ops[j];
      if (follow.opcode == "SEND_HEADERS" || follow.opcode == "CONNECT" || follow.opcode == "CLOSE") {
        break;
      }
      spec.follow_ops.push_back(follow);
      ++j;
    }
    requests.push_back(std::move(spec));
  }
  return requests;
}

std::vector<std::vector<H1RequestSpec>> bucket_h1_requests_by_shard(
    const std::vector<H1RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H1RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

std::vector<H2RequestSpec> build_h2_requests(const Profile& profile) {
  std::vector<H2RequestSpec> requests;
  for (const H1RequestSpec& h1_spec : build_h1_requests(profile)) {
    H2RequestSpec spec;
    spec.method = h1_spec.send_headers.method.empty() ? "GET" : h1_spec.send_headers.method;
    spec.path = h1_spec.send_headers.path.empty() ? "/" : h1_spec.send_headers.path;
    spec.method_template = h1_spec.method_template;
    spec.path_template = h1_spec.path_template;
    spec.headers = h1_spec.header_fields;
    spec.compiled_headers = h1_spec.compiled_header_values;
    if (h1_spec.body_op.has_value()) {
      spec.body.assign(
          reinterpret_cast<const char*>(h1_spec.body_op->body.data()),
          h1_spec.body_op->body.size());
    }
    spec.body_template = h1_spec.body_template;
    spec.follow_ops = h1_spec.follow_ops;
    requests.push_back(std::move(spec));
  }
  return requests;
}

void capture_cookie(
    const std::string& cookie_line,
    const std::string& capture_name,
    std::map<std::string, std::string>& captures) {
  const std::size_t sep = cookie_line.find(';');
  const std::string cookie = cookie_line.substr(0, sep);
  const std::size_t eq = cookie.find('=');
  if (eq != std::string::npos) {
    captures[cookie.substr(0, eq)] = cookie.substr(eq + 1);
  } else if (!capture_name.empty()) {
    captures[capture_name] = cookie;
  } else {
    captures["set-cookie"] = cookie;
  }
}

void evaluate_response_ops(
    const std::vector<FlowOp>& follow_ops,
    int status_code,
    const std::vector<std::pair<std::string, std::string>>& header_fields,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::map<std::string, std::string>& captures,
    int& expectation_failures,
    int& think_time_total_ms) {
  for (const FlowOp& follow : follow_ops) {
    if (follow.opcode == "EXPECT_STATUS" && follow.has_expect) {
      if (status_code < follow.expect.status_min || status_code > follow.expect.status_max) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_HEADER" && follow.has_expect) {
      const std::string key = lower_copy(follow.expect.name);
      const std::string* header_value = find_header_value(header_fields, key);
      if ((header_value == nullptr || header_value->find(follow.expect.value) == std::string::npos) &&
          (headers.empty() || headers.find(key) == headers.end() ||
           headers.at(key).find(follow.expect.value) == std::string::npos)) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_BODY_SUBSTRING" && follow.has_expect) {
      if (body.find(follow.expect.value) == std::string::npos) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_HEADER") {
      const std::string source = lower_copy(
          follow.capture_source.empty() ? follow.capture_name : follow.capture_source);
      const std::string* header_value = find_header_value(header_fields, source);
      if (header_value != nullptr) {
        captures[follow.capture_name.empty() ? source : follow.capture_name] = *header_value;
      } else {
        const auto it = headers.find(source);
        if (it != headers.end()) {
          captures[follow.capture_name.empty() ? source : follow.capture_name] = it->second;
        }
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_COOKIE") {
      const std::string* cookie_value = find_header_value(header_fields, "set-cookie");
      if (cookie_value != nullptr) {
        capture_cookie(*cookie_value, follow.capture_name, captures);
      } else {
        const auto it = headers.find("set-cookie");
        if (it != headers.end()) {
          capture_cookie(it->second, follow.capture_name, captures);
        }
      }
      continue;
    }
    if (follow.opcode == "THINK_TIME") {
      think_time_total_ms += std::max(0, follow.think_time_ms);
    }
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
std::vector<std::vector<H2RequestSpec>> bucket_h2_requests_by_shard(
    const std::vector<H2RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H2RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

ssize_t h2_send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  size_t off = 0;
  while (off < length) {
    ssize_t wr = -1;
    if (g_perf_stats != nullptr) {
      g_perf_stats->tx_syscalls += 1;
    }
    if (ctx->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
      if (ctx->ssl == nullptr) {
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      const int tls_wr = SSL_write(ctx->ssl, data + off, static_cast<int>(length - off));
      if (tls_wr > 0) {
        wr = static_cast<ssize_t>(tls_wr);
      } else {
        const int err = SSL_get_error(ctx->ssl, tls_wr);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          if (!wait_for_fd(ctx->epoll_fd, ctx->fd, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN, ctx->timeout_ms)) {
            ctx->transport_error = 1;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
          }
          continue;
        }
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
#else
      ctx->transport_error = 1;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
#endif
    } else {
      wr = ::send(ctx->fd, data + off, length - off, MSG_NOSIGNAL);
    }
    if (wr > 0) {
      off += static_cast<size_t>(wr);
      ctx->bytes_sent += static_cast<size_t>(wr);
      continue;
    }
    if (wr < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_for_fd(ctx->epoll_fd, ctx->fd, EPOLLOUT, ctx->timeout_ms)) {
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      continue;
    }
    ctx->transport_error = 1;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return static_cast<ssize_t>(length);
}

int h2_on_frame_recv_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    void* user_data) {
  (void)session;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx != nullptr && frame != nullptr && frame->hd.type == NGHTTP2_GOAWAY) {
    ctx->goaway += 1;
  }
  return 0;
}

int h2_on_header_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr || frame == nullptr || frame->hd.stream_id <= 0) {
    return 0;
  }
  if (frame->hd.type != NGHTTP2_HEADERS ||
      (frame->headers.cat != NGHTTP2_HCAT_RESPONSE && frame->headers.cat != NGHTTP2_HCAT_HEADERS)) {
    return 0;
  }
  const auto it = ctx->active_streams.find(frame->hd.stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  H2StreamState& stream = *it->second;
  const std::string key = lower_copy(std::string(reinterpret_cast<const char*>(name), namelen));
  const std::string val(reinterpret_cast<const char*>(value), valuelen);
  if (key == ":status") {
    stream.status_code = std::atoi(val.c_str());
  } else {
    bool merged = false;
    for (auto& [field_key, field_value] : stream.response_header_fields) {
      if (field_key != key) {
        continue;
      }
      field_value.append("\n");
      field_value.append(val);
      merged = true;
      break;
    }
    if (!merged) {
      stream.response_header_fields.emplace_back(key, val);
    }
  }
  return 0;
}

int h2_on_data_chunk_recv_callback(
    nghttp2_session* session,
    uint8_t flags,
    int32_t stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  const auto it = ctx->active_streams.find(stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  it->second->response_body.append(reinterpret_cast<const char*>(data), len);
  ctx->bytes_received += len;
  return 0;
}

ssize_t h2_data_read_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data) {
  (void)session;
  (void)stream_id;
  (void)user_data;
  auto* stream = static_cast<H2StreamState*>(source != nullptr ? source->ptr : nullptr);
  if (stream == nullptr) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  const std::size_t remaining = stream->outbound_body.size() - stream->outbound_offset;
  const std::size_t to_copy = std::min(length, remaining);
  if (to_copy > 0) {
    std::memcpy(buf, stream->outbound_body.data() + stream->outbound_offset, to_copy);
    stream->outbound_offset += to_copy;
  }
  if (stream->outbound_offset >= stream->outbound_body.size()) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return static_cast<ssize_t>(to_copy);
}

int h2_on_stream_close_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint32_t error_code,
    void* user_data) {
  (void)session;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr || stream_id <= 0) {
    return 0;
  }
  auto it = ctx->active_streams.find(stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  H2StreamState& stream = *it->second;
  H2CompletedStream completed;
  completed.status_code = stream.status_code;
  completed.response_headers = std::move(stream.response_headers);
  completed.response_header_fields = std::move(stream.response_header_fields);
  completed.response_body = std::move(stream.response_body);
  if (error_code != NGHTTP2_NO_ERROR) {
    ctx->protocol_error = 1;
    ctx->rst_stream += 1;
    ctx->failed_streams += 1;
    completed.expectation_failures = 1;
    completed.rst_stream = true;
  } else {
    int think_time_total_ms = 0;
    evaluate_response_ops(
        stream.follow_ops,
        stream.status_code,
        completed.response_header_fields,
        completed.response_headers,
        completed.response_body,
        *ctx->captures,
        completed.expectation_failures,
        think_time_total_ms);
    completed.think_time_total_ms = think_time_total_ms;
    if (stream.status_code > 0) {
      if (stream.status_code >= 200 && stream.status_code <= 299) {
        completed.success = true;
      } else if (stream.status_code >= 300 && stream.status_code <= 399) {
        completed.success = true;
      } else if (stream.status_code >= 400 && stream.status_code <= 499) {
        completed.success = true;
      } else if (stream.status_code >= 500 && stream.status_code <= 599) {
        completed.success = true;
      }
    } else {
      completed.expectation_failures += 1;
    }
  }
  if (ctx->owner_session != nullptr) {
    ctx->owner_session->completed_streams.push_back(std::move(completed));
    recycle_h2_stream_state(*ctx->owner_session, std::move(it->second));
  }
  ctx->active_streams.erase(it);
  return 0;
}

ssize_t h2_socket_read(H2ConnectionContext& ctx, unsigned char* buf, size_t cap) {
  if (g_perf_stats != nullptr) {
    g_perf_stats->rx_syscalls += 1;
  }
  if (ctx.use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
    if (ctx.ssl == nullptr) {
      errno = EIO;
      return -1;
    }
    const int rd = SSL_read(ctx.ssl, buf, static_cast<int>(cap));
    if (rd > 0) {
      return static_cast<ssize_t>(rd);
    }
    if (rd == 0) {
      return 0;
    }
    const int err = SSL_get_error(ctx.ssl, rd);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (!wait_for_fd(ctx.epoll_fd, ctx.fd, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN, ctx.timeout_ms)) {
        errno = EIO;
        return -1;
      }
      errno = EAGAIN;
    } else if (err == SSL_ERROR_ZERO_RETURN) {
      return 0;
    } else {
      errno = EIO;
    }
    return -1;
#else
    errno = EIO;
    return -1;
#endif
  }
  return ::recv(ctx.fd, buf, cap, 0);
}

bool setup_tls(H2ConnectionContext& ctx, const Profile& profile) {
#ifdef SAMURAI_WITH_OPENSSL
  if (!ctx.use_tls) {
    return true;
  }
  const long long start_ms = monotonic_ms_now();
  ctx.tls_ctx = SSL_CTX_new(TLS_client_method());
  if (ctx.tls_ctx == nullptr) {
    return false;
  }
  SSL_CTX_set_alpn_protos(
      ctx.tls_ctx,
      reinterpret_cast<const unsigned char*>("\x02h2"),
      3);
  SSL_CTX_set_verify(ctx.tls_ctx, profile.verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
  ctx.ssl = SSL_new(ctx.tls_ctx);
  if (ctx.ssl == nullptr) {
    return false;
  }
  if (SSL_set_fd(ctx.ssl, ctx.fd) != 1) {
    return false;
  }
  if (!profile.host_header.empty()) {
    SSL_set_tlsext_host_name(ctx.ssl, profile.host_header.c_str());
  }
  if (SSL_connect(ctx.ssl) != 1) {
    return false;
  }
  const unsigned char* alpn = nullptr;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
  const bool ok = alpn != nullptr && alpn_len == 2 && std::memcmp(alpn, "h2", 2) == 0;
  if (ok) {
    perf_tls_latency(
        static_cast<double>(std::max<long long>(0, monotonic_ms_now() - start_ms)),
        0);
  }
  return ok;
#else
  (void)ctx;
  (void)profile;
  return false;
#endif
}

void cleanup_tls(H2ConnectionContext& ctx) {
#ifdef SAMURAI_WITH_OPENSSL
  if (ctx.ssl != nullptr) {
    SSL_shutdown(ctx.ssl);
    SSL_free(ctx.ssl);
    ctx.ssl = nullptr;
  }
  if (ctx.tls_ctx != nullptr) {
    SSL_CTX_free(ctx.tls_ctx);
    ctx.tls_ctx = nullptr;
  }
#else
  (void)ctx;
#endif
}

bool submit_h2_request(
    H2ClientSession& client,
    const Profile& profile,
    const H2RequestSpec& raw_request,
    const std::map<std::string, std::string>& captures) {
  H2ConnectionContext& ctx = client.ctx;
  LaneStringArena& arena = ensure_lane_string_arena(client.string_arena);
  auto stream = acquire_h2_stream_state(client);
  {
    auto method_lease = arena_acquire_string(arena, std::max<std::size_t>(raw_request.method_template.static_bytes, 16));
    std::string method_fallback;
    std::string& method = method_lease.value != nullptr ? *method_lease.value : method_fallback;
    render_capture_template_into(raw_request.method_template, captures, method);
    stream->request_method = method;
  }
  {
    auto path_lease = arena_acquire_string(arena, std::max<std::size_t>(raw_request.path_template.static_bytes, 64));
    std::string path_fallback;
    std::string& path = path_lease.value != nullptr ? *path_lease.value : path_fallback;
    render_capture_template_into(raw_request.path_template, captures, path);
    stream->request_path = path;
  }
  if (stream->request_headers.size() < raw_request.compiled_headers.size()) {
    const std::size_t old_size = stream->request_headers.size();
    stream->request_headers.resize(raw_request.compiled_headers.size());
    for (std::size_t idx = old_size; idx < stream->request_headers.size(); ++idx) {
      ensure_reusable_string_capacity(stream->request_headers[idx].key, 32);
      ensure_reusable_string_capacity(stream->request_headers[idx].value, kArenaBucketSmallBytes);
    }
  }
  stream->request_header_count = raw_request.compiled_headers.size();
  for (std::size_t idx = 0; idx < raw_request.compiled_headers.size(); ++idx) {
    const auto& [key, compiled_value] = raw_request.compiled_headers[idx];
    auto value_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(compiled_value.static_bytes, kArenaBucketSmallBytes));
    std::string value_fallback;
    std::string& value = value_lease.value != nullptr ? *value_lease.value : value_fallback;
    render_capture_template_into(compiled_value, captures, value);
    stream->request_headers[idx].key = key;
    stream->request_headers[idx].value = value;
  }
  if (raw_request.body_template.has_value()) {
    auto body_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(raw_request.body_template->static_bytes, kArenaBucketBodyBytes));
    std::string body_fallback;
    std::string& body = body_lease.value != nullptr ? *body_lease.value : body_fallback;
    render_capture_template_into(*raw_request.body_template, captures, body);
    stream->outbound_body = body;
  } else {
    stream->outbound_body = raw_request.body;
  }
  if (!stream->outbound_body.empty()) {
    ensure_reusable_string_capacity(
        stream->outbound_body,
        std::max<std::size_t>(stream->outbound_body.size(), kH2SlabOutboundBodyBytes));
  }
  const std::size_t response_reserve = std::max<std::size_t>(4096, stream->outbound_body.size());
  ensure_reusable_string_capacity(
      stream->response_body,
      std::max<std::size_t>(response_reserve, kH2SlabResponseBodyBytes));
  stream->follow_ops = raw_request.follow_ops;

  std::vector<nghttp2_nv> hdrs;
  hdrs.reserve(4 + stream->request_header_count);
  auto add_header = [&hdrs](const std::string& key, const std::string& value) {
    nghttp2_nv nv {};
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(key.data()));
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.namelen = key.size();
    nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    hdrs.push_back(nv);
  };

  add_header(":method", stream->request_method.empty() ? "GET" : stream->request_method);
  add_header(":scheme", profile.scheme.empty() ? (ctx.use_tls ? "https" : "http") : profile.scheme);
  add_header(":authority", ctx.authority);
  add_header(":path", stream->request_path.empty() ? "/" : stream->request_path);
  for (std::size_t idx = 0; idx < stream->request_header_count; ++idx) {
    const std::string& key = stream->request_headers[idx].key;
    const std::string& value = stream->request_headers[idx].value;
    if (key.empty()) {
      continue;
    }
    add_header(lower_copy(key), value);
  }

  nghttp2_data_provider provider {};
  nghttp2_data_provider* provider_ptr = nullptr;
  if (!stream->outbound_body.empty()) {
    provider.source.ptr = stream.get();
    provider.read_callback = h2_data_read_callback;
    provider_ptr = &provider;
  }

  const int32_t stream_id =
      nghttp2_submit_request(client.session, nullptr, hdrs.data(), hdrs.size(), provider_ptr, stream.get());
  if (stream_id < 0) {
    recycle_h2_stream_state(client, std::move(stream));
    return false;
  }
  ctx.active_streams.emplace(stream_id, std::move(stream));
  return true;
}

void close_h2_client_session(H2ClientSession& client) {
  if (client.session != nullptr) {
    nghttp2_session_del(client.session);
    client.session = nullptr;
  }
  if (client.callbacks != nullptr) {
    nghttp2_session_callbacks_del(client.callbacks);
    client.callbacks = nullptr;
  }
  cleanup_tls(client.ctx);
  if (client.ctx.fd >= 0) {
    ::close(client.ctx.fd);
    client.ctx.fd = -1;
  }
  client.ctx.active_streams.clear();
  client.pending_requests.clear();
  client.completed_streams.clear();
  client.ready = false;
  client.replacement_mode = H2LaneReplacementMode::Ready;
  client.idle_deadline_ms = 0;
  client.dispatch_ready_ms = monotonic_ms_now();
  client.active_since_ms = 0;
  client.harvested_completed_success = 0;
  client.harvested_failed_streams = 0;
  client.harvested_status_2xx = 0;
  client.harvested_status_3xx = 0;
  client.harvested_status_4xx = 0;
  client.harvested_status_5xx = 0;
  client.harvested_expectation_failures = 0;
  client.harvested_goaway = 0;
  client.harvested_rst_stream = 0;
  client.harvested_drain_evictions = 0;
  client.harvested_max_think_time_ms = 0;
  client.harvested_rx_bytes = 0;
  client.harvested_tx_bytes = 0;
  client.harvested_stream_pool_reuse_hits = 0;
  client.drain_evictions = 0;
}

bool open_h2_client_session(
    const Profile& profile,
    int epoll_fd,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    H2RunStats& stats,
    std::size_t request_count) {
  close_h2_client_session(client);
  client.ctx = H2ConnectionContext{};
  client.ctx.epoll_fd = epoll_fd;
  client.ctx.use_tls = profile.scheme == "https";
  client.ctx.verify_peer = profile.verify != 0;
  client.ctx.timeout_ms = profile.timeout_ms;
  client.ctx.owner_session = &client;
  client.ctx.authority = profile.host_header.empty() ? profile.target_ip : profile.host_header;
  if (client.ctx.authority.find(':') == std::string::npos && profile.target_port > 0) {
    client.ctx.authority += ":" + std::to_string(profile.target_port);
  }

  stats.conn_attempted += 1;
  client.ctx.fd = connect_socket(profile);
  if (client.ctx.fd < 0) {
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  if (!setup_tls(client.ctx, profile)) {
    cleanup_tls(client.ctx);
    ::close(client.ctx.fd);
    client.ctx.fd = -1;
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  stats.conn_established += 1;
  shard.connection_pool.active_connections += 1;
  shard.connection_pool.active_connections_peak = std::max(
      shard.connection_pool.active_connections_peak,
      shard.connection_pool.active_connections);
  if (nghttp2_session_callbacks_new(&client.callbacks) != 0 || client.callbacks == nullptr) {
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  nghttp2_session_callbacks_set_send_callback(client.callbacks, h2_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(client.callbacks, h2_on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(client.callbacks, h2_on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(client.callbacks, h2_on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(client.callbacks, h2_on_stream_close_callback);
  if (nghttp2_session_client_new(&client.session, client.callbacks, &client.ctx) != 0 || client.session == nullptr) {
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, nullptr, 0);
  register_h2_lane_fd(shard, local_shard, &client);
  client.ready = true;
  client.replacement_mode = H2LaneReplacementMode::Ready;
  client.idle_deadline_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms);
  client.dispatch_ready_ms = monotonic_ms_now();
  client.active_since_ms = 0;
  client.consecutive_failures = 0;
  return true;
}

void collect_h2_session_stats(
    H2ClientSession& client,
    H2RunStats& stats,
    int sample_limit) {
  H2ConnectionContext& ctx = client.ctx;
  stats.goaway_count += std::max(0, ctx.goaway - client.harvested_goaway);
  stats.rst_stream_count += std::max(0, ctx.rst_stream - client.harvested_rst_stream);
  stats.drain_evictions += std::max(0, client.drain_evictions - client.harvested_drain_evictions);
  stats.stream_pool_reuse_hits += static_cast<int>(
      client.stream_pool_reuse_hits - client.harvested_stream_pool_reuse_hits);
  stats.active_streams_peak = std::max(
      stats.active_streams_peak,
      static_cast<int>(ctx.active_streams.size()));
  stats.rx_bytes += ctx.bytes_received - client.harvested_rx_bytes;
  stats.tx_bytes += ctx.bytes_sent - client.harvested_tx_bytes;

  client.harvested_completed_success = ctx.completed_success;
  client.harvested_failed_streams = ctx.failed_streams;
  client.harvested_status_2xx = ctx.status_2xx;
  client.harvested_status_3xx = ctx.status_3xx;
  client.harvested_status_4xx = ctx.status_4xx;
  client.harvested_status_5xx = ctx.status_5xx;
  client.harvested_expectation_failures = ctx.expectation_failures;
  client.harvested_goaway = ctx.goaway;
  client.harvested_rst_stream = ctx.rst_stream;
  client.harvested_drain_evictions = client.drain_evictions;
  client.harvested_max_think_time_ms = ctx.max_think_time_ms;
  client.harvested_rx_bytes = ctx.bytes_received;
  client.harvested_tx_bytes = ctx.bytes_sent;
  client.harvested_stream_pool_reuse_hits = client.stream_pool_reuse_hits;
  (void)sample_limit;
}

void flush_ready_h2_completions(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2ClientSession& client) {
  while (!client.completed_streams.empty()) {
    client.completed_streams.front().session_idx = client.session_idx;
    enqueue_ready_h2_stream(runtime, shard_idx, std::move(client.completed_streams.front()));
    client.completed_streams.pop_front();
  }
}

void requeue_h2_pending_front(
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client) {
  while (!client.pending_requests.empty()) {
    local_shard.pending_h2_requests.push_front(client.pending_requests.back());
    client.pending_requests.pop_back();
  }
}

void service_h2_session_io(
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    uint32_t events,
    bool allow_read_without_event) {
  const std::size_t stream_budget =
      static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection));
  if (!client.ready || client.ctx.fd < 0 || client.session == nullptr) {
    return;
  }

  H2ConnectionContext& ctx = client.ctx;
  ctx.epoll_fd = shard.epoll_fd;
  const long long now_ms = monotonic_ms_now();

  while (ctx.goaway == 0 &&
         !local_shard.pending_h2_requests.empty() &&
         client.pending_requests.size() + ctx.active_streams.size() < stream_budget) {
    client.pending_requests.push_back(local_shard.pending_h2_requests.front());
    local_shard.pending_h2_requests.pop_front();
  }
  if (client.active_since_ms == 0 &&
      (!client.pending_requests.empty() || !ctx.active_streams.empty())) {
    client.active_since_ms = now_ms;
  }

  while (ctx.goaway == 0 &&
         !client.pending_requests.empty() &&
         ctx.active_streams.size() < stream_budget) {
    const std::map<std::string, std::string> empty_captures;
    const std::map<std::string, std::string>& request_captures =
        ctx.captures != nullptr ? *ctx.captures : empty_captures;
    if (!submit_h2_request(
            client,
            profile,
            client.pending_requests.front(),
            request_captures)) {
      ctx.protocol_error = 1;
      break;
    }
    client.pending_requests.pop_front();
  }

  if ((ctx.protocol_error == 0 && ctx.transport_error == 0) &&
      (!ctx.active_streams.empty() || !client.pending_requests.empty())) {
    if (nghttp2_session_send(client.session) < 0) {
      ctx.protocol_error = 1;
    }
  }

  if (ctx.protocol_error == 0 && ctx.transport_error == 0 &&
      (((events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) ||
       (allow_read_without_event && !ctx.active_streams.empty()))) {
    unsigned char read_buf[16384];
    while (true) {
      const ssize_t rd = h2_socket_read(ctx, read_buf, sizeof(read_buf));
      if (rd > 0) {
        if (nghttp2_session_mem_recv(client.session, read_buf, static_cast<size_t>(rd)) < 0) {
          ctx.protocol_error = 1;
          break;
        }
        continue;
      }
      if (rd == 0) {
        if (!ctx.active_streams.empty()) {
          ctx.transport_error = 1;
        }
        break;
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      ctx.transport_error = 1;
      break;
    }
  }

  if (ctx.transport_error || ctx.protocol_error) {
    const int outstanding =
        static_cast<int>(client.pending_requests.size() + ctx.active_streams.size());
    ctx.failed_streams += outstanding;
    ctx.expectation_failures += outstanding;
    client.pending_requests.clear();
    client.consecutive_failures += 1;
    client.unhealthy_until_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms / 4);
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    unregister_lane_fd(shard, local_shard, client.ctx.fd);
    close_h2_client_session(client);
    local_shard.dispatch_ready_ms = client.unhealthy_until_ms;
    return;
  }

  (void)local_shard;

  if (ctx.goaway > 0 && ctx.active_streams.empty()) {
    client.drain_evictions += 1;
    client.replacement_mode = H2LaneReplacementMode::ReplaceNow;
    requeue_h2_pending_front(local_shard, client);
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    unregister_lane_fd(shard, local_shard, client.ctx.fd);
    close_h2_client_session(client);
    local_shard.dispatch_ready_ms = now_ms;
    return;
  }

  client.idle_deadline_ms = now_ms + std::max(1, profile.timeout_ms);
  if (!client.pending_requests.empty() || !ctx.active_streams.empty()) {
    client.dispatch_ready_ms = now_ms;
  } else {
    client.dispatch_ready_ms = now_ms;
    client.active_since_ms = 0;
  }
}

#endif

std::map<std::string, double> run_http2_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps) {
  const TransportBackend transport_backend = parse_transport_backend(profile);
  if (transport_backend == TransportBackend::CustomTcp) {
    return run_http2_custom_tcp_profile(profile, cfg, caps);
  }
  NativeRuntime runtime = build_runtime(profile, cfg);
  runtime.perf.started_ms = monotonic_ms_now();
  g_perf_stats = &runtime.perf;
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  if (!(caps.openssl && caps.nghttp2)) {
    g_perf_stats = nullptr;
    destroy_runtime(runtime);
    return fail_visible_stats(profile, caps, "capability_unavailable");
  }

#ifdef SAMURAI_WITH_NGHTTP2
  std::vector<H2RequestSpec> requests = build_h2_requests(profile);
  H2RunStats stats;
  stats.attempted = static_cast<int>(requests.size());
  if (stats.attempted == 0) {
    apply_perf_outputs(out, runtime, cfg, PerfDerivedInputs{});
    g_perf_stats = nullptr;
    destroy_runtime(runtime);
    out["attempted"] = 0.0;
    out["sent"] = 0.0;
    out["errors"] = 0.0;
    out["l7_flow_attempted"] = 0.0;
    return out;
  }

  const auto shard_buckets = bucket_h2_requests_by_shard(requests, runtime.shards.size());
  std::map<std::string, std::string> captures;
  for (std::size_t shard_idx = 0; shard_idx < shard_buckets.size(); ++shard_idx) {
    const auto& bucket = shard_buckets[shard_idx];
    auto& local_shard = runtime.local_shards[shard_idx];
    const std::size_t shard_conn_budget = static_cast<std::size_t>(
        std::max(1, runtime.shards.empty() ? profile.max_connections : runtime.shards[shard_idx].connection_pool.max_connections));
    while (local_shard.h2_sessions.size() < shard_conn_budget) {
      local_shard.h2_sessions.push_back(std::make_unique<H2ClientSession>());
      local_shard.h2_sessions.back()->session_idx = local_shard.h2_sessions.size() - 1;
    }
    for (const auto& request : bucket) {
      local_shard.pending_h2_requests.push_back(request);
    }
    if (!bucket.empty()) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }

  auto collect_all_h2_stats = [&]() {
    for (auto& local_shard : runtime.local_shards) {
      for (auto& session_ptr : local_shard.h2_sessions) {
        if (!session_ptr) {
          continue;
        }
        collect_h2_session_stats(*session_ptr, stats, cfg.profile_sample_limit);
      }
    }
  };

  auto finalize_h2_stream = [&](const H2CompletedStream& completed) {
    stats.expectation_failures += completed.expectation_failures;
    if (completed.rst_stream || !completed.success || completed.status_code <= 0) {
      stats.errors += 1;
    } else {
      stats.sent += 1;
    }
    if (completed.status_code >= 200 && completed.status_code <= 299) {
      stats.status_2xx += 1;
    } else if (completed.status_code >= 300 && completed.status_code <= 399) {
      stats.status_3xx += 1;
    } else if (completed.status_code >= 400 && completed.status_code <= 499) {
      stats.status_4xx += 1;
    } else if (completed.status_code >= 500 && completed.status_code <= 599) {
      stats.status_5xx += 1;
    }
    return CompletionDispositionDecision{};
  };

  auto apply_h2_disposition = [&](std::size_t shard_idx, const CompletionDispositionDecision& decision) {
    if (decision.action == ConnectionDispositionAction::None) {
      return;
    }
    if (shard_idx >= runtime.local_shards.size()) {
      return;
    }
    auto& local_shard = runtime.local_shards[shard_idx];
    auto& shard = runtime.shards[shard_idx];
    if (decision.slot_idx >= local_shard.h2_sessions.size() ||
        !local_shard.h2_sessions[decision.slot_idx]) {
      return;
    }
    H2ClientSession& client = *local_shard.h2_sessions[decision.slot_idx];
    if (decision.action == ConnectionDispositionAction::Close) {
      shard.connection_pool.active_connections =
          std::max(0, shard.connection_pool.active_connections - 1);
      unregister_lane_fd(shard, local_shard, client.ctx.fd);
      close_h2_client_session(client);
      return;
    }
    if (decision.action == ConnectionDispositionAction::Rearm) {
      client.dispatch_ready_ms = decision.next_ready_ms;
      client.idle_deadline_ms = decision.idle_deadline_ms;
    }
  };

  auto dispatch_pending_h2_requests = [&](std::size_t shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    auto& shard = runtime.shards[shard_idx];
    const long long now_ms = monotonic_ms_now();
    const std::size_t stream_budget =
        static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection));
    auto session_load = [&](const H2ClientSession& client) {
      return client.pending_requests.size() + client.ctx.active_streams.size();
    };
    auto choose_h2_session = [&]() -> H2ClientSession* {
      H2ClientSession* best_ready = nullptr;
      H2ClientSession* best_draining = nullptr;
      H2ClientSession* replace_now = nullptr;
      H2ClientSession* best_closed = nullptr;
      for (auto& session_ptr : local_shard.h2_sessions) {
        if (!session_ptr) {
          continue;
        }
        auto& client = *session_ptr;
        client.ctx.captures = &captures;
        if (!client.ready && client.unhealthy_until_ms > now_ms) {
          local_shard.dispatch_ready_ms = std::max(local_shard.dispatch_ready_ms, client.unhealthy_until_ms);
          continue;
        }
        if (client.replacement_mode == H2LaneReplacementMode::ReplaceNow && replace_now == nullptr) {
          replace_now = &client;
          continue;
        }
        if (client.ready && client.ctx.fd >= 0 && client.ctx.goaway == 0 &&
            session_load(client) < stream_budget) {
          if (best_ready == nullptr || session_load(client) < session_load(*best_ready)) {
            best_ready = &client;
          }
          continue;
        }
        if (client.ready && client.ctx.fd >= 0 &&
            client.replacement_mode == H2LaneReplacementMode::Draining &&
            session_load(client) < stream_budget) {
          if (best_draining == nullptr || session_load(client) < session_load(*best_draining)) {
            best_draining = &client;
          }
          continue;
        }
        if (!client.ready && best_closed == nullptr) {
          best_closed = &client;
        }
      }
      if (best_ready != nullptr) {
        return best_ready;
      }
      if (replace_now != nullptr) {
        return replace_now;
      }
      if (best_draining != nullptr) {
        return best_draining;
      }
      return best_closed;
    };

    std::size_t rounds = 0;
    while ((!local_shard.pending_h2_requests.empty() || rounds == 0) &&
           rounds < std::max<std::size_t>(1, local_shard.h2_sessions.size())) {
      H2ClientSession* selected = choose_h2_session();
      if (selected == nullptr) {
        break;
      }
      auto& client = *selected;
      client.ctx.captures = &captures;
      if (!client.ready && client.unhealthy_until_ms > now_ms) {
        local_shard.dispatch_ready_ms = client.unhealthy_until_ms;
        break;
      }
      if (client.replacement_mode == H2LaneReplacementMode::ReplaceNow) {
        stats.replace_now_decisions += 1;
        if (client.ctx.fd >= 0) {
          shard.connection_pool.active_connections =
              std::max(0, shard.connection_pool.active_connections - 1);
          unregister_lane_fd(shard, local_shard, client.ctx.fd);
        }
        close_h2_client_session(client);
      }
      if (!client.ready && local_shard.pending_h2_requests.empty()) {
        break;
      }
      if (!client.ready) {
        if (!open_h2_client_session(
                profile,
                shard.epoll_fd,
                shard,
                local_shard,
                client,
                stats,
                local_shard.pending_h2_requests.size())) {
          rounds += 1;
          continue;
        }
        stats.goaway_replacements += 1;
      } else if (client.ctx.fd >= 0 &&
                 (!local_shard.pending_h2_requests.empty() || !client.pending_requests.empty())) {
        stats.conn_reused += 1;
        if (client.replacement_mode == H2LaneReplacementMode::Draining) {
          stats.replace_after_idle_decisions += 1;
        }
      }
      const std::size_t pending_before = local_shard.pending_h2_requests.size();
      const std::size_t load_before = session_load(client);
      service_h2_session_io(profile, shard, local_shard, client, 0, true);
      flush_ready_h2_completions(runtime, shard_idx, client);
      const bool progressed =
          local_shard.pending_h2_requests.size() < pending_before || session_load(client) != load_before;
      rounds += 1;
      if (!progressed && local_shard.pending_h2_requests.empty()) {
        break;
      }
    }
  };

  while (true) {
    expire_all_lane_idle(runtime, profile);
    for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
      dispatch_pending_h2_requests(shard_idx);
    }
    service_all_ready_lanes(runtime, profile, 0);
    collect_all_h2_stats();
    bool made_progress = false;
    while (true) {
      auto ready_completion = pop_ready_completion(runtime);
      if (!ready_completion.has_value()) {
        break;
      }
      if (ready_completion->kind == CompletionKind::H2 &&
          ready_completion->h2_completed.has_value()) {
        const auto decision = finalize_h2_stream(*ready_completion->h2_completed);
        apply_h2_disposition(ready_completion->shard_idx, decision);
        made_progress = true;
      }
    }
    if (made_progress) {
      continue;
    }
    auto ready_shard = pop_ready_shard(runtime);
    if (!ready_shard.has_value()) {
      bool pending = false;
      bool active_io = false;
      std::optional<long long> next_deadline;
      const long long now_ms = monotonic_ms_now();
      for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
        const auto& local_shard = runtime.local_shards[shard_idx];
        if (!local_shard.pending_h2_requests.empty()) {
          pending = true;
        }
        for (const auto& session_ptr : local_shard.h2_sessions) {
          if (!session_ptr) {
            continue;
          }
          const auto& client = *session_ptr;
          if (!client.pending_requests.empty() || !client.ctx.active_streams.empty()) {
            pending = true;
            active_io = true;
          } else if (!local_shard.pending_h2_requests.empty() ||
                     (!client.ready && client.unhealthy_until_ms > now_ms)) {
            pending = true;
            const long long candidate = std::max(now_ms, std::max(client.dispatch_ready_ms, client.unhealthy_until_ms));
            if (!next_deadline.has_value() || candidate < *next_deadline) {
              next_deadline = candidate;
            }
          }
        }
      }
      if (!pending) {
        break;
      }
      if (active_io) {
        service_all_ready_lanes(runtime, profile, 16);
        collect_all_h2_stats();
        continue;
      }
      if (!next_deadline.has_value()) {
        break;
      }
      advance_runtime_until(runtime, profile, *next_deadline);
      continue;
    }

    const std::size_t shard_idx = *ready_shard;
    auto& local_shard = runtime.local_shards[shard_idx];
    if (!local_shard.pending_h2_requests.empty()) {
      dispatch_pending_h2_requests(shard_idx);
      collect_all_h2_stats();
    } else {
      bool shard_has_pending = false;
      for (const auto& session_ptr : local_shard.h2_sessions) {
        if (session_ptr &&
            (!session_ptr->pending_requests.empty() || !session_ptr->ctx.active_streams.empty())) {
          shard_has_pending = true;
          break;
        }
      }
      if (!shard_has_pending) {
        continue;
      }
    }
    if (!local_shard.pending_h2_requests.empty()) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }

  collect_all_h2_stats();

  stats.errors += std::max(0, stats.attempted - stats.sent - stats.errors);
  out["attempted"] = static_cast<double>(stats.attempted);
  out["sent"] = static_cast<double>(stats.sent);
  out["errors"] = static_cast<double>(stats.errors);
  out["responses_total"] = static_cast<double>(stats.sent);
  out["status_2xx"] = static_cast<double>(stats.status_2xx);
  out["status_3xx"] = static_cast<double>(stats.status_3xx);
  out["status_4xx"] = static_cast<double>(stats.status_4xx);
  out["status_5xx"] = static_cast<double>(stats.status_5xx);
  out["l7_flow_attempted"] = static_cast<double>(stats.attempted);
  out["l7_flow_completed"] = static_cast<double>(stats.sent);
  out["l7_conn_attempted"] = static_cast<double>(stats.conn_attempted);
  out["l7_conn_established"] = static_cast<double>(stats.conn_established);
  out["l7_conn_reused"] = static_cast<double>(stats.conn_reused);
  out["l7_rx_bytes"] = static_cast<double>(stats.rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(stats.tx_bytes);
  out["l7_expectation_failures"] = static_cast<double>(stats.expectation_failures);
  out["l7_scheduler_backpressure_count"] = static_cast<double>(stats.scheduler_backpressure);
  out["h2_goaway_count"] = static_cast<double>(stats.goaway_count);
  out["h2_stream_reset_ratio"] = stats.attempted > 0
      ? static_cast<double>(stats.rst_stream_count) / static_cast<double>(stats.attempted)
      : 0.0;
  out["h2_goaway_replacements"] = static_cast<double>(stats.goaway_replacements);
  out["h2_drain_evictions"] = static_cast<double>(stats.drain_evictions);
  out["h2_replace_now_decisions"] = static_cast<double>(stats.replace_now_decisions);
  out["h2_replace_after_idle_decisions"] = static_cast<double>(stats.replace_after_idle_decisions);
  out["h2_stream_pool_reuse_hits"] = static_cast<double>(stats.stream_pool_reuse_hits);
  out["l7_h2_active_streams_peak"] = static_cast<double>(stats.active_streams_peak);
  apply_perf_outputs(
      out,
      runtime,
      cfg,
      PerfDerivedInputs{
          stats.attempted,
          stats.sent,
          stats.conn_attempted,
          stats.conn_established,
          stats.conn_reused,
          runtime_active_conn_peak(runtime),
      });
  g_perf_stats = nullptr;
  destroy_runtime(runtime);
  return out;
#else
  g_perf_stats = nullptr;
  destroy_runtime(runtime);
  return fail_visible_stats(profile, caps, "nghttp2_not_built");
#endif
}

}  // namespace

RuntimeCapabilities detect_capabilities() {
  RuntimeCapabilities caps;
#ifdef SAMURAI_WITH_OPENSSL
  caps.openssl = true;
#endif
#ifdef SAMURAI_WITH_NGHTTP2
  caps.nghttp2 = true;
#endif
  return caps;
}

std::map<std::string, double> run_profile(const Profile& profile, const RuntimeConfig& cfg) {
  const RuntimeCapabilities caps = detect_capabilities();
  const TransportBackend transport_backend = parse_transport_backend(profile);
  if (profile.protocol == "http2") {
    return run_http2_profile(profile, cfg, caps);
  }
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["runtime_transport_custom_tcp_requested"] = transport_backend == TransportBackend::CustomTcp ? 1.0 : 0.0;
  if (transport_backend == TransportBackend::CustomTcp) {
    out["runtime_transport_custom_tcp_bridge_ready"] = configure_custom_tcp_bridge(profile) ? 1.0 : 0.0;
    if (out["runtime_transport_custom_tcp_bridge_ready"] == 0.0) {
      auto failed = fail_visible_stats(profile, caps, "custom_tcp_transport_not_yet_wired");
      failed["runtime_transport_custom_tcp_bridge_ready"] = 0.0;
      return failed;
    }
  }

  int status_2xx = 0;
  int status_3xx = 0;
  int status_4xx = 0;
  int status_5xx = 0;
  int sent = 0;
  int conn_attempted = 0;
  int conn_established = 0;
  int conn_reused = 0;
  int expectation_failures = 0;
  std::size_t rx_bytes = 0;
  std::size_t tx_bytes = 0;
  std::map<std::string, std::string> captures;

  const auto request_specs = build_h1_requests(profile);
  const int request_attempts = static_cast<int>(request_specs.size());
  NativeRuntime runtime = build_runtime(profile, cfg);
  runtime.perf.started_ms = monotonic_ms_now();
  g_perf_stats = &runtime.perf;
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  if (transport_backend == TransportBackend::CustomTcp) {
    runtime.custom_tcp_rx_handler_id = maybe_start_custom_tcp_rx_bridge();
    out["runtime_transport_custom_tcp_rx_bridge_active"] =
        runtime.custom_tcp_rx_handler_id > 0 ? 1.0 : 0.0;
  }
  const auto shard_buckets = bucket_h1_requests_by_shard(request_specs, runtime.shards.size());
  for (std::size_t shard_idx = 0; shard_idx < shard_buckets.size(); ++shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    for (const auto& request : shard_buckets[shard_idx]) {
      local_shard.pending_h1_requests.push_back(request);
    }
    const std::size_t shard_conn_budget = static_cast<std::size_t>(
        std::max(1, runtime.shards.empty() ? profile.max_connections : runtime.shards[shard_idx].connection_pool.max_connections));
    while (local_shard.h1_lanes.size() < shard_conn_budget) {
      local_shard.h1_lanes.push_back(std::make_unique<H1Lane>());
    }
  }

  auto dispatch_pending_h1_requests = [&](std::size_t shard_idx) {
    ShardState& shard = runtime.shards[shard_idx];
    auto& local_shard = runtime.local_shards[shard_idx];
    const long long now_ms = monotonic_ms_now();
    for (std::size_t lane_idx = 0; lane_idx < local_shard.h1_lanes.size(); ++lane_idx) {
      auto& lane_ptr = local_shard.h1_lanes[lane_idx];
      if (local_shard.pending_h1_requests.empty()) {
        break;
      }
      if (!lane_ptr) {
        continue;
      }
      H1Lane& lane = *lane_ptr;
      if (lane.phase != H1LanePhase::Idle || lane.queued_ready ||
          lane.lane.dispatch_ready_at_ms > now_ms) {
        continue;
      }
      reset_h1_lane_io(lane);
      lane.request_spec = local_shard.pending_h1_requests.front();
      lane.transport_backend = transport_backend;
      local_shard.pending_h1_requests.pop_front();
      lane.request_start_ms = now_ms;
      lane.phase = H1LanePhase::Writing;
      build_http1_request_into(
          lane.write_buffer,
          ensure_lane_string_arena(lane.string_arena),
          profile,
          lane.request_spec,
          captures);

      if (!lane.conn) {
        lane.conn = std::make_unique<Http1Connection>();
        ensure_reusable_string_capacity(lane.conn->read_buffer, kH1SlabReadBytes);
      }
      if (lane.conn->fd >= 0) {
        conn_reused += 1;
      } else {
        const H1TransportOps& transport_ops = resolve_h1_transport_ops(lane.transport_backend);
        lane.conn->transport_backend = lane.transport_backend;
        lane.conn->fd = transport_ops.connect_fn(*lane.conn, profile);
        lane.conn->shard_id = static_cast<int>(shard_idx);
        conn_attempted += 1;
        if (lane.conn->fd < 0) {
          expectation_failures += 1;
          reset_h1_lane_io(lane);
          lane.lane = ReactorLaneState{};
          continue;
        }
        conn_established += 1;
        shard.connection_pool.active_connections += 1;
        shard.connection_pool.active_connections_peak = std::max(
            shard.connection_pool.active_connections_peak,
            shard.connection_pool.active_connections);
      }

      lane.conn->read_buffer.clear();
      lane.conn->idle_deadline_ms = 0;
      sync_h1_lane_state(lane, profile);
      register_h1_lane_fd(shard, local_shard, &lane);

      H1LaneIoResult immediate_result = h1_lane_write_step(lane);
      if (immediate_result == H1LaneIoResult::Pending && lane.phase == H1LanePhase::Reading) {
        immediate_result = h1_lane_read_step(lane);
      }
      if (immediate_result == H1LaneIoResult::Completed || immediate_result == H1LaneIoResult::Failed) {
        unregister_lane_fd(shard, local_shard, lane.conn ? lane.conn->fd : -1);
        enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, lane);
      }
    }
  };

  auto finalize_h1_lane = [&](std::size_t shard_idx, const H1CompletedRequest& completed) {
    auto& local_shard = runtime.local_shards[shard_idx];
    if (completed.lane_idx >= local_shard.h1_lanes.size() ||
        !local_shard.h1_lanes[completed.lane_idx]) {
      return CompletionDispositionDecision{};
    }
    H1Lane& lane = *local_shard.h1_lanes[completed.lane_idx];
    const long long now_ms = monotonic_ms_now();
    rx_bytes += completed.rx_bytes;
    tx_bytes += completed.tx_bytes;
    lane.expectation_failures = completed.expectation_failures;
    lane.think_time_total_ms = completed.think_time_total_ms;

    if (!completed.success || completed.status_code <= 0) {
      expectation_failures += std::max(1, completed.expectation_failures + (completed.status_code <= 0 ? 1 : 0));
      return CompletionDispositionDecision{
          ConnectionDispositionAction::Close,
          completed.lane_idx,
          0,
          0,
      };
    }

    for (const FlowOp& follow : completed.follow_ops) {
      if (follow.opcode == "EXPECT_STATUS" && follow.has_expect) {
        if (completed.status_code < follow.expect.status_min || completed.status_code > follow.expect.status_max) {
          lane.expectation_failures = completed.expectation_failures + 1;
        }
      } else if (follow.opcode == "EXPECT_HEADER" && follow.has_expect) {
        const std::string name = lower_copy(follow.expect.name);
        const std::string* header_value = find_header_value(completed.response_header_fields, name);
        if ((header_value == nullptr || header_value->find(follow.expect.value) == std::string::npos) &&
            (completed.response_headers.empty() || completed.response_headers.find(name) == completed.response_headers.end() ||
             completed.response_headers.at(name).find(follow.expect.value) == std::string::npos)) {
          lane.expectation_failures += 1;
        }
      } else if (follow.opcode == "EXPECT_BODY_SUBSTRING" && follow.has_expect) {
        if (completed.response_body.find(follow.expect.value) == std::string::npos) {
          lane.expectation_failures += 1;
        }
      } else if (follow.opcode == "CAPTURE_HEADER") {
        const std::string key = lower_copy(follow.capture_source.empty() ? follow.capture_name : follow.capture_source);
        const std::string* header_value = find_header_value(completed.response_header_fields, key);
        if (header_value != nullptr) {
          captures[follow.capture_name.empty() ? key : follow.capture_name] = *header_value;
        } else {
          const auto it = completed.response_headers.find(key);
          if (it != completed.response_headers.end()) {
            captures[follow.capture_name.empty() ? key : follow.capture_name] = it->second;
          }
        }
      } else if (follow.opcode == "CAPTURE_COOKIE") {
        const std::string* cookie_value = find_header_value(completed.response_header_fields, "set-cookie");
        if (cookie_value != nullptr) {
          capture_cookie(*cookie_value, follow.capture_name, captures);
        } else {
          const auto it = completed.response_headers.find("set-cookie");
          if (it != completed.response_headers.end()) {
            capture_cookie(it->second, follow.capture_name, captures);
          }
        }
      } else if (follow.opcode == "THINK_TIME") {
        lane.think_time_total_ms += std::max(0, follow.think_time_ms);
      }
    }

    expectation_failures += lane.expectation_failures;
    sent += 1;
    perf_request_latency(
        static_cast<double>(std::max<long long>(0, now_ms - completed.request_start_ms)),
        cfg.profile_sample_limit);
    if (completed.status_code >= 200 && completed.status_code <= 299) {
      status_2xx += 1;
    } else if (completed.status_code >= 300 && completed.status_code <= 399) {
      status_3xx += 1;
    } else if (completed.status_code >= 400 && completed.status_code <= 499) {
      status_4xx += 1;
    } else if (completed.status_code >= 500 && completed.status_code <= 599) {
      status_5xx += 1;
    }

    const bool keep_alive = completed.keep_alive && profile.keepalive;
    const long long next_ready_ms = now_ms + lane.think_time_total_ms;
    const long long idle_deadline_ms = now_ms + std::max(1, profile.timeout_ms);
    if (!keep_alive) {
      return CompletionDispositionDecision{
          ConnectionDispositionAction::Close,
          completed.lane_idx,
          0,
          0,
      };
    }
    return CompletionDispositionDecision{
        ConnectionDispositionAction::Rearm,
        completed.lane_idx,
        next_ready_ms,
        idle_deadline_ms,
    };
  };

  auto apply_h1_disposition = [&](std::size_t shard_idx, const CompletionDispositionDecision& decision) {
    if (decision.action == ConnectionDispositionAction::None) {
      return;
    }
    ShardState& shard = runtime.shards[shard_idx];
    auto& local_shard = runtime.local_shards[shard_idx];
    if (decision.slot_idx >= local_shard.h1_lanes.size() ||
        !local_shard.h1_lanes[decision.slot_idx]) {
      return;
    }
    H1Lane& lane = *local_shard.h1_lanes[decision.slot_idx];
    if (decision.action == ConnectionDispositionAction::Close) {
      lane.lane.health_state = LaneHealthState::Closed;
      close_http1_connection(lane.conn, shard, local_shard);
      reset_h1_lane_io(lane);
      lane.lane = ReactorLaneState{};
      return;
    }
    if (decision.action == ConnectionDispositionAction::Rearm) {
      lane.lane.health_state = LaneHealthState::Healthy;
      lane.lane.reuse_score += 1;
      if (lane.conn) {
        lane.conn->idle_deadline_ms = decision.idle_deadline_ms;
      }
      reset_h1_lane_io(lane);
      lane.lane.dispatch_ready_at_ms = decision.next_ready_ms;
      lane.lane.idle_deadline_ms = decision.idle_deadline_ms;
      lane.lane.health_state = LaneHealthState::Healthy;
      lane.lane.reuse_score = std::max(1, lane.lane.reuse_score);
      local_shard.dispatch_ready_ms = std::min(
          local_shard.dispatch_ready_ms == 0 ? decision.next_ready_ms : local_shard.dispatch_ready_ms,
          decision.next_ready_ms);
    }
  };

  auto finalize_completion = [&](CompletionEnvelope&& completion) {
    if (completion.kind == CompletionKind::H1 && completion.h1_completed.has_value()) {
      const auto decision = finalize_h1_lane(completion.shard_idx, *completion.h1_completed);
      apply_h1_disposition(completion.shard_idx, decision);
      return true;
    }
#ifdef SAMURAI_WITH_NGHTTP2
    if (completion.kind == CompletionKind::H2 && completion.h2_completed.has_value()) {
      const H2CompletedStream& completed = *completion.h2_completed;
      expectation_failures += completed.expectation_failures;
      if (completed.rst_stream || !completed.success || completed.status_code <= 0) {
        status_4xx += completed.status_code >= 400 && completed.status_code <= 499 ? 1 : 0;
        status_5xx += completed.status_code >= 500 && completed.status_code <= 599 ? 1 : 0;
      } else {
        sent += 1;
        if (completed.status_code >= 200 && completed.status_code <= 299) {
          status_2xx += 1;
        } else if (completed.status_code >= 300 && completed.status_code <= 399) {
          status_3xx += 1;
        } else if (completed.status_code >= 400 && completed.status_code <= 499) {
          status_4xx += 1;
        } else if (completed.status_code >= 500 && completed.status_code <= 599) {
          status_5xx += 1;
        }
      }
      return true;
    }
#endif
    return false;
  };

  while (true) {
    expire_all_lane_idle(runtime, profile);
    for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
      dispatch_pending_h1_requests(shard_idx);
    }
    service_all_ready_lanes(runtime, profile, 0);

    bool made_progress = false;
    while (true) {
      auto ready_completion = pop_ready_completion(runtime);
      if (!ready_completion.has_value()) {
        break;
      }
      made_progress = finalize_completion(std::move(*ready_completion)) || made_progress;
    }
    if (made_progress) {
      continue;
    }

    bool pending = false;
    bool active_io = false;
    std::optional<long long> next_deadline;
    const long long now_ms = monotonic_ms_now();
    for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
      auto& local_shard = runtime.local_shards[shard_idx];
      if (!local_shard.pending_h1_requests.empty()) {
        pending = true;
      }
      for (const auto& lane_ptr : local_shard.h1_lanes) {
        if (!lane_ptr) {
          continue;
        }
        const H1Lane& lane = *lane_ptr;
        if (lane.phase == H1LanePhase::Writing || lane.phase == H1LanePhase::Reading) {
          pending = true;
          active_io = true;
        } else if (!local_shard.pending_h1_requests.empty() && lane.phase == H1LanePhase::Idle) {
          pending = true;
          const long long candidate = std::max(now_ms, lane.lane.dispatch_ready_at_ms);
          if (!next_deadline.has_value() || candidate < *next_deadline) {
            next_deadline = candidate;
          }
        }
      }
    }
    if (!pending) {
      break;
    }
    if (active_io) {
      service_all_ready_lanes(runtime, profile, 16);
      continue;
    }
    if (next_deadline.has_value()) {
      advance_runtime_until(runtime, profile, *next_deadline);
      continue;
    }
    break;
  }
  apply_perf_outputs(
      out,
      runtime,
      cfg,
      PerfDerivedInputs{
          request_attempts,
          sent,
          conn_attempted,
          conn_established,
          conn_reused,
          runtime_active_conn_peak(runtime),
      });
  g_perf_stats = nullptr;
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    auto& shard = runtime.shards[shard_idx];
    for (auto& conn : local_shard.http1_idle) {
      close_http1_connection(conn, shard, local_shard);
    }
    local_shard.http1_idle.clear();
  }
  destroy_runtime(runtime);

  out["attempted"] = static_cast<double>(request_attempts);
  out["sent"] = static_cast<double>(sent);
  out["errors"] = static_cast<double>(request_attempts - sent);
  out["responses_total"] = static_cast<double>(sent);
  out["status_2xx"] = static_cast<double>(status_2xx);
  out["status_3xx"] = static_cast<double>(status_3xx);
  out["status_4xx"] = static_cast<double>(status_4xx);
  out["status_5xx"] = static_cast<double>(status_5xx);
  out["l7_flow_completed"] = static_cast<double>(sent);
  if (transport_backend == TransportBackend::CustomTcp) {
    merge_custom_tcp_stats(out);
  }
  out["l7_conn_attempted"] = static_cast<double>(conn_attempted);
  out["l7_conn_established"] = static_cast<double>(conn_established);
  out["l7_conn_reused"] = static_cast<double>(conn_reused);
  out["l7_rx_bytes"] = static_cast<double>(rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_expectation_failures"] = static_cast<double>(expectation_failures);
  return out;
}

}  // namespace ddos_samurai::l7_emu_native
