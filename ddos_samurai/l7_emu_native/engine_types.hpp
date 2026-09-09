#pragma once

#include "engine.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sched.h>
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <limits>
#include <mutex>
#include <optional>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include "../l4/tcp_dataplane_ffi.h"
#include "../af_packet/af_packet.h"
#include "../dpdk/dpdk_core.hpp"
#include "tls_session_engine.hpp"

namespace ddos_samurai::l7_emu_native {

class TlsSessionEngine;
struct ThreadLocalTlsContext;

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

struct H1ReadBuffer {
  std::string storage{};
  std::size_t head{0};

  std::size_t size() const {
    return head <= storage.size() ? storage.size() - head : 0;
  }

  bool empty() const {
    return size() == 0;
  }

  std::string_view view() const {
    return std::string_view(storage.data() + head, size());
  }

  void append(const char* data, std::size_t len) {
    storage.append(data, len);
  }

  // Take ownership of an already-materialised buffer without copying its bytes.
  // Only valid when empty() (all prior bytes consumed); callers guard on that.
  void adopt(std::string&& s) {
    storage = std::move(s);
    head = 0;
  }

  void consume(std::size_t len) {
    head += std::min(len, size());
    compact_if_needed();
  }

  void clear() {
    storage.clear();
    head = 0;
  }

  void reset_reusable(std::size_t keep_limit, std::size_t min_capacity);

  void compact_if_needed() {
    if (head == 0) {
      return;
    }
    if (head >= storage.size()) {
      clear();
      return;
    }
    if (head >= 32768 || head * 2 >= storage.size()) {
      storage.erase(0, head);
      head = 0;
    }
  }
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

struct ShardAccum {
  int status_2xx{0};
  int status_3xx{0};
  int status_4xx{0};
  int status_5xx{0};
  int sent{0};
  int conn_attempted{0};
  int conn_established{0};
  int conn_reused{0};
  int expectation_failures{0};
  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
};

struct InboxEvent {
  enum class Kind { ConnectEstablished, Terminal, RxPayload };
  Kind kind{Kind::RxPayload};
  std::size_t lane_idx{0};
  std::string payload{};  // populated only for RxPayload
};

struct ShardIo {
  std::mutex mu;
  std::deque<InboxEvent> inbox;
};

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
  TransportBackend transport_backend{TransportBackend::CustomTcp};
  uint64_t custom_flow_id{0};
  bool custom_connect_ready{false};
  bool custom_send_enqueued{false};
  std::uint32_t custom_send_outstanding{0};
  std::size_t custom_send_queued_bytes{0};
  std::uint32_t custom_send_enqueue_count{0};
  bool custom_terminal{false};
  bool custom_rx_pending{false};
  H1ReadBuffer read_buffer{};
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
  std::string scenario_flow{};
  std::string scenario_vu_id{};
  std::string scenario_on_failure{"retry"};
};

enum class H1LanePhase {
  Idle = 0,
  Writing = 1,
  Reading = 2,
  Complete = 3,
  Failed = 4,
};

struct LaneStringArena;

struct H1Lane {
  ReactorLaneState lane{};
  std::unique_ptr<Http1Connection> conn{};
  H1ParserState parser{};
  ResponseInfo response{};
  std::string write_buffer{};
  std::unique_ptr<LaneStringArena> string_arena{};
  std::size_t write_offset{0};
  long long request_start_ms{0};
  H1RequestSpec request_spec{};
  TransportBackend transport_backend{TransportBackend::CustomTcp};
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
constexpr std::size_t kArenaOverflowSlots = 8;
constexpr std::size_t kReusableHeaderSlotReserve = 16;
constexpr std::size_t kReusableResponseHeaderReserve = 16;
constexpr std::size_t kReusableResponseBodyBytes = 4096;
constexpr int kVirtualCustomTcpFd = 1;
constexpr std::uint16_t kCustomTcpWireStride = 2048;

struct ArenaStringBucket {
  std::size_t capacity{0};
  std::vector<std::string> slots{};
  std::vector<unsigned char> in_use{};
};

struct LaneStringArena {
  std::vector<ArenaStringBucket> buckets{};
  ArenaStringBucket overflow{};
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
    if (arena == nullptr || value == nullptr) {
      arena = nullptr;
      value = nullptr;
      return;
    }
    ArenaStringBucket* bucket_ptr = nullptr;
    if (bucket_idx < arena->buckets.size()) {
      bucket_ptr = &arena->buckets[bucket_idx];
    } else if (bucket_idx == arena->buckets.size()) {
      bucket_ptr = &arena->overflow;
    }
    if (bucket_ptr == nullptr) {
      arena = nullptr;
      value = nullptr;
      return;
    }
    auto& bucket = *bucket_ptr;
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
  std::string scenario_flow{};
  std::string scenario_vu_id{};
  std::string scenario_on_failure{"retry"};
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
  long long request_start_ms{0};
  std::string scenario_flow{};
  std::string scenario_vu_id{};
  std::string scenario_on_failure{"retry"};
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
  std::string scenario_flow{};
  std::string scenario_vu_id{};
  std::string scenario_on_failure{"retry"};
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

#ifdef SAMURAI_WITH_NGHTTP2
struct H2ClientSession;
struct H2StreamState;

struct H2StreamState {
  struct HeaderSlot {
    std::string key;
    std::string value;
  };
  std::string request_method;
  std::string request_path;
  std::vector<HeaderSlot> request_headers;
  std::size_t request_header_count{0};
  std::vector<std::string> submit_header_names;
  std::vector<std::string> submit_header_values;
  std::string outbound_body;
  std::size_t outbound_offset{0};
  int status_code{0};
  std::map<std::string, std::string> response_headers;
  std::vector<std::pair<std::string, std::string>> response_header_fields;
  std::string response_body;
  std::vector<FlowOp> follow_ops;
  bool completed{false};
  long long request_start_ms{0};
  std::string scenario_flow;
  std::string scenario_vu_id;
  std::string scenario_on_failure{"retry"};
};

struct H2ConnectionContext {
  int fd{-1};
  int epoll_fd{-1};
  TransportBackend transport_backend{TransportBackend::CustomTcp};
  bool use_tls{false};
  bool verify_peer{true};
  std::string authority;
  int timeout_ms{5000};
  uint64_t custom_flow_id{0};
  bool custom_connect_ready{false};
  bool custom_terminal{false};
  bool tls_handshake_complete{false};
  std::string read_buffer;
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
  std::unordered_map<int32_t, std::unique_ptr<H2StreamState>> active_streams;
#ifdef SAMURAI_WITH_OPENSSL
  SSL_CTX* tls_ctx{nullptr};
  SSL* ssl{nullptr};
  ThreadLocalTlsContext* tls_tctx{nullptr};
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
#endif

struct NativeRuntime {
  RuntimeCapabilities caps{};
  std::vector<ShardState> shards{};
  std::deque<std::size_t> ready_shards{};
  DataplanePerfStats perf{};
  int worker_threads{1};
  int32_t custom_tcp_rx_handler_id{0};
  struct CustomTcpFlowBinding {
    ReactorLaneKind kind{ReactorLaneKind::H1};
    std::size_t shard_idx{0};
    std::size_t lane_idx{0};
    H1Lane* h1_lane{nullptr};
#ifdef SAMURAI_WITH_NGHTTP2
    H2ClientSession* h2_session{nullptr};
#endif
  };
  std::unordered_map<uint64_t, CustomTcpFlowBinding> custom_tcp_flow_registry{};
  bool custom_tcp_own_wire_used{false};
  tcpdp_stats_snapshot_t custom_tcp_shard_stats{};
  struct LocalShard {
    LocalShard() = default;
    LocalShard(const LocalShard&) = delete;
    LocalShard& operator=(const LocalShard&) = delete;
    LocalShard(LocalShard&&) noexcept = default;
    LocalShard& operator=(LocalShard&&) noexcept = default;

    struct RegisteredLaneFd {
      ReactorLaneKind kind{ReactorLaneKind::H1};
      H1Lane* h1_lane{nullptr};
      std::size_t lane_idx{0};
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
    std::deque<CompletionEnvelope> ready_completions{};
    std::unordered_map<int, RegisteredLaneFd> active_fd_registry{};
    std::vector<epoll_event> ready_events{};
    std::vector<std::vector<TimerEntry>> timer_slots{};
    long long last_timer_tick_ms{0};
    long long dispatch_ready_ms{0};
    std::size_t h2_dispatch_cursor{0};
    bool in_ready_queue{false};
#ifdef SAMURAI_WITH_NGHTTP2
    std::vector<std::unique_ptr<H2ClientSession>> h2_sessions{};
#endif
    ThreadLocalTlsContext* tls_tctx{nullptr};
  };
  std::vector<LocalShard> local_shards{};
  std::unique_ptr<TlsSessionEngine> tls_engine{};
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

  void merge_from(const H2RunStats& o) {
    sent += o.sent;
    errors += o.errors;
    conn_attempted += o.conn_attempted;
    conn_established += o.conn_established;
    conn_reused += o.conn_reused;
    expectation_failures += o.expectation_failures;
    status_2xx += o.status_2xx;
    status_3xx += o.status_3xx;
    status_4xx += o.status_4xx;
    status_5xx += o.status_5xx;
    scheduler_backpressure += o.scheduler_backpressure;
    goaway_count += o.goaway_count;
    rst_stream_count += o.rst_stream_count;
    goaway_replacements += o.goaway_replacements;
    drain_evictions += o.drain_evictions;
    replace_now_decisions += o.replace_now_decisions;
    replace_after_idle_decisions += o.replace_after_idle_decisions;
    stream_pool_reuse_hits += o.stream_pool_reuse_hits;
    active_streams_peak = std::max(active_streams_peak, o.active_streams_peak);
    rx_bytes += o.rx_bytes;
    tx_bytes += o.tx_bytes;
  }
};

struct H1TransportOps {
  int (*connect_fn)(Http1Connection& conn, const Profile& profile);
  ssize_t (*send_fn)(Http1Connection& conn, const void* buf, std::size_t len);
  ssize_t (*recv_fn)(Http1Connection& conn, void* buf, std::size_t len);
  int (*close_fn)(Http1Connection& conn);
  const char* name;
};

enum class H1LaneIoResult {
  Pending = 0,
  Completed = 1,
  Failed = 2,
};

struct PercentileTripletMs {
  double p50{0.0};
  double p95{0.0};
  double p99{0.0};
};

struct ShardPortRange {
  std::uint16_t lo;
  std::uint16_t hi;
};

enum class WireKind { AfPacket, Dpdk };

struct CustomTcpWireConfig {
  std::string iface;
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  bool have_iface{false};
  bool have_src_mac{false};
  WireKind kind{WireKind::AfPacket};
  uint16_t dpdk_port{0};
};

struct DpdkOwnWire {
  long manager{0};
  uint16_t mask{0};
  bool active{false};
};

struct ShardWire {
  WireKind kind{WireKind::AfPacket};
  afpkt_wire_t* afpkt{nullptr};
  long dpdk_handle{0};
  uint16_t dpdk_queue{0};
  bool lcore_registered{false};
};

}  // namespace ddos_samurai::l7_emu_native
