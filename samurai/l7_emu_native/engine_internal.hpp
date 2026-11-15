#pragma once

#include "engine_types.hpp"

namespace samurai::l7_emu_native {

// Monotonic per-worker-thread tag source for io_uring connection generations.
// Each shard runs on one thread, so a thread-local counter yields values unique
// across the connection instances that pass through a given lane slot; 0 is
// skipped so it never collides with a default-initialised uring_gen.
inline uint16_t next_h1_uring_gen() {
  static thread_local uint16_t seq = 0;
  ++seq;
  if (seq == 0) {
    ++seq;
  }
  return seq;
}

// Thread-local performance and scenario tracking
extern thread_local DataplanePerfStats* g_perf_stats;
extern thread_local std::vector<ScenarioStepResult> g_last_scenario_step_results;
extern thread_local int g_worker_idle_passes;

// Arena allocator and string utility functions (engine_arena.cpp)
void trim_reusable_string(std::string& value, std::size_t keep_limit = kHotPathReusableBufferLimit);
void ensure_reusable_string_capacity(std::string& value, std::size_t min_capacity);
void perf_alloc(std::size_t bytes);
void perf_request_latency(double latency_ms, int sample_limit);
void perf_tls_latency(double latency_ms, int sample_limit);
void record_scenario_step_result(
    const std::string& protocol,
    const std::string& flow,
    const std::string& vu_id,
    const std::string& on_failure,
    bool success,
    bool timeout,
    int status_code,
    double latency_ms);
void cpu_relax();
void worker_idle_reset();
void worker_idle_backoff();
std::size_t percentile_index(std::size_t sample_count, double pct);
PercentileTripletMs percentile_triplet_ms(const std::vector<double>& values);
LaneStringArena& ensure_lane_string_arena(std::unique_ptr<LaneStringArena>& arena_ptr);
ArenaStringLease arena_acquire_string(LaneStringArena& arena, std::size_t min_capacity);
std::string& arena_string_or_throw(ArenaStringLease& lease, const char* context);
std::string lower_copy(const std::string& in);
std::string lowercase_copy(std::string_view value);
std::string trim_header_value_copy(std::string_view value);
bool ascii_iequals(std::string_view a, std::string_view b);
bool ascii_icontains(std::string_view haystack, std::string_view needle);
std::size_t find_crlf(std::string_view payload, std::size_t start);
long long monotonic_ms_now();
void reset_response_info(ResponseInfo& response);
void reset_h1_lane_io(H1Lane& lane);

// HTTP/1 transport operations & connection bridge (engine_h1_transport.cpp)
bool is_custom_tcp_backend(TransportBackend backend);
TransportBackend parse_transport_backend(const Profile& profile);
bool parse_ipv4_u32(const std::string& text, uint32_t* out_ip);
uint32_t custom_tcp_src_ip(const Profile& profile);
const H1TransportOps& resolve_h1_transport_ops(TransportBackend backend);
bool wait_for_fd(int epoll_fd, int fd, uint32_t events, int timeout_ms);
bool set_fd_nonblocking(int fd);
int connect_h2_tcp_socket(const Profile& profile, int epoll_fd);

// HTTP/1 parsing & lane I/O (engine_h1_parser.cpp)
int parse_http_status_code(std::string_view status_line);
std::optional<std::size_t> parse_chunked_body_length(std::string_view payload, std::size_t body_offset);
void sync_h1_lane_state(H1Lane& lane, const Profile& profile);
bool h1_lane_try_parse_response(H1Lane& lane);
H1LaneIoResult h1_lane_write_step(H1Lane& lane);
H1LaneIoResult h1_lane_read_step(H1Lane& lane);
void enqueue_ready_h1_lane(NativeRuntime& runtime, std::size_t shard_idx, std::size_t lane_idx, H1Lane& lane);
void enqueue_ready_h2_stream(NativeRuntime& runtime, std::size_t shard_idx, H2CompletedStream&& completed);
std::optional<CompletionEnvelope> pop_ready_completion(NativeRuntime& runtime, std::size_t shard_idx);
std::optional<CompletionEnvelope> pop_ready_completion_any(NativeRuntime& runtime);
uint32_t reactor_interest_mask();
void register_h1_lane_fd(ShardState& shard, NativeRuntime::LocalShard& local_shard, H1Lane* lane, std::size_t lane_idx);
void unregister_lane_fd(ShardState& shard, NativeRuntime::LocalShard& local_shard, int fd);
int service_ready_lanes(NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx, int timeout_ms);
int service_ready_lanes_io_uring(NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx, int timeout_ms);
void service_custom_tcp_shard_lanes(NativeRuntime& runtime, std::size_t shard_idx);
void service_all_ready_lanes(NativeRuntime& runtime, const Profile& profile, int timeout_ms);

// HTTP/2 nghttp2 session management (engine_h2_session.cpp)
#ifdef SAMURAI_WITH_NGHTTP2
void reset_h2_stream_state(H2StreamState& stream);
std::unique_ptr<H2StreamState> acquire_h2_stream_state(H2ClientSession& client);
void recycle_h2_stream_state(H2ClientSession& client, std::unique_ptr<H2StreamState> stream);
void register_custom_tcp_h2_flow_binding(NativeRuntime& runtime, std::size_t shard_idx, H2ClientSession& client);
void unregister_custom_tcp_h2_flow_binding(NativeRuntime& runtime, H2ClientSession& client);
void register_h2_lane_fd(ShardState& shard, NativeRuntime::LocalShard& local_shard, H2ClientSession* session);
void service_custom_tcp_h2_shard_sessions(NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx);
void collect_h2_session_stats(H2ClientSession& client, H2RunStats& stats, int sample_limit);
void flush_ready_h2_completions(NativeRuntime& runtime, std::size_t shard_idx, H2ClientSession& client);
void requeue_h2_pending_front(NativeRuntime::LocalShard& local_shard, H2ClientSession& client);
void service_h2_session_io(
    NativeRuntime& runtime,
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    uint32_t events,
    bool allow_read_without_event);
// Unified mem-BIO byte-path helpers, shared by the epoll (service_h2_session_io)
// and io_uring (service_ready_lanes_io_uring) reactors. None block.
void h2_pull_pending_requests(
    NativeRuntime::LocalShard& local_shard, H2ClientSession& client, const Profile& profile);
bool h2_pump_outbound(H2ClientSession& client);
bool h2_ingest_inbound(H2ClientSession& client);
bool h2_finalize_session_io(
    NativeRuntime& runtime,
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client);
bool submit_h2_request(
    H2ClientSession& client,
    const Profile& profile,
    const H2RequestSpec& raw_request,
    const std::map<std::string, std::string>& captures);
void close_h2_client_session(H2ClientSession& client);
bool open_h2_client_session(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    const Profile& profile,
    int epoll_fd,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    H2RunStats& stats,
    std::size_t request_count);
bool setup_tls(H2ConnectionContext& ctx, const Profile& profile);
void cleanup_tls(H2ConnectionContext& ctx);
#endif
const std::string& build_h2_preface_and_settings();

// Custom TCP wire pump & DPDK (engine_custom_tcp.cpp)
std::mutex& custom_tcp_registry_mu();
std::mutex& custom_tcp_shard_stats_mu();
void accumulate_custom_tcp_shard_stats(NativeRuntime& runtime);
void unregister_custom_tcp_flow_binding(NativeRuntime& runtime, uint64_t flow_id);
void register_custom_tcp_h1_flow_binding(NativeRuntime& runtime, std::size_t shard_idx, std::size_t lane_idx, H1Lane& lane);
NativeRuntime::CustomTcpFlowBinding* find_custom_tcp_flow_binding(NativeRuntime& runtime, uint64_t flow_id);
void apply_custom_tcp_core_events(NativeRuntime& runtime);
bool pump_custom_tcp_shard_wire(
    NativeRuntime& runtime,
    afpkt_wire_t* wire,
    const uint8_t dst_mac[6],
    uint8_t* rxbuf,
    uint16_t* rxlens,
    uint16_t rx_budget);
bool resolve_wire_iface_mac(const std::string& iface, uint8_t out[6]);
CustomTcpWireConfig resolve_custom_tcp_wire_config();
ShardPortRange custom_tcp_shard_port_range(std::size_t sh, std::size_t n);
void maybe_pin_shard_worker(std::size_t sh);
bool custom_tcp_use_own_wire(const NativeRuntime& runtime, TransportBackend backend, const std::string& protocol);
std::string dpdk_eal_args_from_env();
uint16_t custom_tcp_dpdk_mask(std::size_t shard_count);
bool pump_custom_tcp_shard_dpdk(
    NativeRuntime& runtime,
    long handle,
    uint16_t queue,
    const uint8_t dst_mac[6],
    const uint8_t src_mac[6],
    uint8_t* rxbuf,
    uint16_t* rxlens,
    uint16_t rx_budget,
    std::vector<std::uint8_t>& txscratch);
DpdkOwnWire open_dpdk_own_wire(const CustomTcpWireConfig& cfg, std::size_t shard_count);
void close_dpdk_own_wire(DpdkOwnWire& dw);
ShardWire open_shard_wire(
    const CustomTcpWireConfig& cfg,
    const DpdkOwnWire& dw,
    std::size_t sh,
    std::size_t shard_count,
    const ShardPortRange& pr);
bool pump_shard_wire(
    NativeRuntime& runtime,
    const CustomTcpWireConfig& cfg,
    ShardWire& w,
    uint8_t* rxbuf,
    uint16_t* rxlens,
    uint16_t budget,
    std::vector<std::uint8_t>& txscratch);
void close_shard_wire(ShardWire& w);
void service_custom_tcp_lanes(NativeRuntime& runtime, const Profile& profile);
void custom_tcp_wire_pump(
    NativeRuntime& runtime,
    std::vector<std::unique_ptr<ShardIo>>& shard_io,
    std::atomic<bool>& wire_stop,
    ReactorLaneKind want_kind);
bool configure_custom_tcp_bridge(const Profile& profile);
int32_t maybe_start_custom_tcp_rx_bridge();
void merge_custom_tcp_stats(const NativeRuntime& runtime, std::map<std::string, double>& out);

// Runtime & Scheduler (engine_runtime.cpp)
void init_stats(const Profile& profile, std::map<std::string, double>& out);
double runtime_failure_reason_code(const std::string& reason);
std::map<std::string, double> fail_visible_stats(const Profile& profile, const RuntimeCapabilities& caps, const std::string& reason);
int runtime_active_conn_peak(const NativeRuntime& runtime);
void apply_perf_outputs(
    std::map<std::string, double>& out,
    NativeRuntime& runtime,
    const RuntimeConfig& cfg,
    const PerfDerivedInputs& inputs);
NativeRuntime build_runtime(const Profile& profile, const RuntimeConfig& cfg);
void destroy_runtime(NativeRuntime& runtime);
std::mutex& ready_shards_mu();
void enqueue_ready_shard(NativeRuntime& runtime, std::size_t shard_idx);
void refresh_ready_queue(NativeRuntime& runtime);
std::optional<std::size_t> pop_ready_shard(NativeRuntime& runtime);
void erase_active_http1(NativeRuntime::LocalShard& local_shard, Http1Connection* conn);
void close_http1_connection(
    NativeRuntime& runtime,
    std::unique_ptr<Http1Connection>& conn,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard);
void expire_http1_idle(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    int response_timeout_ms);
void expire_all_http1_idle(NativeRuntime& runtime, int response_timeout_ms);
#ifdef SAMURAI_WITH_NGHTTP2
void expire_h2_idle(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard);
#endif
void expire_all_lane_idle(NativeRuntime& runtime, const Profile& profile);
void expire_lane_idle_shard(NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx);
void advance_runtime_until(NativeRuntime& runtime, const Profile& profile, long long deadline_ms);

// Request templates & scenario evaluation (engine_h1_request.cpp)
const std::string* find_scenario_header(const std::map<std::string, std::string>& headers, const char* needle);
const std::string* find_header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& key);
CompiledCaptureTemplate compile_capture_template(const std::string& input);
void render_capture_template_into(
    const CompiledCaptureTemplate& compiled,
    const std::map<std::string, std::string>& captures,
    std::string& out);
void build_http1_request_into(
    std::string& out,
    LaneStringArena& arena,
    const Profile& profile,
    const H1RequestSpec& request,
    const std::map<std::string, std::string>& captures);
std::vector<H1RequestSpec> build_h1_requests(const Profile& profile);
std::vector<std::vector<H1RequestSpec>> bucket_h1_requests_by_shard(
    const std::vector<H1RequestSpec>& requests,
    std::size_t shard_count);
std::vector<H2RequestSpec> build_h2_requests(const Profile& profile);
std::vector<std::vector<H2RequestSpec>> bucket_h2_requests_by_shard(
    const std::vector<H2RequestSpec>& requests,
    std::size_t shard_count);
void capture_cookie(
    const std::string& cookie_line,
    const std::string& capture_name,
    std::map<std::string, std::string>& captures);
bool extract_json_field(const std::string& body, const std::string& path, std::string* out);
void capture_body_json(
    const FlowOp& follow,
    const std::string& body,
    std::map<std::string, std::string>& captures);
void evaluate_response_ops(
    const std::vector<FlowOp>& follow_ops,
    int status_code,
    const std::vector<std::pair<std::string, std::string>>& header_fields,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::map<std::string, std::string>& captures,
    int& expectation_failures,
    int& think_time_total_ms);

// Profile runners (engine_h2_profile.cpp, engine_dns_l2l3.cpp)
std::map<std::string, double> run_http2_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps);
std::map<std::string, double> run_dns_profile(const Profile& profile, const RuntimeConfig& cfg);
std::map<std::string, double> run_l2l3_profile(const Profile& profile, const RuntimeConfig& cfg);

}  // namespace samurai::l7_emu_native
