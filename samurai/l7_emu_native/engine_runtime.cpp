#include "engine_internal.hpp"
#include "tls_session_engine.hpp"

namespace samurai::l7_emu_native {

int runtime_active_conn_peak(const NativeRuntime& runtime) {
  int peak = 0;
  for (const auto& shard : runtime.shards) {
    peak = std::max(peak, shard.connection_pool.active_connections_peak);
  }
  return peak;
}

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
  out["l7_request_timeouts"] = static_cast<double>(runtime.perf.request_timeouts);
  out["l7_rx_syscalls"] = static_cast<double>(runtime.perf.rx_syscalls);
  out["l7_tx_syscalls"] = static_cast<double>(runtime.perf.tx_syscalls);
  out["l7_alloc_bytes"] = static_cast<double>(runtime.perf.alloc_bytes);
  out["l7_alloc_count"] = static_cast<double>(runtime.perf.alloc_count);
  out["l7_io_uring_sqe_submitted"] = static_cast<double>(runtime.perf.io_uring_sqe_submitted);
  out["l7_io_uring_cqe_reaped"] = static_cast<double>(runtime.perf.io_uring_cqe_reaped);
  const auto tls_pct = percentile_triplet_ms(runtime.perf.tls_handshake_samples_ms);
  out["l7_tls_handshake_p50_ms"] = tls_pct.p50;
  out["l7_tls_handshake_p95_ms"] = tls_pct.p95;
  out["l7_tls_handshake_p99_ms"] = tls_pct.p99;
  const auto req_pct = percentile_triplet_ms(runtime.perf.request_latency_samples_ms);
  out["l7_request_latency_p50_ms"] = req_pct.p50;
  out["l7_request_latency_p95_ms"] = req_pct.p95;
  out["l7_request_latency_p99_ms"] = req_pct.p99;
  out["l7_profile_enabled"] = cfg.profile_l7 != 0 ? 1.0 : 0.0;
  out["l7_profile_snapshot_count"] = static_cast<double>(runtime.perf.profile_snapshot_count);
  bool uring_any_active = false;
  for (const auto& shard : runtime.local_shards) {
    if (shard.uring_active) {
      uring_any_active = true;
      break;
    }
  }
  out["runtime_reactor_io_uring_active"] = uring_any_active ? 1.0 : 0.0;
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
  out["l7_io_uring_sqe_submitted"] = 0.0;
  out["l7_io_uring_cqe_reaped"] = 0.0;
  out["runtime_reactor_io_uring_active"] = 0.0;
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
  out["runtime_failure_reason_code"] = 0.0;
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

double runtime_failure_reason_code(const std::string& reason) {
  if (reason == "custom_tcp_transport_not_yet_wired") {
    return 1.0;
  }
  if (reason == "custom_tcp_connect_enqueue_failed") {
    return 2.0;
  }
  if (reason == "invalid_target_ip") {
    return 3.0;
  }
  if (reason == "capability_unavailable") {
    return 4.0;
  }
  if (reason == "nghttp2_not_built") {
    return 5.0;
  }
  return 0.0;
}

std::map<std::string, double> fail_visible_stats(
    const Profile& profile,
    const RuntimeCapabilities& caps,
    const std::string& reason) {
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
  out["runtime_failure_reason_code"] = runtime_failure_reason_code(reason);
  return out;
}

NativeRuntime build_runtime(const Profile& profile, const RuntimeConfig& cfg) {
  NativeRuntime runtime;
  runtime.caps = detect_capabilities();
  runtime.custom_tcp_flow_registry.reserve(static_cast<std::size_t>(std::max(16, profile.max_connections * 2)));
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
    local.active_fd_registry.reserve(shard_conn_budget);
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
    const TransportBackend transport_backend = parse_transport_backend(profile);
    const ReactorBackend effective_reactor =
        is_custom_tcp_backend(transport_backend)
            ? ReactorBackend::SocketEpoll
            : resolve_reactor_backend(profile.reactor_backend, runtime.caps.io_uring);
    if (effective_reactor == ReactorBackend::SocketIoUring) {
      const unsigned kRingDepth = static_cast<unsigned>(std::max(64, std::min(4096, profile.max_connections * 2)));
      // CQSIZE only. IORING_SETUP_SINGLE_ISSUER is deliberately NOT set: the ring
      // is created here on the builder thread but submitted from the shard worker
      // thread, which violates single-issuer and makes io_uring_enter fail (the
      // reactor would stall). Give the completion queue headroom over the SQ:
      // multishot recv/poll and pipelined completions land several CQEs per
      // submitted SQE and an overflowing CQ drops completions. init() peels the
      // CQSIZE flag automatically if the kernel rejects it, so passing the depth
      // is always safe.
      unsigned flags = kUringSetupCqsize;
      if (local.uring.init(kRingDepth, flags, kRingDepth * 2)) {
        local.uring_active = true;
        // Register a provided buffer ring so the H1 read path can use a single
        // persistent multishot recv per connection (one SQE fans many reads into
        // kernel-selected buffers). Size the pool to a power of two of the ring
        // depth; if the kernel lacks PBUF_RING support the call fails cleanly and
        // the reactor transparently falls back to single-shot recv.
        unsigned buf_entries = 128;
        while (buf_entries < kRingDepth && buf_entries < 4096) {
          buf_entries <<= 1;
        }
        (void)local.uring.setup_buf_ring(/*bgid=*/0, buf_entries, /*entry_size=*/8192);
      }
    }
    runtime.local_shards.push_back(std::move(local));
  }
  runtime.tls_engine = std::make_unique<TlsSessionEngine>();
  SniPoolConfig sni_cfg{};
  CipherSuiteConfig cipher_cfg{};
  // Wire the operator-supplied cipher preference through to the TLS engine; when
  // unset, get_thread_context() falls back to the AES-NI-friendly default so the
  // symmetric-crypto load stays off the critical path (previously this profile
  // field was parsed but never applied).
  cipher_cfg.cipher_list = profile.tls_cipher_list;
  runtime.tls_engine->configure(sni_cfg, cipher_cfg, profile.verify, 256);
  return runtime;
}

void destroy_runtime(NativeRuntime& runtime) {
  if (runtime.custom_tcp_rx_handler_id > 0) {
    (void)tcpdp_stop_rx_handler(runtime.custom_tcp_rx_handler_id);
    runtime.custom_tcp_rx_handler_id = 0;
  }
  runtime.custom_tcp_flow_registry.clear();
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
      if (session->ctx.fd >= 0 && !is_custom_tcp_backend(session->ctx.transport_backend)) {
        ::close(session->ctx.fd);
      }
      session->ctx.fd = -1;
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
  for (auto& local_shard : runtime.local_shards) {
    if (local_shard.uring_active) {
      local_shard.uring.cleanup();
      local_shard.uring_active = false;
    }
  }
}

std::mutex& ready_shards_mu() {
  static std::mutex mu;
  return mu;
}

void enqueue_ready_shard(NativeRuntime& runtime, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  std::lock_guard<std::mutex> lk(ready_shards_mu());
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
  std::lock_guard<std::mutex> lk(ready_shards_mu());
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
    NativeRuntime& runtime,
    std::unique_ptr<Http1Connection>& conn,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  if (!conn) {
    return;
  }
  erase_active_http1(local_shard, conn.get());
  unregister_lane_fd(shard, local_shard, conn->fd);
  if (conn->fd >= 0) {
    if (conn->transport_backend == TransportBackend::CustomTcp) {
      unregister_custom_tcp_flow_binding(runtime, conn->custom_flow_id);
    }
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
    NativeRuntime& runtime,
    std::size_t shard_idx,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    int response_timeout_ms) {
  const long long now_ms = monotonic_ms_now();
  for (std::size_t lane_idx = 0; lane_idx < local_shard.h1_lanes.size(); ++lane_idx) {
    auto& lane = local_shard.h1_lanes[lane_idx];
    if (!lane || !lane->conn || lane->conn->fd < 0) {
      continue;
    }
    // In-flight response-stall guard: a request whose reply never arrives (e.g. an
    // inline IPS silently dropping/holding a packet, or a wedged peer) leaves the
    // lane in Writing/Reading forever — the drive loop then spins on active_io and
    // never completes the run. Evict it once past the per-request deadline, finalize
    // it as a FAILED request (surfaces as an error / expectation_failure, and on the
    // custom_tcp userspace stack as a timeout_close), and let the normal completion
    // path close the connection so the loop can progress.
    if (lane->phase != H1LanePhase::Idle) {
      if (response_timeout_ms > 0 && lane->request_start_ms > 0 &&
          (now_ms - lane->request_start_ms) > response_timeout_ms) {
        lane->phase = H1LanePhase::Failed;
        enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, *lane);
        if (g_perf_stats != nullptr) {
          g_perf_stats->request_timeouts += 1;
        }
      }
      continue;
    }
    if (lane->lane.idle_deadline_ms <= 0 || lane->lane.idle_deadline_ms > now_ms) {
      continue;
    }
    close_http1_connection(runtime, lane->conn, shard, local_shard);
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
          close_http1_connection(runtime, *it, shard, local_shard);
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

void expire_all_http1_idle(NativeRuntime& runtime, int response_timeout_ms) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    expire_http1_idle(runtime, shard_idx, runtime.shards[shard_idx],
                      runtime.local_shards[shard_idx], response_timeout_ms);
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
void expire_h2_idle(
    NativeRuntime& runtime,
    std::size_t shard_idx,
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
      unregister_custom_tcp_h2_flow_binding(runtime, *session);
      close_h2_client_session(*session);
      if (g_perf_stats != nullptr) {
        g_perf_stats->idle_evictions += 1;
      }
    }
    if (session->unhealthy_until_ms > now_ms && local_shard.dispatch_ready_ms < session->unhealthy_until_ms) {
      local_shard.dispatch_ready_ms = session->unhealthy_until_ms;
    }
  }
  (void)shard_idx;
  (void)profile;
}
#endif

void expire_all_lane_idle(NativeRuntime& runtime, const Profile& profile) {
  expire_all_http1_idle(runtime, profile.timeout_ms);
#ifdef SAMURAI_WITH_NGHTTP2
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    expire_h2_idle(runtime, shard_idx, profile, runtime.shards[shard_idx], runtime.local_shards[shard_idx]);
  }
#else
  (void)profile;
#endif
}

void expire_lane_idle_shard(NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  expire_http1_idle(runtime, shard_idx, runtime.shards[shard_idx],
                    runtime.local_shards[shard_idx], profile.timeout_ms);
#ifdef SAMURAI_WITH_NGHTTP2
  expire_h2_idle(runtime, shard_idx, profile, runtime.shards[shard_idx], runtime.local_shards[shard_idx]);
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

}  // namespace samurai::l7_emu_native
