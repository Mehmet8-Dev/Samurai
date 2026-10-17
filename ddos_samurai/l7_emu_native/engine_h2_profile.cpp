#include "engine_internal.hpp"

namespace ddos_samurai::l7_emu_native {

std::map<std::string, double> run_http2_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps) {
  const TransportBackend transport_backend = parse_transport_backend(profile);
  NativeRuntime runtime = build_runtime(profile, cfg);
  runtime.perf.started_ms = monotonic_ms_now();
  g_perf_stats = &runtime.perf;
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  out["runtime_transport_custom_tcp_requested"] =
      is_custom_tcp_backend(transport_backend) ? 1.0 : 0.0;
  if (transport_backend == TransportBackend::CustomTcp) {
    out["runtime_transport_custom_tcp_bridge_ready"] =
        configure_custom_tcp_bridge(profile) ? 1.0 : 0.0;
    out["runtime_h2_transport_contract"] = 1.0;
    out["runtime_h2_transport_mode_custom_tcp"] = 1.0;
    if (out["runtime_transport_custom_tcp_bridge_ready"] == 0.0) {
      if (profile.stateful_runtime_strict != 0) {
        g_perf_stats = nullptr;
        destroy_runtime(runtime);
        auto failed = fail_visible_stats(profile, caps, "custom_tcp_transport_not_yet_wired");
        failed["runtime_transport_custom_tcp_requested"] = 1.0;
        failed["runtime_transport_custom_tcp_bridge_ready"] = 0.0;
        failed["runtime_h2_transport_contract"] = 0.0;
        failed["runtime_h2_transport_mode_custom_tcp"] = 1.0;
        return failed;
      }
      out["runtime_failure_reason_code"] =
          runtime_failure_reason_code("custom_tcp_transport_not_yet_wired");
    }
    runtime.custom_tcp_rx_handler_id =
        custom_tcp_use_own_wire(runtime, transport_backend, profile.protocol) ? 0 : maybe_start_custom_tcp_rx_bridge();
    out["runtime_transport_custom_tcp_rx_bridge_active"] =
        runtime.custom_tcp_rx_handler_id > 0 ? 1.0 : 0.0;
  }
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

  auto collect_shard_h2_stats = [&](H2RunStats& st, std::size_t shard_idx) {
    if (shard_idx >= runtime.local_shards.size()) {
      return;
    }
    for (auto& session_ptr : runtime.local_shards[shard_idx].h2_sessions) {
      if (!session_ptr) {
        continue;
      }
      collect_h2_session_stats(*session_ptr, st, cfg.profile_sample_limit);
    }
  };

  auto collect_all_h2_stats = [&](H2RunStats& st) {
    for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
      collect_shard_h2_stats(st, shard_idx);
    }
  };

  auto finalize_h2_stream = [&](H2RunStats& st, const H2CompletedStream& completed) {
    const bool ok = !(completed.rst_stream || !completed.success || completed.status_code <= 0) &&
                    completed.expectation_failures == 0;
    st.expectation_failures += completed.expectation_failures;
    if (completed.rst_stream || !completed.success || completed.status_code <= 0) {
      st.errors += 1;
    } else {
      st.sent += 1;
    }
    if (completed.status_code >= 200 && completed.status_code <= 299) {
      st.status_2xx += 1;
    } else if (completed.status_code >= 300 && completed.status_code <= 399) {
      st.status_3xx += 1;
    } else if (completed.status_code >= 400 && completed.status_code <= 499) {
      st.status_4xx += 1;
    } else if (completed.status_code >= 500 && completed.status_code <= 599) {
      st.status_5xx += 1;
    }
    record_scenario_step_result(
        "http2",
        completed.scenario_flow,
        completed.scenario_vu_id,
        completed.scenario_on_failure,
        ok,
        completed.status_code <= 0,
        completed.status_code,
        static_cast<double>(std::max<long long>(0, monotonic_ms_now() - completed.request_start_ms)));
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
      if (!is_custom_tcp_backend(client.ctx.transport_backend) && client.ctx.fd >= 0) {
        unregister_lane_fd(shard, local_shard, client.ctx.fd);
      }
      unregister_custom_tcp_h2_flow_binding(runtime, client);
      close_h2_client_session(client);
      return;
    }
    if (decision.action == ConnectionDispositionAction::Rearm) {
      client.dispatch_ready_ms = decision.next_ready_ms;
      client.idle_deadline_ms = decision.idle_deadline_ms;
    }
  };

  auto dispatch_pending_h2_requests = [&](H2RunStats& st,
                                          std::map<std::string, std::string>& captures_map,
                                          std::size_t shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    auto& shard = runtime.shards[shard_idx];
    const long long now_ms = monotonic_ms_now();
    const std::size_t stream_budget =
        static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection));
    auto session_load = [&](const H2ClientSession& client) {
      return client.pending_requests.size() + client.ctx.active_streams.size();
    };
    const std::size_t session_count = local_shard.h2_sessions.size();
    if (session_count == 0) {
      return;
    }
    std::size_t visited = 0;
    bool made_progress = false;
    while ((!local_shard.pending_h2_requests.empty() || !made_progress) && visited < session_count) {
      const std::size_t session_idx = (local_shard.h2_dispatch_cursor + visited) % session_count;
      auto& selected_ptr = local_shard.h2_sessions[session_idx];
      visited += 1;
      if (!selected_ptr) {
        continue;
      }
      H2ClientSession* selected = selected_ptr.get();
      if (selected == nullptr) {
        break;
      }
      auto& client = *selected;
      client.ctx.captures = &captures_map;
      if (!client.ready && client.unhealthy_until_ms > now_ms) {
        local_shard.dispatch_ready_ms = std::max(local_shard.dispatch_ready_ms, client.unhealthy_until_ms);
        continue;
      }
      if (client.replacement_mode == H2LaneReplacementMode::ReplaceNow) {
        st.replace_now_decisions += 1;
        if (!is_custom_tcp_backend(client.ctx.transport_backend) && client.ctx.fd >= 0) {
          shard.connection_pool.active_connections =
              std::max(0, shard.connection_pool.active_connections - 1);
          unregister_lane_fd(shard, local_shard, client.ctx.fd);
        }
        unregister_custom_tcp_h2_flow_binding(runtime, client);
        close_h2_client_session(client);
      }
      if (client.ready && client.ctx.fd >= 0 && client.ctx.goaway == 0 &&
          session_load(client) >= stream_budget) {
        continue;
      }
      if (client.ready && client.ctx.fd >= 0 &&
          client.replacement_mode == H2LaneReplacementMode::Draining &&
          session_load(client) >= stream_budget) {
        continue;
      }
      if (!client.ready && local_shard.pending_h2_requests.empty()) {
        continue;
      }
      if (!client.ready) {
        if (!open_h2_client_session(
                runtime,
                shard_idx,
                profile,
                shard.epoll_fd,
                shard,
                local_shard,
                client,
                st,
                local_shard.pending_h2_requests.size())) {
          continue;
        }
        st.goaway_replacements += 1;
      } else if (client.ctx.fd >= 0 &&
                 (!local_shard.pending_h2_requests.empty() || !client.pending_requests.empty())) {
        st.conn_reused += 1;
        if (client.replacement_mode == H2LaneReplacementMode::Draining) {
          st.replace_after_idle_decisions += 1;
        }
      }
      const std::size_t pending_before = local_shard.pending_h2_requests.size();
      const std::size_t load_before = session_load(client);
      if (local_shard.uring_active) {
        // The io_uring reactor (service_ready_lanes_io_uring) owns the byte path
        // for this shard: it pumps mem_send output onto ring Send SQEs and feeds
        // ring Recv completions into mem_recv. Here we only queue the requests
        // onto the session; driving I/O synchronously would bypass the ring.
        h2_pull_pending_requests(local_shard, client, profile);
      } else {
        service_h2_session_io(runtime, profile, shard, local_shard, client, 0, true);
        flush_ready_h2_completions(runtime, shard_idx, client);
      }
      const bool progressed =
          local_shard.pending_h2_requests.size() < pending_before || session_load(client) != load_before;
      made_progress = made_progress || progressed;
      local_shard.h2_dispatch_cursor = (session_idx + 1) % session_count;
      if (local_shard.pending_h2_requests.empty()) {
        break;
      }
    }
  };

  const bool custom_tcp_threaded =
      is_custom_tcp_backend(transport_backend) && runtime.shards.size() > 1;
  const bool kernel_threaded =
      transport_backend == TransportBackend::KernelSocket && runtime.shards.size() > 1;
  const bool own_wire_threaded = custom_tcp_use_own_wire(runtime, transport_backend, profile.protocol);
  const CustomTcpWireConfig wire_cfg =
      own_wire_threaded ? resolve_custom_tcp_wire_config() : CustomTcpWireConfig{};
  const bool threaded = custom_tcp_threaded || kernel_threaded || own_wire_threaded;
  if (threaded) {
    const std::size_t shard_count = runtime.shards.size();
    std::vector<DataplanePerfStats> shard_perf(shard_count);
    std::vector<H2RunStats> shard_stats(shard_count);
    std::vector<std::map<std::string, std::string>> captures_by_shard(shard_count);
    std::vector<std::vector<ScenarioStepResult>> shard_steps(shard_count);

    std::vector<std::thread> workers;
    workers.reserve(shard_count);

    if (own_wire_threaded) {
      DpdkOwnWire dpdk_wire = open_dpdk_own_wire(wire_cfg, shard_count);
      for (std::size_t sh = 0; sh < shard_count; ++sh) {
        workers.emplace_back([&, sh]() {
          maybe_pin_shard_worker(sh);
          g_perf_stats = &shard_perf[sh];
          void* shard_core = tcpdp_core_create();
          tcpdp_core_bind_current(shard_core);
          (void)configure_custom_tcp_bridge(profile);
          const ShardPortRange pr = custom_tcp_shard_port_range(sh, shard_count);
          tcpdp_set_flow_id_base(static_cast<std::uint64_t>(sh + 1) << 40);
          ShardWire wire = open_shard_wire(wire_cfg, dpdk_wire, sh, shard_count, pr);
          std::vector<std::uint8_t> rxbuf(static_cast<std::size_t>(kCustomTcpWireStride) * 256);
          std::vector<std::uint16_t> rxlens(256);
          std::vector<std::uint8_t> txscratch(static_cast<std::size_t>(kCustomTcpWireStride) * 256);
          auto& local_shard = runtime.local_shards[sh];
          auto& st = shard_stats[sh];
          auto& shard_captures = captures_by_shard[sh];
          while (true) {
            bool did_work = false;
            did_work |= pump_shard_wire(
                runtime, wire_cfg, wire, rxbuf.data(), rxlens.data(), 256, txscratch);
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h2_requests(st, shard_captures, sh);
            service_custom_tcp_h2_shard_sessions(runtime, profile, sh);
            collect_shard_h2_stats(st, sh);
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              if (ready->kind == CompletionKind::H2 && ready->h2_completed.has_value()) {
                finalize_h2_stream(st, *ready->h2_completed);
              }
              did_work = true;
            }
            bool has_inflight = false;
            for (const auto& session_ptr : local_shard.h2_sessions) {
              if (session_ptr &&
                  (!session_ptr->pending_requests.empty() ||
                   !session_ptr->ctx.active_streams.empty())) {
                has_inflight = true;
                break;
              }
            }
            if (!has_inflight && local_shard.pending_h2_requests.empty() && !did_work) {
              break;
            }
            if (!did_work) {
              worker_idle_backoff();
            } else {
              worker_idle_reset();
            }
          }
          collect_shard_h2_stats(st, sh);
          shard_steps[sh] = std::move(g_last_scenario_step_results);
          g_last_scenario_step_results.clear();
          g_perf_stats = nullptr;
          accumulate_custom_tcp_shard_stats(runtime);
          close_shard_wire(wire);
          tcpdp_core_bind_current(nullptr);
          tcpdp_core_destroy(shard_core);
        });
      }
      for (auto& w : workers) {
        w.join();
      }
      close_dpdk_own_wire(dpdk_wire);
    } else if (kernel_threaded) {
      for (std::size_t sh = 0; sh < shard_count; ++sh) {
        workers.emplace_back([&, sh]() {
          maybe_pin_shard_worker(sh);
          g_perf_stats = &shard_perf[sh];
          auto& local_shard = runtime.local_shards[sh];
          auto& st = shard_stats[sh];
          auto& shard_captures = captures_by_shard[sh];
          while (true) {
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h2_requests(st, shard_captures, sh);
            const int rc = service_ready_lanes(runtime, profile, sh, 4);
            collect_shard_h2_stats(st, sh);
            bool did_work = rc > 0;
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              if (ready->kind == CompletionKind::H2 && ready->h2_completed.has_value()) {
                finalize_h2_stream(st, *ready->h2_completed);
              }
              did_work = true;
            }
            bool has_inflight = false;
            for (const auto& session_ptr : local_shard.h2_sessions) {
              if (session_ptr &&
                  (!session_ptr->pending_requests.empty() ||
                   !session_ptr->ctx.active_streams.empty())) {
                has_inflight = true;
                break;
              }
            }
            if (!has_inflight && local_shard.pending_h2_requests.empty() && !did_work) {
              break;
            }
            if (!did_work) {
              worker_idle_backoff();
            } else {
              worker_idle_reset();
            }
          }
          collect_shard_h2_stats(st, sh);
          shard_steps[sh] = std::move(g_last_scenario_step_results);
          g_last_scenario_step_results.clear();
          g_perf_stats = nullptr;
        });
      }
      for (auto& w : workers) {
        w.join();
      }
    } else {
      std::vector<std::unique_ptr<ShardIo>> shard_io(shard_count);
      for (auto& io : shard_io) {
        io = std::make_unique<ShardIo>();
      }
      std::atomic<bool> wire_stop{false};

      std::thread wire([&]() {
        custom_tcp_wire_pump(runtime, shard_io, wire_stop, ReactorLaneKind::H2);
      });

      for (std::size_t sh = 0; sh < shard_count; ++sh) {
        workers.emplace_back([&, sh]() {
          maybe_pin_shard_worker(sh);
          g_perf_stats = &shard_perf[sh];
          auto& local_shard = runtime.local_shards[sh];
          auto& st = shard_stats[sh];
          auto& shard_captures = captures_by_shard[sh];
          while (true) {
            bool did_work = false;
            std::deque<InboxEvent> events;
            {
              std::lock_guard<std::mutex> lk(shard_io[sh]->mu);
              events.swap(shard_io[sh]->inbox);
            }
            for (auto& ev : events) {
              if (ev.lane_idx >= local_shard.h2_sessions.size()) {
                continue;
              }
              auto& session_ptr = local_shard.h2_sessions[ev.lane_idx];
              if (!session_ptr) {
                continue;
              }
              H2ConnectionContext& ctx = session_ptr->ctx;
              switch (ev.kind) {
                case InboxEvent::Kind::ConnectEstablished:
                  ctx.custom_connect_ready = true;
                  break;
                case InboxEvent::Kind::Terminal:
                  ctx.custom_terminal = true;
                  ctx.transport_error = 1;
                  break;
                case InboxEvent::Kind::RxPayload:
                  if (ctx.read_buffer.empty()) {
                    ctx.read_buffer = std::move(ev.payload);
                  } else {
                    ctx.read_buffer.append(ev.payload.data(), ev.payload.size());
                  }
                  break;
              }
              did_work = true;
            }
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h2_requests(st, shard_captures, sh);
            service_custom_tcp_h2_shard_sessions(runtime, profile, sh);
            collect_shard_h2_stats(st, sh);
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              if (ready->kind == CompletionKind::H2 && ready->h2_completed.has_value()) {
                finalize_h2_stream(st, *ready->h2_completed);
              }
              did_work = true;
            }
            bool has_inflight = false;
            for (const auto& session_ptr : local_shard.h2_sessions) {
              if (session_ptr &&
                  (!session_ptr->pending_requests.empty() ||
                   !session_ptr->ctx.active_streams.empty())) {
                has_inflight = true;
                break;
              }
            }
            bool inbox_empty = true;
            {
              std::lock_guard<std::mutex> lk(shard_io[sh]->mu);
              inbox_empty = shard_io[sh]->inbox.empty();
            }
            if (!has_inflight && local_shard.pending_h2_requests.empty() &&
                inbox_empty && !did_work) {
              break;
            }
            if (!did_work) {
              worker_idle_backoff();
            } else {
              worker_idle_reset();
            }
          }
          collect_shard_h2_stats(st, sh);
          shard_steps[sh] = std::move(g_last_scenario_step_results);
          g_last_scenario_step_results.clear();
          g_perf_stats = nullptr;
        });
      }
      for (auto& w : workers) {
        w.join();
      }
      wire_stop.store(true, std::memory_order_relaxed);
      wire.join();
    }

    for (const DataplanePerfStats& sp : shard_perf) {
      runtime.perf.epoll_wakeups += sp.epoll_wakeups;
      runtime.perf.idle_evictions += sp.idle_evictions;
      runtime.perf.request_timeouts += sp.request_timeouts;
      runtime.perf.rx_syscalls += sp.rx_syscalls;
      runtime.perf.tx_syscalls += sp.tx_syscalls;
      runtime.perf.io_uring_sqe_submitted += sp.io_uring_sqe_submitted;
      runtime.perf.io_uring_cqe_reaped += sp.io_uring_cqe_reaped;
      runtime.perf.alloc_bytes += sp.alloc_bytes;
      runtime.perf.alloc_count += sp.alloc_count;
      runtime.perf.profile_snapshot_count += sp.profile_snapshot_count;
      runtime.perf.scheduler_queue_depth_peak = std::max(
          runtime.perf.scheduler_queue_depth_peak, sp.scheduler_queue_depth_peak);
      runtime.perf.request_latency_samples_ms.insert(
          runtime.perf.request_latency_samples_ms.end(),
          sp.request_latency_samples_ms.begin(), sp.request_latency_samples_ms.end());
      runtime.perf.tls_handshake_samples_ms.insert(
          runtime.perf.tls_handshake_samples_ms.end(),
          sp.tls_handshake_samples_ms.begin(), sp.tls_handshake_samples_ms.end());
    }
    for (const H2RunStats& ss : shard_stats) {
      stats.merge_from(ss);
    }
    for (auto& steps : shard_steps) {
      for (auto& r : steps) {
        g_last_scenario_step_results.push_back(std::move(r));
      }
    }
  } else {
    while (true) {
      expire_all_lane_idle(runtime, profile);
      for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
        dispatch_pending_h2_requests(stats, captures, shard_idx);
      }
      service_all_ready_lanes(runtime, profile, 0);
      collect_all_h2_stats(stats);
      bool made_progress = false;
      while (true) {
        auto ready_completion = pop_ready_completion_any(runtime);
        if (!ready_completion.has_value()) {
          break;
        }
        if (ready_completion->kind == CompletionKind::H2 &&
            ready_completion->h2_completed.has_value()) {
          const auto decision = finalize_h2_stream(stats, *ready_completion->h2_completed);
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
          collect_all_h2_stats(stats);
          if (is_custom_tcp_backend(transport_backend)) {
            std::this_thread::yield();
          }
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
        dispatch_pending_h2_requests(stats, captures, shard_idx);
        collect_all_h2_stats(stats);
      } else {
        bool shard_has_pending = false;
        long long next_idle_ms = std::numeric_limits<long long>::max();
        for (const auto& session_ptr : local_shard.h2_sessions) {
          if (session_ptr) {
            if (!session_ptr->pending_requests.empty() || !session_ptr->ctx.active_streams.empty()) {
              shard_has_pending = true;
              break;
            }
            next_idle_ms = std::min(next_idle_ms, session_ptr->idle_deadline_ms);
          }
        }
        if (!shard_has_pending) {
          local_shard.dispatch_ready_ms =
              next_idle_ms == std::numeric_limits<long long>::max()
                  ? monotonic_ms_now() + std::max<long long>(1, profile.timeout_ms)
                  : next_idle_ms;
          continue;
        }
      }
      if (!local_shard.pending_h2_requests.empty()) {
        enqueue_ready_shard(runtime, shard_idx);
      }
    }
  }

  collect_all_h2_stats(stats);
  if (is_custom_tcp_backend(transport_backend)) {
    merge_custom_tcp_stats(runtime, out);
  }

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

}  // namespace ddos_samurai::l7_emu_native
