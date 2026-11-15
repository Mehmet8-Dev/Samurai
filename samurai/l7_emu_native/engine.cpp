#include "engine_internal.hpp"
#include "custom_quic_stack/quic_stack.hpp"

namespace samurai::l7_emu_native {

RuntimeCapabilities detect_capabilities() {
  RuntimeCapabilities caps;
#ifdef SAMURAI_WITH_OPENSSL
  caps.openssl = true;
#endif
#ifdef SAMURAI_WITH_NGHTTP2
  caps.nghttp2 = true;
#endif
#ifdef SAMURAI_WITH_NGTCP2
  caps.ngtcp2 = true;
#endif
#ifdef SAMURAI_WITH_NGHTTP3
  caps.nghttp3 = true;
#endif
#if defined(SAMURAI_HAS_LINUX_IO_URING) && defined(__NR_io_uring_setup)
  caps.io_uring = SamuraiUring::probe_kernel_support();
#endif
  return caps;
}

std::map<std::string, double> run_profile(const Profile& profile, const RuntimeConfig& cfg) {
  g_last_scenario_step_results.clear();
  const RuntimeCapabilities caps = detect_capabilities();
  const TransportBackend transport_backend = parse_transport_backend(profile);
  if (profile.protocol == "quic") {
    return custom_quic_stack::run_quic_profile(profile, cfg, caps, transport_backend);
  }
  if (profile.protocol == "http2") {
    return run_http2_profile(profile, cfg, caps);
  }
  if (profile.protocol == "dns") {
    return run_dns_profile(profile, cfg);
  }
  if (profile.protocol == "dhcp" || profile.protocol == "igmp" ||
      profile.protocol == "nd" || profile.protocol == "ipv6_nd" || profile.protocol == "arp") {
    return run_l2l3_profile(profile, cfg);
  }
  std::map<std::string, double> out;

  init_stats(profile, out);
  out["runtime_transport_custom_tcp_requested"] = transport_backend == TransportBackend::CustomTcp ? 1.0 : 0.0;
  if (transport_backend == TransportBackend::CustomTcp) {
    out["runtime_transport_custom_tcp_bridge_ready"] = configure_custom_tcp_bridge(profile) ? 1.0 : 0.0;
    if (out["runtime_transport_custom_tcp_bridge_ready"] == 0.0) {
      if (profile.stateful_runtime_strict != 0) {
        auto failed = fail_visible_stats(profile, caps, "custom_tcp_transport_not_yet_wired");
        failed["runtime_transport_custom_tcp_bridge_ready"] = 0.0;
        return failed;
      }
      out["runtime_failure_reason_code"] = runtime_failure_reason_code("custom_tcp_transport_not_yet_wired");
    }
  }

  std::vector<ShardAccum> accum;
  std::vector<std::map<std::string, std::map<std::string, std::string>>> captures_by_vu;

  const auto request_specs = build_h1_requests(profile);
  const int request_attempts = static_cast<int>(request_specs.size());
  NativeRuntime runtime = build_runtime(profile, cfg);
  accum.resize(std::max<std::size_t>(1, runtime.shards.size()));
  captures_by_vu.resize(std::max<std::size_t>(1, runtime.shards.size()));
  runtime.perf.started_ms = monotonic_ms_now();
  g_perf_stats = &runtime.perf;
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  if (transport_backend == TransportBackend::CustomTcp) {
    runtime.custom_tcp_rx_handler_id =
        custom_tcp_use_own_wire(runtime, transport_backend, profile.protocol) ? 0 : maybe_start_custom_tcp_rx_bridge();
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
      auto& captures = captures_by_vu[shard_idx][lane.request_spec.scenario_vu_id];
      build_http1_request_into(
          lane.write_buffer,
          ensure_lane_string_arena(lane.string_arena),
          profile,
          lane.request_spec,
          captures);

      if (!lane.conn) {
        lane.conn = std::make_unique<Http1Connection>();
        ensure_reusable_string_capacity(lane.conn->read_buffer.storage, kH1SlabReadBytes);
      }
      if (lane.conn->fd >= 0) {
        accum[shard_idx].conn_reused += 1;
      } else {
        const H1TransportOps& transport_ops = resolve_h1_transport_ops(lane.transport_backend);
        lane.conn->transport_backend = lane.transport_backend;
        lane.conn->fd = transport_ops.connect_fn(*lane.conn, profile);
        lane.conn->shard_id = static_cast<int>(shard_idx);
        accum[shard_idx].conn_attempted += 1;
        if (lane.conn->fd < 0) {
          accum[shard_idx].expectation_failures += 1;
          reset_h1_lane_io(lane);
          lane.lane = ReactorLaneState{};
          continue;
        }
        accum[shard_idx].conn_established += 1;
        // Fresh io_uring generation for this new connection instance so any
        // completions still in flight from a prior connection on this lane slot
        // are rejected by the reactor.
        lane.conn->uring_gen = next_h1_uring_gen();
        lane.conn->uring_multishot = false;
        shard.connection_pool.active_connections += 1;
        shard.connection_pool.active_connections_peak = std::max(
            shard.connection_pool.active_connections_peak,
            shard.connection_pool.active_connections);
      }

      lane.conn->read_buffer.clear();
      lane.conn->idle_deadline_ms = 0;
      if (is_custom_tcp_backend(lane.transport_backend)) {
        register_custom_tcp_h1_flow_binding(runtime, shard_idx, lane_idx, lane);
      }
      sync_h1_lane_state(lane, profile);
      register_h1_lane_fd(shard, local_shard, &lane, lane_idx);

      if (local_shard.uring_active) {
        auto* sqe = local_shard.uring.get_sqe();
        if (sqe != nullptr) {
          prep_uring_send(
              sqe,
              lane.conn->fd,
              lane.write_buffer.data() + lane.write_offset,
              lane.write_buffer.size() - lane.write_offset,
              MSG_NOSIGNAL,
              make_uring_user_data(static_cast<uint32_t>(lane_idx), IoUringOp::Send, lane.conn->uring_gen));
          lane.conn->uring_in_flight = true;
          lane.conn->uring_pending_op = IoUringOp::Send;
          if (g_perf_stats != nullptr) {
            g_perf_stats->io_uring_sqe_submitted += 1;
          }
        }
      } else {
        H1LaneIoResult immediate_result = h1_lane_write_step(lane);
        if (immediate_result == H1LaneIoResult::Pending && lane.phase == H1LanePhase::Reading) {
          immediate_result = h1_lane_read_step(lane);
        }
        if (immediate_result == H1LaneIoResult::Completed || immediate_result == H1LaneIoResult::Failed) {
          unregister_lane_fd(shard, local_shard, lane.conn ? lane.conn->fd : -1);
          enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, lane);
        }
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
    ShardAccum& acc = accum[shard_idx];
    auto& captures = captures_by_vu[shard_idx][completed.scenario_vu_id];
    const long long now_ms = monotonic_ms_now();
    acc.rx_bytes += completed.rx_bytes;
    acc.tx_bytes += completed.tx_bytes;
    lane.expectation_failures = completed.expectation_failures;
    lane.think_time_total_ms = completed.think_time_total_ms;

    if (!completed.success || completed.status_code <= 0) {
      acc.expectation_failures += std::max(1, completed.expectation_failures + (completed.status_code <= 0 ? 1 : 0));
      record_scenario_step_result(
          "http1",
          completed.scenario_flow,
          completed.scenario_vu_id,
          completed.scenario_on_failure,
          false,
          completed.status_code <= 0,
          completed.status_code,
          static_cast<double>(std::max<long long>(0, now_ms - completed.request_start_ms)));
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
      } else if (follow.opcode == "CAPTURE_BODY_JSON") {
        capture_body_json(follow, completed.response_body, captures);
      } else if (follow.opcode == "THINK_TIME") {
        lane.think_time_total_ms += std::max(0, follow.think_time_ms);
      }
    }

    acc.expectation_failures += lane.expectation_failures;
    acc.sent += 1;
    record_scenario_step_result(
        "http1",
        completed.scenario_flow,
        completed.scenario_vu_id,
        completed.scenario_on_failure,
        lane.expectation_failures == 0,
        false,
        completed.status_code,
        static_cast<double>(std::max<long long>(0, now_ms - completed.request_start_ms)));
    perf_request_latency(
        static_cast<double>(std::max<long long>(0, now_ms - completed.request_start_ms)),
        cfg.profile_sample_limit);
    if (completed.status_code >= 200 && completed.status_code <= 299) {
      acc.status_2xx += 1;
    } else if (completed.status_code >= 300 && completed.status_code <= 399) {
      acc.status_3xx += 1;
    } else if (completed.status_code >= 400 && completed.status_code <= 499) {
      acc.status_4xx += 1;
    } else if (completed.status_code >= 500 && completed.status_code <= 599) {
      acc.status_5xx += 1;
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
      close_http1_connection(runtime, lane.conn, shard, local_shard);
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
      ShardAccum& acc = accum[completion.shard_idx];
      const bool ok = !(completed.rst_stream || !completed.success || completed.status_code <= 0) &&
                      completed.expectation_failures == 0;
      acc.expectation_failures += completed.expectation_failures;
      if (completed.rst_stream || !completed.success || completed.status_code <= 0) {
        acc.status_4xx += completed.status_code >= 400 && completed.status_code <= 499 ? 1 : 0;
        acc.status_5xx += completed.status_code >= 500 && completed.status_code <= 599 ? 1 : 0;
      } else {
        acc.sent += 1;
        if (completed.status_code >= 200 && completed.status_code <= 299) {
          acc.status_2xx += 1;
        } else if (completed.status_code >= 300 && completed.status_code <= 399) {
          acc.status_3xx += 1;
        } else if (completed.status_code >= 400 && completed.status_code <= 499) {
          acc.status_4xx += 1;
        } else if (completed.status_code >= 500 && completed.status_code <= 599) {
          acc.status_5xx += 1;
        }
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
      return true;
    }
#endif
    return false;
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
          while (true) {
            bool did_work = false;
            did_work |= pump_shard_wire(
                runtime, wire_cfg, wire, rxbuf.data(), rxlens.data(), 256, txscratch);
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h1_requests(sh);
            service_custom_tcp_shard_lanes(runtime, sh);
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              finalize_completion(std::move(*ready));
              did_work = true;
            }
            bool has_inflight = false;
            for (const auto& lane_ptr : local_shard.h1_lanes) {
              if (lane_ptr && (lane_ptr->phase == H1LanePhase::Writing ||
                               lane_ptr->phase == H1LanePhase::Reading)) {
                has_inflight = true;
                break;
              }
            }
            if (!has_inflight && local_shard.pending_h1_requests.empty() && !did_work) {
              break;
            }
            if (!did_work) {
              worker_idle_backoff();
            } else {
              worker_idle_reset();
            }
          }
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
          while (true) {
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h1_requests(sh);

            bool did_work = false;
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              finalize_completion(std::move(*ready));
              did_work = true;
            }
            if (did_work) {
              continue;
            }

            bool pending = false;
            bool active_io = false;
            std::optional<long long> next_deadline;
            const long long now_ms = monotonic_ms_now();
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
              } else if (!local_shard.pending_h1_requests.empty() &&
                         lane.phase == H1LanePhase::Idle) {
                pending = true;
                const long long candidate = std::max(now_ms, lane.lane.dispatch_ready_at_ms);
                if (!next_deadline.has_value() || candidate < *next_deadline) {
                  next_deadline = candidate;
                }
              }
            }
            if (!pending) {
              break;
            }
            if (active_io) {
              service_ready_lanes(runtime, profile, sh, 16);
              continue;
            }
            if (next_deadline.has_value()) {
              const long long wait_ms = std::min<long long>(
                  std::max<long long>(1, *next_deadline - now_ms), 16);
              std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
              continue;
            }
            break;
          }
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
        custom_tcp_wire_pump(runtime, shard_io, wire_stop, ReactorLaneKind::H1);
      });

      for (std::size_t sh = 0; sh < shard_count; ++sh) {
        workers.emplace_back([&, sh]() {
          maybe_pin_shard_worker(sh);
          g_perf_stats = &shard_perf[sh];
          auto& local_shard = runtime.local_shards[sh];
          while (true) {
            bool did_work = false;
            std::deque<InboxEvent> events;
            {
              std::lock_guard<std::mutex> lk(shard_io[sh]->mu);
              events.swap(shard_io[sh]->inbox);
            }
            for (auto& ev : events) {
              if (ev.lane_idx >= local_shard.h1_lanes.size()) {
                continue;
              }
              auto& lane_ptr = local_shard.h1_lanes[ev.lane_idx];
              if (!lane_ptr || !lane_ptr->conn) {
                continue;
              }
              H1Lane& lane = *lane_ptr;
              Http1Connection& conn = *lane.conn;
              switch (ev.kind) {
                case InboxEvent::Kind::ConnectEstablished:
                  conn.custom_connect_ready = true;
                  break;
                case InboxEvent::Kind::Terminal:
                  conn.custom_terminal = true;
                  conn.custom_send_enqueued = false;
                  conn.custom_send_outstanding = 0;
                  lane.phase = H1LanePhase::Failed;
                  break;
                case InboxEvent::Kind::RxPayload: {
                  const std::size_t plen = ev.payload.size();
                  if (conn.read_buffer.empty()) {
                    conn.read_buffer.adopt(std::move(ev.payload));
                  } else {
                    conn.read_buffer.append(ev.payload.data(), ev.payload.size());
                  }
                  conn.custom_rx_pending = true;
                  lane.response.bytes_received += plen;
                  lane.rx_bytes += plen;
                  if (conn.custom_send_outstanding > 0) {
                    conn.custom_send_outstanding -= 1;
                  }
                  conn.custom_send_enqueued = conn.custom_send_outstanding > 0;
                  break;
                }
              }
              did_work = true;
            }
            expire_lane_idle_shard(runtime, profile, sh);
            dispatch_pending_h1_requests(sh);
            service_custom_tcp_shard_lanes(runtime, sh);
            while (true) {
              auto ready = pop_ready_completion(runtime, sh);
              if (!ready.has_value()) {
                break;
              }
              finalize_completion(std::move(*ready));
              did_work = true;
            }
            bool has_inflight = false;
            for (const auto& lane_ptr : local_shard.h1_lanes) {
              if (lane_ptr && (lane_ptr->phase == H1LanePhase::Writing ||
                               lane_ptr->phase == H1LanePhase::Reading)) {
                has_inflight = true;
                break;
              }
            }
            bool inbox_empty = true;
            {
              std::lock_guard<std::mutex> lk(shard_io[sh]->mu);
              inbox_empty = shard_io[sh]->inbox.empty();
            }
            if (!has_inflight && local_shard.pending_h1_requests.empty() &&
                inbox_empty && !did_work) {
              break;
            }
            if (!did_work) {
              worker_idle_backoff();
            } else {
              worker_idle_reset();
            }
          }
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
      runtime.perf.alloc_bytes += sp.alloc_bytes;
      runtime.perf.alloc_count += sp.alloc_count;
      runtime.perf.io_uring_sqe_submitted += sp.io_uring_sqe_submitted;
      runtime.perf.io_uring_cqe_reaped += sp.io_uring_cqe_reaped;
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
    for (auto& steps : shard_steps) {
      for (auto& r : steps) {
        g_last_scenario_step_results.push_back(std::move(r));
      }
    }
  } else {
    while (true) {
      expire_all_lane_idle(runtime, profile);
      for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
        dispatch_pending_h1_requests(shard_idx);
      }
      service_all_ready_lanes(runtime, profile, 0);

      bool made_progress = false;
      while (true) {
        auto ready_completion = pop_ready_completion_any(runtime);
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
  }

  int sent = 0;
  int conn_attempted = 0;
  int conn_established = 0;
  int conn_reused = 0;
  int expectation_failures = 0;
  int status_2xx = 0;
  int status_3xx = 0;
  int status_4xx = 0;
  int status_5xx = 0;
  std::size_t rx_bytes = 0;
  std::size_t tx_bytes = 0;
  for (const ShardAccum& acc : accum) {
    sent += acc.sent;
    conn_attempted += acc.conn_attempted;
    conn_established += acc.conn_established;
    conn_reused += acc.conn_reused;
    expectation_failures += acc.expectation_failures;
    status_2xx += acc.status_2xx;
    status_3xx += acc.status_3xx;
    status_4xx += acc.status_4xx;
    status_5xx += acc.status_5xx;
    rx_bytes += acc.rx_bytes;
    tx_bytes += acc.tx_bytes;
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
      close_http1_connection(runtime, conn, shard, local_shard);
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
    merge_custom_tcp_stats(runtime, out);
  }
  out["l7_conn_attempted"] = static_cast<double>(conn_attempted);
  out["l7_conn_established"] = static_cast<double>(conn_established);
  out["l7_conn_reused"] = static_cast<double>(conn_reused);
  out["l7_rx_bytes"] = static_cast<double>(rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_expectation_failures"] = static_cast<double>(expectation_failures);
  return out;
}

std::vector<ScenarioStepResult> consume_last_scenario_step_results() {
  std::vector<ScenarioStepResult> out = std::move(g_last_scenario_step_results);
  g_last_scenario_step_results.clear();
  return out;
}

}  // namespace samurai::l7_emu_native
