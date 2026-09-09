#include "engine_internal.hpp"

namespace ddos_samurai::l7_emu_native {

int parse_http_status_code(std::string_view status_line) {
  const std::size_t first_space = status_line.find(' ');
  if (first_space == std::string_view::npos) {
    return 0;
  }
  std::size_t pos = first_space;
  while (pos < status_line.size() && status_line[pos] == ' ') {
    ++pos;
  }
  int status = 0;
  int digits = 0;
  while (pos < status_line.size() && std::isdigit(static_cast<unsigned char>(status_line[pos])) && digits < 3) {
    status = status * 10 + static_cast<int>(status_line[pos] - '0');
    ++pos;
    ++digits;
  }
  return digits == 3 ? status : 0;
}

std::optional<std::size_t> parse_chunked_body_length(std::string_view payload, std::size_t body_offset) {
  std::size_t cursor = body_offset;
  while (true) {
    const std::size_t line_end = find_crlf(payload, cursor);
    if (line_end == std::string_view::npos) {
      return std::nullopt;
    }
    std::uint64_t chunk_size = 0;
    bool saw_digit = false;
    for (std::size_t pos = cursor; pos < line_end; ++pos) {
      const unsigned char ch = static_cast<unsigned char>(payload[pos]);
      if (ch == ';') {
        break;
      }
      unsigned value = 0;
      if (ch >= '0' && ch <= '9') value = ch - '0';
      else if (ch >= 'a' && ch <= 'f') value = ch - 'a' + 10;
      else if (ch >= 'A' && ch <= 'F') value = ch - 'A' + 10;
      else if (ch == ' ' || ch == '\t') continue;
      else return std::nullopt;
      saw_digit = true;
      chunk_size = (chunk_size << 4U) + value;
    }
    if (!saw_digit || chunk_size > std::numeric_limits<std::size_t>::max()) {
      return std::nullopt;
    }
    cursor = line_end + 2;
    const std::size_t chunk_len = static_cast<std::size_t>(chunk_size);
    if (payload.size() < cursor + chunk_len + 2) {
      return std::nullopt;
    }
    cursor += chunk_len;
    if (payload.substr(cursor, 2) != "\r\n") {
      return std::nullopt;
    }
    cursor += 2;
    if (chunk_len == 0) {
      return cursor - body_offset;
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

bool h1_lane_try_parse_response(H1Lane& lane) {
  if (!lane.conn) {
    return false;
  }
  H1ReadBuffer& buffer = lane.conn->read_buffer;
  const std::string_view data = buffer.view();
  if (!lane.parser.header_complete) {
    const std::size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
      return false;
    }
    lane.parser.header_complete = true;
    lane.parser.header_end = header_end;
    lane.parser.body_offset = header_end + 4;
    const std::size_t line_end = find_crlf(data, 0);
    if (line_end != std::string_view::npos) {
      lane.response.status_code = parse_http_status_code(data.substr(0, line_end));
    }
    std::size_t pos = line_end == std::string_view::npos ? 0 : line_end + 2;
    bool has_content_length = false;
    std::size_t content_length_value = 0;
    while (pos < header_end) {
      const std::size_t next = find_crlf(data, pos);
      if (next == std::string_view::npos || next > header_end) {
        break;
      }
      const std::string_view line = data.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string_view::npos) {
        const std::string_view key_view = line.substr(0, colon);
        const std::string_view value_view = line.substr(colon + 1);
        std::string key = lowercase_copy(key_view);
        std::string value = trim_header_value_copy(value_view);
        if (ascii_iequals(key_view, "content-length")) {
          has_content_length = true;
          content_length_value = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
        } else if (ascii_iequals(key_view, "transfer-encoding") &&
                   ascii_icontains(value_view, "chunked")) {
          lane.parser.chunked = true;
        }
        lane.response.header_fields.emplace_back(std::move(key), std::move(value));
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
    const auto parsed = parse_chunked_body_length(data, lane.parser.body_offset);
    if (!parsed.has_value()) {
      return false;
    }
    lane.parser.expected_body_length = *parsed;
  } else if (lane.parser.close_delimited) {
    return false;
  } else if (data.size() < lane.parser.body_offset + lane.parser.expected_body_length) {
    return false;
  }

  lane.response.body.assign(
      data.substr(lane.parser.body_offset, lane.parser.expected_body_length));
  lane.response.consumed_bytes = lane.parser.body_offset + lane.parser.expected_body_length;
  const std::string* connection_header_raw =
      find_header_value(lane.response.header_fields, "connection");
  lane.response.keep_alive =
      !lane.parser.close_delimited &&
      (connection_header_raw == nullptr || !ascii_iequals(*connection_header_raw, "close"));
  if (lane.response.consumed_bytes <= data.size()) {
    buffer.consume(lane.response.consumed_bytes);
  } else {
    buffer.clear();
  }
  return true;
}

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
  if (is_custom_tcp_backend(lane.transport_backend)) {
    if (h1_lane_try_parse_response(lane)) {
      lane.phase = H1LanePhase::Complete;
      return H1LaneIoResult::Completed;
    }
    if (lane.conn->custom_terminal) {
      if (lane.parser.header_complete && lane.parser.close_delimited) {
        const std::string_view data = lane.conn->read_buffer.view();
        lane.parser.expected_body_length =
            data.size() > lane.parser.body_offset
            ? data.size() - lane.parser.body_offset
            : 0;
        lane.response.body.assign(data.substr(
            lane.parser.body_offset,
            lane.parser.expected_body_length));
        lane.response.consumed_bytes = lane.parser.body_offset + lane.parser.expected_body_length;
        lane.response.keep_alive = false;
        lane.conn->read_buffer.clear();
        lane.phase = lane.response.status_code > 0 ? H1LanePhase::Complete : H1LanePhase::Failed;
        return lane.response.status_code > 0 ? H1LaneIoResult::Completed : H1LaneIoResult::Failed;
      }
      lane.phase = H1LanePhase::Failed;
      return H1LaneIoResult::Failed;
    }
    return H1LaneIoResult::Pending;
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
        const std::string_view data = lane.conn->read_buffer.view();
        lane.parser.expected_body_length =
            data.size() > lane.parser.body_offset
            ? data.size() - lane.parser.body_offset
            : 0;
        lane.response.body.assign(data.substr(
            lane.parser.body_offset,
            lane.parser.expected_body_length));
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
  completed.scenario_flow = std::move(lane.request_spec.scenario_flow);
  completed.scenario_vu_id = std::move(lane.request_spec.scenario_vu_id);
  completed.scenario_on_failure = std::move(lane.request_spec.scenario_on_failure);
  if (shard_idx < runtime.local_shards.size()) {
    runtime.local_shards[shard_idx].ready_completions.push_back(CompletionEnvelope{
        CompletionKind::H1,
        shard_idx,
        std::move(completed),
        std::nullopt,
    });
  }
}

void enqueue_ready_h2_stream(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2CompletedStream&& completed) {
  CompletionEnvelope envelope;
  envelope.kind = CompletionKind::H2;
  envelope.shard_idx = shard_idx;
  envelope.h2_completed = std::move(completed);
  if (shard_idx < runtime.local_shards.size()) {
    runtime.local_shards[shard_idx].ready_completions.push_back(std::move(envelope));
  }
}

std::optional<CompletionEnvelope> pop_ready_completion(NativeRuntime& runtime, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return std::nullopt;
  }
  auto& q = runtime.local_shards[shard_idx].ready_completions;
  if (q.empty()) {
    return std::nullopt;
  }
  CompletionEnvelope entry = std::move(q.front());
  q.pop_front();
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

std::optional<CompletionEnvelope> pop_ready_completion_any(NativeRuntime& runtime) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    auto entry = pop_ready_completion(runtime, shard_idx);
    if (entry.has_value()) {
      return entry;
    }
  }
  return std::nullopt;
}

uint32_t reactor_interest_mask() {
  return EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;
}

void register_h1_lane_fd(
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H1Lane* lane,
    std::size_t lane_idx) {
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
      lane_idx,
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
          const std::size_t lane_idx = it->second.lane_idx;
          unregister_lane_fd(shard, local_shard, fd);
          enqueue_ready_h1_lane(runtime, shard_idx, lane_idx, lane);
        }
      }
    }
#ifdef SAMURAI_WITH_NGHTTP2
    else if (it->second.h2_session != nullptr) {
      service_h2_session_io(
          runtime,
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

void service_custom_tcp_shard_lanes(NativeRuntime& runtime, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  auto& local_shard = runtime.local_shards[shard_idx];
  for (std::size_t lane_idx = 0; lane_idx < local_shard.h1_lanes.size(); ++lane_idx) {
    auto& lane_ptr = local_shard.h1_lanes[lane_idx];
    if (!lane_ptr || !is_custom_tcp_backend(lane_ptr->transport_backend) || !lane_ptr->conn) {
      continue;
    }
    H1Lane& lane = *lane_ptr;
    H1LaneIoResult result = H1LaneIoResult::Pending;
    if (lane.phase == H1LanePhase::Writing) {
      result = h1_lane_write_step(lane);
    } else if (lane.phase == H1LanePhase::Reading) {
      if (lane.conn->custom_rx_pending || lane.conn->custom_terminal) {
        lane.conn->custom_rx_pending = false;
        result = h1_lane_read_step(lane);
      }
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

void service_all_ready_lanes(NativeRuntime& runtime, const Profile& profile, int timeout_ms) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    service_ready_lanes(runtime, profile, shard_idx, timeout_ms);
  }
  service_custom_tcp_lanes(runtime, profile);
}

}  // namespace ddos_samurai::l7_emu_native
