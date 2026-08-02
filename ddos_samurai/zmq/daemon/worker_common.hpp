#pragma once

// Shared ZMQ worker framework helpers.
//
// These functions were previously copy-pasted verbatim into every worker
// translation unit (cpu/gpu/afxdp/dpdk/doca/l7/defense/scenario). They are the
// common wire/pacing/telemetry primitives that all ZMQ workers rely on, so they
// live here once and are pulled in via `using` declarations by each worker.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <zmq.h>

#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace samurai::daemon {

inline std::string ReadFixed(const char* raw, std::size_t n) {
  return std::string(raw, strnlen(raw, n));
}

inline std::optional<int> OptionalIntFromWire(std::uint64_t raw) {
  if (raw == 0ull) return std::nullopt;
  return static_cast<int>(raw);
}

// A single trailing `send_flags` argument (default 0) covers both the plain and
// the non-blocking (ZMQ_DONTWAIT) send paths used across the workers.
inline int SendFrame(
    void* event_socket,
    std::uint8_t msg_type,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id,
    const std::vector<std::uint8_t>& payload = {},
    int send_flags = 0) {
  samurai::wire::SamuraiWireHeaderV1 header = samurai::daemon::MakeHeader(
      msg_type,
      static_cast<std::uint32_t>(payload.size()),
      correlation_id,
      worker_kind,
      job_id);
  zmq_msg_t msg;
  const std::size_t total = sizeof(header) + payload.size();
  if (zmq_msg_init_size(&msg, total) != 0) return -1;
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (!payload.empty()) std::memcpy(p + sizeof(header), payload.data(), payload.size());
  const int rc = zmq_msg_send(&msg, event_socket, send_flags);
  zmq_msg_close(&msg);
  return rc;
}

inline std::vector<std::uint8_t> JsonError(const std::string& reason) {
  const std::string json = "{\"status\":\"error\",\"error\":\"" + reason + "\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

inline samurai_pacing_config_t PacingFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  samurai_pacing_config_t out{};
  out.mode = env.pacing_mode;
  out.target_rps = env.target_rps;
  out.ipg_ns = env.ipg_ns;
  out.burst_size = env.burst_size > 0u ? env.burst_size : 1u;
  out.burst_gap_ns = env.burst_gap_ns;
  return out;
}

inline samurai::wire::MetricSnapshotV1 BuildSnapshot(
    std::uint64_t now_ns,
    std::uint64_t start_ns,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    const samurai_pacing_config_t& pace_cfg,
    const samurai_pacing_state_t& pace_state) {
  const double duration_s = std::max(1e-9, static_cast<double>(now_ns - start_ns) / 1e9);
  const double actual_rps = static_cast<double>(packets_sent) / duration_s;
  double rate_accuracy_pct = 100.0;
  if (pace_cfg.mode == SAMURAI_PACING_RPS && pace_cfg.target_rps > 0.0) {
    const double err_abs = std::abs(actual_rps - pace_cfg.target_rps);
    rate_accuracy_pct = std::max(0.0, 100.0 - ((err_abs * 100.0) / pace_cfg.target_rps));
  }
  samurai::wire::MetricSnapshotV1 snap{};
  snap.timestamp_ns = now_ns;
  snap.packets_sent = packets_sent;
  snap.packets_errors = packets_errors;
  snap.bytes_sent = bytes_sent;
  snap.actual_rps = actual_rps;
  snap.jitter_p99_ns = 0.0;
  snap.rate_accuracy_pct = rate_accuracy_pct;
  snap.busywait_cycles = 0;
  snap.sleep_calls = static_cast<std::uint32_t>(pace_state.sleep_calls & 0xFFFFFFFFu);
  return snap;
}

inline std::vector<std::uint8_t> SerializeSnapshot(const samurai::wire::MetricSnapshotV1& snap) {
  std::vector<std::uint8_t> payload(sizeof(snap));
  std::memcpy(payload.data(), &snap, sizeof(snap));
  return payload;
}

}  // namespace samurai::daemon
