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
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <zmq.h>

#include "engine.hpp"
#include "json.hpp"
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
  if (!event_socket) return -1;
  samurai::wire::SamuraiWireHeaderV1 header = samurai::daemon::MakeHeader(
      msg_type,
      static_cast<std::uint32_t>(payload.size()),
      correlation_id,
      worker_kind,
      job_id);
  zmq_msg_t msg;
  const std::size_t total = sizeof(header) + payload.size();
  if (zmq_msg_init_size(&msg, total) != 0) {
    std::cerr << "[worker_frame] zmq_msg_init_size failed: " << zmq_strerror(zmq_errno()) << "\n";
    return -1;
  }
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (!payload.empty()) std::memcpy(p + sizeof(header), payload.data(), payload.size());
  const int rc = zmq_msg_send(&msg, event_socket, send_flags);
  if (rc < 0) {
    std::cerr << "[worker_frame] zmq_msg_send error: " << zmq_strerror(zmq_errno()) << "\n";
  }
  zmq_msg_close(&msg);
  return rc;
}

inline std::vector<std::uint8_t> JsonError(const std::string& reason) {
  samurai::core::json::Value val = samurai::core::json::Value::Object();
  val.set("status", samurai::core::json::Value::Str("error"));
  val.set("error", samurai::core::json::Value::Str(reason));
  const std::string json = val.dump();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

inline std::vector<std::uint8_t> JsonPayloadFromStats(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct,
    const std::string& note = "done") {
  samurai::core::json::Value val = samurai::core::json::Value::Object();
  val.set("status", samurai::core::json::Value::Str("ok"));
  val.set("correlation_id", samurai::core::json::Value::Int(static_cast<int64_t>(correlation_id)));
  val.set("job_id", samurai::core::json::Value::Str(job_id));
  val.set("packets_sent", samurai::core::json::Value::Int(static_cast<int64_t>(packets_sent)));
  val.set("packets_errors", samurai::core::json::Value::Int(static_cast<int64_t>(packets_errors)));
  val.set("bytes_sent", samurai::core::json::Value::Int(static_cast<int64_t>(bytes_sent)));
  val.set("actual_rps", samurai::core::json::Value::Double(actual_rps));
  val.set("rate_accuracy_pct", samurai::core::json::Value::Double(rate_accuracy_pct));
  val.set("note", samurai::core::json::Value::Str(note));
  const std::string json = val.dump();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

inline ddos_samurai::cpu_native::PacketConfig ConfigFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  ddos_samurai::cpu_native::PacketConfig cfg;
  cfg.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  cfg.target_port = static_cast<int>(env.target_port);
  cfg.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  if (cfg.protocol.empty()) {
    cfg.protocol = "tcp";
  }
  cfg.spoof = env.spoof_enabled != 0u;
  cfg.spoof_opts = ddos_samurai::cpu_native::SpoofOptions{
      .mode = ReadFixed(env.spoof_mode, sizeof(env.spoof_mode)),
      .subnet = [&]() -> std::optional<std::string> {
        const std::string v = ReadFixed(env.spoof_subnet, sizeof(env.spoof_subnet));
        return v.empty() ? std::nullopt : std::optional<std::string>(v);
      }(),
      .list_file = [&]() -> std::optional<std::string> {
        const std::string v = ReadFixed(env.spoof_list_file, sizeof(env.spoof_list_file));
        return v.empty() ? std::nullopt : std::optional<std::string>(v);
      }(),
  };
  cfg.has_payload = env.has_payload != 0u;
  cfg.tcp_flags = ReadFixed(env.tcp_flags, sizeof(env.tcp_flags));
  if (cfg.tcp_flags.empty()) {
    cfg.tcp_flags = "S";
  }
  cfg.ttl = OptionalIntFromWire(env.ttl);
  cfg.tos = OptionalIntFromWire(env.tos);
  cfg.window = OptionalIntFromWire(env.window);
  cfg.fragment_enabled = env.fragment_enabled != 0u;
  cfg.fragment_size = static_cast<int>(env.fragment_size);
  cfg.pad_size = static_cast<int>(env.pad_size);
  cfg.attack_vector = ReadFixed(env.attack_vector, sizeof(env.attack_vector));
  if (cfg.attack_vector.empty()) {
    cfg.attack_vector = "basic";
  }
  cfg.dns_name = ReadFixed(env.dns_name, sizeof(env.dns_name));
  if (cfg.dns_name.empty()) {
    cfg.dns_name = "example.com";
  }
  cfg.dns_edns = env.dns_edns != 0u;
  cfg.dns_recursive = env.dns_recursive != 0u;
  const std::string qtypes_raw = ReadFixed(env.dns_qtype, sizeof(env.dns_qtype));
  if (!qtypes_raw.empty()) {
    cfg.dns_qtypes.clear();
    std::size_t start = 0;
    while (start < qtypes_raw.size()) {
      const std::size_t comma = qtypes_raw.find(',', start);
      const std::size_t end = (comma == std::string::npos) ? qtypes_raw.size() : comma;
      const std::string part = qtypes_raw.substr(start, end - start);
      if (!part.empty()) {
        cfg.dns_qtypes.push_back(part);
      }
      if (comma == std::string::npos) {
        break;
      }
      start = comma + 1;
    }
  }
  return cfg;
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

// Version-agnostic overload: derives the pacing config from either a V1 or a V2
// envelope payload (the pacing fields live in the shared V1 prefix).
inline samurai_pacing_config_t PacingFromEnvelope(
    const samurai::wire::SamuraiWireHeaderV1& header, const std::uint8_t* payload) {
  samurai_pacing_config_t out{};
  if (payload == nullptr) {
    return out;
  }
  if (header.version == samurai::wire::kVersionV2) {
    samurai::wire::JobEnvelopeV2 env{};
    std::memcpy(&env, payload, sizeof(env));
    return PacingFromEnvelope(env.base);
  }
  samurai::wire::JobEnvelopeV1 env{};
  std::memcpy(&env, payload, sizeof(env));
  return PacingFromEnvelope(env);
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

inline std::vector<std::uint8_t> SerializeSnapshotV2(const samurai::wire::MetricSnapshotV2& snap) {
  std::vector<std::uint8_t> payload(sizeof(snap));
  std::memcpy(payload.data(), &snap, sizeof(snap));
  return payload;
}

}  // namespace samurai::daemon
