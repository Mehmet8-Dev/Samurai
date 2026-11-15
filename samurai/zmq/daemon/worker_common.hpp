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
#if __has_include("flow_cache.hpp")
#define SAMURAI_HAS_TELEMETRY_SINK 1
#include "telemetry_sink.hpp"
#else
#define SAMURAI_HAS_TELEMETRY_SINK 0
#endif
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
    const std::string& note = "done",
    std::uint64_t ipfix_exported_packets = 0,
    std::uint64_t ipfix_exported_records = 0) {
  samurai::core::json::Value val = samurai::core::json::Value::Object();
  val.set("status", samurai::core::json::Value::Str("ok"));
  val.set("correlation_id", samurai::core::json::Value::Int(static_cast<int64_t>(correlation_id)));
  val.set("job_id", samurai::core::json::Value::Str(job_id));
  val.set("packets_sent", samurai::core::json::Value::Int(static_cast<int64_t>(packets_sent)));
  val.set("packets_errors", samurai::core::json::Value::Int(static_cast<int64_t>(packets_errors)));
  val.set("bytes_sent", samurai::core::json::Value::Int(static_cast<int64_t>(bytes_sent)));
  val.set("actual_rps", samurai::core::json::Value::Double(actual_rps));
  val.set("rate_accuracy_pct", samurai::core::json::Value::Double(rate_accuracy_pct));
  val.set("ipfix_exported_packets",
          samurai::core::json::Value::Int(static_cast<int64_t>(ipfix_exported_packets)));
  val.set("ipfix_exported_records",
          samurai::core::json::Value::Int(static_cast<int64_t>(ipfix_exported_records)));
  val.set("note", samurai::core::json::Value::Str(note));
  const std::string json = val.dump();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

inline samurai::cpu_native::PacketConfig ConfigFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  samurai::cpu_native::PacketConfig cfg;
  cfg.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  if (cfg.target_ip.empty()) {
    cfg.target_ip = "127.0.0.1";
  }
  cfg.target_port = static_cast<int>(env.target_port);
  if (cfg.target_port <= 0 || cfg.target_port > 65535) {
    cfg.target_port = 80;
  }
  cfg.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  if (cfg.protocol.empty()) {
    cfg.protocol = "tcp";
  }
  const bool env_spoof = (std::getenv("SAMURAI_SPOOF") != nullptr && std::strcmp(std::getenv("SAMURAI_SPOOF"), "1") == 0);
  cfg.spoof = (env.spoof_enabled != 0u) || env_spoof;
  std::string s_mode = ReadFixed(env.spoof_mode, sizeof(env.spoof_mode));
  if (s_mode.empty() && env_spoof) {
    const char* sm = std::getenv("SAMURAI_SPOOF_MODE");
    s_mode = (sm && sm[0]) ? sm : "random";
  }
  cfg.spoof_opts = samurai::cpu_native::SpoofOptions{
      .mode = s_mode,
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
  out.jitter_model = env.jitter_model;
  out.jitter_pct = env.jitter_pct;
  out.use_so_txtime = env.use_so_txtime;
  return out;
}

// Version-agnostic overload: derives the pacing config from V1, V2, or V3
// decoded frame payload.
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

inline samurai_pacing_config_t PacingFromDecodedFrame(
    const samurai::wire::DecodedWireFrame& frame) {
  if (frame.version == samurai::wire::kVersionV3) {
    samurai::wire::JobV3Payload v3{};
    if (samurai::wire::ParseJobV3Payload(
            frame.payload_ptr, frame.actual_payload_len, frame.ext_count, v3)) {
      return PacingFromEnvelope(samurai::wire::ToJobEnvelopeV1(v3.base));
    }
    return samurai_pacing_config_t{};
  }
  return PacingFromEnvelope(frame.as_v1_header, frame.payload_ptr);
}

#if SAMURAI_HAS_TELEMETRY_SINK
inline void ApplyTelemetrySectionV3(
    const samurai::wire::JobSectionTelemetryV3& sec, TelemetrySink* sink) {
  if (!sink) return;
  samurai::wire::TelemetryConfigV1 tcfg{};
  tcfg.enabled = sec.enabled;
  tcfg.netflow_v9 = sec.netflow_v9;
  tcfg.collector_port = sec.collector_port;
  tcfg.sample_rate = sec.sample_rate;
  tcfg.domain_id = sec.domain_id;
  tcfg.export_interval_ms = sec.export_interval_ms;
  std::memcpy(tcfg.collector_ip, sec.collector_ip, sizeof(tcfg.collector_ip));
  sink->ApplyWireConfig(tcfg, samurai_pacing_monotonic_now_ns());
}

inline bool DecodeJobEnvelopeV1Frame(
    const samurai::wire::DecodedWireFrame& frame,
    samurai::wire::JobEnvelopeV1& out,
    TelemetrySink* telemetry = nullptr) {
  if (frame.version == samurai::wire::kVersionV3) {
    samurai::wire::JobV3Payload v3{};
    if (!samurai::wire::ParseJobV3Payload(
            frame.payload_ptr, frame.actual_payload_len, frame.ext_count, v3)) {
      return false;
    }
    out = samurai::wire::ToJobEnvelopeV1(v3.base);
    if (v3.has_telemetry) ApplyTelemetrySectionV3(v3.telemetry, telemetry);
    return true;
  }
  if (!frame.payload_ptr ||
      frame.actual_payload_len != sizeof(samurai::wire::JobEnvelopeV1) ||
      frame.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
    return false;
  }
  std::memcpy(&out, frame.payload_ptr, sizeof(out));
  return true;
}
#endif  // SAMURAI_HAS_TELEMETRY_SINK

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
  snap.jitter_p99_ns = samurai_pacing_get_jitter_p99_ns(&pace_state);
  snap.rate_accuracy_pct = rate_accuracy_pct;
  snap.busywait_cycles = static_cast<std::uint32_t>(
      pace_state.busywait_cycles > 0xFFFFFFFFull ? 0xFFFFFFFFull : pace_state.busywait_cycles);
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

inline bool ApplyReconfigureWindow(
    const std::uint8_t* payload,
    std::size_t payload_len,
    samurai_pacing_config_t& pace_cfg,
    samurai_pacing_state_t& pace_state,
    std::uint32_t* request_mix = nullptr,
    std::uint32_t* source_rotation = nullptr,
    std::uint32_t* telco_rate_cps = nullptr) {
  if (!payload || payload_len < sizeof(samurai::wire::ReconfigureWindowV1)) {
    return false;
  }
  samurai::wire::ReconfigureWindowV1 w{};
  std::memcpy(&w, payload, sizeof(w));
  if (w.flags & samurai::wire::ReconfigureFlag::kPacingMode) {
    pace_cfg.mode = w.pacing_mode;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kRps) {
    pace_cfg.target_rps = w.target_rps;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kIpg) {
    pace_cfg.ipg_ns = w.ipg_ns;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kJitter) {
    pace_cfg.jitter_model = w.jitter_model;
    pace_cfg.jitter_pct = w.jitter_pct;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kBurst) {
    pace_cfg.burst_size = w.burst_size > 0u ? w.burst_size : 1u;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kRequestMix && request_mix) {
    *request_mix = w.request_mix;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kSourceRotation && source_rotation) {
    *source_rotation = w.source_rotation;
  }
  if (w.flags & samurai::wire::ReconfigureFlag::kTelcoCps && telco_rate_cps) {
    *telco_rate_cps = w.telco_rate_cps;
  }
  samurai_pacing_reconfigure(&pace_state, &pace_cfg);
  return true;
}

#if SAMURAI_HAS_TELEMETRY_SINK
inline bool HandleSetTelemetryFrame(
    const std::uint8_t* payload,
    std::size_t payload_len,
    TelemetrySink& sink,
    std::uint64_t now_ns = 0) {
  if (!payload || payload_len < sizeof(samurai::wire::TelemetryConfigV1)) {
    return false;
  }
  samurai::wire::TelemetryConfigV1 cfg{};
  std::memcpy(&cfg, payload, sizeof(cfg));
  sink.ApplyWireConfig(cfg, now_ns);
  return true;
}

inline bool HandleCommonIdleMessage(
    void* push,
    samurai::wire::WorkerKind kind,
    const samurai::wire::DecodedWireFrame& frame,
    TelemetrySink& telemetry,
    bool& running) {
  const auto msg_type = static_cast<samurai::wire::MessageType>(frame.msg_type);
  if (msg_type == samurai::wire::MessageType::PING ||
      msg_type == samurai::wire::MessageType::STOP_JOB ||
      msg_type == samurai::wire::MessageType::ABORT ||
      msg_type == samurai::wire::MessageType::RECONFIGURE_JOB) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                    frame.correlation_id, kind, frame.job_id);
    return true;
  }
  if (msg_type == samurai::wire::MessageType::SHUTDOWN) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                    frame.correlation_id, kind, frame.job_id);
    running = false;
    return true;
  }
  if (msg_type == samurai::wire::MessageType::SET_TELEMETRY) {
    if (HandleSetTelemetryFrame(frame.payload_ptr, frame.actual_payload_len, telemetry,
                                samurai_pacing_monotonic_now_ns())) {
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                      frame.correlation_id, kind, frame.job_id);
    } else {
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                      frame.correlation_id, kind, frame.job_id,
                      JsonError("telemetry_config_size_mismatch"));
    }
    return true;
  }
  return false;
}

// Overload for V1-header callers.
inline bool HandleCommonIdleMessage(
    void* push,
    samurai::wire::WorkerKind kind,
    const samurai::wire::SamuraiWireHeaderV1& header,
    const std::string& job_id,
    const std::uint8_t* payload_ptr,
    std::size_t payload_len,
    TelemetrySink& telemetry,
    bool& running) {
  samurai::wire::DecodedWireFrame frame{};
  frame.version = header.version;
  frame.msg_type = header.msg_type;
  frame.worker_kind = header.worker_kind;
  frame.flags = header.flags;
  frame.payload_len = header.payload_len;
  frame.correlation_id = header.correlation_id;
  frame.job_id = job_id;
  frame.payload_ptr = payload_ptr;
  frame.actual_payload_len = payload_len;
  frame.as_v1_header = header;
  return HandleCommonIdleMessage(push, kind, frame, telemetry, running);
}

struct ControlPollState {
  bool stop_job = false;
  bool shutdown = false;
  bool reconfigure = false;
  samurai::wire::ReconfigureWindowV1 reconf{};
};

inline void PollControlNonBlocking(
    void* pull,
    void* push,
    samurai::wire::WorkerKind kind,
    TelemetrySink* telemetry,
    ControlPollState& state) {
  if (!pull) return;
  zmq_msg_t cmsg;
  zmq_msg_init(&cmsg);
  while (zmq_msg_recv(&cmsg, pull, ZMQ_DONTWAIT) > 0) {
    const std::size_t csz = static_cast<std::size_t>(zmq_msg_size(&cmsg));
    samurai::wire::DecodedWireFrame cfrm{};
    if (samurai::wire::DecodeWireFrame(zmq_msg_data(&cmsg), csz, cfrm)) {
      const auto ctype = static_cast<samurai::wire::MessageType>(cfrm.msg_type);
      const std::string& cjid = cfrm.job_id;
      const std::size_t cplen = cfrm.actual_payload_len;
      const std::uint8_t* cpdata = cfrm.payload_ptr;
      if (ctype == samurai::wire::MessageType::PING) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                        cfrm.correlation_id, kind, cjid);
      } else if (ctype == samurai::wire::MessageType::SHUTDOWN) {
        state.stop_job = true;
        state.shutdown = true;
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                        cfrm.correlation_id, kind, cjid);
      } else if (ctype == samurai::wire::MessageType::STOP_JOB ||
                 ctype == samurai::wire::MessageType::ABORT) {
        state.stop_job = true;
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                        cfrm.correlation_id, kind, cjid);
      } else if (ctype == samurai::wire::MessageType::SET_TELEMETRY && telemetry) {
        if (HandleSetTelemetryFrame(cpdata, cplen, *telemetry, samurai_pacing_monotonic_now_ns())) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                          cfrm.correlation_id, kind, cjid);
        } else {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                          cfrm.correlation_id, kind, cjid,
                          JsonError("telemetry_config_size_mismatch"));
        }
      } else if (ctype == samurai::wire::MessageType::RECONFIGURE_JOB &&
                 cplen >= sizeof(samurai::wire::ReconfigureWindowV1)) {
        std::memcpy(&state.reconf, cpdata, sizeof(state.reconf));
        state.reconfigure = true;
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK),
                        cfrm.correlation_id, kind, cjid);
      }
    }
    zmq_msg_close(&cmsg);
    if (state.stop_job) return;
    zmq_msg_init(&cmsg);
  }
  zmq_msg_close(&cmsg);
}

inline void RecordBatchToTelemetry(
    TelemetrySink& sink,
    const std::string& target_ip,
    std::uint16_t target_port,
    const std::string& proto_name,
    std::uint64_t packets_count,
    std::uint32_t avg_pkt_bytes,
    std::uint64_t now_ns) noexcept {
  if (__builtin_expect(!sink.Enabled() || packets_count == 0u, 1)) {
    return;
  }
  const std::uint32_t src_be = htonl(0x0A000001u);
  const std::uint32_t dst_be = TelemetrySink::ParseIpBe(target_ip);
  const std::uint16_t dst_port_be = htons(target_port);
  const std::uint8_t proto = TelemetrySink::ProtoFromName(proto_name);
  const std::uint8_t flags = (proto == 6u) ? 0x02u : 0x00u;
  const std::uint64_t limit = std::min<std::uint64_t>(packets_count, 1024u);
  for (std::uint64_t k = 0; k < limit; ++k) {
    sink.RecordPacketNet(src_be, dst_be, htons(static_cast<std::uint16_t>(1024u + (k & 0x3FFu))),
                         dst_port_be, proto, avg_pkt_bytes, flags, 0, now_ns);
  }
}
#endif  // SAMURAI_HAS_TELEMETRY_SINK

}  // namespace samurai::daemon
