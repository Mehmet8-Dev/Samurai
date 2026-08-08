#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <zmq.h>

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

#include "compiler.hpp"
#include "json.hpp"
#include "scheduler.hpp"
#include "sla.hpp"

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_scenario";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_scenario";




int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::SCENARIO, job_id);
}


bool ReadAllFile(const std::string& path, std::vector<std::uint8_t>& out, std::string& err) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    err = "scenario_payload_ref_missing";
    return false;
  }
  f.seekg(0, std::ios::end);
  const std::streamoff sz = f.tellg();
  if (sz < 0) {
    err = "scenario_payload_ref_read_failed";
    return false;
  }
  f.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(sz));
  if (!out.empty() && !f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()))) {
    err = "scenario_payload_ref_read_failed";
    return false;
  }
  return true;
}

std::size_t CountToken(const std::string& hay, const std::string& needle) {
  if (needle.empty()) return 0u;
  std::size_t pos = 0;
  std::size_t count = 0;
  while (true) {
    pos = hay.find(needle, pos);
    if (pos == std::string::npos) break;
    ++count;
    pos += needle.size();
  }
  return count;
}

PacketConfig ConfigFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  PacketConfig cfg;
  cfg.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  cfg.target_port = static_cast<int>(env.target_port);
  cfg.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  if (cfg.protocol.empty()) cfg.protocol = "tcp";
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
  if (cfg.tcp_flags.empty()) cfg.tcp_flags = "S";
  cfg.ttl = OptionalIntFromWire(env.ttl);
  cfg.tos = OptionalIntFromWire(env.tos);
  cfg.window = OptionalIntFromWire(env.window);
  cfg.fragment_enabled = env.fragment_enabled != 0u;
  cfg.fragment_size = static_cast<int>(env.fragment_size);
  cfg.pad_size = static_cast<int>(env.pad_size);
  cfg.attack_vector = ReadFixed(env.attack_vector, sizeof(env.attack_vector));
  if (cfg.attack_vector.empty()) cfg.attack_vector = "basic";
  cfg.dns_name = ReadFixed(env.dns_name, sizeof(env.dns_name));
  if (cfg.dns_name.empty()) cfg.dns_name = "example.com";
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
      if (!part.empty()) cfg.dns_qtypes.push_back(part);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
  }
  return cfg;
}




std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    std::uint64_t scenario_payload_bytes,
    std::uint64_t scenario_steps_est,
    std::uint64_t scenario_flows_est,
    std::uint64_t scenario_sessions,
    const std::string& scenario_backend,
    std::int64_t scenario_sla_passed,
    double actual_rps,
    double rate_accuracy_pct) {
  std::ostringstream oss;
  oss
      << "{\"status\":\"ok\",\"worker_kind\":\"scenario\""
      << ",\"correlation_id\":" << correlation_id
      << ",\"job_id\":\"" << job_id << "\""
      << ",\"packets_sent\":" << packets_sent
      << ",\"packets_errors\":" << packets_errors
      << ",\"bytes_sent\":" << bytes_sent
      << ",\"scenario_payload_bytes\":" << scenario_payload_bytes
      << ",\"scenario_steps_est\":" << scenario_steps_est
      << ",\"scenario_flows_est\":" << scenario_flows_est
      << ",\"scenario_sessions\":" << scenario_sessions
      << ",\"scenario_backend\":\"" << scenario_backend << "\""
      << ",\"scenario_sla_passed\":" << scenario_sla_passed
      << ",\"actual_rps\":" << actual_rps
      << ",\"rate_accuracy_pct\":" << rate_accuracy_pct
      << ",\"scenario_engine_path\":\"samurai_scenario_static_cpp\""
      << ",\"note\":\"scenario_payload_ref+compile_soa+sla_native+pacing_static\"}";
  const std::string json = oss.str();
  return std::vector<std::uint8_t>(json.begin(), json.end());
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

    if (msg_type == samurai::wire::MessageType::STOP_JOB) {
      zmq_msg_close(&msg);
      (void)SendAck(push, header.correlation_id, job_id);
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"scenario\"}";
      (void)SendFrame(
          push,
          static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
          header.correlation_id,
          samurai::wire::WorkerKind::SCENARIO,
          job_id,
          std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::SCENARIO,
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
        const std::string scenario_ref = ReadFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref));
        if (scenario_ref.empty()) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::SCENARIO,
              job_id,
              JsonError("scenario_payload_ref_missing"));
          continue;
        }

        std::vector<std::uint8_t> scenario_blob;
        std::string io_err;
        if (!ReadAllFile(scenario_ref, scenario_blob, io_err)) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::SCENARIO,
              job_id,
              JsonError(io_err));
          continue;
        }
        if (scenario_blob.empty()) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::SCENARIO,
              job_id,
              JsonError("scenario_payload_empty"));
          continue;
        }

        const std::string scenario_text(
            reinterpret_cast<const char*>(scenario_blob.data()),
            scenario_blob.size());
        std::uint64_t scenario_steps_est = 1u;
        std::uint64_t scenario_flows_est = 1u;
        std::uint64_t scenario_sessions = 0u;
        std::string scenario_backend = "http";
        std::int64_t scenario_sla_passed = -1;
        const samurai::core::json::ParseResult parsed = samurai::core::json::Parse(scenario_text);
        if (parsed.ok) {
          try {
            const ddos_samurai::scenario_native::ScenarioSpecNative spec =
                ddos_samurai::scenario_native::parse_spec(parsed.value);
            if (!spec.flows.empty()) {
              scenario_flows_est = spec.flows.size();
              scenario_backend = spec.load_model.backend;
              std::mt19937_64 rng(std::random_device{}());
              const int sessions =
                  std::min<int>(spec.load_model.concurrent_vus > 0 ? spec.load_model.concurrent_vus : 16, 512);
              std::vector<std::string> flow_names;
              std::vector<std::uint64_t> seeds;
              flow_names.reserve(static_cast<std::size_t>(sessions));
              seeds.reserve(static_cast<std::size_t>(sessions));
              for (int i = 0; i < sessions; ++i) {
                flow_names.push_back(spec.flows[static_cast<std::size_t>(rng() % spec.flows.size())].name);
                seeds.push_back(rng());
              }
              const samurai::core::json::Value soa =
                  ddos_samurai::scenario_native::compile_session_plans_packed_bulk_soa_native(
                      spec, flow_names, seeds);
              const samurai::core::json::Value* offsets = soa.find("session_offsets");
              if (offsets != nullptr && offsets->is_array() && !offsets->elements().empty()) {
                scenario_steps_est = static_cast<std::uint64_t>(offsets->elements().back().as_int(0));
              }
              const samurai::core::json::Value* attempts = soa.find("session_step_attempted");
              if (attempts != nullptr && attempts->is_array()) {
                for (const auto& a : attempts->elements()) {
                  scenario_steps_est += static_cast<std::uint64_t>(a.as_int(0));
                }
              }
              const samurai::core::json::Value* sf = soa.find("session_flow");
              if (sf != nullptr && sf->is_array()) scenario_sessions = sf->elements().size();
              const samurai::core::json::Value* sla = parsed.value.find("sla");
              if (sla != nullptr) {
                const samurai::core::json::Value ev = ddos_samurai::scenario_native::evaluate_sla_native(
                    *sla,
                    static_cast<int>(scenario_sessions),
                    static_cast<int>(scenario_sessions),
                    static_cast<int>(scenario_steps_est),
                    0,
                    0.0,
                    false,
                    0,
                    0,
                    0,
                    0);
                const samurai::core::json::Value* passed = ev.find("passed");
                if (passed != nullptr) scenario_sla_passed = passed->as_bool(false) ? 1 : 0;
              }
            }
          } catch (const std::exception&) {
            scenario_steps_est = static_cast<std::uint64_t>(
                CountToken(scenario_text, "\"opcode\"") + CountToken(scenario_text, "\"type\""));
            scenario_flows_est = static_cast<std::uint64_t>(
                CountToken(scenario_text, "\"flow\"") + CountToken(scenario_text, "\"flow_name\""));
            if (scenario_steps_est == 0u) scenario_steps_est = 1u;
            if (scenario_flows_est == 0u) scenario_flows_est = 1u;
          }
        }

        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
        const std::size_t stride = pool.packet_size;

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;

        if (stride == 0 || pool.size() < stride) {
          packets_errors = static_cast<std::uint64_t>(packet_count);
        } else {
          for (int i = 0; i < packet_count; ++i) {
            samurai_pacing_wait_next(&pace_state, &pace_cfg);
            const std::size_t off = static_cast<std::size_t>(i) * stride;
            if (off + stride > pool.size()) {
              packets_errors += 1u;
            } else {
              packets_sent += 1u;
              bytes_sent += static_cast<std::uint64_t>(stride);
            }

            const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
            if (now_ns - last_hb_ns >= 1'000'000'000ull) {
              (void)SendFrame(
                  push,
                  static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                  header.correlation_id,
                  samurai::wire::WorkerKind::SCENARIO,
                  job_id);
              last_hb_ns = now_ns;
            }
            if (now_ns - last_metric_ns >= 2'000'000'000ull) {
              const samurai::wire::MetricSnapshotV1 snap =
                  BuildSnapshot(now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
              (void)SendFrame(
                  push,
                  static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                  header.correlation_id,
                  samurai::wire::WorkerKind::SCENARIO,
                  job_id,
                  SerializeSnapshot(snap));
              last_metric_ns = now_ns;
              last_hb_ns = now_ns;
            }
          }
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap =
            BuildSnapshot(end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::SCENARIO,
            job_id,
            SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonDone(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            static_cast<std::uint64_t>(scenario_blob.size()),
            scenario_steps_est,
            scenario_flows_est,
            scenario_sessions,
            scenario_backend,
            scenario_sla_passed,
            snap.actual_rps,
            snap.rate_accuracy_pct);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::SCENARIO,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::SCENARIO,
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
        samurai::wire::WorkerKind::SCENARIO,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
