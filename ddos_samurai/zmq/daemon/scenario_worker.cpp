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
#include "afpacket_tx.hpp"

#include "compiler.hpp"
#include "json.hpp"
#include "scheduler.hpp"
#include "sla.hpp"
#include "bridge.hpp"

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

using samurai::daemon::ConfigFromEnvelope;




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
    double rate_accuracy_pct,
    double scenario_latency_p95_ms,
    bool scenario_l7_executed) {
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
      << ",\"scenario_latency_p95_ms\":" << scenario_latency_p95_ms
      << ",\"scenario_dataplane\":\"" << (scenario_l7_executed ? "l7_emu_native_real_http" : "afpacket_packet_pool") << "\""
      << ",\"actual_rps\":" << actual_rps
      << ",\"rate_accuracy_pct\":" << rate_accuracy_pct
      << ",\"scenario_engine_path\":\"samurai_scenario_static_cpp\""
      << ",\"note\":\"" << (scenario_l7_executed
                                ? "scenario_payload_ref+compile_soa+l7emu_exec+sla_native_real"
                                : "scenario_payload_ref+compile_soa+sla_native+pacing_static") << "\"}";
  const std::string json = oss.str();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

// --- Scenario -> L7 emu execution bridge --------------------------------
// scenario_engine derlenmiş senaryoyu, l7_emu_native veri düzlemi üzerinden
// GERÇEK, stateful HTTP/1.1, HTTP/2, HTTP/3(QUIC) olarak koşturur. Böylece
// senaryonun adımları (method/path/headers/think_time/token-capture) hedefe
// gerçek istek olarak gider; eski af_packet paket-havuzu sentezi yerine geçer.
namespace scn = ddos_samurai::scenario_native;
namespace l7emu = ddos_samurai::l7_emu_native;

std::string LowerStr(std::string s) {
  for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

struct ScenarioL7Result {
  bool ok{false};
  std::uint64_t sent{0};
  std::uint64_t errors{0};
  std::uint64_t bytes{0};
  double rps{0.0};
  double latency_p95_ms{0.0};
  bool has_latency{false};
  int attempted{0};
  int completed{0};
  int failed{0};
  int sessions{0};
  int sla_passed{-1};
  std::string backend_detail;
};

// backend/protocol string -> emu protocol + varsayılan (stateful) transport.
// Karar: kernel_socket varsayılan (commodity, her yerde tele çıkar); senaryo
// load_model.transport / transport_backend ile custom_tcp/dpdk_direct'e
// geçebilir; QUIC daima custom_quic.
void ResolveProtocolTransport(
    const samurai::core::json::Value& raw,
    const scn::ScenarioSpecNative& spec,
    std::string& emu_protocol,
    std::string& transport,
    bool& use_tls) {
  std::string req = LowerStr(spec.load_model.backend);
  if (const auto* p = raw.find("protocol"); p != nullptr && p->is_string()) req = LowerStr(p->as_string());
  if (req == "http2" || req == "h2") emu_protocol = "http2";
  else if (req == "http3" || req == "h3" || req == "quic") emu_protocol = "quic";
  else emu_protocol = "http1";

  transport = "kernel_socket";
  if (const auto* lm = raw.find("load_model"); lm != nullptr) {
    if (const auto* t = lm->find("transport"); t != nullptr && t->is_string()) transport = LowerStr(t->as_string());
  }
  if (const auto* t = raw.find("transport_backend"); t != nullptr && t->is_string()) transport = LowerStr(t->as_string());

  use_tls = false;
  if (const auto* s = raw.find("scheme"); s != nullptr && s->is_string()) use_tls = (LowerStr(s->as_string()) == "https");
  if (const auto* tv = raw.find("tls"); tv != nullptr && tv->is_bool()) use_tls = tv->as_bool(false);

  if (emu_protocol == "quic") { transport = "custom_quic"; use_tls = true; }
  if (transport.empty()) transport = "kernel_socket";
}

bool IsHttpBackend(const std::string& emu_protocol) {
  return emu_protocol == "http1" || emu_protocol == "http2" || emu_protocol == "quic";
}

ScenarioL7Result RunScenarioL7(
    const scn::ScenarioSpecNative& spec,
    const samurai::core::json::Value& raw,
    const std::string& target_ip,
    int target_port) {
  using samurai::core::json::Value;
  ScenarioL7Result R;
  if (spec.flows.empty()) return R;

  std::string emu_protocol, transport;
  bool use_tls = false;
  ResolveProtocolTransport(raw, spec, emu_protocol, transport, use_tls);
  if (!IsHttpBackend(emu_protocol)) return R;  // L3/L4 backend -> legacy paket-havuzu

  const int vus = spec.load_model.concurrent_vus > 0
                      ? std::min(spec.load_model.concurrent_vus, 512)
                      : 16;

  std::string host = target_ip;
  int req_timeout = 5000;

  Value ops = Value::Array();
  int total_requests = 0;
  for (int s = 0; s < vus; ++s) {
    const scn::Flow& flow = spec.flows[static_cast<std::size_t>(s) % spec.flows.size()];
    const scn::Persona* persona = nullptr;
    if (auto it = spec.personas.find(flow.persona); it != spec.personas.end()) persona = &it->second;
    if (persona != nullptr && persona->request_timeout_ms > 0) req_timeout = persona->request_timeout_ms;

    for (const scn::Step& st : flow.steps) {
      if (st.type != scn::StepType::Request) continue;  // yalnız HTTP istek adımları L7'yi sürer

      const int tt = (st.think_time.max_ms > 0)
                         ? (st.think_time.min_ms + st.think_time.max_ms) / 2
                         : st.think_time.mean_ms;
      if (tt > 0) {
        Value think = Value::Object();
        think.set("opcode", Value::Str("THINK_TIME"));
        think.set("think_time_ms", Value::Int(tt));
        ops.push_back(std::move(think));
      }

      Value op = Value::Object();
      op.set("opcode", Value::Str("SEND_HEADERS"));
      op.set("method", Value::Str(st.method.empty() ? std::string("GET") : st.method));
      op.set("path", Value::Str(st.path.empty() ? std::string("/") : st.path));

      Value hdrs = Value::Object();
      if (persona != nullptr) for (const auto& kv : persona->headers) hdrs.set(kv.first, Value::Str(kv.second));
      for (const auto& kv : st.headers) hdrs.set(kv.first, Value::Str(kv.second));
      if (const auto* h = hdrs.find("Host"); h != nullptr && h->is_string()) host = h->as_string();
      op.set("headers", std::move(hdrs));
      if (!st.tls_sni.empty()) op.set("tls_sni", Value::Str(st.tls_sni));
      if (!st.tls_alpn.empty()) op.set("tls_alpn", Value::Str(st.tls_alpn));
      ops.push_back(std::move(op));
      ++total_requests;

      if (!st.body_template.empty()) {
        Value body = Value::Object();
        body.set("opcode", Value::Str("SEND_BODY"));
        body.set("body", Value::Str(st.body_template));
        ops.push_back(std::move(body));
      }
      if (!st.token_variable_name.empty()) {
        Value cap = Value::Object();
        cap.set("opcode", Value::Str("CAPTURE_COOKIE"));
        cap.set("capture_name", Value::Str(st.token_variable_name));
        ops.push_back(std::move(cap));
      }
    }
  }
  if (total_requests == 0) return R;

  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str(transport));
  conn.set("target_ip", Value::Str(target_ip));
  conn.set("target_port", Value::Int(target_port));
  conn.set("scheme", Value::Str(use_tls ? "https" : "http"));
  conn.set("host_header", Value::Str(host));
  conn.set("keepalive", Value::Int(1));  // stateful oturum: adımlar aynı bağlantıda
  conn.set("timeout_ms", Value::Int(req_timeout));
  conn.set("max_connections", Value::Int(vus));
  if (emu_protocol == "http2" || emu_protocol == "quic")
    conn.set("max_streams_per_connection", Value::Int(std::max(1, total_requests / std::max(1, vus))));

  Value profile = Value::Object();
  profile.set("protocol", Value::Str(emu_protocol));
  profile.set("flow_attempted", Value::Int(total_requests));
  profile.set("connection_template", std::move(conn));
  Value fp = Value::Object();
  fp.set("ops", std::move(ops));
  profile.set("flow_program", std::move(fp));

  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(vus));
  cfg.set("profile_l7", Value::Int(1));
  cfg.set("profile_sample_limit", Value::Int(0));

  const Value res = l7emu::run_profile_json(profile, cfg);
  auto num = [&](const char* k) -> double {
    const Value* v = res.find(k);
    return (v != nullptr && v->is_number()) ? v->as_double() : 0.0;
  };
  R.sent = static_cast<std::uint64_t>(std::max(0.0, num("sent")));
  R.errors = static_cast<std::uint64_t>(std::max(0.0, num("errors")));
  R.bytes = static_cast<std::uint64_t>(std::max(0.0, num("l7_tx_bytes")));
  R.rps = num("l7_rps");
  R.attempted = static_cast<int>(num("attempted"));
  R.completed = static_cast<int>(num("l7_flow_completed"));

  // Adım-bazlı gerçek sonuçlardan completion/fail/p95
  std::vector<double> lats;
  int ok_rows = 0, failed = 0;
  if (const Value* rows = res.find("scenario_step_results"); rows != nullptr && rows->is_array()) {
    for (const auto& r : rows->elements()) {
      const Value* succ = r.find("success");
      const Value* lat = r.find("latency_ms");
      if (succ != nullptr && succ->as_bool(false)) ++ok_rows; else ++failed;
      if (lat != nullptr && lat->is_number()) lats.push_back(lat->as_double());
    }
  }
  if (!lats.empty()) {
    std::sort(lats.begin(), lats.end());
    std::size_t idx = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(lats.size()))) - 1;
    if (idx >= lats.size()) idx = lats.size() - 1;
    R.latency_p95_ms = lats[idx];
    R.has_latency = true;
  }
  R.failed = (failed > 0) ? failed : static_cast<int>(R.errors);
  R.sessions = vus;
  const int attempted = (R.attempted > 0) ? R.attempted : total_requests;
  const int completed_sessions = (R.failed == 0) ? vus : std::max(0, vus - R.failed);

  const Value* sla = raw.find("sla");
  const Value ev = scn::evaluate_sla_native(
      sla != nullptr ? *sla : Value::Object(),
      vus, completed_sessions, attempted, R.failed,
      R.latency_p95_ms, R.has_latency,
      vus, completed_sessions, 0, R.failed);
  const Value* passed = ev.find("passed");
  R.sla_passed = (passed != nullptr && passed->as_bool(false)) ? 1 : 0;
  R.backend_detail = emu_protocol + "/" + transport + "+l7emu";
  R.ok = true;
  return R;
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
        bool scenario_l7_executed = false;
        std::uint64_t l7_sent = 0u, l7_errors = 0u, l7_bytes = 0u;
        double l7_rps = 0.0;
        double l7_p95 = 0.0;
        // Gerçek yürütme (RunScenarioL7) parse bloğu içinde olduğundan, süre
        // penceresini burada başlat ki actual_rps HTTP yürütmesini yansıtsın.
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
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

              // GERÇEK yürütme: senaryoyu l7_emu_native ile stateful HTTP olarak koştur.
              const std::string tgt_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
              const int tgt_port = static_cast<int>(env.target_port);
              const ScenarioL7Result l7 = RunScenarioL7(spec, parsed.value, tgt_ip, tgt_port);
              if (l7.ok) {
                scenario_l7_executed = true;
                l7_sent = l7.sent;
                l7_errors = l7.errors;
                l7_bytes = l7.bytes;
                l7_rps = l7.rps;
                l7_p95 = l7.latency_p95_ms;
                scenario_sla_passed = l7.sla_passed;           // plan-SLA yerine GERÇEK SLA
                scenario_steps_est = static_cast<std::uint64_t>(std::max(0, l7.attempted));
                scenario_sessions = static_cast<std::uint64_t>(std::max(0, l7.sessions));
                scenario_backend = l7.backend_detail;          // örn. "http1/kernel_socket+l7emu"
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

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;

        if (scenario_l7_executed) {
          // GERÇEK L7 yürütmesi zaten yapıldı (RunScenarioL7 -> run_profile_json).
          // Sayaçları emu sonuçlarından devral; sentetik paket-havuzunu atla.
          packets_sent = l7_sent;
          packets_errors = l7_errors;
          bytes_sent = l7_bytes;
        } else {
          // Legacy yol: yalnız L3/L4 (http-olmayan) backend'lerde sentetik paket havuzu.
          PacketConfig cfg = ConfigFromEnvelope(env);
          const int packet_count = std::max(1, static_cast<int>(env.packet_count));
          const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
          const std::size_t stride = pool.packet_size;
          if (stride == 0 || pool.size() < stride) {
            packets_errors = static_cast<std::uint64_t>(packet_count);
          } else if (samurai::daemon::AfPacketTxEnabled()) {
            // Real transmission of the scenario's synthesized traffic over the
            // af_packet kernel-socket backend (commodity NICs, no AF_XDP/DPDK).
            const long long ipg_ns =
                (pace_cfg.mode == SAMURAI_PACING_IPG) ? static_cast<long long>(pace_cfg.ipg_ns) : 0;
            const auto tx = samurai::daemon::AfPacketSendPool(
                cfg, pool.data(), pool.size(), static_cast<int>(stride), packet_count, ipg_ns);
            packets_sent = tx.packets_sent;
            packets_errors = tx.packets_errors;
            bytes_sent = tx.bytes_sent;
            scenario_backend += "+" + tx.note;  // surface the af_packet path taken
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
        }
        (void)l7_rps;

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
            snap.rate_accuracy_pct,
            l7_p95,
            scenario_l7_executed);
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
