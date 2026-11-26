#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
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

// Opt-in DPDK: senaryo load_model.transport="dpdk_direct" dediğinde L7 profilini,
// dpdk_worker ile AYNI paylaşılan userspace stateful fast-path sürücüsü üzerinden
// (NIC'i DpdkShim sahiplenir, driver wire'ı pump eder) koştururuz. Header'lar
// SAMURAI_WITH_DPDK yokken boş guard olur; kernel_socket varsayılan yol değişmez.
#include <atomic>
#include <cstdlib>
#include <memory>
#include "stateful_fastpath.hpp"
#include "dpdk_fastpath_shim.hpp"

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

using samurai::cpu_native::PacketConfig;
using samurai::cpu_native::SpoofOptions;

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
  int step_succeeded{0};
  int failed{0};
  int sessions{0};
  int completed_sessions{0};
  int sla_passed{-1};
  std::uint64_t status_2xx{0};
  std::uint64_t status_3xx{0};
  std::uint64_t status_4xx{0};
  std::uint64_t status_5xx{0};
  std::uint64_t expectation_failures{0};
  int tcp_connect_attempts{0};
  int tcp_connect_established{0};
  int tcp_timeout_close_count{0};
  std::map<int, int> status_codes;
  std::vector<samurai::core::json::Value> step_results;
  std::uint64_t soak_rounds{0};
  double elapsed_s{0.0};
  std::string backend_detail;
  std::string dataplane_detail{"l7_emu_native_real_http"};
  std::string note_detail{"scenario_payload_ref+compile_soa+l7emu_exec+sla_native_real"};
};

std::string EscapeJsonStr(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (unsigned char c : in) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char hex[8];
          std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
          out += hex;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
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
    double rate_accuracy_pct,
    double scenario_latency_p95_ms,
    bool scenario_l7_executed,
    const ScenarioL7Result* sc_res = nullptr,
    std::uint64_t ipfix_exported_packets = 0,
    std::uint64_t ipfix_exported_records = 0) {
  const std::string dataplane = (scenario_l7_executed && sc_res != nullptr)
                                    ? sc_res->dataplane_detail
                                    : (scenario_l7_executed ? "l7_emu_native_real_http" : "afpacket_packet_pool");
  const std::string note = (scenario_l7_executed && sc_res != nullptr)
                               ? sc_res->note_detail
                               : (scenario_l7_executed
                                      ? "scenario_payload_ref+compile_soa+l7emu_exec+sla_native_real"
                                      : "scenario_payload_ref+compile_soa+sla_native+pacing_static");
  std::ostringstream oss;
  oss
      << "{\"status\":\"ok\",\"worker_kind\":\"scenario\""
      << ",\"correlation_id\":" << correlation_id
      << ",\"job_id\":\"" << EscapeJsonStr(job_id) << "\""
      << ",\"packets_sent\":" << packets_sent
      << ",\"packets_errors\":" << packets_errors
      << ",\"bytes_sent\":" << bytes_sent
      << ",\"scenario_payload_bytes\":" << scenario_payload_bytes
      << ",\"scenario_steps_est\":" << scenario_steps_est
      << ",\"scenario_flows_est\":" << scenario_flows_est
      << ",\"scenario_sessions\":" << scenario_sessions
      << ",\"scenario_backend\":\"" << EscapeJsonStr(scenario_backend) << "\""
      << ",\"scenario_sla_passed\":" << scenario_sla_passed
      << ",\"scenario_latency_p95_ms\":" << scenario_latency_p95_ms
      << ",\"scenario_dataplane\":\"" << EscapeJsonStr(dataplane) << "\""
      << ",\"actual_rps\":" << actual_rps
      << ",\"rate_accuracy_pct\":" << rate_accuracy_pct
      << ",\"ipfix_exported_packets\":" << ipfix_exported_packets
      << ",\"ipfix_exported_records\":" << ipfix_exported_records
      << ",\"scenario_engine_path\":\"samurai_scenario_static_cpp\""
      << ",\"note\":\"" << EscapeJsonStr(note) << "\"";

  if (sc_res != nullptr && sc_res->ok) {
    oss << ",\"sessions_started\":" << sc_res->sessions
        << ",\"sessions_completed\":" << sc_res->completed_sessions
        << ",\"soak_rounds\":" << sc_res->soak_rounds
        << ",\"elapsed_s\":" << sc_res->elapsed_s
        << ",\"step_attempted\":" << sc_res->attempted
        << ",\"step_succeeded\":" << sc_res->step_succeeded
        << ",\"step_failed\":" << sc_res->failed
        << ",\"expectation_failures\":" << sc_res->expectation_failures
        << ",\"status_2xx\":" << sc_res->status_2xx
        << ",\"status_3xx\":" << sc_res->status_3xx
        << ",\"status_4xx\":" << sc_res->status_4xx
        << ",\"status_5xx\":" << sc_res->status_5xx
        << ",\"tcp_connect_attempts\":" << sc_res->tcp_connect_attempts
        << ",\"tcp_connect_established\":" << sc_res->tcp_connect_established
        << ",\"tcp_timeout_close_count\":" << sc_res->tcp_timeout_close_count;
    oss << ",\"status_codes\":{";
    bool first_sc = true;
    for (const auto& [code, cnt] : sc_res->status_codes) {
      if (!first_sc) oss << ",";
      first_sc = false;
      oss << "\"" << code << "\":" << cnt;
    }
    oss << "}";
    samurai::core::json::Value steps_arr = samurai::core::json::Value::Array();
    for (const auto& sr : sc_res->step_results) {
      steps_arr.push_back(sr);
    }
    oss << ",\"step_results\":" << steps_arr.dump();
  }
  oss << "}";
  const std::string json = oss.str();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

// --- Scenario -> L7 emu execution bridge --------------------------------
// scenario_engine derlenmiş senaryoyu, l7_emu_native veri düzlemi üzerinden
// GERÇEK, stateful HTTP/1.1, HTTP/2, HTTP/3(QUIC) olarak koşturur. Böylece
// senaryonun adımları (method/path/headers/think_time/token-capture) hedefe
// gerçek istek olarak gider; eski af_packet paket-havuzu sentezi yerine geçer.
namespace scn = samurai::scenario_native;
namespace l7emu = samurai::l7_emu_native;

std::string LowerStr(std::string s) {
  for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

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

// profile.connection_template.transport_backend'i yerinde değiştirir (json::Value
// find() yalnız const olduğundan sub-object'i kopyalayıp geri set eder).
void RewriteProfileTransport(samurai::core::json::Value& profile, const std::string& transport) {
  using samurai::core::json::Value;
  const Value* conn = profile.find("connection_template");
  Value conn_copy = (conn != nullptr && conn->is_object()) ? *conn : Value::Object();
  conn_copy.set("transport_backend", Value::Str(transport));
  profile.set("connection_template", std::move(conn_copy));
}

double ResolveScenarioDurationS(
    const scn::ScenarioSpecNative& spec,
    const samurai::core::json::Value& raw) {
  if (const char* env_dur = std::getenv("SAMURAI_SCENARIO_DURATION_S")) {
    if (env_dur[0] != '\0') {
      char* end = nullptr;
      const double v = std::strtod(env_dur, &end);
      if (end != env_dur && *end == '\0' && v > 0.0) return v;
    }
  }
  if (spec.load_model.duration_s > 0.0) return spec.load_model.duration_s;
  if (const auto* d = raw.find("duration_s"); d && d->is_number() && d->as_double(0.0) > 0.0) {
    return d->as_double(0.0);
  }
  return 0.0;
}

// Derlenmiş L7 profilini yürütür ve run_profile_json çıktısını döner.
//
// transport dpdk/dpdk_direct ise: worker NIC'i DpdkShim ile sahiplenir ve profili
// StatefulFastpathDriver'ın ikinci thread'inde koşar (dpdk_worker L7 dalıyla aynı
// yol); driver TEK wire sahibi olarak RX/poll/TX pump eder. Aksi halde (kernel_socket
// / custom_tcp) profil doğrudan çağıran thread'te koşar.
//
// DPDK istenmiş ama bu worker DPDK'sız derlenmiş / EAL veya port açılamıyorsa:
// transport kernel_socket'e yeniden yazılır ve senaryo gerçek HTTP olarak commodity
// kernel soketiyle koşar. transport_used bu düşüşü açıkça raporlar (sessiz değil).
samurai::core::json::Value ExecuteScenarioProfile(
    samurai::core::json::Value profile,
    const samurai::core::json::Value& cfg,
    const std::string& transport,
    std::string& transport_used,
    double soak_duration_s = 0.0) {
  using samurai::core::json::Value;
  transport_used = transport;
  const bool wants_dpdk = (transport == "dpdk" || transport == "dpdk_direct");

#ifdef SAMURAI_WITH_DPDK
  if (wants_dpdk) {
    const std::uint16_t port_id = static_cast<std::uint16_t>(std::max(0,
        std::getenv("SAMURAI_DPDK_PORT_ID") ? std::atoi(std::getenv("SAMURAI_DPDK_PORT_ID")) : 0));
    const std::uint16_t queue_id = static_cast<std::uint16_t>(std::max(0,
        std::getenv("SAMURAI_DPDK_QUEUE_ID") ? std::atoi(std::getenv("SAMURAI_DPDK_QUEUE_ID")) : 0));
    std::string eal_args;
    if (const char* p = std::getenv("SAMURAI_DPDK_EAL_ARGS")) eal_args = p;

    std::string err;
    if (samurai::dpdk::ensure_eal(eal_args, err)) {
      samurai::daemon::DpdkShim shim(port_id, queue_id, eal_args);
      if (shim.ok()) {
        samurai::daemon::FastpathParams params;
        params.backend = "dpdk";
        const std::uint64_t default_dur_ms = (soak_duration_s > 0.0)
            ? std::max<std::uint64_t>(15000ull, static_cast<std::uint64_t>(soak_duration_s * 1000.0) + 5000ull)
            : 15000ull;
        params.max_duration_ms = std::getenv("SAMURAI_FASTPATH_MAX_DURATION_MS")
            ? static_cast<std::uint64_t>(std::strtoull(std::getenv("SAMURAI_FASTPATH_MAX_DURATION_MS"), nullptr, 10))
            : default_dur_ms;
        params.drain_ms = std::getenv("SAMURAI_FASTPATH_DRAIN_MS")
            ? static_cast<std::uint64_t>(std::strtoull(std::getenv("SAMURAI_FASTPATH_DRAIN_MS"), nullptr, 10))
            : 500ull;

        samurai::daemon::StatefulFastpathDriver driver(shim);
        samurai::daemon::FastpathHooks hooks;  // worker nihai telemetriyi kendi yayınlar
        std::atomic<bool> stop{false};
        Value result = Value::Object();
        // dpdk_direct: L7 modunda driver.Configure/SeedL4 yok; tcpdp'yi run_profile_json
        // (engine configure_custom_tcp_bridge) yapılandırır, driver yalnız wire'ı sürer.
        RewriteProfileTransport(profile, "dpdk_direct");
        auto profile_ptr = std::make_shared<Value>(std::move(profile));
        auto runner = [profile_ptr, &cfg, &result](const std::atomic<bool>&) {
          result = l7emu::run_profile_json(*profile_ptr, cfg);
        };
        (void)driver.Run(params, runner, stop, hooks);
        transport_used = "dpdk_direct";
        return result;
      }
    }
    // DPDK istendi ama açılamadı: kernel_socket'e düş (gerçek HTTP korunur).
    transport_used = "kernel_socket(dpdk_open_failed)";
    RewriteProfileTransport(profile, "kernel_socket");
    return l7emu::run_profile_json(profile, cfg);
  }
#else
  if (wants_dpdk) {
    // Bu worker DPDK'sız derlendi: dpdk_direct'i wire-owner olmadan koşmak asılır;
    // kernel_socket'e yeniden yazıp senaryoyu gerçek HTTP olarak koştur.
    transport_used = "kernel_socket(dpdk_not_built)";
    RewriteProfileTransport(profile, "kernel_socket");
    return l7emu::run_profile_json(profile, cfg);
  }
#endif

  return l7emu::run_profile_json(profile, cfg);
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
      op.set("scenario_flow", Value::Str(flow.name));
      op.set("scenario_vu_id", Value::Str("vu-" + std::to_string(s)));
      op.set("scenario_on_failure", Value::Str(st.on_failure));

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
      if (st.expect_status_min > 0 || st.expect_status_max > 0) {
        Value exp_st = Value::Object();
        exp_st.set("opcode", Value::Str("EXPECT_STATUS"));
        Value exp_obj = Value::Object();
        const int smin = st.expect_status_min > 0 ? st.expect_status_min : st.expect_status_max;
        const int smax = st.expect_status_max > 0 ? st.expect_status_max : smin;
        exp_obj.set("status_min", Value::Int(smin));
        exp_obj.set("status_max", Value::Int(smax));
        exp_st.set("expect", std::move(exp_obj));
        ops.push_back(std::move(exp_st));
      }
      if (!st.expect_body_contains.empty()) {
        Value exp_b = Value::Object();
        exp_b.set("opcode", Value::Str("EXPECT_BODY_SUBSTRING"));
        Value exp_obj = Value::Object();
        exp_obj.set("value", Value::Str(st.expect_body_contains));
        exp_b.set("expect", std::move(exp_obj));
        ops.push_back(std::move(exp_b));
      }
      if (!st.expect_header_name.empty()) {
        Value exp_h = Value::Object();
        exp_h.set("opcode", Value::Str("EXPECT_HEADER"));
        Value exp_obj = Value::Object();
        exp_obj.set("name", Value::Str(st.expect_header_name));
        exp_obj.set("value", Value::Str(st.expect_header_value));
        exp_h.set("expect", std::move(exp_obj));
        ops.push_back(std::move(exp_h));
      }
      if (!st.token_variable_name.empty()) {
        // Bind the login token from wherever the API returns it: Set-Cookie
        // (default), a response header, a JSON body field, or a regex capture.
        Value cap = Value::Object();
        const std::string src = LowerStr(st.token_source.empty() ? std::string("cookie") : st.token_source);
        if (!st.extract_token_regex.empty() &&
            (src == "regex" || src == "body_regex" || st.token_path.empty())) {
          cap.set("opcode", Value::Str("CAPTURE_BODY_REGEX"));
          cap.set("capture_name", Value::Str(st.token_variable_name));
          cap.set("capture_source", Value::Str(st.extract_token_regex));
        } else if (src == "body_json") {
          cap.set("opcode", Value::Str("CAPTURE_BODY_JSON"));
          cap.set("capture_name", Value::Str(st.token_variable_name));
          cap.set("capture_source",
                  Value::Str(st.token_path.empty() ? st.token_variable_name : st.token_path));
        } else if (src == "header") {
          cap.set("opcode", Value::Str("CAPTURE_HEADER"));
          cap.set("capture_name", Value::Str(st.token_variable_name));
          cap.set("capture_source",
                  Value::Str(st.token_path.empty() ? st.token_variable_name : st.token_path));
        } else {
          cap.set("opcode", Value::Str("CAPTURE_COOKIE"));
          cap.set("capture_name", Value::Str(st.token_variable_name));
        }
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

  const double duration_s = ResolveScenarioDurationS(spec, raw);
  const auto wall_t0 = std::chrono::steady_clock::now();
  const auto deadline = (duration_s > 0.0)
      ? wall_t0 + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                      std::chrono::duration<double>(duration_s))
      : wall_t0;

  std::string transport_used;
  std::vector<double> lats;
  double last_single_rps = 0.0;

  do {
    Value profile_round = profile;
    const Value res = ExecuteScenarioProfile(std::move(profile_round), cfg, transport, transport_used, duration_s);
    auto num = [&](const char* k) -> double {
      const Value* v = res.find(k);
      return (v != nullptr && v->is_number()) ? v->as_double() : 0.0;
    };
    const std::uint64_t r_sent = static_cast<std::uint64_t>(std::max(0.0, num("sent")));
    const std::uint64_t r_err = static_cast<std::uint64_t>(std::max(0.0, num("errors")));
    const std::uint64_t r_exp_fail = static_cast<std::uint64_t>(std::max(0.0, num("l7_expectation_failures")));
    const int r_att_raw = static_cast<int>(num("attempted"));
    const int r_attempted = (r_att_raw > 0) ? r_att_raw : total_requests;

    R.sent += r_sent;
    R.errors += r_err;
    R.bytes += static_cast<std::uint64_t>(std::max(0.0, num("l7_tx_bytes")));
    last_single_rps = num("l7_rps");
    R.attempted += r_attempted;
    R.completed += static_cast<int>(num("l7_flow_completed"));
    R.status_2xx += static_cast<std::uint64_t>(std::max(0.0, num("status_2xx")));
    R.status_3xx += static_cast<std::uint64_t>(std::max(0.0, num("status_3xx")));
    R.status_4xx += static_cast<std::uint64_t>(std::max(0.0, num("status_4xx")));
    R.status_5xx += static_cast<std::uint64_t>(std::max(0.0, num("status_5xx")));
    R.expectation_failures += r_exp_fail;
    R.tcp_connect_attempts += static_cast<int>(std::max(0.0, num("l7_conn_attempted")));
    R.tcp_connect_established += static_cast<int>(std::max(0.0, num("l7_conn_established")));

    // Adım-bazlı gerçek sonuçlardan completion/fail/p95 ve HTTP status dağılımı
    std::set<std::string> failed_vus;
    int ok_rows = 0, failed = 0;
    if (const Value* rows = res.find("scenario_step_results"); rows != nullptr && rows->is_array()) {
      for (const auto& r : rows->elements()) {
        const Value* succ = r.find("success");
        const Value* lat = r.find("latency_ms");
        const Value* st_code = r.find("status_code");
        const Value* vu = r.find("vu_id");
        const bool row_ok = (succ != nullptr && succ->as_bool(false));
        if (row_ok) {
          ++ok_rows;
        } else {
          ++failed;
          if (vu && vu->is_string() && !vu->as_string().empty()) {
            failed_vus.insert(vu->as_string());
          }
        }
        if (st_code != nullptr && st_code->is_number()) {
          const int sc = static_cast<int>(st_code->as_int(0));
          if (sc > 0) R.status_codes[sc] += 1;
        }
        if (lat != nullptr && lat->is_number() && lats.size() < 100000) {
          lats.push_back(lat->as_double());
        }
        if (R.step_results.size() < 64) {
          R.step_results.push_back(r);
        }
      }
    }
    R.step_succeeded += ok_rows;
    const int r_failed = (failed > 0) ? failed : static_cast<int>(r_err + r_exp_fail);
    R.failed += r_failed;
    R.sessions += vus;
    const int r_completed_sessions = !failed_vus.empty()
                                         ? std::max(0, vus - static_cast<int>(failed_vus.size()))
                                         : (r_failed == 0 ? vus : std::max(0, vus - r_failed));
    R.completed_sessions += r_completed_sessions;
    R.soak_rounds += 1;
  } while (duration_s > 0.0 && std::chrono::steady_clock::now() < deadline);

  R.elapsed_s = std::max(1e-6, std::chrono::duration<double>(
      std::chrono::steady_clock::now() - wall_t0).count());
  R.rps = (R.soak_rounds == 1 && duration_s <= 0.0 && last_single_rps > 0.0)
              ? last_single_rps
              : (static_cast<double>(R.sent) / R.elapsed_s);

  if (!lats.empty()) {
    std::sort(lats.begin(), lats.end());
    std::size_t idx = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(lats.size()))) - 1;
    if (idx >= lats.size()) idx = lats.size() - 1;
    R.latency_p95_ms = lats[idx];
    R.has_latency = true;
  }

  const Value* sla = raw.find("sla");
  const Value ev = scn::evaluate_sla_native(
      sla != nullptr ? *sla : Value::Object(),
      R.sessions, R.completed_sessions, R.attempted, R.failed,
      R.latency_p95_ms, R.has_latency,
      R.tcp_connect_attempts > 0 ? R.tcp_connect_attempts : R.sessions,
      R.tcp_connect_established > 0 ? R.tcp_connect_established : R.completed_sessions,
      0, R.failed);
  const Value* passed = ev.find("passed");
  R.sla_passed = (passed != nullptr && passed->as_bool(false)) ? 1 : 0;
  R.backend_detail = emu_protocol + "/" + transport_used + "+l7emu";
  R.dataplane_detail = "l7_emu_native_real_http";
  R.note_detail = "scenario_payload_ref+compile_soa+l7emu_exec+sla_native_real";
  R.ok = true;
  return R;
}

bool HasL4TcpSteps(const scn::ScenarioSpecNative& spec) {
  for (const auto& f : spec.flows) {
    for (const auto& st : f.steps) {
      if (st.type == scn::StepType::TcpConnect ||
          st.type == scn::StepType::TcpSend ||
          st.type == scn::StepType::TcpExpect ||
          st.type == scn::StepType::TcpClose) {
        return true;
      }
    }
  }
  return false;
}

bool HasHttpRequestSteps(const scn::ScenarioSpecNative& spec) {
  for (const auto& f : spec.flows) {
    for (const auto& st : f.steps) {
      if (st.type == scn::StepType::Request) return true;
    }
  }
  return false;
}

int TcpConnectWithTimeout(const std::string& ip, int port, int timeout_ms, std::string& err_out) {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    err_out = std::strerror(errno);
    return -1;
  }
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    err_out = std::strerror(errno);
    ::close(fd);
    return -1;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    err_out = "invalid_ipv4";
    ::close(fd);
    return -1;
  }
  const int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
  if (rc != 0) {
    if (errno != EINPROGRESS) {
      err_out = std::strerror(errno);
      ::close(fd);
      return -1;
    }
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const int pr = ::poll(&pfd, 1, std::max(50, timeout_ms));
    if (pr <= 0) {
      err_out = pr == 0 ? "connect_timeout" : std::strerror(errno);
      ::close(fd);
      return -1;
    }
    int so_err = 0;
    socklen_t slen = sizeof(so_err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) {
      err_out = so_err != 0 ? std::strerror(so_err) : std::strerror(errno);
      ::close(fd);
      return -1;
    }
  }
  ::fcntl(fd, F_SETFL, flags);
  return fd;
}

ScenarioL7Result RunScenarioL4Tcp(
    const scn::ScenarioSpecNative& spec,
    const samurai::core::json::Value& raw,
    const std::string& target_ip,
    int target_port) {
  using samurai::core::json::Value;
  ScenarioL7Result R;
  if (spec.flows.empty() || !HasL4TcpSteps(spec)) return R;

  const int vus = spec.load_model.concurrent_vus > 0
                      ? std::min(spec.load_model.concurrent_vus, 64)
                      : 1;
  const double duration_s = ResolveScenarioDurationS(spec, raw);
  const auto wall_t0 = std::chrono::steady_clock::now();
  const auto deadline = (duration_s > 0.0)
      ? wall_t0 + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                      std::chrono::duration<double>(duration_s))
      : wall_t0;
  std::vector<double> lats;
  int completed_sessions = 0;

  do {
    for (int s = 0; s < vus; ++s) {
    const scn::Flow& flow = spec.flows[static_cast<std::size_t>(s) % spec.flows.size()];
    const scn::Persona* persona = nullptr;
    if (auto it = spec.personas.find(flow.persona); it != spec.personas.end()) persona = &it->second;
    const int default_timeout_ms = (persona && persona->request_timeout_ms > 0) ? persona->request_timeout_ms : 3000;
    const std::string vu_id = "vu-" + std::to_string(s);

    int fd = -1;
    bool session_ok = true;
    for (const scn::Step& st : flow.steps) {
      if (st.type == scn::StepType::EndSession) break;
      if (st.type == scn::StepType::Pause) {
        const int tt = (st.think_time.max_ms > 0)
                           ? (st.think_time.min_ms + st.think_time.max_ms) / 2
                           : st.think_time.mean_ms;
        if (tt > 0) std::this_thread::sleep_for(std::chrono::milliseconds(std::min(tt, 2000)));
        continue;
      }
      if (st.type != scn::StepType::TcpConnect &&
          st.type != scn::StepType::TcpSend &&
          st.type != scn::StepType::TcpExpect &&
          st.type != scn::StepType::TcpClose) {
        continue;
      }

      R.attempted += 1;
      const auto step_t0 = std::chrono::steady_clock::now();
      bool step_ok = false;
      bool step_timeout = false;
      std::string step_error;
      const int to_ms = st.timeout_ms > 0 ? st.timeout_ms : default_timeout_ms;

      if (st.type == scn::StepType::TcpConnect) {
        if (fd >= 0) {
          ::close(fd);
          fd = -1;
        }
        R.tcp_connect_attempts += 1;
        const int port = st.dst_port > 0 ? static_cast<int>(st.dst_port) : target_port;
        std::string err;
        fd = TcpConnectWithTimeout(target_ip, port, to_ms, err);
        if (fd >= 0) {
          R.tcp_connect_established += 1;
          R.sent += 1;
          step_ok = true;
        } else {
          R.errors += 1;
          R.failed += 1;
          if (err == "connect_timeout") {
            R.tcp_timeout_close_count += 1;
            step_timeout = true;
          }
          session_ok = false;
        }
      } else if (st.type == scn::StepType::TcpSend) {
        const std::string& payload = !st.payload_template.empty() ? st.payload_template : st.body_template;
        if (fd < 0) {
          R.errors += 1;
          R.failed += 1;
          session_ok = false;
        } else {
          std::size_t off = 0;
          bool send_ok = true;
          while (off < payload.size()) {
            const ssize_t n = ::send(fd, payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
              send_ok = false;
              break;
            }
            off += static_cast<std::size_t>(n);
          }
          if (send_ok) {
            R.sent += 1;
            R.bytes += static_cast<std::uint64_t>(off);
            step_ok = true;
          } else {
            R.errors += 1;
            R.failed += 1;
            session_ok = false;
          }
        }
      } else if (st.type == scn::StepType::TcpExpect) {
        if (fd < 0) {
          R.errors += 1;
          R.failed += 1;
          session_ok = false;
        } else {
          pollfd pfd{};
          pfd.fd = fd;
          pfd.events = POLLIN;
          const int pr = ::poll(&pfd, 1, std::max(50, to_ms));
          if (pr <= 0) {
            R.errors += 1;
            R.failed += 1;
            if (pr == 0) {
              R.tcp_timeout_close_count += 1;
              step_timeout = true;
            }
            session_ok = false;
          } else {
            char buf[4096];
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) {
              R.errors += 1;
              R.failed += 1;
              session_ok = false;
            } else {
              const std::string rx(buf, static_cast<std::size_t>(n));
              if (st.condition.empty() || rx.find(st.condition) != std::string::npos) {
                R.sent += 1;
                step_ok = true;
              } else {
                R.errors += 1;
                R.failed += 1;
                R.expectation_failures += 1;
                std::string rx_clean;
                for (unsigned char c : rx) {
                  if (rx_clean.size() >= 80) break;
                  if (c >= 0x20 && c <= 0x7E) rx_clean.push_back(static_cast<char>(c));
                }
                step_error = "expected '" + st.condition + "', got '" + rx_clean + "'";
                session_ok = false;
              }
            }
          }
        }
      } else if (st.type == scn::StepType::TcpClose) {
        if (fd >= 0) {
          ::close(fd);
          fd = -1;
        }
        R.sent += 1;
        step_ok = true;
      }

      const double lat_ms = std::chrono::duration<double, std::milli>(
          std::chrono::steady_clock::now() - step_t0).count();
      if (lats.size() < 100000) lats.push_back(lat_ms);
      if (step_ok) R.step_succeeded += 1;
      if (R.step_results.size() < 64) {
        Value row = Value::Object();
        row.set("flow", Value::Str(flow.name));
        row.set("vu_id", Value::Str(vu_id));
        row.set("success", Value::Bool(step_ok));
        row.set("timeout", Value::Bool(step_timeout));
        row.set("status_code", Value::Int(0));
        row.set("latency_ms", Value::Double(lat_ms));
        row.set("protocol", Value::Str("tcp"));
        if (!step_error.empty()) row.set("error", Value::Str(step_error));
        R.step_results.push_back(std::move(row));
      }
      if (!session_ok && fd < 0) break;
    }
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
    if (session_ok) ++completed_sessions;
    }
    R.sessions += vus;
    R.soak_rounds += 1;
  } while (duration_s > 0.0 && std::chrono::steady_clock::now() < deadline);

  R.elapsed_s = std::max(1e-6, std::chrono::duration<double>(
      std::chrono::steady_clock::now() - wall_t0).count());
  R.rps = static_cast<double>(R.sent) / R.elapsed_s;
  if (!lats.empty()) {
    std::sort(lats.begin(), lats.end());
    std::size_t idx = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(lats.size()))) - 1;
    if (idx >= lats.size()) idx = lats.size() - 1;
    R.latency_p95_ms = lats[idx];
    R.has_latency = true;
  }
  R.completed = completed_sessions;
  R.completed_sessions = completed_sessions;

  const Value* sla = raw.find("sla");
  const Value ev = scn::evaluate_sla_native(
      sla != nullptr ? *sla : Value::Object(),
      R.sessions, completed_sessions, R.attempted, R.failed,
      R.latency_p95_ms, R.has_latency,
      R.tcp_connect_attempts, R.tcp_connect_established,
      0, R.tcp_timeout_close_count);
  const Value* passed = ev.find("passed");
  R.sla_passed = (passed != nullptr && passed->as_bool(false)) ? 1 : 0;
  R.backend_detail = "tcp/kernel_socket+l4_scenario";
  R.dataplane_detail = "l4_tcp_native_real_socket";
  R.note_detail = "scenario_payload_ref+compile_soa+l4_tcp_exec+sla_native_real";
  R.ok = (R.attempted > 0);
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

  samurai::daemon::TelemetrySink telemetry;
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
    samurai::wire::DecodedWireFrame frame{};
    if (!samurai::wire::DecodeWireFrame(zmq_msg_data(&msg), sz, frame)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto msg_type = static_cast<samurai::wire::MessageType>(frame.msg_type);
    const std::string& job_id = frame.job_id;
    const auto header = frame.as_v1_header;

    if (samurai::daemon::HandleCommonIdleMessage(
            push, samurai::wire::WorkerKind::SCENARIO, frame, telemetry, running)) {
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      telemetry.BeginJob();
      samurai::wire::JobEnvelopeV1 env{};
      if (!samurai::daemon::DecodeJobEnvelopeV1Frame(frame, env, &telemetry)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            frame.correlation_id,
            samurai::wire::WorkerKind::SCENARIO,
            job_id,
            JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }
      (void)SendAck(push, frame.correlation_id, job_id);
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
        ScenarioL7Result l7_result;
        // Gerçek yürütme (RunScenarioL7) parse bloğu içinde olduğundan, süre
        // penceresini burada başlat ki actual_rps HTTP yürütmesini yansıtsın.
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        const samurai::core::json::ParseResult parsed = samurai::core::json::Parse(scenario_text);
        if (parsed.ok) {
          try {
            const samurai::scenario_native::ScenarioSpecNative spec =
                samurai::scenario_native::parse_spec(parsed.value);
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
                  samurai::scenario_native::compile_session_plans_packed_bulk_soa_native(
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
                const samurai::core::json::Value ev = samurai::scenario_native::evaluate_sla_native(
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

              // GERÇEK yürütme: L4 TCP veya L7 HTTP olarak koştur.
              const std::string tgt_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
              const int tgt_port = static_cast<int>(env.target_port);
              ScenarioL7Result l7;
              if (HasL4TcpSteps(spec) && !HasHttpRequestSteps(spec)) {
                l7 = RunScenarioL4Tcp(spec, parsed.value, tgt_ip, tgt_port);
              } else {
                l7 = RunScenarioL7(spec, parsed.value, tgt_ip, tgt_port);
              }
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
                l7_result = std::move(l7);
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
        telemetry.BeginJob();

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
          const auto pool = samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
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
            telemetry.FlushEnd(samurai_pacing_monotonic_now_ns());
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::SCENARIO,
                job_id,
                JsonError("afpacket_tx_disabled_dry_run_removed"));
            continue;
          }
        }
        (void)l7_rps;

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const std::uint32_t avg_bytes = packets_sent > 0
            ? static_cast<std::uint32_t>(std::max<std::uint64_t>(64u, bytes_sent / packets_sent))
            : env.packet_size;
        samurai::daemon::RecordBatchToTelemetry(
            telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
            scenario_l7_executed
                ? (l7_result.backend_detail.rfind("tcp/", 0) == 0 ? std::string("tcp") : std::string("http"))
                : ReadFixed(env.protocol, sizeof(env.protocol)),
            packets_sent, avg_bytes, end_ns);
        telemetry.FlushEnd(end_ns);
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
            scenario_l7_executed,
            l7_result.ok ? &l7_result : nullptr,
            telemetry.JobExportedPackets(),
            telemetry.JobExportedRecords());
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
