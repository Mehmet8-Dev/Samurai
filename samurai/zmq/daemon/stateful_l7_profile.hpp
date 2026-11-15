#pragma once
//
// stateful_l7_profile — fast-path worker'ları (dpdk/afxdp) için L7 runner kurucusu.
//
// Job envelope'undan (V2) l7_emu_native Profile+cfg JSON'u kurar ve
// StatefulFastpathDriver::Run'a verilecek bir l7_runner lambda'sı döner. Runner,
// run_profile_json'u transport_backend="dpdk_direct" ile çağırır; böylece L7 HTTP
// akışı harici fast-path sürücüsünün sahip olduğu wire üzerinden (kernel-socket'siz)
// koşar. Sürücü tek wire sahibi olduğundan Profile custom_tcp/H2 iç TX drain'ini
// yapmaz (engine.cpp DpdkDirect gate'leri).
//
// Bu başlık bridge.hpp/json.hpp gerektirir; yalnız samurai_l7emu linkli worker'larda
// include edilmelidir (dpdk/afxdp/scenario). Sürücü çekirdeği (stateful_fastpath.*)
// bunu include ETMEZ — l7emu'dan bağımsız kalır.
//
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "bridge.hpp"
#include "json.hpp"
#include "wire_protocol.h"

namespace samurai::daemon {

// Envelope L7 profili mi istiyor? (aksi halde pure-L4 stateful).
inline bool JobWantsL7Fastpath(const samurai::wire::JobEnvelopeV1& base) {
  auto lower = [](std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
  };
  const std::string proto = lower(std::string(base.protocol, strnlen(base.protocol, sizeof(base.protocol))));
  const std::string av = std::string(base.attack_vector, strnlen(base.attack_vector, sizeof(base.attack_vector)));
  const std::string scen(base.scenario_payload_ref, strnlen(base.scenario_payload_ref, sizeof(base.scenario_payload_ref)));
  if (!scen.empty()) return true;
  if (av == "l7_custom_tcp") return true;
  return proto == "http1" || proto == "http2" || proto == "https" || proto == "quic";
}

// Runner + sonuç kabı. Worker, driver.Run döndükten sonra *result'ı JOB_DONE'a koyar.
struct L7RunnerBundle {
  std::function<void(const std::atomic<bool>&)> runner;
  std::shared_ptr<samurai::core::json::Value> result;  // run_profile_json çıktısı
};

namespace detail {

inline bool ReadWholeFile(const std::string& path, std::vector<std::uint8_t>& out) {
  out.clear();
  if (path.empty()) return false;
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return false;
  std::uint8_t buf[8192];
  std::size_t n = 0;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
  std::fclose(f);
  return true;
}

}  // namespace detail

// V2 envelope + transport_backend'ten L7 runner kurar. transport_backend fast-path
// için "dpdk_direct" olmalı (dpdk ve afxdp harici-wire modunda aynı gate'i kullanır).
inline L7RunnerBundle MakeL7Runner(
    const samurai::wire::JobEnvelopeV2& env,
    const std::string& transport_backend) {
  using samurai::core::json::Value;
  using samurai::core::json::Parse;
  using samurai::core::json::ParseResult;

  const samurai::wire::JobEnvelopeV1& base = env.base;
  const std::string target(base.target_ip, strnlen(base.target_ip, sizeof(base.target_ip)));
  const int port = static_cast<int>(base.target_port);
  auto lower = [](std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
  };
  const std::string proto_lc = lower(std::string(base.protocol, strnlen(base.protocol, sizeof(base.protocol))));
  const std::string scheme(env.scheme, strnlen(env.scheme, sizeof(env.scheme)));
  const std::string host_header(env.host_header, strnlen(env.host_header, sizeof(env.host_header)));
  const std::string scenario_ref(base.scenario_payload_ref, strnlen(base.scenario_payload_ref, sizeof(base.scenario_payload_ref)));
  const std::string payload_ref(base.payload_ref, strnlen(base.payload_ref, sizeof(base.payload_ref)));
  const int flows = std::max(1, static_cast<int>(base.packet_count));
  const int concurrency = std::max(1, static_cast<int>(env.concurrency));
  const int max_conns = std::max(1, static_cast<int>(env.max_connections));
  const int max_streams = std::max(1, static_cast<int>(env.max_streams_per_connection));

  // Profil: scenario_ref dosyası varsa taban olarak yükle, üzerine bağlantı knob'ları.
  Value profile = Value::Object();
  std::vector<std::uint8_t> scen;
  if (!scenario_ref.empty() && detail::ReadWholeFile(scenario_ref, scen) && !scen.empty()) {
    const ParseResult pr = Parse(std::string(reinterpret_cast<const char*>(scen.data()), scen.size()));
    if (pr.ok && pr.value.is_object()) profile = pr.value;
  }

  Value conn = Value::Object();
  if (const Value* ex = profile.find("connection_template"); ex != nullptr && ex->is_object()) conn = *ex;
  conn.set("transport_backend", Value::Str(transport_backend));
  if (conn.find("target_ip") == nullptr) conn.set("target_ip", Value::Str(target));
  if (conn.find("target_port") == nullptr) conn.set("target_port", Value::Int(port));
  const bool tls = !scheme.empty() ? (scheme == "https") : (proto_lc == "https" || proto_lc == "quic");
  if (conn.find("scheme") == nullptr) conn.set("scheme", Value::Str(tls ? "https" : "http"));
  if (conn.find("host_header") == nullptr)
    conn.set("host_header", Value::Str(host_header.empty() ? target : host_header));
  if (conn.find("verify") == nullptr) conn.set("verify", Value::Int(env.verify_tls ? 1 : 0));
  if (conn.find("keepalive") == nullptr) conn.set("keepalive", Value::Int(env.keepalive ? 1 : 0));
  if (conn.find("timeout_ms") == nullptr)
    conn.set("timeout_ms", Value::Int(static_cast<std::int64_t>(env.l7_timeout_ms > 0 ? env.l7_timeout_ms : 10000u)));
  if (conn.find("max_connections") == nullptr) conn.set("max_connections", Value::Int(max_conns));
  if (conn.find("max_streams_per_connection") == nullptr)
    conn.set("max_streams_per_connection", Value::Int(max_streams));
  if (conn.find("session_repeats") == nullptr) conn.set("session_repeats", Value::Int(flows));
  profile.set("connection_template", conn);

  if (profile.find("flow_attempted") == nullptr) profile.set("flow_attempted", Value::Int(flows));
  if (profile.find("protocol") == nullptr) {
    const char* emu = "http1";
    if (proto_lc == "http2") emu = "http2";
    else if (proto_lc == "quic") emu = "quic";
    profile.set("protocol", Value::Str(emu));
  }
  // Varsayılan istek gövdesi (profilde flow_program yoksa): basit GET /.
  if (profile.find("flow_program") == nullptr) {
    const std::string req = "GET / HTTP/1.1\r\nHost: " +
        (host_header.empty() ? target : host_header) + "\r\nConnection: close\r\n\r\n";
    Value op = Value::Object();
    op.set("opcode", Value::Str("SEND_HEADERS"));
    op.set("method", Value::Str("GET"));
    op.set("path", Value::Str("/"));
    Value body = Value::Object();
    body.set("kind", Value::Str("raw"));
    Value body_bytes = Value::Array();
    for (const char c : req) body_bytes.push_back(Value::Int(static_cast<std::int64_t>(static_cast<std::uint8_t>(c))));
    body.set("bytes", body_bytes);
    op.set("body", body);
    Value ops = Value::Array();
    for (int r = 0; r < flows; ++r) ops.push_back(op);
    Value fp = Value::Object();
    fp.set("ops", ops);
    profile.set("flow_program", fp);
  }
  (void)payload_ref;  // İleride payload_ref dosyası body olarak kullanılabilir.

  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(concurrency));
  cfg.set("profile_l7", Value::Int(1));
  cfg.set("profile_sample_limit", Value::Int(0));

  L7RunnerBundle bundle;
  bundle.result = std::make_shared<Value>(Value::Object());
  auto profile_ptr = std::make_shared<Value>(std::move(profile));
  auto cfg_ptr = std::make_shared<Value>(std::move(cfg));
  auto result = bundle.result;
  bundle.runner = [profile_ptr, cfg_ptr, result](const std::atomic<bool>& /*stop*/) {
    // run_profile_json monolitik/bloke edicidir; profildeki timeout'lar sonlandırır.
    *result = samurai::l7_emu_native::run_profile_json(*profile_ptr, *cfg_ptr);
  };
  return bundle;
}

}  // namespace samurai::daemon
