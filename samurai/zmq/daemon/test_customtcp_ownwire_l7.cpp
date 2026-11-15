// Shared-nothing custom_tcp own-wire e2e verification (real AF_PACKET over veth).
//
// Unlike test_stateful_fastpath_l7 (which drives an in-process loopback shim),
// this exercises the ENGINE's own per-shard af_packet wire path added for
// per-core scaling: with transport_backend=custom_tcp, concurrency>1 and
// SAMURAI_CUSTOM_TCP_RX_IFACE set, each shard opens its own AF_PACKET socket
// (BPF-filtered to its src-port range), owns its own tcpdp core, and drives the
// wire inline -- no shared wire thread / registry / inbox.
//
// It must run inside a network namespace with a veth pair wired to a live HTTP
// server; the accompanying harness (run_customtcp_ownwire_veth.sh) sets that up
// and exports SAMURAI_CUSTOM_TCP_RX_IFACE / SAMURAI_CUSTOM_TCP_SRC_IP /
// OWNWIRE_TARGET_IP / OWNWIRE_TARGET_PORT. Without those env vars it skips (exit
// 0) so a plain build/test run does not fail on machines without the harness.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "bridge.hpp"
#include "json.hpp"

namespace {

int env_int(const char* name, int fallback) {
  const char* v = std::getenv(name);
  if (v == nullptr || v[0] == '\0') return fallback;
  return std::atoi(v);
}

}  // namespace

int main() {
  using samurai::core::json::Value;

  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
  const char* target_ip = std::getenv("OWNWIRE_TARGET_IP");
  if (iface == nullptr || iface[0] == '\0' || target_ip == nullptr || target_ip[0] == '\0') {
    std::printf("SKIP: own-wire veth harness env not set "
                "(need SAMURAI_CUSTOM_TCP_RX_IFACE + OWNWIRE_TARGET_IP)\n");
    return 0;
  }
  const int target_port = env_int("OWNWIRE_TARGET_PORT", 8080);
  const int flows = env_int("OWNWIRE_FLOWS", 4);
  const char* proto_env = std::getenv("OWNWIRE_PROTO");
  const std::string proto = (proto_env != nullptr && proto_env[0] != '\0') ? proto_env : "http1";
  const bool is_h2 = (proto == "http2" || proto == "h2");

  Value profile = Value::Object();
  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str("custom_tcp"));
  conn.set("target_ip", Value::Str(target_ip));
  conn.set("target_port", Value::Int(target_port));
  conn.set("scheme", Value::Str("http"));
  conn.set("host_header", Value::Str(target_ip));
  conn.set("keepalive", Value::Int(0));
  conn.set("max_connections", Value::Int(flows));
  conn.set("max_streams_per_connection", Value::Int(1));
  conn.set("session_repeats", Value::Int(flows));
  conn.set("timeout_ms", Value::Int(5000));
  profile.set("connection_template", conn);
  profile.set("flow_attempted", Value::Int(flows));
  profile.set("protocol", Value::Str(is_h2 ? "http2" : "http1"));
  if (is_h2) {
    // H2: SEND_HEADERS (GET /) only; the nghttp2 reactor builds the frames. No body
    // => HEADERS carries END_STREAM. One connection per flow (max_streams=1).
    Value op = Value::Object();
    op.set("opcode", Value::Str("SEND_HEADERS"));
    op.set("method", Value::Str("GET"));
    op.set("path", Value::Str("/"));
    Value ops = Value::Array();
    for (int i = 0; i < flows; ++i) ops.push_back(op);
    Value fp = Value::Object();
    fp.set("ops", ops);
    profile.set("flow_program", fp);
  } else {
    const std::string req =
        std::string("GET / HTTP/1.1\r\nHost: ") + target_ip + "\r\nConnection: close\r\n\r\n";
    Value op = Value::Object();
    op.set("opcode", Value::Str("SEND_HEADERS"));
    op.set("method", Value::Str("GET"));
    op.set("path", Value::Str("/"));
    Value body = Value::Object();
    body.set("kind", Value::Str("raw"));
    Value bytes = Value::Array();
    for (char c : req) bytes.push_back(Value::Int(static_cast<std::uint8_t>(c)));
    body.set("bytes", bytes);
    op.set("body", body);
    Value ops = Value::Array();
    for (int i = 0; i < flows; ++i) ops.push_back(op);
    Value fp = Value::Object();
    fp.set("ops", ops);
    profile.set("flow_program", fp);
  }

  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(flows));  // >1 => threaded shared-nothing path
  cfg.set("profile_l7", Value::Int(1));

  const Value result = samurai::l7_emu_native::run_profile_json(profile, cfg);

  auto num = [&](const char* k) -> double {
    const Value* v = result.find(k);
    return (v != nullptr && v->is_number()) ? v->as_double() : 0.0;
  };

  const int shards = static_cast<int>(num("runtime_shards"));
  const int sent = static_cast<int>(num("sent"));
  const int s2xx = static_cast<int>(num("status_2xx"));
  const int errors = static_cast<int>(num("errors"));
  const int tcp_est = static_cast<int>(num("tcp_connect_established"));

  std::printf("proto=%s runtime_shards=%d flows=%d sent=%d status_2xx=%d errors=%d tcp_connect_established=%d\n",
              proto.c_str(), shards, flows, sent, s2xx, errors, tcp_est);

  int fails = 0;
  if (shards <= 1) {
    std::fprintf(stderr, "FAIL: expected threaded shared-nothing path (runtime_shards>1), got %d\n", shards);
    ++fails;
  }
  if (tcp_est < flows) {
    std::fprintf(stderr, "FAIL: only %d handshakes completed over the real wire (expected %d)\n",
                 tcp_est, flows);
    ++fails;
  }
  if (s2xx < flows) {
    std::fprintf(stderr, "FAIL: only %d HTTP 2xx responses (expected %d)\n", s2xx, flows);
    ++fails;
  }
  if (sent < flows) {
    std::fprintf(stderr, "FAIL: only %d requests sent (expected %d)\n", sent, flows);
    ++fails;
  }

  if (fails == 0) {
    std::printf("ALL CUSTOM_TCP OWN-WIRE L7 TESTS PASSED\n");
    return 0;
  }
  std::printf("CUSTOM_TCP OWN-WIRE L7 TESTS FAILED (%d)\n", fails);
  std::fprintf(stderr, "full result: %s\n", result.dump().c_str());
  return 1;
}
