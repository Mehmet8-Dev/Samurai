// Self-test for JobEnvelopeV2 ABI + L7 dispatch field mapping (Faz 0).
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "job_builder.hpp"
#include "l7_request_variants.hpp"
#include "wire_protocol.h"

namespace {

bool expect(bool cond, const char* msg) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", msg);
    return false;
  }
  return true;
}

std::string read_fixed(const char* buf, std::size_t cap) {
  return std::string(buf, strnlen(buf, cap));
}

}  // namespace

int main() {
  bool ok = true;

  ok = expect(sizeof(samurai::wire::JobEnvelopeV1) == 480, "JobEnvelopeV1 size") && ok;
  ok = expect(sizeof(samurai::wire::JobEnvelopeV2) > sizeof(samurai::wire::JobEnvelopeV1),
              "JobEnvelopeV2 extends V1") &&
       ok;
  ok = expect(offsetof(samurai::wire::JobEnvelopeV2, base) == 0, "V2.base at offset 0") && ok;
  ok = expect(samurai::wire::IsVersionSupported(samurai::wire::kVersionV1), "V1 supported") && ok;
  ok = expect(samurai::wire::IsVersionSupported(samurai::wire::kVersionV2), "V2 supported") && ok;
  ok = expect(!samurai::wire::IsVersionSupported(99), "unknown version rejected") && ok;

  samurai::orchestrator::JobOptions opt{};
  opt.target_ip = "10.0.0.9";
  opt.target_port = 8443;
  opt.protocol = "http1";
  opt.attack_vector = "http_get";
  opt.packet_count = 42;
  opt.concurrency = 64;
  opt.max_connections = 4096;
  opt.max_streams_per_connection = 8;
  opt.verify_tls = 1;
  opt.keepalive = 1;
  opt.scheme = "https";
  opt.host_header = "example.test";
  opt.l7_timeout_ms = 2500;
  opt.l7_profile_file = "profiles/demo.json";
  opt.l7_payload_file = "payloads/req.bin";
  opt.request_mix = 3;
  opt.source_rotation = 8;
  opt.auth_mode = 1;
  opt.evasion_tactic = 3;
  opt.auth_payload = "{\"username\":\"admin\",\"password\":\"samurai\"}";

  const samurai::wire::JobEnvelopeV2 env = samurai::orchestrator::BuildJobEnvelopeV2(opt);

  ok = expect(read_fixed(env.base.target_ip, sizeof(env.base.target_ip)) == "10.0.0.9", "target_ip") &&
       ok;
  ok = expect(env.base.target_port == 8443, "target_port") && ok;
  ok = expect(read_fixed(env.base.protocol, sizeof(env.base.protocol)) == "http1", "protocol") && ok;
  ok = expect(env.base.packet_count == 42, "packet_count") && ok;
  ok = expect(env.base.has_payload == 1u, "has_payload") && ok;
  ok = expect(read_fixed(env.base.scenario_payload_ref, sizeof(env.base.scenario_payload_ref)) ==
                  "profiles/demo.json",
              "scenario_payload_ref") &&
       ok;
  ok = expect(read_fixed(env.base.payload_ref, sizeof(env.base.payload_ref)) == "payloads/req.bin",
              "payload_ref") &&
       ok;
  ok = expect(env.concurrency == 64u, "concurrency not hardcoded to 1") && ok;
  ok = expect(env.max_connections == 4096u, "max_connections not hardcoded to 1") && ok;
  ok = expect(env.max_streams_per_connection == 8u, "max_streams_per_connection") && ok;
  ok = expect(env.verify_tls == 1u, "verify_tls") && ok;
  ok = expect(env.keepalive == 1u, "keepalive") && ok;
  ok = expect(read_fixed(env.scheme, sizeof(env.scheme)) == "https", "scheme") && ok;
  ok = expect(read_fixed(env.host_header, sizeof(env.host_header)) == "example.test", "host_header") &&
       ok;
  ok = expect(env.l7_timeout_ms == 2500u, "l7_timeout_ms") && ok;
  ok = expect(env.request_mix == 3u, "request_mix carried on the wire") && ok;
  ok = expect(env.source_rotation == 8u, "source_rotation carried on the wire") && ok;
  ok = expect(env.auth_mode == 1u, "auth_mode carried on wire") && ok;
  ok = expect(env.evasion_tactic == 3u, "evasion_tactic carried on wire") && ok;
  ok = expect(read_fixed(env.auth_payload, sizeof(env.auth_payload)) == opt.auth_payload,
              "auth_payload carried on wire") && ok;

  // V2 size is pinned: includes levers + auth_payload
  ok = expect(sizeof(samurai::wire::JobEnvelopeV2) == 786, "V2 size pinned at 786") && ok;

  // Verify kRequestVariantCount == 12 and wrapping
  ok = expect(samurai::l7::kRequestVariantCount == 12, "kRequestVariantCount is 12") && ok;
  ok = expect(std::string(samurai::l7::VariantFor(0).method) == "GET" &&
                  std::string(samurai::l7::VariantFor(0).path) == "/",
              "request_mix 0 == GET /") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(3).method) == "POST" &&
                  std::string(samurai::l7::VariantFor(3).path) == "/login",
              "request_mix 3 == POST /login") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(5).path) == "/static/../../etc/passwd",
              "request_mix 5 == path traversal") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(6).path) == "/public/..%2f..%2fetc/passwd",
              "request_mix 6 == url encoded traversal") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(7).path) == "/..;/..;/",
              "request_mix 7 == matrix parameter traversal") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(8).path) == "/search?q=1&q=samurai",
              "request_mix 8 == HPP") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(9).path) == "/%2e%2e/",
              "request_mix 9 == hex traversal") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(10).path) == "//multiple//slashes",
              "request_mix 10 == slashes normalization") &&
       ok;
  ok = expect(std::string(samurai::l7::VariantFor(11).path) == "/static/%2e%2e/%2e%2e/etc/passwd",
              "request_mix 11 == multi-level fuzzy traversal") &&
       ok;
  ok = expect(samurai::l7::VariantFor(samurai::l7::kRequestVariantCount).path ==
                  samurai::l7::VariantFor(0).path,
              "request_mix wraps out of range") &&
       ok;

  // Basic BuildHttp1Request tests
  {
    const std::string r0 = samurai::l7::BuildHttp1Request(0, "example.test");
    const std::string r1 = samurai::l7::BuildHttp1Request(1, "example.test");
    const std::string rp = samurai::l7::BuildHttp1Request(3, "example.test");
    ok = expect(r0.rfind("GET / HTTP/1.1\r\n", 0) == 0, "variant 0 request line") && ok;
    ok = expect(r0.find("Host: example.test\r\n") != std::string::npos, "variant host header") && ok;
    ok = expect(r0.find("Connection: close\r\n\r\n") != std::string::npos, "default Connection: close") && ok;
    ok = expect(r1 != r0, "variant 1 differs from baseline") && ok;
    ok = expect(rp.find("Content-Length: 0\r\n") != std::string::npos,
                "empty POST variant carries Content-Length: 0") &&
         ok;
  }

  // Dynamic Login, JSON body & SessionContext tests
  {
    samurai::l7::Http1BuildOptions post_opts;
    post_opts.host = "api.target.test";
    post_opts.auth_payload = "{\"username\":\"admin\",\"password\":\"secret123\"}";
    post_opts.keep_alive = true;

    const std::string req_login = samurai::l7::BuildHttp1Request(3, post_opts);
    ok = expect(req_login.find("POST /login HTTP/1.1\r\n") != std::string::npos, "POST /login line") && ok;
    ok = expect(req_login.find("Content-Type: application/json\r\n") != std::string::npos,
                "Content-Type: application/json injected") && ok;
    ok = expect(req_login.find("Content-Length: 43\r\n") != std::string::npos,
                "Dynamic Content-Length injected") && ok;
    ok = expect(req_login.find("Connection: keep-alive\r\n\r\n") != std::string::npos,
                "Connection: keep-alive honored") && ok;
    ok = expect(req_login.rfind("{\"username\":\"admin\",\"password\":\"secret123\"}") ==
                    req_login.size() - 43,
                "auth_payload appended to POST body") && ok;

    // Test SessionContext parsing from simulated server response
    samurai::l7::SessionContext sess;
    const std::string simulated_resp_headers =
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session_id=samurai_sess_xyz987; Path=/; HttpOnly\r\n"
        "Set-Cookie: csrf_token=csrf_val_12345; Path=/\r\n"
        "Content-Type: application/json\r\n";
    const std::string simulated_resp_body =
        "{\"access_token\":\"jwt_mock_token_abc.123.def\",\"token_type\":\"Bearer\"}";

    sess.UpdateFromResponse(simulated_resp_headers, simulated_resp_body);
    ok = expect(sess.has_token, "SessionContext captured access_token") && ok;
    ok = expect(sess.access_token == "jwt_mock_token_abc.123.def", "token value matches") && ok;
    ok = expect(sess.has_cookie, "SessionContext captured cookie") && ok;
    ok = expect(sess.cookie.find("session_id=samurai_sess_xyz987") != std::string::npos,
                "cookie contains session_id") && ok;

    // Next request carrying Bearer JWT (auth_mode = 1)
    samurai::l7::Http1BuildOptions jwt_opts;
    jwt_opts.host = "api.target.test";
    jwt_opts.auth_mode = 1;
    jwt_opts.session = &sess;
    const std::string req_jwt = samurai::l7::BuildHttp1Request(2, jwt_opts);
    ok = expect(req_jwt.find("Authorization: Bearer jwt_mock_token_abc.123.def\r\n") != std::string::npos,
                "Bearer token injected from session context") && ok;

    // Next request carrying Session Cookie (auth_mode = 2)
    samurai::l7::Http1BuildOptions cookie_opts;
    cookie_opts.host = "api.target.test";
    cookie_opts.auth_mode = 2;
    cookie_opts.session = &sess;
    const std::string req_cookie = samurai::l7::BuildHttp1Request(2, cookie_opts);
    ok = expect(req_cookie.find("Cookie: session_id=samurai_sess_xyz987; csrf_token=csrf_val_12345\r\n") !=
                    std::string::npos,
                "Cookie header injected from session context") && ok;

    // Header spoofing evasion (evasion_tactic = 3)
    samurai::l7::Http1BuildOptions spoof_opts;
    spoof_opts.host = "target.test";
    spoof_opts.evasion_tactic = 3;
    const std::string req_spoof = samurai::l7::BuildHttp1Request(0, spoof_opts);
    ok = expect(req_spoof.find("X-Forwarded-For: 127.0.0.1\r\n") != std::string::npos,
                "X-Forwarded-For header spoofing injected") && ok;
    ok = expect(req_spoof.find("X-Real-IP: 127.0.0.1\r\n") != std::string::npos,
                "X-Real-IP header spoofing injected") && ok;
  }

  // Zero concurrency must clamp to 1 (engine-safe default).
  opt.concurrency = 0;
  opt.max_connections = 0;
  const samurai::wire::JobEnvelopeV2 clamped = samurai::orchestrator::BuildJobEnvelopeV2(opt);
  ok = expect(clamped.concurrency == 1u, "concurrency clamp") && ok;
  ok = expect(clamped.max_connections == 1u, "max_connections clamp") && ok;

  // V1 prefix of a V2 blob must be readable as JobEnvelopeV1.
  samurai::wire::JobEnvelopeV1 v1_view{};
  std::memcpy(&v1_view, &env, sizeof(v1_view));
  ok = expect(read_fixed(v1_view.target_ip, sizeof(v1_view.target_ip)) == "10.0.0.9",
              "V1 prefix downgrade") &&
       ok;

  if (!ok) {
    return 1;
  }
  std::printf("l7_dispatch selftest ok\n");
  return 0;
}
