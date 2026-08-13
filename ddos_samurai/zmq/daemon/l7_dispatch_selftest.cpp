// Self-test for JobEnvelopeV2 ABI + L7 dispatch field mapping (Faz 0).
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "job_builder.hpp"
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
