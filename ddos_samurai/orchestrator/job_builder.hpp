#pragma once

// Builds a wire JobEnvelopeV1 from a small, orchestrator-level options struct.
//
// The envelope layout itself lives in wire_protocol.h and is shared verbatim
// with every worker, so a job built here is binary-compatible with the worker
// that consumes it by construction (see the static_asserts in wire_protocol.h).

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "wire_protocol.h"

namespace samurai::orchestrator {

// Orchestrator-facing job description. Extend this as more of the Python CLI
// surface is ported; every field maps onto a JobEnvelopeV1 member.
struct JobOptions {
  std::string target_ip = "127.0.0.1";
  std::uint16_t target_port = 80;
  std::uint32_t packet_count = 1000;
  std::uint32_t packet_size = 64;
  std::uint8_t pacing_mode = 0;
  double target_rps = 0.0;
  std::uint64_t ipg_ns = 0;
  std::uint32_t burst_size = 1;
  std::uint64_t burst_gap_ns = 0;
  std::int32_t pin_cpu = -1;
  std::string protocol = "udp";
  std::string attack_vector = "flood";
  std::uint8_t ttl = 64;
  bool spoof = false;
  std::string spoof_mode;   // e.g. "random" / "realistic"
  std::string dns_name;
  std::string dns_qtype;

  // L7 stateful-runtime options (wire JobEnvelopeV2). Defaults mirror the
  // l7_emu_native engine defaults so a bare job behaves like today.
  std::uint32_t concurrency = 1;
  std::uint32_t max_connections = 1;
  std::uint32_t max_streams_per_connection = 1;
  std::uint8_t verify_tls = 0;
  std::uint8_t keepalive = 0;
  std::string scheme;        // http | https (empty = derived from protocol)
  std::string host_header;   // Host/SNI override (empty = target_ip)
  std::uint32_t l7_timeout_ms = 5000;
  std::string l7_profile_file;  // scenario_payload_ref (JSON L7 profile)
  std::string l7_payload_file;  // payload_ref (raw request bytes)
  // Mahoraga shaping levers (RL action dims). 0 = baseline / no shaping.
  std::uint32_t request_mix = 0;      // request-variant selector honored by the L7 worker
  std::uint32_t source_rotation = 0;  // client source-identity spread (advisory to the L7 path)
  std::uint32_t auth_mode = 0;        // 0=Anon, 1=Bearer JWT, 2=Cookie
  std::uint32_t evasion_tactic = 0;   // 0=Normal, 1=Path Traversal, 2=URL Encoded, 3=Header Spoof
  std::string auth_payload;           // Dynamic JSON body for login
};

// Copies a std::string into a fixed-size char buffer, always NUL-terminating and
// never overrunning (the trailing byte is reserved for the NUL).
inline void CopyFixed(char* dst, std::size_t cap, const std::string& src) {
  std::memset(dst, 0, cap);
  if (cap == 0) {
    return;
  }
  const std::size_t n = std::min(src.size(), cap - 1);
  std::memcpy(dst, src.data(), n);
}

inline samurai::wire::JobEnvelopeV1 BuildJobEnvelope(const JobOptions& opt) {
  samurai::wire::JobEnvelopeV1 env{};
  CopyFixed(env.target_ip, sizeof(env.target_ip), opt.target_ip);
  env.target_port = opt.target_port;
  env.packet_count = opt.packet_count;
  env.packet_size = opt.packet_size;
  env.pacing_mode = opt.pacing_mode;
  env.target_rps = opt.target_rps;
  env.ipg_ns = opt.ipg_ns;
  env.burst_size = opt.burst_size > 0u ? opt.burst_size : 1u;
  env.burst_gap_ns = opt.burst_gap_ns;
  env.pin_cpu = opt.pin_cpu;
  CopyFixed(env.protocol, sizeof(env.protocol), opt.protocol);
  CopyFixed(env.attack_vector, sizeof(env.attack_vector), opt.attack_vector);
  env.ttl = opt.ttl;
  env.spoof_enabled = opt.spoof ? 1u : 0u;
  CopyFixed(env.spoof_mode, sizeof(env.spoof_mode), opt.spoof_mode);
  CopyFixed(env.dns_name, sizeof(env.dns_name), opt.dns_name);
  CopyFixed(env.dns_qtype, sizeof(env.dns_qtype), opt.dns_qtype);
  CopyFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref), opt.l7_profile_file);
  CopyFixed(env.payload_ref, sizeof(env.payload_ref), opt.l7_payload_file);
  env.has_payload = opt.l7_payload_file.empty() ? 0u : 1u;
  return env;
}

// Builds the V2 envelope used by the L7 worker. `base` carries the same fields
// as V1 plus the scenario/payload refs; the tail adds the stateful-runtime knobs.
inline samurai::wire::JobEnvelopeV2 BuildJobEnvelopeV2(const JobOptions& opt) {
  samurai::wire::JobEnvelopeV2 env{};
  env.base = BuildJobEnvelope(opt);
  env.concurrency = std::max(1u, opt.concurrency);
  env.max_connections = std::max(1u, opt.max_connections);
  env.max_streams_per_connection = std::max(1u, opt.max_streams_per_connection);
  env.verify_tls = opt.verify_tls != 0u ? 1u : 0u;
  env.keepalive = opt.keepalive != 0u ? 1u : 0u;
  CopyFixed(env.scheme, sizeof(env.scheme), opt.scheme);
  CopyFixed(env.host_header, sizeof(env.host_header), opt.host_header);
  env.l7_timeout_ms = opt.l7_timeout_ms > 0u ? opt.l7_timeout_ms : 5000u;
  env.request_mix = opt.request_mix;
  env.source_rotation = opt.source_rotation;
  env.auth_mode = opt.auth_mode;
  env.evasion_tactic = opt.evasion_tactic;
  CopyFixed(env.auth_payload, sizeof(env.auth_payload), opt.auth_payload);
  return env;
}

}  // namespace samurai::orchestrator
