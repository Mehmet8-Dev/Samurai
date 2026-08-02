#pragma once

// Builds a wire JobEnvelopeV1 from a small, orchestrator-level options struct.
//
// The envelope layout itself lives in wire_protocol.h and is shared verbatim
// with every worker, so a job built here is binary-compatible with the worker
// that consumes it by construction (see the static_asserts in wire_protocol.h).

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
  return env;
}

}  // namespace samurai::orchestrator
