#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../engine.hpp"
#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

struct MinimalH3ParseResult {
  bool valid{false};
  bool headers_ok{false};
  bool body_ok{false};
  bool expected_header_ok{false};
  bool expected_body_match_ok{false};
};

std::vector<std::uint8_t> build_minimal_h3_request(
    const std::string& method,
    const std::string& path,
    const std::vector<std::uint8_t>& body);

MinimalH3ParseResult parse_minimal_h3_response(
    const std::uint8_t* data,
    std::size_t len);

bool run_h3_minimal_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out);

}  // namespace samurai::l7_emu_native::custom_quic_stack
