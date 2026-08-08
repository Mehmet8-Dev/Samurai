#pragma once

#include <cstdint>
#include <string>

#include "engine.hpp"
#include "json.hpp"

namespace ddos_samurai::l7_emu_native {

// JSON bridge for the native L7 emulation runtime. The pybind facade is gone;
// the ZMQ l7 worker feeds JSON profile/config documents and consumes the JSON
// result. Binary payloads cross the boundary hex-encoded.

Profile parse_profile(const samurai::core::json::Value& profile_dict);
RuntimeConfig parse_runtime_cfg(const samurai::core::json::Value& cfg_dict);

samurai::core::json::Value runtime_capabilities_json();
samurai::core::json::Value run_profile_json(
    const samurai::core::json::Value& profile_dict,
    const samurai::core::json::Value& cfg_dict);

samurai::core::json::Value compile_topology_json(
    const std::string& json_text,
    int seed,
    bool strict);
samurai::core::json::Value topology_tuple_preview_json(
    const samurai::core::json::Value& compiled_plan,
    int sample_size);

// Custom TCP (L4 dataplane) diagnostics.
samurai::core::json::Value peek_custom_tcp_tx_buffer_strided_json();
int consume_custom_tcp_tx_packets(std::uint32_t max_packets);
int ingest_custom_tcp_rx_frame_hex(const std::string& hex_frame);
samurai::core::json::Value snapshot_custom_tcp_stats_json();

// Minimal H3 wire-format diagnostics.
std::string build_minimal_h3_request_hex(
    const std::string& method,
    const std::string& path,
    const std::string& body_hex);
samurai::core::json::Value parse_minimal_h3_response_hex(const std::string& response_hex);

}  // namespace ddos_samurai::l7_emu_native
