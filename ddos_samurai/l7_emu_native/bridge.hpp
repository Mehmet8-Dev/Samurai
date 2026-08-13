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

struct FiveTuple {
  std::string client_ip;
  std::string server_ip;
  uint16_t client_port{0};
  uint16_t server_port{0};
  std::string protocol{"tcp"};
  std::string client_group;
  std::string server_group;
  std::string template_name;
};

samurai::core::json::Value compile_topology_json(
    const std::string& json_text,
    int seed,
    bool strict);
samurai::core::json::Value topology_tuple_preview_json(
    const samurai::core::json::Value& compiled_plan,
    int sample_size);
FiveTuple generate_5tuple(
    const samurai::core::json::Value& compiled_plan,
    uint64_t index);


// Custom TCP (L4 dataplane) diagnostics and direct zero-copy binary interfaces.
samurai::core::json::Value peek_custom_tcp_tx_buffer_strided_json();
int consume_custom_tcp_tx_packets(std::uint32_t max_packets);
int ingest_custom_tcp_rx_frame_hex(const std::string& hex_frame);
samurai::core::json::Value snapshot_custom_tcp_stats_json();

int peek_custom_tcp_tx_packets_raw(
    std::uint32_t max_packets,
    const std::uint8_t** out_base,
    std::uint32_t* out_count,
    std::size_t* out_packet_size,
    std::size_t* out_stride);
int consume_custom_tcp_tx_packets_raw(std::uint32_t max_packets, std::uint32_t* out_consumed);
int ingest_custom_tcp_rx_frame_raw(const std::uint8_t* raw_bytes, std::size_t len, std::uint32_t* out_updated);

// Minimal H3 wire-format diagnostics.
std::string build_minimal_h3_request_hex(
    const std::string& method,
    const std::string& path,
    const std::string& body_hex);
samurai::core::json::Value parse_minimal_h3_response_hex(const std::string& response_hex);

}  // namespace ddos_samurai::l7_emu_native
