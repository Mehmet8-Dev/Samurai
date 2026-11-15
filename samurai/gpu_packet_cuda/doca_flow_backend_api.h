#pragma once

#include <cstddef>
#include <cstdint>

// Optional external flow steering shim contract.
//
// Implement this symbol in a separate .so and point
// SAMURAI_GPU_DOCA_FLOW_SHIM_SO to that shared object.
//
// Return codes:
//   0  -> steering programmed successfully
//  <0  -> failure
extern "C" int samurai_doca_flow_program_steering_v1(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    char* err,
    size_t err_len);

struct samurai_doca_flow_stream_rule_v1 {
  uint32_t stream_id;
  uint32_t proto_mask;
  uint32_t ipv4_dst_be;      // optional, big-endian IPv4
  uint16_t l4_dst_port_be;   // optional, big-endian L4 dst port
  uint16_t rxq_id;           // target RX queue id
  uint32_t reserved;
};

// Optional per-stream steering contract.
//
// Return codes:
//   0  -> steering programmed successfully
//  <0  -> failure
extern "C" int samurai_doca_flow_program_steering_streams_v1(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count,
    char* err,
    size_t err_len);
