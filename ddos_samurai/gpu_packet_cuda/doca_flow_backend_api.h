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

