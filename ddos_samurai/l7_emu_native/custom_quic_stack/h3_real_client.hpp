#pragma once

#include "../engine.hpp"
#include "udp_io.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

// Compatibility entrypoint for legacy "real client" callers.
// Uses in-process ngtcp2/nghttp3 native runtime (no shell curl path).
bool run_h3_real_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
