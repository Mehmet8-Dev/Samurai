#pragma once

#include "../engine.hpp"
#include "udp_io.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

// Runs a real HTTP/3 request path via system curl (--http3-only), collecting
// counters into the existing QUIC metric surface.
bool run_h3_real_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
