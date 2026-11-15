#pragma once

#include "../engine.hpp"
#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

// Experimental in-process QUIC client based on ngtcp2 + gnutls helper.
// Returns true if the backend was usable and at least attempted the run.
// Returns false when backend prerequisites are unavailable.
bool run_h3_ngtcp2_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out);

}  // namespace samurai::l7_emu_native::custom_quic_stack
