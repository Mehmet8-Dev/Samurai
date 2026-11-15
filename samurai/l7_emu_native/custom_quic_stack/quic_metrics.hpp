#pragma once

#include <map>
#include <string>

#include "../engine.hpp"
#include "loss_recovery.hpp"
#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> init_quic_stats(
    const Profile& profile,
    TransportBackend transport_backend,
    const RuntimeCapabilities& caps);

void apply_quic_run_metrics(
    std::map<std::string, double>* out,
    const Profile& profile,
    const UdpProbeCounters& udp,
    const LossRecoveryCounters& recovery);

}  // namespace samurai::l7_emu_native::custom_quic_stack
