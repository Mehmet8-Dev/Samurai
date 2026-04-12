#pragma once

#include <map>

#include "../engine.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> run_quic_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps,
    TransportBackend transport_backend);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
