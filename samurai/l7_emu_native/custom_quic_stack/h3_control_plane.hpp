#pragma once

#include <map>

#include "../engine.hpp"
#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

struct H3ControlPlaneState {
  int goaway_events{0};
  int drain_cycles{0};
  int replace_now{0};
  int replace_after_idle{0};
  int control_plane_failures{0};
  double graceful_close_ratio{0.0};
};

H3ControlPlaneState derive_h3_control_plane_state(
    const Profile& profile,
    const UdpProbeCounters& udp);

void apply_h3_control_plane_metrics(
    std::map<std::string, double>* out,
    const H3ControlPlaneState& state);

}  // namespace samurai::l7_emu_native::custom_quic_stack
