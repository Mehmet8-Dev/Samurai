#include "h3_control_plane.hpp"

#include <algorithm>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

bool profile_requests_goaway(const Profile& profile) {
  for (const auto& op : profile.ops) {
    if (op.opcode == "H3_GOAWAY") {
      return true;
    }
  }
  return false;
}

}  // namespace

H3ControlPlaneState derive_h3_control_plane_state(
    const Profile& profile,
    const UdpProbeCounters& udp) {
  H3ControlPlaneState state {};

  const bool requested_goaway = profile_requests_goaway(profile);
  const int established = std::max(0, udp.conn_established);
  const int hard_failures = std::max(0, udp.connect_fail + udp.handshake_fail + udp.timeouts);
  const int validation_failures = std::max(0, udp.response_validation_fail);

  if (requested_goaway && established > 0) {
    state.goaway_events = 1;
    state.drain_cycles = std::max(1, std::min(established, std::max(1, udp.responses)));
  } else if (!requested_goaway && established > 0 && hard_failures > 0) {
    // Fail-visible closure path still reports a control-plane event for observability.
    state.goaway_events = 1;
    state.drain_cycles = 1;
  }

  state.replace_now = hard_failures;
  state.replace_after_idle = std::max(0, state.goaway_events - state.replace_now);
  state.control_plane_failures = validation_failures + (requested_goaway && state.goaway_events == 0 ? 1 : 0);

  if (established > 0) {
    const int graceful = std::max(0, established - state.replace_now);
    state.graceful_close_ratio = static_cast<double>(graceful) / static_cast<double>(established);
  }

  return state;
}

void apply_h3_control_plane_metrics(
    std::map<std::string, double>* out,
    const H3ControlPlaneState& state) {
  if (out == nullptr) {
    return;
  }
  (*out)["quic_h3_goaway_events"] = static_cast<double>(state.goaway_events);
  (*out)["quic_h3_drain_cycles"] = static_cast<double>(state.drain_cycles);
  (*out)["quic_h3_replace_now"] = static_cast<double>(state.replace_now);
  (*out)["quic_h3_replace_after_idle"] = static_cast<double>(state.replace_after_idle);
  (*out)["quic_h3_control_plane_failures"] = static_cast<double>(state.control_plane_failures);
  (*out)["quic_h3_graceful_close_ratio"] = state.graceful_close_ratio;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
