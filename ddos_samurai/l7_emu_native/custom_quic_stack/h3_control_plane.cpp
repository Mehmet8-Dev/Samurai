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
  const int runtime_goaway_events = std::max(0, udp.h3_goaway_events);
  const int runtime_drain_cycles = std::max(0, udp.h3_drain_cycles);
  const int runtime_replace_now = std::max(0, udp.h3_replace_now);
  const int runtime_replace_after_idle = std::max(0, udp.h3_replace_after_idle);
  const int runtime_cp_failures = std::max(0, udp.h3_control_plane_failures);
  const int runtime_graceful_close = std::max(0, udp.h3_graceful_close_count);

  if (runtime_goaway_events > 0) {
    // Real runtime GOAWAY / drain observations win.
    state.goaway_events = runtime_goaway_events;
    state.drain_cycles = std::max(runtime_drain_cycles, 1);
    state.replace_now = runtime_replace_now;
    state.replace_after_idle = runtime_replace_after_idle;
    state.control_plane_failures = runtime_cp_failures + validation_failures;
  } else if (requested_goaway && established > 0) {
    // Requested GOAWAY but not observed at runtime -> fail-visible.
    state.goaway_events = 0;
    state.drain_cycles = 0;
    state.replace_now = std::max(0, hard_failures);
    state.replace_after_idle = 0;
    state.control_plane_failures = validation_failures + 1;
  } else {
    // Do not synthesize GOAWAY from unrelated hard failures.
    state.goaway_events = 0;
    state.drain_cycles = runtime_drain_cycles;
    state.replace_now = runtime_replace_now > 0 ? runtime_replace_now : hard_failures;
    state.replace_after_idle = runtime_replace_after_idle;
    state.control_plane_failures = validation_failures + runtime_cp_failures;
  }

  if (established > 0) {
    const int graceful = runtime_graceful_close > 0
        ? std::min(established, runtime_graceful_close)
        : std::max(0, established - state.replace_now);
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
