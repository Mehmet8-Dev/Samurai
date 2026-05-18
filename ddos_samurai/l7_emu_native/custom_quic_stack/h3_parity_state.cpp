#include "h3_parity_state.hpp"

#include <algorithm>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

H3ParityState derive_h3_parity_state(
    const Profile& profile,
    const UdpProbeCounters& udp,
    bool runtime_handshake_ready) {
  H3ParityState state {};

  bool requested_qpack_dynamic = false;
  bool requested_goaway = false;
  bool requested_priority_update = false;
  bool requested_extended_connect = false;
  bool requested_datagram = false;
  bool requested_server_push = false;

  for (const auto& op : profile.ops) {
    const std::string& opcode = op.opcode;
    if (opcode == "H3_QPACK_DYNAMIC") {
      requested_qpack_dynamic = true;
    } else if (opcode == "H3_GOAWAY") {
      requested_goaway = true;
    } else if (opcode == "H3_PRIORITY_UPDATE") {
      requested_priority_update = true;
    } else if (opcode == "H3_EXTENDED_CONNECT") {
      requested_extended_connect = true;
    } else if (opcode == "H3_DATAGRAM") {
      requested_datagram = true;
    } else if (opcode == "H3_SERVER_PUSH") {
      requested_server_push = true;
    }
  }

  const bool observed_h3_activity =
      std::max(0, udp.responses) > 0 ||
      std::max(0, udp.response_headers_ok) > 0 ||
      std::max(0, udp.response_body_ok) > 0;
  const int qpack_events = std::max(0, udp.h3_qpack_dynamic_events);
  const int priority_events = std::max(0, udp.h3_priority_update_events);
  const int ext_connect_events = std::max(0, udp.h3_extended_connect_events);
  const int datagram_tx_events = std::max(0, udp.h3_datagram_tx_events);
  const int datagram_rx_events = std::max(0, udp.h3_datagram_rx_events);
  const int server_push_events = std::max(0, udp.h3_server_push_events);
  const int goaway_events = std::max(0, udp.h3_goaway_events);
  state.control_stream_ready = runtime_handshake_ready ? 1 : 0;
  const bool feature_gate = runtime_handshake_ready && observed_h3_activity;
  state.qpack_dynamic_ready = requested_qpack_dynamic && feature_gate && qpack_events > 0 ? 1 : 0;
  state.goaway_ready = requested_goaway && feature_gate && goaway_events > 0 ? 1 : 0;
  state.priority_update_ready = requested_priority_update && feature_gate && priority_events > 0 ? 1 : 0;
  state.extended_connect_ready = requested_extended_connect && feature_gate && ext_connect_events > 0 ? 1 : 0;
  state.datagram_ready = requested_datagram && feature_gate && datagram_tx_events > 0 && datagram_rx_events > 0 ? 1 : 0;
  state.server_push_ready = requested_server_push && feature_gate && server_push_events > 0 ? 1 : 0;

  // Phase model:
  // 1: minimal headers+data
  // 2: control/goaway
  // 3: qpack dynamic
  // 4: priority update + extended connect
  // 5: datagram + server push parity
  int phase = 1;
  if (!feature_gate) {
    state.phase = 1;
    return state;
  }
  if (state.goaway_ready > 0) {
    phase = std::max(phase, 2);
  }
  if (state.qpack_dynamic_ready > 0) {
    phase = std::max(phase, 3);
  }
  if (state.priority_update_ready > 0 || state.extended_connect_ready > 0) {
    phase = std::max(phase, 4);
  }
  if (state.datagram_ready > 0 || state.server_push_ready > 0) {
    phase = std::max(phase, 5);
  }

  state.phase = std::min(std::max(1, phase), state.target_phase);
  return state;
}

void apply_h3_parity_metrics(std::map<std::string, double>* out, const H3ParityState& state) {
  if (out == nullptr) {
    return;
  }

  const int phase = std::min(std::max(1, state.phase), std::max(1, state.target_phase));
  const int target = std::max(1, state.target_phase);
  const int gap = std::max(0, target - phase);

  (*out)["quic_h3_parity_phase"] = static_cast<double>(phase);
  (*out)["quic_h3_parity_target_phase"] = static_cast<double>(target);
  (*out)["quic_h3_parity_progress_ratio"] = static_cast<double>(phase) / static_cast<double>(target);
  (*out)["quic_h3_parity_gap"] = static_cast<double>(gap);

  (*out)["quic_h3_control_stream_ready"] = static_cast<double>(state.control_stream_ready);
  (*out)["quic_h3_qpack_dynamic_ready"] = static_cast<double>(state.qpack_dynamic_ready);
  (*out)["quic_h3_goaway_ready"] = static_cast<double>(state.goaway_ready);
  (*out)["quic_h3_priority_update_ready"] = static_cast<double>(state.priority_update_ready);
  (*out)["quic_h3_extended_connect_ready"] = static_cast<double>(state.extended_connect_ready);
  (*out)["quic_h3_datagram_ready"] = static_cast<double>(state.datagram_ready);
  (*out)["quic_h3_server_push_ready"] = static_cast<double>(state.server_push_ready);
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
