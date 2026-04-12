#pragma once

#include <map>
#include <string>

#include "../engine.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

struct H3ParityState {
  int phase{1};
  int target_phase{5};
  int control_stream_ready{1};
  int qpack_dynamic_ready{0};
  int goaway_ready{0};
  int priority_update_ready{0};
  int extended_connect_ready{0};
  int datagram_ready{0};
  int server_push_ready{0};
};

H3ParityState derive_h3_parity_state(const Profile& profile);

void apply_h3_parity_metrics(std::map<std::string, double>* out, const H3ParityState& state);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
