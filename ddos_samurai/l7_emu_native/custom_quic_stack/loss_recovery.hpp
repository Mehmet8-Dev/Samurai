#pragma once

#include "udp_io.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

struct LossRecoveryCounters {
  int pto_count{0};
  int retransmission_count{0};
};

LossRecoveryCounters derive_loss_recovery(const UdpProbeCounters& udp);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
