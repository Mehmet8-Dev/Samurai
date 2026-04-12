#include "loss_recovery.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

LossRecoveryCounters derive_loss_recovery(const UdpProbeCounters& udp) {
  LossRecoveryCounters out;
  out.pto_count = udp.timeouts;
  // Minimal placeholder: each timeout is treated as one retransmission cycle.
  out.retransmission_count = udp.timeouts;
  return out;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
