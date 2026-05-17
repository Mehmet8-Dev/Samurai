#include "loss_recovery.hpp"

#include <algorithm>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

LossRecoveryCounters derive_loss_recovery(const UdpProbeCounters& udp) {
  LossRecoveryCounters out;
  // PTO driven primarily by timeout pressure plus post-connect handshake losses.
  const int handshake_phase_fail =
      std::max(0, std::max(0, udp.handshake_fail) - std::max(0, udp.connect_fail));
  out.pto_count = std::max(std::max(0, udp.timeouts), handshake_phase_fail);

  // Retransmission heuristic blends packet-level delivery gap with request-level
  // failures that happened after transport connect.
  const int tx_dgrams = std::max(0, udp.tx_datagrams);
  const int rx_dgrams = std::max(0, udp.rx_datagrams);
  const int datagram_gap = std::max(0, tx_dgrams - rx_dgrams);
  const int attempted_requests = std::max(0, udp.send_ok + udp.response_validation_fail);
  const int completed_requests = std::max(0, udp.send_ok);
  const int connect_fail = std::max(0, udp.connect_fail);
  const int post_connect_request_fail =
      std::max(0, attempted_requests - completed_requests - connect_fail);
  out.retransmission_count = std::max(datagram_gap, post_connect_request_fail);
  return out;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
