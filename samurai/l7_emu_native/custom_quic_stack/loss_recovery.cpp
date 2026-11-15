#include "loss_recovery.hpp"

#include <algorithm>

namespace samurai::l7_emu_native::custom_quic_stack {

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

QuicCongestionState derive_bbr_congestion_state(const UdpProbeCounters& udp, double rtt_ms) {
  QuicCongestionState state;
  state.rtt_sample_ms = (rtt_ms > 0.1) ? rtt_ms : 20.0;
  LossRecoveryCounters lr = derive_loss_recovery(udp);

  // BBR pacing rate derivation based on bandwidth & RTT estimate
  const double rtt_sec = state.rtt_sample_ms / 1000.0;
  if (lr.retransmission_count > 0 || udp.timeouts > 0) {
    // Loss detected: scale back cwnd and pacing rate
    const double loss_factor = std::max(0.5, 1.0 - (lr.retransmission_count * 0.05));
    state.cwnd_bytes = static_cast<uint32_t>(state.cwnd_bytes * loss_factor);
    state.ssthresh_bytes = state.cwnd_bytes;
  } else {
    // Increase congestion window during clean delivery
    state.cwnd_bytes = std::min<uint32_t>(1048576u, state.cwnd_bytes + 1460u * std::max(1, udp.send_ok));
  }
  state.pacing_rate_bps = (static_cast<double>(state.cwnd_bytes) * 8.0) / rtt_sec;
  return state;
}

}  // namespace samurai::l7_emu_native::custom_quic_stack
