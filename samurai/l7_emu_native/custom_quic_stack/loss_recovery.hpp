#pragma once

#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

struct LossRecoveryCounters {
  int pto_count{0};
  int retransmission_count{0};
};

struct QuicCongestionState {
  uint32_t cwnd_bytes{14600};          // Initial 10 MSS (14600 bytes)
  uint32_t ssthresh_bytes{65536};      // Slow start threshold
  double rtt_sample_ms{20.0};          // Measured RTT sample (ms)
  double pacing_rate_bps{10000000.0};  // Pacing rate (bps)
  bool bbr_mode{true};
};

LossRecoveryCounters derive_loss_recovery(const UdpProbeCounters& udp);
QuicCongestionState derive_bbr_congestion_state(const UdpProbeCounters& udp, double rtt_ms);

}  // namespace samurai::l7_emu_native::custom_quic_stack
