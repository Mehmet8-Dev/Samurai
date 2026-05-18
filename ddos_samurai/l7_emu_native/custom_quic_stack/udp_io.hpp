#pragma once

#include <cstddef>

#include "../engine.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

struct UdpProbeCounters {
  int conn_attempted{0};
  int conn_established{0};
  int responses{0};
  int timeouts{0};
  int connect_fail{0};
  int handshake_fail{0};
  int send_ok{0};
  int errors{0};
  int response_headers_ok{0};
  int response_body_ok{0};
  int response_expected_header_ok{0};
  int response_expected_body_match_ok{0};
  int response_validation_fail{0};
  int h3_goaway_events{0};
  int h3_drain_cycles{0};
  int h3_replace_now{0};
  int h3_replace_after_idle{0};
  int h3_control_plane_failures{0};
  int h3_graceful_close_count{0};
  int tx_datagrams{0};
  int rx_datagrams{0};
  int pacing_wait_events{0};
  std::size_t tx_bytes{0};
  std::size_t rx_bytes{0};
};

using UdpResponseObserver = bool (*)(const unsigned char* data, std::size_t len, void* ctx);

bool run_udp_probe_batch(
    const Profile& profile,
    int attempted,
    int timeout_ms,
    const unsigned char* payload_data,
    std::size_t payload_len,
    UdpResponseObserver observer,
    void* observer_ctx,
    UdpProbeCounters* out);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
