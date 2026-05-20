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
  int h3_qpack_dynamic_events{0};
  int h3_priority_update_events{0};
  int h3_extended_connect_events{0};
  int h3_datagram_tx_events{0};
  int h3_datagram_rx_events{0};
  int h3_server_push_events{0};
  int h3_feature_failures{0};
  int runtime_udp_io_backend{0};  // 0=kernel_socket, 1=af_xdp, 2=dpdk
  int runtime_native_hot_path_ready{0};
  int runtime_backend_requested{0};  // 0=kernel_socket, 1=af_xdp, 2=dpdk
  int backend_fallback_count{0};
  int tx_datagrams{0};
  int rx_datagrams{0};
  int pacing_wait_events{0};
  int tls_session_resume_attempted{0};
  int tls_session_resume_applied{0};
  int tls_session_resumed{0};
  int tls_early_data_accepted{0};
  int tls_session_ticket_received{0};
  int tls_cache_load_hit{0};
  int tls_cache_store_updates{0};
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
