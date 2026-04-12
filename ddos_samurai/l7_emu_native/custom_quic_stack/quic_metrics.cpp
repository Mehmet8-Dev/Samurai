#include "quic_metrics.hpp"

#include <algorithm>

#include "crypto_backend.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> init_quic_stats(
    const Profile& profile,
    TransportBackend transport_backend,
    const RuntimeCapabilities& caps) {
  const int attempted = std::max(0, profile.flow_attempted);
  std::map<std::string, double> out;
  out["attempted"] = static_cast<double>(attempted);
  out["sent"] = 0.0;
  out["errors"] = static_cast<double>(attempted);
  out["responses_total"] = 0.0;

  out["l7_flow_attempted"] = static_cast<double>(attempted);
  out["l7_flow_completed"] = 0.0;
  out["l7_conn_attempted"] = 0.0;
  out["l7_conn_established"] = 0.0;
  out["l7_conn_reused"] = 0.0;
  out["l7_rx_bytes"] = 0.0;
  out["l7_tx_bytes"] = 0.0;
  out["l7_status_2xx"] = 0.0;
  out["l7_status_3xx"] = 0.0;
  out["l7_status_4xx"] = 0.0;
  out["l7_status_5xx"] = 0.0;
  out["l7_expectation_failures"] = static_cast<double>(attempted);

  out["runtime_transport_custom_tcp_requested"] = transport_backend == TransportBackend::CustomTcp ? 1.0 : 0.0;
  out["runtime_transport_custom_tcp_bridge_ready"] = transport_backend == TransportBackend::CustomTcp ? 0.0 : 1.0;
  out["runtime_transport_custom_tcp_rx_bridge_active"] = 0.0;
  out["runtime_transport_seam_ready"] = transport_backend == TransportBackend::CustomTcp ? 0.0 : 1.0;

  out["quic_capability_available"] = quic_crypto_ready(caps) ? 1.0 : 0.0;
  out["quic_connection_attempts"] = static_cast<double>(attempted);
  out["quic_connection_success"] = 0.0;
  out["quic_requests_sent"] = 0.0;
  out["quic_responses_received"] = 0.0;
  out["quic_timeouts"] = 0.0;
  out["quic_errors"] = static_cast<double>(attempted);
  out["quic_handshake_success_ratio"] = 0.0;
  out["quic_alpn_h3_ratio"] = 0.0;
  out["quic_connect_fail_count"] = 0.0;
  out["quic_connect_timeout_count"] = 0.0;
  out["quic_handshake_fail_count"] = 0.0;
  out["quic_stream_fail_count"] = static_cast<double>(attempted);
  out["quic_stream_fail_ratio"] = attempted > 0 ? 1.0 : 0.0;
  out["quic_handshake_fail_ratio"] = attempted > 0 ? 1.0 : 0.0;
  out["quic_response_headers_ok_count"] = 0.0;
  out["quic_response_body_ok_count"] = 0.0;
  out["quic_response_expected_header_ok_count"] = 0.0;
  out["quic_response_expected_body_match_ok_count"] = 0.0;
  out["quic_response_validation_fail_count"] = static_cast<double>(attempted);
  out["quic_response_validation_fail_ratio"] = attempted > 0 ? 1.0 : 0.0;
  out["quic_conn_pool_size"] = static_cast<double>(std::max(1, profile.max_connections));
  out["quic_pto_count"] = 0.0;
  out["quic_retransmission_count"] = 0.0;
  out["quic_h3_goaway_events"] = 0.0;
  out["quic_h3_drain_cycles"] = 0.0;
  out["quic_h3_replace_now"] = 0.0;
  out["quic_h3_replace_after_idle"] = 0.0;
  out["quic_h3_control_plane_failures"] = 0.0;
  out["quic_h3_graceful_close_ratio"] = 0.0;
  return out;
}

void apply_quic_run_metrics(
    std::map<std::string, double>* out,
    const Profile& profile,
    const UdpProbeCounters& udp,
    const LossRecoveryCounters& recovery) {
  if (out == nullptr) {
    return;
  }
  const int attempted = std::max(0, profile.flow_attempted);
  const int sent = std::max(0, udp.responses);
  const int errors = std::max(std::max(0, udp.errors), attempted - sent);
  const double denom = static_cast<double>(std::max(1, attempted));

  (*out)["sent"] = static_cast<double>(sent);
  (*out)["errors"] = static_cast<double>(errors);
  (*out)["responses_total"] = static_cast<double>(udp.responses);
  (*out)["l7_flow_attempted"] = static_cast<double>(attempted);
  (*out)["l7_flow_completed"] = static_cast<double>(sent);
  (*out)["l7_conn_attempted"] = static_cast<double>(udp.conn_attempted);
  (*out)["l7_conn_established"] = static_cast<double>(udp.conn_established);
  (*out)["l7_conn_reused"] = 0.0;
  (*out)["l7_rx_bytes"] = static_cast<double>(udp.rx_bytes);
  (*out)["l7_tx_bytes"] = static_cast<double>(udp.tx_bytes);
  (*out)["l7_status_2xx"] = static_cast<double>(sent);
  (*out)["l7_status_3xx"] = 0.0;
  (*out)["l7_status_4xx"] = 0.0;
  (*out)["l7_status_5xx"] = 0.0;
  (*out)["l7_expectation_failures"] = static_cast<double>(errors);

  (*out)["quic_connection_attempts"] = static_cast<double>(udp.conn_attempted);
  (*out)["quic_connection_success"] = static_cast<double>(udp.conn_established);
  (*out)["quic_requests_sent"] = static_cast<double>(attempted);
  (*out)["quic_responses_received"] = static_cast<double>(udp.responses);
  (*out)["quic_timeouts"] = static_cast<double>(udp.timeouts);
  (*out)["quic_errors"] = static_cast<double>(errors);
  (*out)["quic_connect_fail_count"] = static_cast<double>(udp.connect_fail);
  (*out)["quic_connect_timeout_count"] = static_cast<double>(udp.timeouts);
  (*out)["quic_handshake_fail_count"] = static_cast<double>(udp.handshake_fail);
  (*out)["quic_stream_fail_count"] = static_cast<double>(errors);
  (*out)["quic_stream_fail_ratio"] = static_cast<double>(errors) / denom;
  (*out)["quic_handshake_fail_ratio"] = static_cast<double>(udp.handshake_fail) / denom;
  (*out)["quic_response_headers_ok_count"] = static_cast<double>(udp.response_headers_ok);
  (*out)["quic_response_body_ok_count"] = static_cast<double>(udp.response_body_ok);
  (*out)["quic_response_expected_header_ok_count"] = static_cast<double>(udp.response_expected_header_ok);
  (*out)["quic_response_expected_body_match_ok_count"] = static_cast<double>(udp.response_expected_body_match_ok);
  (*out)["quic_response_validation_fail_count"] = static_cast<double>(udp.response_validation_fail);
  (*out)["quic_response_validation_fail_ratio"] = static_cast<double>(udp.response_validation_fail) / denom;
  (*out)["quic_handshake_success_ratio"] = static_cast<double>(udp.conn_established) / denom;
  (*out)["quic_alpn_h3_ratio"] = static_cast<double>(udp.responses) / denom;
  (*out)["quic_pto_count"] = static_cast<double>(recovery.pto_count);
  (*out)["quic_retransmission_count"] = static_cast<double>(recovery.retransmission_count);
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
