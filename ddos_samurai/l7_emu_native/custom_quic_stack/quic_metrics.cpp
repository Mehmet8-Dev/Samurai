#include "quic_metrics.hpp"

#include <algorithm>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> init_quic_stats(
    const Profile& profile,
    TransportBackend transport_backend,
    const RuntimeCapabilities& caps) {
  (void)caps;
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
  out["quic_runtime_udp_io_backend"] = 0.0;  // 0=kernel_socket, 1=af_xdp, 2=dpdk, 3=af_packet
  out["quic_runtime_backend_requested"] = 0.0;  // 0=kernel/default, 1=af_xdp, 2=dpdk, 3=af_packet
  out["quic_runtime_native_hot_path_ready"] = 0.0;
  out["quic_runtime_backend_fallback_count"] = 0.0;

  out["quic_capability_available"] = 0.0;
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
  out["quic_h3_qpack_dynamic_events"] = 0.0;
  out["quic_h3_qpack_encoder_inserts"] = 0.0;
  out["quic_h3_qpack_decoder_inserts"] = 0.0;
  out["quic_h3_qpack_evictions"] = 0.0;
  out["quic_h3_priority_update_events"] = 0.0;
  out["quic_h3_extended_connect_events"] = 0.0;
  out["quic_h3_datagram_tx_events"] = 0.0;
  out["quic_h3_datagram_rx_events"] = 0.0;
  out["quic_h3_server_push_events"] = 0.0;
  out["quic_h3_feature_failures"] = 0.0;
  out["quic_tx_datagrams"] = 0.0;
  out["quic_rx_datagrams"] = 0.0;
  out["quic_pacing_wait_events"] = 0.0;
  out["quic_tls_session_resume_attempted"] = 0.0;
  out["quic_tls_session_resume_applied"] = 0.0;
  out["quic_tls_session_resumed"] = 0.0;
  out["quic_tls_early_data_accepted"] = 0.0;
  out["quic_tls_session_ticket_received"] = 0.0;
  out["quic_tls_cache_load_hit"] = 0.0;
  out["quic_tls_cache_store_updates"] = 0.0;
  out["quic_tls_session_resume_hit_ratio"] = 0.0;
  out["quic_tls_early_data_accept_ratio"] = 0.0;
  out["quic_requests_per_connection_eff"] = 0.0;
  out["quic_retransmission_ratio"] = 0.0;
  out["quic_cuda_crypto_available"] = 0.0;
  out["quic_cuda_crypto_batches"] = 0.0;
  out["quic_cuda_initial_keys_derived"] = 0.0;
  out["quic_cuda_hp_masks_computed"] = 0.0;
  out["quic_cuda_aead_packets"] = 0.0;
  out["quic_cuda_crypto_ms"] = 0.0;
  out["latency_p50_ms"] = 0.0;
  out["latency_p95_ms"] = 0.0;
  out["latency_p99_ms"] = 0.0;
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
  const int effective_conn_success = std::max(1, udp.conn_established);
  const int logical_reuse = std::max(0, std::max(udp.send_ok, udp.responses) - udp.conn_established);

  (*out)["sent"] = static_cast<double>(sent);
  (*out)["errors"] = static_cast<double>(errors);
  (*out)["responses_total"] = static_cast<double>(udp.responses);
  (*out)["l7_flow_attempted"] = static_cast<double>(attempted);
  (*out)["l7_flow_completed"] = static_cast<double>(sent);
  (*out)["l7_conn_attempted"] = static_cast<double>(udp.conn_attempted);
  (*out)["l7_conn_established"] = static_cast<double>(udp.conn_established);
  (*out)["l7_conn_reused"] = static_cast<double>(logical_reuse);
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
  (*out)["quic_h3_qpack_dynamic_events"] = static_cast<double>(udp.h3_qpack_dynamic_events);
  (*out)["quic_h3_qpack_encoder_inserts"] = static_cast<double>(udp.h3_qpack_encoder_inserts);
  (*out)["quic_h3_qpack_decoder_inserts"] = static_cast<double>(udp.h3_qpack_decoder_inserts);
  (*out)["quic_h3_qpack_evictions"] = static_cast<double>(udp.h3_qpack_evictions);
  (*out)["quic_h3_priority_update_events"] = static_cast<double>(udp.h3_priority_update_events);
  (*out)["quic_h3_extended_connect_events"] = static_cast<double>(udp.h3_extended_connect_events);
  (*out)["quic_h3_datagram_tx_events"] = static_cast<double>(udp.h3_datagram_tx_events);
  (*out)["quic_h3_datagram_rx_events"] = static_cast<double>(udp.h3_datagram_rx_events);
  (*out)["quic_h3_server_push_events"] = static_cast<double>(udp.h3_server_push_events);
  (*out)["quic_h3_feature_failures"] = static_cast<double>(udp.h3_feature_failures);
  (*out)["quic_tx_datagrams"] = static_cast<double>(udp.tx_datagrams);
  (*out)["quic_rx_datagrams"] = static_cast<double>(udp.rx_datagrams);
  (*out)["quic_pacing_wait_events"] = static_cast<double>(udp.pacing_wait_events);
  (*out)["quic_tls_session_resume_attempted"] = static_cast<double>(udp.tls_session_resume_attempted);
  (*out)["quic_tls_session_resume_applied"] = static_cast<double>(udp.tls_session_resume_applied);
  (*out)["quic_tls_session_resumed"] = static_cast<double>(udp.tls_session_resumed);
  (*out)["quic_tls_early_data_accepted"] = static_cast<double>(udp.tls_early_data_accepted);
  (*out)["quic_tls_session_ticket_received"] = static_cast<double>(udp.tls_session_ticket_received);
  (*out)["quic_tls_cache_load_hit"] = static_cast<double>(udp.tls_cache_load_hit);
  (*out)["quic_tls_cache_store_updates"] = static_cast<double>(udp.tls_cache_store_updates);
  (*out)["quic_tls_session_resume_hit_ratio"] =
      static_cast<double>(udp.tls_session_resumed) /
      static_cast<double>(std::max(1, udp.tls_session_resume_attempted));
  (*out)["quic_tls_early_data_accept_ratio"] =
      static_cast<double>(udp.tls_early_data_accepted) /
      static_cast<double>(std::max(1, udp.tls_session_resume_attempted));
  (*out)["quic_requests_per_connection_eff"] =
      static_cast<double>(std::max(0, udp.send_ok)) / static_cast<double>(effective_conn_success);
  (*out)["quic_retransmission_ratio"] =
      static_cast<double>(recovery.retransmission_count) / static_cast<double>(std::max(1, udp.tx_datagrams));
  (*out)["quic_cuda_crypto_available"] = static_cast<double>(udp.cuda_crypto_available);
  (*out)["quic_cuda_crypto_batches"] = static_cast<double>(udp.cuda_crypto_batches);
  (*out)["quic_cuda_initial_keys_derived"] = static_cast<double>(udp.cuda_initial_keys_derived);
  (*out)["quic_cuda_hp_masks_computed"] = static_cast<double>(udp.cuda_hp_masks_computed);
  (*out)["quic_cuda_aead_packets"] = static_cast<double>(udp.cuda_aead_packets);
  (*out)["quic_cuda_crypto_ms"] = udp.cuda_crypto_ms;
  (*out)["latency_p50_ms"] = udp.latency_p50_ms;
  (*out)["latency_p95_ms"] = udp.latency_p95_ms;
  (*out)["latency_p99_ms"] = udp.latency_p99_ms;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
