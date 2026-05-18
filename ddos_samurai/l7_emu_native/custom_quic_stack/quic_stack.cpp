#include "quic_stack.hpp"

#include <algorithm>
#include <map>

#include "crypto_backend.hpp"
#include "h3_control_plane.hpp"
#include "h3_ngtcp2_client.hpp"
#include "h3_parity_state.hpp"
#include "loss_recovery.hpp"
#include "quic_metrics.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> run_quic_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps,
    TransportBackend transport_backend) {
  std::map<std::string, double> out = init_quic_stats(profile, transport_backend, caps);

  // QUIC custom stack currently runs over its own UDP probe transport.
  // Treat transport seam as ready to avoid unrelated custom-tcp fallback signaling.
  out["runtime_transport_custom_tcp_bridge_ready"] = 1.0;
  out["runtime_transport_seam_ready"] = 1.0;

  const int attempted = std::max(0, profile.flow_attempted);
  const int conn_pool = std::max(1, std::min(std::max(1, profile.max_connections), std::max(1, cfg.concurrency)));
  const int stream_budget = std::max(1, profile.max_streams_per_connection);
  const int target_requests_per_conn = std::max(1, std::min(stream_budget, attempted > 0 ? attempted : 1));
  out["quic_conn_pool_size"] = static_cast<double>(conn_pool);
  out["quic_runtime_stream_budget"] = static_cast<double>(stream_budget);
  out["quic_runtime_target_requests_per_connection"] = static_cast<double>(target_requests_per_conn);
  out["quic_runtime_session_repeats"] = static_cast<double>(std::max(1, profile.session_repeats));

  if (attempted <= 0) {
    const UdpProbeCounters empty_udp{};
    apply_h3_parity_metrics(&out, derive_h3_parity_state(profile, empty_udp, false));
    out["errors"] = 0.0;
    out["quic_errors"] = 0.0;
    out["quic_stream_fail_count"] = 0.0;
    out["quic_response_validation_fail_count"] = 0.0;
    out["l7_expectation_failures"] = 0.0;
    return out;
  }

  if (!quic_crypto_ready(caps)) {
    const UdpProbeCounters empty_udp{};
    apply_h3_parity_metrics(&out, derive_h3_parity_state(profile, empty_udp, false));
    out["errors"] = static_cast<double>(attempted);
    out["quic_errors"] = static_cast<double>(attempted);
    out["quic_timeouts"] = static_cast<double>(attempted);
    out["quic_connect_fail_count"] = static_cast<double>(attempted);
    out["quic_handshake_fail_count"] = static_cast<double>(attempted);
    out["quic_stream_fail_count"] = static_cast<double>(attempted);
    out["quic_response_validation_fail_count"] = static_cast<double>(attempted);
    out["l7_expectation_failures"] = static_cast<double>(attempted);
    return out;
  }

  UdpProbeCounters udp{};
  const bool ngtcp2_ready = run_h3_ngtcp2_client(profile, cfg, &udp);
  const bool run_ok = ngtcp2_ready;
  out["quic_runtime_ngtcp2_ready"] = ngtcp2_ready ? 1.0 : 0.0;
  out["quic_runtime_real_client_ready"] = ngtcp2_ready ? 1.0 : 0.0;
  out["quic_runtime_transport_path"] = ngtcp2_ready ? 2.0 : -1.0;
  const bool runtime_handshake_ready = run_ok && udp.conn_established > 0;
  out["quic_capability_available"] = runtime_handshake_ready ? 1.0 : 0.0;
  apply_h3_parity_metrics(&out, derive_h3_parity_state(profile, udp, runtime_handshake_ready));
  if (!run_ok) {
    udp.conn_attempted = attempted;
    udp.errors = attempted;
    udp.connect_fail = std::max(udp.connect_fail, attempted);
    udp.handshake_fail = std::max(udp.handshake_fail, attempted);
    udp.timeouts = std::max(udp.timeouts, attempted);
  }

  const LossRecoveryCounters recovery = derive_loss_recovery(udp);
  apply_quic_run_metrics(&out, profile, udp, recovery);
  apply_h3_control_plane_metrics(&out, derive_h3_control_plane_state(profile, udp));
  return out;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
