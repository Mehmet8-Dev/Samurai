#include "quic_stack.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <string>

#include "crypto_backend.hpp"
#include "h3_control_plane.hpp"
#include "h3_ngtcp2_client.hpp"
#include "h3_parity_state.hpp"
#include "h3_minimal_client.hpp"
#include "h3_real_client.hpp"
#include "loss_recovery.hpp"
#include "quic_metrics.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> run_quic_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps,
    TransportBackend transport_backend) {
  std::map<std::string, double> out = init_quic_stats(profile, transport_backend, caps);
  apply_h3_parity_metrics(&out, derive_h3_parity_state(profile));

  // QUIC custom stack currently runs over its own UDP probe transport.
  // Treat transport seam as ready to avoid unrelated custom-tcp fallback signaling.
  out["runtime_transport_custom_tcp_bridge_ready"] = 1.0;
  out["runtime_transport_seam_ready"] = 1.0;

  const int attempted = std::max(0, profile.flow_attempted);
  const int conn_pool = std::max(1, std::min(std::max(1, profile.max_connections), std::max(1, cfg.concurrency)));
  out["quic_conn_pool_size"] = static_cast<double>(conn_pool);

  if (attempted <= 0) {
    out["errors"] = 0.0;
    out["quic_errors"] = 0.0;
    out["quic_stream_fail_count"] = 0.0;
    out["quic_response_validation_fail_count"] = 0.0;
    out["l7_expectation_failures"] = 0.0;
    return out;
  }

  if (!quic_crypto_ready(caps)) {
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
  bool run_ok = ngtcp2_ready;
  out["quic_runtime_ngtcp2_ready"] = ngtcp2_ready ? 1.0 : 0.0;
  out["quic_runtime_real_client_ready"] = 0.0;
  out["quic_runtime_transport_path"] = ngtcp2_ready ? 2.0 : 0.0;
  if (!run_ok) {
    const bool real_client_ready = run_h3_real_client(profile, cfg, &udp);
    run_ok = real_client_ready;
    out["quic_runtime_real_client_ready"] = real_client_ready ? 1.0 : 0.0;
    if (real_client_ready) {
      out["quic_runtime_transport_path"] = 1.0;
    }
  }
  if (!run_ok) {
    const char* allow_probe_fallback_env = std::getenv("SAMURAI_QUIC_ALLOW_UDP_PROBE_FALLBACK");
    const bool allow_probe_fallback =
        allow_probe_fallback_env != nullptr &&
        std::string(allow_probe_fallback_env) == "1";
    if (allow_probe_fallback) {
      run_ok = run_h3_minimal_client(profile, cfg, &udp);
      if (run_ok) out["quic_runtime_transport_path"] = 0.0;
    }
  }
  if (!run_ok) {
    out["quic_capability_available"] = 0.0;
  }
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
