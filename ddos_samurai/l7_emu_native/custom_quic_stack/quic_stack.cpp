#include "quic_stack.hpp"

#include <algorithm>
#include <map>

#include "crypto_backend.hpp"
#include "h3_control_plane.hpp"
#include "h3_parity_state.hpp"
#include "h3_minimal_client.hpp"
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

  if (transport_backend == TransportBackend::CustomTcp) {
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
  const bool run_ok = run_h3_minimal_client(profile, cfg, &udp);
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
