#include "quic_stack.hpp"

#include <algorithm>
#include <cctype>
#include <map>

#include "crypto_backend.hpp"
#include "h3_control_plane.hpp"
#include "h3_ngtcp2_client.hpp"
#include "h3_parity_state.hpp"
#include "loss_recovery.hpp"
#include "quic_metrics.hpp"
#include "udp_io.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

std::map<std::string, double> run_quic_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps,
    TransportBackend transport_backend) {
  std::map<std::string, double> out = init_quic_stats(profile, transport_backend, caps);

  out["runtime_transport_custom_tcp_bridge_ready"] = 1.0;
  out["runtime_transport_seam_ready"] = 1.0;
  const auto req_backend = resolve_quic_udp_io_backend(profile);
  out["quic_runtime_backend_requested"] = static_cast<double>(req_backend);
  out["quic_runtime_udp_io_backend"] = static_cast<double>(req_backend);
  out["quic_runtime_native_hot_path_ready"] = is_native_hot_path_backend(req_backend) ? 1.0 : 0.0;

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
  out["quic_runtime_udp_io_backend"] = static_cast<double>(udp.runtime_udp_io_backend);
  out["quic_runtime_native_hot_path_ready"] = static_cast<double>(udp.runtime_native_hot_path_ready);
  if (udp.runtime_backend_requested >= 0) {
    out["quic_runtime_backend_requested"] = static_cast<double>(udp.runtime_backend_requested);
  }
  out["quic_runtime_backend_fallback_count"] = static_cast<double>(udp.backend_fallback_count);
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

  // Multi-step scenario / per-step SLA telemetry (H1/H2 parity surface).
  const int steps_completed = std::max(0, udp.scenario_steps_completed);
  out["quic_scenario_multi_step"] = static_cast<double>(udp.scenario_multi_step);
  out["quic_scenario_steps_planned"] = static_cast<double>(std::max(0, udp.scenario_steps_planned));
  out["quic_scenario_steps_completed"] = static_cast<double>(steps_completed);
  out["quic_scenario_steps_passed"] = static_cast<double>(std::max(0, udp.scenario_steps_passed));
  out["quic_scenario_steps_failed"] = static_cast<double>(std::max(0, udp.scenario_steps_failed));
  out["quic_scenario_think_time_total_ms"] =
      static_cast<double>(std::max(0, udp.scenario_think_time_total_ms));
  out["quic_scenario_step_latency_ms_avg"] =
      steps_completed > 0 ? udp.scenario_step_latency_ms_sum / static_cast<double>(steps_completed) : 0.0;
  out["quic_scenario_step_latency_ms_max"] = udp.scenario_step_latency_ms_max;
  out["quic_scenario_step_pass_ratio"] =
      steps_completed > 0
          ? static_cast<double>(std::max(0, udp.scenario_steps_passed)) / static_cast<double>(steps_completed)
          : 0.0;
  out["quic_scenario_state_carry_ready"] =
      (udp.scenario_multi_step != 0 && udp.scenario_steps_passed > 0) ? 1.0 : 0.0;
  return out;
}

}  // namespace samurai::l7_emu_native::custom_quic_stack
