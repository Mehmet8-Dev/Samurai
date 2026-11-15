#pragma once

// Native aggregation of worker metric snapshots into a run summary
// (merge_worker_stats + recompute_loss_metrics), operating directly on the wire
// MetricSnapshotV1 that the workers emit.

#include <cstdint>
#include <string>

#include "wire_protocol.h"

namespace samurai::orchestrator {

struct RunStats {
  std::uint64_t attempted = 0;
  std::uint64_t sent = 0;
  std::uint64_t errors = 0;
  std::uint64_t bytes_sent = 0;
  double actual_rps = 0.0;
  double rate_accuracy_pct = 0.0;
  std::uint64_t sleep_calls = 0;
  // Derived (see RecomputeLoss).
  std::uint64_t wire_loss_est_packets = 0;
  double wire_loss_est_pct = 0.0;
  
  // Phase 6 L7 metrics
  std::uint64_t tcp_active_tcb_count = 0;
  std::uint64_t tcp_timer_wheel_overflows = 0;
  std::uint64_t tls_handshakes_completed = 0;
  std::uint64_t tls_session_reuse_hits = 0;
  std::uint64_t dns_queries_sent = 0;
  std::uint64_t dns_responses_parsed = 0;
  std::uint64_t dns_ecs_injected = 0;
  std::uint64_t dhcp_leases_active = 0;
  std::uint64_t arp_resolved_entries = 0;
  std::uint64_t igmp_active_groups = 0;
  std::uint64_t hot_path_zero_copy_tx_bytes = 0;
  std::uint64_t hot_path_zero_copy_rx_bytes = 0;

  // L7 defense-reaction signals — the SUT's WAF/rate-limiter/overload pushback,
  // folded from the worker's JOB_DONE engine_result JSON (the binary metric
  // snapshot carries no HTTP status breakdown). Zero for L4 floods that emit no
  // L7 telemetry. Counters add across snapshots; ratios/latency are latest-gauge.
  // These are the raw inputs RlDefenseJson surfaces for the Mahoraga features —
  // keep the field set in lockstep with its key list.
  std::uint64_t responses_total = 0;
  std::uint64_t status_2xx = 0;
  std::uint64_t status_3xx = 0;
  std::uint64_t status_4xx = 0;
  std::uint64_t status_5xx = 0;
  std::uint64_t l7_conn_attempted = 0;
  std::uint64_t l7_conn_established = 0;
  std::uint64_t l7_expectation_failures = 0;
  std::uint64_t l7_scheduler_backpressure_count = 0;
  std::uint64_t h2_goaway_count = 0;
  double h2_stream_reset_ratio = 0.0;      // gauge
  double l7_request_latency_p99_ms = 0.0;  // gauge
  double l7_tls_handshake_p99_ms = 0.0;    // gauge

  // Flow / connection-level defense signals (network-layer, below HTTP). These
  // surface active IPS / conntrack behavior — RST injection, SYN-drop timeouts,
  // throttling-induced retransmits — that no status code reveals. Populated only
  // by the userspace TCP stack (custom_tcp/dpdk); ~0 on the kernel_socket path,
  // where the OS owns the connection. Carried into the corpus defense block for
  // the fingerprint layer (not the RL feature vector).
  std::uint64_t tcp_peer_rst_count = 0;         // peer RSTs — reset injection / hard refusal
  std::uint64_t tcp_connect_timeout_count = 0;  // SYN never answered — filtering / drop
  std::uint64_t tcp_retransmit_count = 0;       // loss/throttle-induced retransmits
  std::uint64_t tcp_timeout_close_count = 0;    // idle/stall closes under pressure

  // Production IPFIX / NetFlow telemetry export totals
  std::uint64_t ipfix_exported_packets = 0;
  std::uint64_t ipfix_exported_records = 0;

  // Telco control & user plane telemetry
  std::uint64_t telco_active_sessions = 0;
  std::uint64_t telco_established_sessions = 0;
  std::uint64_t telco_failed_sessions = 0;
  std::uint32_t telco_current_cps = 0;
  std::uint32_t telco_avg_setup_latency_us = 0;
  std::uint32_t telco_p99_setup_latency_us = 0;
  std::uint64_t telco_retransmit_count = 0;
};

// Folds one snapshot into the accumulator. Counters add up across snapshots;
// rate fields track the last positive report (was merge_worker_stats).
inline void AccumulateSnapshot(RunStats& acc, const samurai::wire::MetricSnapshotV1& s) {
  acc.sent += s.packets_sent;
  acc.errors += s.packets_errors;
  acc.bytes_sent += s.bytes_sent;
  if (s.actual_rps > 0.0) acc.actual_rps = s.actual_rps;
  if (s.rate_accuracy_pct > 0.0) acc.rate_accuracy_pct = s.rate_accuracy_pct;
  acc.sleep_calls += s.sleep_calls;
}

inline void AccumulateSnapshotV2(RunStats& acc, const samurai::wire::MetricSnapshotV2& s) {
  AccumulateSnapshot(acc, s.base);
  // Additive metrics
  acc.tcp_timer_wheel_overflows += s.tcp_timer_wheel_overflows;
  acc.tls_handshakes_completed += s.tls_handshakes_completed;
  acc.tls_session_reuse_hits += s.tls_session_reuse_hits;
  acc.dns_queries_sent += s.dns_queries_sent;
  acc.dns_responses_parsed += s.dns_responses_parsed;
  acc.dns_ecs_injected += s.dns_ecs_injected;
  acc.hot_path_zero_copy_tx_bytes += s.hot_path_zero_copy_tx_bytes;
  acc.hot_path_zero_copy_rx_bytes += s.hot_path_zero_copy_rx_bytes;
  
  // Point-in-time gauges (take the latest value)
  acc.tcp_active_tcb_count = s.tcp_active_tcb_count;
  acc.dhcp_leases_active = s.dhcp_leases_active;
  acc.arp_resolved_entries = s.arp_resolved_entries;
  acc.igmp_active_groups = s.igmp_active_groups;
}

// Computes attempted + wire-loss estimate from the accumulated counters (was
// recompute_loss_metrics). MetricSnapshotV1 carries no explicit "attempted", so
// attempted is estimated as sent + errors.
inline void RecomputeLoss(RunStats& acc) {
  acc.attempted = acc.sent + acc.errors;
  acc.wire_loss_est_packets = (acc.attempted > acc.sent) ? (acc.attempted - acc.sent) : 0;
  const std::uint64_t denom = acc.attempted > 0 ? acc.attempted : 1;
  acc.wire_loss_est_pct = (100.0 * static_cast<double>(acc.wire_loss_est_packets)) /
                          static_cast<double>(denom);
}

inline std::string SummaryJson(const RunStats& s) {
  char buf[4096];
  std::snprintf(
      buf, sizeof(buf),
      "{\"event\":\"run_summary\",\"attempted\":%llu,\"sent\":%llu,\"errors\":%llu,"
      "\"bytes_sent\":%llu,\"actual_rps\":%.2f,\"rate_accuracy_pct\":%.2f,"
      "\"wire_loss_est_packets\":%llu,\"wire_loss_est_pct\":%.4f,"
      "\"ipfix_telemetry\":{\"exported_packets\":%llu,\"exported_records\":%llu},"
      "\"telco_telemetry\":{\"active_sessions\":%llu,\"established_sessions\":%llu,"
      "\"failed_sessions\":%llu,\"current_cps\":%u,\"avg_setup_latency_us\":%u,"
      "\"p99_setup_latency_us\":%u,\"retransmit_count\":%llu},"
      "\"l7_telemetry\":{\"tls_handshakes\":%llu,\"dns_queries\":%llu,"
      "\"tcp_tcb\":%llu,\"zc_tx_bytes\":%llu}}",
      static_cast<unsigned long long>(s.attempted),
      static_cast<unsigned long long>(s.sent),
      static_cast<unsigned long long>(s.errors),
      static_cast<unsigned long long>(s.bytes_sent),
      s.actual_rps,
      s.rate_accuracy_pct,
      static_cast<unsigned long long>(s.wire_loss_est_packets),
      s.wire_loss_est_pct,
      static_cast<unsigned long long>(s.ipfix_exported_packets),
      static_cast<unsigned long long>(s.ipfix_exported_records),
      static_cast<unsigned long long>(s.telco_active_sessions),
      static_cast<unsigned long long>(s.telco_established_sessions),
      static_cast<unsigned long long>(s.telco_failed_sessions),
      static_cast<unsigned>(s.telco_current_cps),
      static_cast<unsigned>(s.telco_avg_setup_latency_us),
      static_cast<unsigned>(s.telco_p99_setup_latency_us),
      static_cast<unsigned long long>(s.telco_retransmit_count),
      static_cast<unsigned long long>(s.tls_handshakes_completed),
      static_cast<unsigned long long>(s.dns_queries_sent),
      static_cast<unsigned long long>(s.tcp_active_tcb_count),
      static_cast<unsigned long long>(s.hot_path_zero_copy_tx_bytes));
  return std::string(buf);
}

}  // namespace samurai::orchestrator
