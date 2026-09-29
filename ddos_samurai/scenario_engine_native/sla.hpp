#pragma once

#include <cstdint>

#include "json.hpp"

namespace ddos_samurai::scenario_native {

// Evaluate an SLA document against the observed run counters.
// Returns {"passed": bool, "detail": {...}}.
samurai::core::json::Value evaluate_sla_native(
    const samurai::core::json::Value& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    double latency_p95_ms,
    bool has_latency,
    int tcp_connect_attempts,
    int tcp_connect_established,
    int tcp_retransmit_count,
    int tcp_timeout_close_count);

}  // namespace ddos_samurai::scenario_native
