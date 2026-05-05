#pragma once

#include <pybind11/pybind11.h>

namespace ddos_samurai::scenario_native {

pybind11::tuple evaluate_sla_native(
    const pybind11::dict& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    pybind11::object latency_p95_ms,
    int tcp_connect_attempts,
    int tcp_connect_established,
    int tcp_retransmit_count,
    int tcp_timeout_close_count);

}  // namespace ddos_samurai::scenario_native
