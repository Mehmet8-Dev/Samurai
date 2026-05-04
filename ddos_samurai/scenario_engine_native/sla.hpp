#pragma once

#include <pybind11/pybind11.h>

namespace ddos_samurai::scenario_native {

pybind11::tuple evaluate_sla_native(
    const pybind11::dict& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    pybind11::object latency_p95_ms);

}  // namespace ddos_samurai::scenario_native
