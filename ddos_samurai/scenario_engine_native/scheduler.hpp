#pragma once

#include <cstdint>
#include <vector>

#include <pybind11/pybind11.h>

#include "types.hpp"

namespace ddos_samurai::scenario_native {

pybind11::tuple build_worker_session_plans_native(
    const ScenarioSpecNative& spec,
    const std::vector<int>& worker_counts,
    std::uint64_t seed);

}  // namespace ddos_samurai::scenario_native
