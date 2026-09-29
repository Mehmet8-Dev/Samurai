#pragma once

#include <cstdint>
#include <vector>

#include "json.hpp"
#include "types.hpp"

namespace ddos_samurai::scenario_native {

// Assign weighted-random flows to each worker and compile their session plans.
// Returns {"plans_by_worker": [...], "metrics": {...}}.
samurai::core::json::Value build_worker_session_plans_native(
    const ScenarioSpecNative& spec,
    const std::vector<int>& worker_counts,
    std::uint64_t seed);

}  // namespace ddos_samurai::scenario_native
