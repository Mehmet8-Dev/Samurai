#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"
#include "types.hpp"

namespace ddos_samurai::scenario_native {

// Scenario compiler kernels. JSON is the native interchange format now that the
// pybind facade is gone; the ZMQ scenario worker feeds the raw scenario JSON
// document and consumes the compiled packed sessions directly.

// Parse a scenario document (load_model/personas/flows) into native structs.
ScenarioSpecNative parse_spec(const samurai::core::json::Value& spec);

// Compile a single flow into one packed session (event arrays).
samurai::core::json::Value compile_session_plan_packed_native(
    const ScenarioSpecNative& spec,
    const std::string& flow_name,
    std::uint64_t seed);

// Compile N sessions, one packed object each (list output).
samurai::core::json::Value compile_session_plans_packed_bulk_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds);

// Compile N sessions into one flat SoA buffer (offsets + interleaved events).
samurai::core::json::Value compile_session_plans_packed_bulk_soa_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds);

}  // namespace ddos_samurai::scenario_native
