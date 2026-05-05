#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>

#include "types.hpp"

namespace ddos_samurai::scenario_native {

ScenarioSpecNative parse_spec(const pybind11::dict& spec);
pybind11::dict compile_session_plan_native(
    const ScenarioSpecNative& spec,
    const std::string& flow_name,
    std::uint64_t seed);
pybind11::dict compile_session_plan_packed_native(
    const ScenarioSpecNative& spec,
    const std::string& flow_name,
    std::uint64_t seed);
pybind11::list compile_session_plans_packed_bulk_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds);
pybind11::dict compile_session_plans_packed_bulk_soa_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds);

}  // namespace ddos_samurai::scenario_native
