#pragma once

#include <cstdint>
#include <string>

#include <pybind11/pybind11.h>

#include "types.hpp"

namespace ddos_samurai::scenario_native {

ScenarioSpecNative parse_spec(const pybind11::dict& spec);
pybind11::dict compile_session_plan_native(
    const ScenarioSpecNative& spec,
    const std::string& flow_name,
    std::uint64_t seed);

}  // namespace ddos_samurai::scenario_native
