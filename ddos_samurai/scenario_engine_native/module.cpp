#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "compiler.hpp"
#include "scheduler.hpp"
#include "sla.hpp"

namespace py = pybind11;

namespace ddos_samurai::scenario_native {

static py::dict compile_session_plan(const py::dict& spec, const std::string& flow_name, std::uint64_t seed) {
  const ScenarioSpecNative native = parse_spec(spec);
  // GAP-2: legacy compile entrypoint is redirected to packed output.
  return compile_session_plan_packed_native(native, flow_name, seed);
}

static py::dict compile_session_plan_packed(const py::dict& spec, const std::string& flow_name, std::uint64_t seed) {
  const ScenarioSpecNative native = parse_spec(spec);
  return compile_session_plan_packed_native(native, flow_name, seed);
}

static py::list compile_session_plans_packed_bulk(
    const py::dict& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  const ScenarioSpecNative native = parse_spec(spec);
  return compile_session_plans_packed_bulk_native(native, flow_names, seeds);
}

static py::dict compile_session_plans_packed_bulk_soa(
    const py::dict& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  const ScenarioSpecNative native = parse_spec(spec);
  return compile_session_plans_packed_bulk_soa_native(native, flow_names, seeds);
}

static py::tuple build_worker_session_plans(const py::dict& spec, const std::vector<int>& worker_counts, std::uint64_t seed) {
  const ScenarioSpecNative native = parse_spec(spec);
  return build_worker_session_plans_native(native, worker_counts, seed);
}

}  // namespace ddos_samurai::scenario_native

PYBIND11_MODULE(_scenario_native, m) {
  m.doc() = "Scenario engine native kernels";
  m.def(
      "compile_session_plan",
      &ddos_samurai::scenario_native::compile_session_plan,
      py::arg("spec"),
      py::arg("flow_name"),
      py::arg("seed"));
  m.def(
      "compile_session_plan_packed",
      &ddos_samurai::scenario_native::compile_session_plan_packed,
      py::arg("spec"),
      py::arg("flow_name"),
      py::arg("seed"));
  m.def(
      "compile_session_plans_packed_bulk",
      &ddos_samurai::scenario_native::compile_session_plans_packed_bulk,
      py::arg("spec"),
      py::arg("flow_names"),
      py::arg("seeds"));
  m.def(
      "compile_session_plans_packed_bulk_soa",
      &ddos_samurai::scenario_native::compile_session_plans_packed_bulk_soa,
      py::arg("spec"),
      py::arg("flow_names"),
      py::arg("seeds"));
  m.def(
      "build_worker_session_plans",
      &ddos_samurai::scenario_native::build_worker_session_plans,
      py::arg("spec"),
      py::arg("worker_counts"),
      py::arg("seed"));
  m.def(
      "evaluate_sla",
      &ddos_samurai::scenario_native::evaluate_sla_native,
      py::arg("sla"),
      py::arg("sessions_started"),
      py::arg("sessions_completed"),
      py::arg("step_attempted"),
      py::arg("step_failed"),
      py::arg("latency_p95_ms") = py::none());
}
