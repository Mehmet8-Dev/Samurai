#include "scheduler.hpp"

#include <algorithm>
#include <random>
#include <vector>

#include "compiler.hpp"

namespace py = pybind11;

namespace ddos_samurai::scenario_native {

py::tuple build_worker_session_plans_native(
    const ScenarioSpecNative& spec,
    const std::vector<int>& worker_counts,
    std::uint64_t seed) {
  std::vector<std::string> flow_names;
  std::vector<double> flow_weights;
  flow_names.reserve(spec.flows.size());
  flow_weights.reserve(spec.flows.size());
  for (const auto& flow : spec.flows) {
    flow_names.push_back(flow.name);
    double w = 1.0;
    auto itp = spec.personas.find(flow.persona);
    if (itp != spec.personas.end()) {
      w = std::max(0.000001, itp->second.weight);
    }
    flow_weights.push_back(w);
  }
  std::mt19937_64 rng(seed);
  std::discrete_distribution<std::size_t> flow_dist(flow_weights.begin(), flow_weights.end());

  py::list plans_by_worker;
  std::uint64_t sessions_started = 0;
  std::uint64_t step_attempted = 0;
  if (flow_names.empty()) {
    for (std::size_t i = 0; i < worker_counts.size(); ++i) plans_by_worker.append(py::list());
  } else {
    for (std::size_t wi = 0; wi < worker_counts.size(); ++wi) {
      const int wc = std::max(0, worker_counts[wi]);
      std::vector<std::string> assigned_flows{};
      std::vector<std::uint64_t> assigned_seeds{};
      assigned_flows.reserve(static_cast<std::size_t>(wc));
      assigned_seeds.reserve(static_cast<std::size_t>(wc));
      for (int i = 0; i < wc; ++i) {
        const auto idx = flow_dist(rng);
        assigned_flows.push_back(flow_names[idx]);
        assigned_seeds.push_back(rng());
      }
      py::list worker_plans = compile_session_plans_packed_bulk_native(spec, assigned_flows, assigned_seeds);
      sessions_started += static_cast<std::uint64_t>(py::len(worker_plans));
      for (auto row : worker_plans) {
        py::dict plan = py::reinterpret_borrow<py::dict>(row);
        step_attempted += static_cast<std::uint64_t>(py::int_(plan["step_attempted"]));
      }
      plans_by_worker.append(worker_plans);
    }
  }

  py::dict metrics;
  metrics["sessions_started"] = py::int_(sessions_started);
  metrics["step_attempted"] = py::int_(step_attempted);
  metrics["scenario_backend"] = spec.load_model.backend;
  metrics["scenario_vus_target"] = spec.load_model.concurrent_vus;
  metrics["scenario_ramp_seconds"] = spec.load_model.ramp_seconds;
  return py::make_tuple(plans_by_worker, metrics);
}

}  // namespace ddos_samurai::scenario_native
