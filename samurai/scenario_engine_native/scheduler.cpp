#include "scheduler.hpp"

#include <algorithm>
#include <random>
#include <vector>

#include "compiler.hpp"

namespace samurai::scenario_native {

namespace json = samurai::core::json;

json::Value build_worker_session_plans_native(
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

  json::Value plans_by_worker = json::Value::Array();
  std::uint64_t sessions_started = 0;
  std::uint64_t step_attempted = 0;
  if (flow_names.empty()) {
    for (std::size_t i = 0; i < worker_counts.size(); ++i) plans_by_worker.push_back(json::Value::Array());
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
      json::Value worker_soa = compile_session_plans_packed_bulk_soa_native(spec, assigned_flows, assigned_seeds);
      json::Value worker_plans = json::Value::Array();
      worker_plans.push_back(worker_soa);
      sessions_started += static_cast<std::uint64_t>(assigned_flows.size());
      const json::Value* attempts = worker_soa.find("session_step_attempted");
      if (attempts != nullptr && attempts->is_array()) {
        for (const auto& a : attempts->elements()) {
          step_attempted += static_cast<std::uint64_t>(a.as_int(0));
        }
      }
      plans_by_worker.push_back(std::move(worker_plans));
    }
  }

  json::Value metrics = json::Value::Object();
  metrics.set("sessions_started", json::Value::Int(static_cast<std::int64_t>(sessions_started)));
  metrics.set("step_attempted", json::Value::Int(static_cast<std::int64_t>(step_attempted)));
  metrics.set("scenario_backend", json::Value::Str(spec.load_model.backend));
  metrics.set("scenario_vus_target", json::Value::Int(spec.load_model.concurrent_vus));
  metrics.set("scenario_ramp_seconds", json::Value::Int(spec.load_model.ramp_seconds));

  json::Value out = json::Value::Object();
  out.set("plans_by_worker", std::move(plans_by_worker));
  out.set("metrics", std::move(metrics));
  return out;
}

}  // namespace samurai::scenario_native
