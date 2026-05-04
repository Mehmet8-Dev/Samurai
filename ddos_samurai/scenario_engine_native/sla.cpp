#include "sla.hpp"

#include <algorithm>

namespace py = pybind11;

namespace ddos_samurai::scenario_native {

py::tuple evaluate_sla_native(
    const py::dict& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    py::object latency_p95_ms) {
  const int started = std::max(0, sessions_started);
  const int completed = std::max(0, sessions_completed);
  const int attempted = std::max(0, step_attempted);
  const int failed = std::max(0, step_failed);
  const double completion_rate = static_cast<double>(completed) / static_cast<double>(std::max(1, started));
  const double step_fail_ratio = static_cast<double>(failed) / static_cast<double>(std::max(1, attempted));
  const double min_completion_rate = sla.contains("min_completion_rate")
      ? static_cast<double>(py::float_(sla["min_completion_rate"]))
      : 0.95;
  const double max_step_fail_ratio = sla.contains("max_step_fail_ratio")
      ? static_cast<double>(py::float_(sla["max_step_fail_ratio"]))
      : 0.05;

  bool latency_ok = true;
  py::object max_latency_obj = py::none();
  if (sla.contains("max_latency_p95_ms")) max_latency_obj = sla["max_latency_p95_ms"];
  if (!max_latency_obj.is_none() && !latency_p95_ms.is_none()) {
    latency_ok = py::float_(latency_p95_ms) <= py::float_(max_latency_obj);
  }
  const bool ok = completion_rate >= min_completion_rate &&
                  step_fail_ratio <= max_step_fail_ratio &&
                  latency_ok;

  py::dict detail;
  detail["session_completion_rate"] = completion_rate;
  detail["l7_step_fail_ratio"] = step_fail_ratio;
  detail["sla_min_completion_rate"] = min_completion_rate;
  detail["sla_max_step_fail_ratio"] = max_step_fail_ratio;
  detail["sla_max_latency_p95_ms"] = max_latency_obj;
  detail["sla_latency_p95_ms"] = latency_p95_ms;
  detail["sla_passed"] = py::int_(ok ? 1 : 0);
  return py::make_tuple(ok, detail);
}

}  // namespace ddos_samurai::scenario_native
