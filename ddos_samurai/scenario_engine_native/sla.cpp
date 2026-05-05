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
    py::object latency_p95_ms,
    int tcp_connect_attempts,
    int tcp_connect_established,
    int tcp_retransmit_count,
    int tcp_timeout_close_count) {
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
  const int connect_attempts = std::max(0, tcp_connect_attempts);
  const int connect_established = std::max(0, tcp_connect_established);
  const int retransmit_count = std::max(0, tcp_retransmit_count);
  const int timeout_close_count = std::max(0, tcp_timeout_close_count);
  double connect_timeout_ratio = 0.0;
  double retransmit_ratio = 0.0;
  bool l4_ok = true;
  if (connect_attempts > 0) {
    connect_timeout_ratio = std::max(0.0, 1.0 - (static_cast<double>(connect_established) / static_cast<double>(connect_attempts)));
    retransmit_ratio = std::max(0.0, static_cast<double>(retransmit_count) / static_cast<double>(connect_attempts));
    const double max_connect_timeout_ratio = sla.contains("max_connect_timeout_ratio")
        ? static_cast<double>(py::float_(sla["max_connect_timeout_ratio"]))
        : 1.0;
    const double max_retransmit_ratio = sla.contains("max_retransmit_ratio")
        ? static_cast<double>(py::float_(sla["max_retransmit_ratio"]))
        : 1.0;
    l4_ok = connect_timeout_ratio <= max_connect_timeout_ratio && retransmit_ratio <= max_retransmit_ratio;
  }
  const bool final_ok = ok && l4_ok;

  py::dict detail;
  detail["session_completion_rate"] = completion_rate;
  detail["l7_step_fail_ratio"] = step_fail_ratio;
  detail["sla_min_completion_rate"] = min_completion_rate;
  detail["sla_max_step_fail_ratio"] = max_step_fail_ratio;
  detail["sla_max_latency_p95_ms"] = max_latency_obj;
  detail["sla_latency_p95_ms"] = latency_p95_ms;
  detail["tcp_connect_attempts"] = connect_attempts;
  detail["tcp_connect_established"] = connect_established;
  detail["tcp_retransmit_count"] = retransmit_count;
  detail["tcp_timeout_close_count"] = timeout_close_count;
  detail["tcp_connect_timeout_ratio"] = connect_timeout_ratio;
  detail["tcp_retransmit_ratio"] = retransmit_ratio;
  detail["sla_max_connect_timeout_ratio"] = sla.contains("max_connect_timeout_ratio") ? sla["max_connect_timeout_ratio"] : py::float_(1.0);
  detail["sla_max_retransmit_ratio"] = sla.contains("max_retransmit_ratio") ? sla["max_retransmit_ratio"] : py::float_(1.0);
  detail["sla_passed"] = py::int_(final_ok ? 1 : 0);
  return py::make_tuple(final_ok, detail);
}

}  // namespace ddos_samurai::scenario_native
