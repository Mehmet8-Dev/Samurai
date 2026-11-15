#include "sla.hpp"

#include <algorithm>

namespace samurai::scenario_native {

namespace json = samurai::core::json;

static double SlaFloat(const json::Value& sla, const std::string& key, double def) {
  const json::Value* p = sla.find(key);
  return p != nullptr ? p->as_double(def) : def;
}

json::Value evaluate_sla_native(
    const json::Value& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    double latency_p95_ms,
    bool has_latency,
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
  const double min_completion_rate = SlaFloat(sla, "min_completion_rate", 0.95);
  const double max_step_fail_ratio = SlaFloat(sla, "max_step_fail_ratio", 0.05);

  bool latency_ok = true;
  double max_latency_ms = 0.0;
  bool has_max_latency = false;
  const json::Value* max_latency_obj = sla.find("max_latency_p95_ms");
  if (max_latency_obj != nullptr && !max_latency_obj->is_null()) {
    has_max_latency = true;
    max_latency_ms = max_latency_obj->as_double(0.0);
    if (has_latency) {
      latency_ok = latency_p95_ms <= max_latency_ms;
    }
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
    const double max_connect_timeout_ratio = SlaFloat(sla, "max_connect_timeout_ratio", 1.0);
    const double max_retransmit_ratio = SlaFloat(sla, "max_retransmit_ratio", 1.0);
    l4_ok = connect_timeout_ratio <= max_connect_timeout_ratio && retransmit_ratio <= max_retransmit_ratio;
  }
  const bool final_ok = ok && l4_ok;

  json::Value detail = json::Value::Object();
  detail.set("session_completion_rate", json::Value::Double(completion_rate));
  detail.set("l7_step_fail_ratio", json::Value::Double(step_fail_ratio));
  detail.set("sla_min_completion_rate", json::Value::Double(min_completion_rate));
  detail.set("sla_max_step_fail_ratio", json::Value::Double(max_step_fail_ratio));
  detail.set("sla_max_latency_p95_ms",
             has_max_latency ? json::Value::Double(max_latency_ms) : json::Value::Null());
  detail.set("sla_latency_p95_ms",
             has_latency ? json::Value::Double(latency_p95_ms) : json::Value::Null());
  detail.set("tcp_connect_attempts", json::Value::Int(connect_attempts));
  detail.set("tcp_connect_established", json::Value::Int(connect_established));
  detail.set("tcp_retransmit_count", json::Value::Int(retransmit_count));
  detail.set("tcp_timeout_close_count", json::Value::Int(timeout_close_count));
  detail.set("tcp_connect_timeout_ratio", json::Value::Double(connect_timeout_ratio));
  detail.set("tcp_retransmit_ratio", json::Value::Double(retransmit_ratio));
  detail.set("sla_max_connect_timeout_ratio",
             json::Value::Double(SlaFloat(sla, "max_connect_timeout_ratio", 1.0)));
  detail.set("sla_max_retransmit_ratio",
             json::Value::Double(SlaFloat(sla, "max_retransmit_ratio", 1.0)));
  detail.set("sla_passed", json::Value::Int(final_ok ? 1 : 0));

  json::Value out = json::Value::Object();
  out.set("passed", json::Value::Bool(final_ok));
  out.set("detail", std::move(detail));
  return out;
}

}  // namespace samurai::scenario_native
