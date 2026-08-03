#include "kpi_gate.hpp"

#include <cstdio>
#include <string>

namespace samurai::cli {

namespace {

void AddRule(KpiGateResult& out, const std::string& name, KpiCmp cmp,
             double threshold, double actual) {
  const bool passed = (cmp == KpiCmp::kMin) ? (actual >= threshold) : (actual <= threshold);
  out.rules.push_back(KpiRule{name, cmp, threshold, actual, passed});
  if (!passed) {
    out.passed = false;
  }
}

}  // namespace

KpiGateResult EvaluateKpiGate(const KpiThresholds& t, const samurai::orchestrator::RunStats& s) {
  KpiGateResult r;
  if (!t.any()) {
    return r;  // evaluated=false, passed=true
  }
  r.evaluated = true;
  if (t.min_rate_accuracy_pct) {
    AddRule(r, "rate_accuracy_pct", KpiCmp::kMin, *t.min_rate_accuracy_pct, s.rate_accuracy_pct);
  }
  if (t.max_wire_loss_pct) {
    AddRule(r, "wire_loss_est_pct", KpiCmp::kMax, *t.max_wire_loss_pct, s.wire_loss_est_pct);
  }
  if (t.max_errors) {
    AddRule(r, "errors", KpiCmp::kMax, *t.max_errors, static_cast<double>(s.errors));
  }
  if (t.min_sent) {
    AddRule(r, "sent", KpiCmp::kMin, *t.min_sent, static_cast<double>(s.sent));
  }
  return r;
}

std::string KpiGateJson(const KpiGateResult& r) {
  std::string out = "{\"event\":\"kpi_gate\",\"evaluated\":";
  out += r.evaluated ? "true" : "false";
  out += ",\"passed\":";
  out += r.passed ? "true" : "false";
  out += ",\"rules\":[";
  for (std::size_t i = 0; i < r.rules.size(); ++i) {
    const KpiRule& k = r.rules[i];
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "%s{\"name\":\"%s\",\"cmp\":\"%s\",\"threshold\":%.4f,\"actual\":%.4f,\"passed\":%s}",
                  i == 0 ? "" : ",",
                  k.name.c_str(),
                  k.cmp == KpiCmp::kMin ? "min" : "max",
                  k.threshold, k.actual,
                  k.passed ? "true" : "false");
    out += buf;
  }
  out += "]}";
  return out;
}

}  // namespace samurai::cli
