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

  // Phase 6 L7 Gates
  if (t.min_tls_handshakes) {
    AddRule(r, "tls_handshakes", KpiCmp::kMin, *t.min_tls_handshakes, static_cast<double>(s.tls_handshakes_completed));
  }
  if (t.min_dns_queries) {
    AddRule(r, "dns_queries", KpiCmp::kMin, *t.min_dns_queries, static_cast<double>(s.dns_queries_sent));
  }
  if (t.min_dhcp_leases) {
    AddRule(r, "dhcp_leases", KpiCmp::kMin, *t.min_dhcp_leases, static_cast<double>(s.dhcp_leases_active));
  }
  if (t.min_zc_tx_bytes) {
    AddRule(r, "zc_tx_bytes", KpiCmp::kMin, *t.min_zc_tx_bytes, static_cast<double>(s.hot_path_zero_copy_tx_bytes));
  }
  if (t.max_tcp_overflows) {
    AddRule(r, "tcp_timer_overflows", KpiCmp::kMax, *t.max_tcp_overflows, static_cast<double>(s.tcp_timer_wheel_overflows));
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
