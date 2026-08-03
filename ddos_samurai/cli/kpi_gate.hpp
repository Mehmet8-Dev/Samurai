#pragma once

// Native KPI gate. C++ reimplementation of the essential engine from the former
// ddos_samurai/kpi_gate.py: evaluate a set of min/max threshold rules against a
// run's aggregated stats and produce an overall pass/fail verdict.
//
// The Python version carried dozens of domain-specific thresholds keyed off the
// old Python result dicts; here we gate the KPIs the native RunStats actually
// produces. Add rules as the native metric surface grows.

#include <optional>
#include <string>
#include <vector>

#include "run_summary.hpp"  // samurai::orchestrator::RunStats

namespace samurai::cli {

enum class KpiCmp {
  kMin,  // pass when actual >= threshold
  kMax,  // pass when actual <= threshold
};

struct KpiRule {
  std::string name;
  KpiCmp cmp;
  double threshold;
  double actual;
  bool passed;
};

struct KpiGateResult {
  bool evaluated = false;  // false when no thresholds were supplied
  bool passed = true;
  std::vector<KpiRule> rules;
};

// KPI thresholds supplied on the CLI. An unset (nullopt) field disables its rule.
struct KpiThresholds {
  std::optional<double> min_rate_accuracy_pct;  // rate_accuracy_pct >= X
  std::optional<double> max_wire_loss_pct;      // wire_loss_est_pct  <= X
  std::optional<double> max_errors;             // errors             <= X
  std::optional<double> min_sent;               // sent               >= X

  bool any() const {
    return min_rate_accuracy_pct || max_wire_loss_pct || max_errors || min_sent;
  }
};

// Evaluates the thresholds against the run stats.
KpiGateResult EvaluateKpiGate(const KpiThresholds& t, const samurai::orchestrator::RunStats& s);

// Serializes the gate result as a single JSON line.
std::string KpiGateJson(const KpiGateResult& r);

}  // namespace samurai::cli
