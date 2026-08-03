#pragma once

// Native run reporting. C++ reimplementation of the essentials from the former
// ddos_samurai/reporting.py: assemble a run report from the job context, the
// aggregated run stats, and the KPI-gate verdict, and serialize it as JSON or a
// human-readable text summary that can be written to a file.

#include <string>

#include "job_builder.hpp"  // samurai::orchestrator::JobOptions
#include "kpi_gate.hpp"      // samurai::cli::KpiGateResult
#include "run_summary.hpp"   // samurai::orchestrator::RunStats

namespace samurai::cli {

struct RunReport {
  std::string worker_name;
  samurai::orchestrator::JobOptions job;
  samurai::orchestrator::RunStats stats;
  KpiGateResult gate;
  int exit_status = 0;
};

// Serializes the report as pretty-ish JSON (was write_json).
std::string ReportJson(const RunReport& r);

// Serializes the report as a human-readable text summary (was write_text/markdown).
std::string ReportText(const RunReport& r);

// Writes `content` to `path` (parent dirs must exist). Returns true on success.
bool WriteReportFile(const std::string& path, const std::string& content);

}  // namespace samurai::cli
