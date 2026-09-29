// samurai — native CLI entrypoint.
//
// Thin driver: parse (args) -> validate (validation) -> run the job via the
// orchestrator's ZMQ supervisor.

#include <cstdio>
#include <string>

#include <unistd.h>

#include "args.hpp"
#include "kpi_gate.hpp"
#include "options.hpp"
#include "profiles.hpp"
#include "reporting.hpp"
#include "rfc_suite.hpp"
#include "run_summary.hpp"
#include "supervisor.hpp"
#include "validation.hpp"
#include "worker_registry.hpp"

int main(int argc, char** argv) {
  using namespace samurai;

  cli::CliOptions opt;
  const cli::ParseStatus status = cli::ParseArgs(argc, argv, opt);
  if (status == cli::ParseStatus::kHelp) {
    cli::PrintUsage(argv[0]);
    return 0;
  }
  if (status == cli::ParseStatus::kError) {
    cli::PrintUsage(argv[0]);
    return 2;
  }
  if (opt.list_profiles) {
    cli::ListProfiles();
    return 0;
  }

  if (!opt.run_rfc_suite.empty()) {
    cli::Rfc2544Config c2544;
    cli::Rfc3511Config c3511;
    cli::Rfc8219Config c8219;
    const cli::RfcSuiteResult res = cli::RfcSuiteEngine::RunAll(c2544, c3511, c8219);
    const std::string md_report = cli::RfcReportGenerator::GenerateMarkdownReport(res);
    const std::string html_report = cli::RfcReportGenerator::GenerateHtmlReport(res);
    std::printf("%s\n", md_report.c_str());

    if (!opt.rfc_report_out.empty()) {
      if (!cli::WriteReportFile(opt.rfc_report_out, html_report)) {
        std::fprintf(stderr, "samurai: failed to write RFC report to %s\n", opt.rfc_report_out.c_str());
      } else {
        std::printf("RFC Benchmark HTML Report written to: %s\n", opt.rfc_report_out.c_str());
      }
    }
    return res.overall_passed ? 0 : 3;
  }

  if (const auto err = cli::Validate(opt)) {
    std::fprintf(stderr, "samurai: %s\n", err->c_str());
    return 2;
  }

  const auto entry = orchestrator::LookupWorker(opt.worker_name);
  // Validate() already guaranteed this lookup succeeds.
  const std::string suffix = std::to_string(static_cast<long>(getpid()));
  orchestrator::SupervisorConfig cfg;
  cfg.worker = *entry;
  cfg.worker_dir = opt.worker_dir;
  cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_" + suffix;
  cfg.events_endpoint = "ipc:///tmp/samurai_events_" + suffix;
  cfg.recv_timeout_ms = opt.timeout_ms;

  orchestrator::RunStats stats;
  int run_status = orchestrator::RunJob(cfg, opt.job, stats);

  // KPI gate: evaluate thresholds against the run stats.
  const cli::KpiGateResult gate = cli::EvaluateKpiGate(opt.kpi, stats);
  if (gate.evaluated) {
    std::printf("%s\n", cli::KpiGateJson(gate).c_str());
    if (!gate.passed && run_status == 0) {
      run_status = 3;  // gate failure surfaces as a non-zero exit
    }
  }

  // Reports.
  if (!opt.report_json_path.empty() || !opt.report_text_path.empty()) {
    cli::RunReport report;
    report.worker_name = opt.worker_name;
    report.job = opt.job;
    report.stats = stats;
    report.gate = gate;
    report.exit_status = run_status;
    if (!opt.report_json_path.empty() &&
        !cli::WriteReportFile(opt.report_json_path, cli::ReportJson(report))) {
      std::fprintf(stderr, "samurai: failed to write %s\n", opt.report_json_path.c_str());
    }
    if (!opt.report_text_path.empty() &&
        !cli::WriteReportFile(opt.report_text_path, cli::ReportText(report))) {
      std::fprintf(stderr, "samurai: failed to write %s\n", opt.report_text_path.c_str());
    }
  }

  return run_status;
}
