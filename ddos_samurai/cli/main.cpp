// samurai — native CLI entrypoint.
//
// Thin driver: parse (args) -> validate (validation) -> run the job via the
// orchestrator's ZMQ supervisor.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include <unistd.h>

#include "anti_tamper.hpp"
#include "args.hpp"
#include "cache.hpp"
#include "client.hpp"
#include "constants.hpp"
#include "gates.hpp"
#include "hwid.hpp"
#include "kpi_gate.hpp"
#include "license_types.hpp"
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

  // 1. Anti-tamper & binary self-integrity verification (after diagnostic flags)
  const licensing::IntegrityResult integrity = licensing::VerifySelfIntegrity();
  if (!integrity.ok) {
    std::fprintf(stderr, "samurai security violation: %s\n", integrity.reason.c_str());
    return 126;
  }

  const bool is_rfc_run = !opt.run_rfc_suite.empty();
  if (is_rfc_run) {
    if (opt.worker_name.empty()) {
      opt.worker_name = "cpu";
    }
    if (!opt.vector_explicit && opt.job.attack_vector == "flood") {
      opt.job.attack_vector = "basic";
    }
  }

  if (const auto err = cli::Validate(opt)) {
    std::fprintf(stderr, "samurai: %s\n", err->c_str());
    return 2;
  }

  // 2. License resolution and feature-gate enforcement
  std::string license_key = opt.license_key;
  if (license_key.empty() && !opt.license_file.empty()) {
    std::ifstream f(opt.license_file);
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      license_key = ss.str();
      const auto first = license_key.find_first_not_of(" \t\r\n");
      const auto last = license_key.find_last_not_of(" \t\r\n");
      license_key = (first == std::string::npos) ? "" : license_key.substr(first, last - first + 1);
    }
  }
  if (license_key.empty()) {
    license_key = licensing::EnvOr("SAMURAI_LICENSE_KEY", "");
  }
  if (license_key.empty()) {
    std::ifstream f(licensing::LicenseKeyFile());
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      license_key = ss.str();
      const auto first = license_key.find_first_not_of(" \t\r\n");
      const auto last = license_key.find_last_not_of(" \t\r\n");
      license_key = (first == std::string::npos) ? "" : license_key.substr(first, last - first + 1);
    }
  }

  const std::string hwid = licensing::GetHardwareId();
  licensing::LicenseResult lr;
  licensing::HttpLicenseClient license_client(licensing::LicenseServerUrl(), licensing::RequestTimeoutS());

  if (licensing::IsDevMode()) {
    lr.valid = true;
    lr.tier = licensing::Tier::kEnterprise;
    lr.features = licensing::TierFeatures(licensing::Tier::kEnterprise);
  } else if (!license_key.empty()) {
    lr = license_client.Validate(license_key, hwid);
    if (lr.valid) {
      licensing::SaveCache(lr, hwid);
    } else {
      licensing::LicenseResult cached;
      if (licensing::LoadCache(hwid, cached) && cached.valid) {
        lr = cached;
      } else {
        std::fprintf(stderr, "samurai license error: license validation failed: %s\n",
                     lr.reason.empty() ? "invalid license key" : lr.reason.c_str());
        return 2;
      }
    }
  } else {
    if (!licensing::LoadCache(hwid, lr) || !lr.valid) {
      lr.valid = true;
      lr.tier = licensing::Tier::kCommunity;
      lr.features = licensing::TierFeatures(licensing::Tier::kCommunity);
      lr.limits = licensing::TierLimitsFor(licensing::Tier::kCommunity);
    }
  }

  licensing::GateInput gate_in;
  gate_in.attack_vector = opt.job.attack_vector.empty() ? opt.job.protocol : opt.job.attack_vector;
  gate_in.compute_backend = opt.worker_name;
  gate_in.spoof = opt.job.spoof;
  gate_in.rps = opt.job.target_rps;
  if (opt.job.target_rps > 0.0 && opt.job.packet_count > 0) {
    gate_in.duration = static_cast<long>(opt.job.packet_count / opt.job.target_rps);
  } else if (opt.job.packet_count > 0) {
    gate_in.duration = 1;
  }
  gate_in.license_key = license_key;
  gate_in.license_file = opt.license_file;

  licensing::GateResult gate_res = licensing::EnforceFeatureGates(gate_in, lr, &license_client);
  if (!gate_res.ok) {
    std::fprintf(stderr, "samurai license error: %s\n%s\n", gate_res.error.c_str(), gate_res.upgrade_hint.c_str());
    return 2;
  }
  for (const auto& w : gate_res.warnings) {
    std::fprintf(stderr, "samurai license warning: %s\n", w.c_str());
  }
  if (gate_res.rps > 0.0 && (opt.job.target_rps <= 0.0 || opt.job.target_rps > gate_res.rps)) {
    opt.job.target_rps = gate_res.rps;
  }
  if (gate_res.duration > 0 && gate_in.duration > gate_res.duration && opt.job.target_rps > 0.0) {
    opt.job.packet_count = static_cast<uint32_t>(gate_res.duration * opt.job.target_rps);
  }

  if (is_rfc_run) {
    cli::Rfc2544Config c2544;
    cli::Rfc3511Config c3511;
    cli::Rfc8219Config c8219;
    if (opt.job.packet_size > 0) {
      c2544.packet_size_bytes = opt.job.packet_size;
    }
    if (gate_res.rps > 0.0) {
      c2544.max_rate_rps = std::min(c2544.max_rate_rps, gate_res.rps);
      c2544.min_rate_rps = std::min(c2544.min_rate_rps, std::max(1.0, c2544.max_rate_rps * 0.1));
      c2544.resolution_rps = std::min(c2544.resolution_rps, std::max(1.0, c2544.max_rate_rps * 0.05));
      c3511.target_cps = std::min(c3511.target_cps, gate_res.rps);
    }

    bool live_dataplane = opt.confirm && !opt.job.target_ip.empty();
    std::function<cli::Rfc2544Trial(double trial_rps)> trial_runner;
    std::function<cli::Rfc3511Sample(double cps)> cps_runner;
    std::function<cli::Rfc8219Sample(double gbps)> inspection_runner;
    orchestrator::WarmWorkerPool rfc_pool;

    if (live_dataplane) {
      const auto rfc_entry = orchestrator::LookupWorker(opt.worker_name);
      if (rfc_entry.has_value()) {
        const std::string suffix = std::to_string(static_cast<long>(getpid()));
        orchestrator::SupervisorConfig sup_cfg;
        sup_cfg.worker = *rfc_entry;
        sup_cfg.worker_dir = opt.worker_dir;
        sup_cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_rfc_" + suffix;
        sup_cfg.events_endpoint = "ipc:///tmp/samurai_events_rfc_" + suffix;
        sup_cfg.recv_timeout_ms = opt.timeout_ms;

        trial_runner = [sup_cfg, opt, c2544, &rfc_pool](double trial_rps) -> cli::Rfc2544Trial {
          orchestrator::JobOptions job = opt.job;
          job.target_rps = trial_rps;
          job.pacing_mode = trial_rps > 0.0 ? 1u : 0u;
          const double duration = std::max(0.5, c2544.trial_duration_s);
          job.packet_count = static_cast<uint32_t>(std::max(1.0, trial_rps * duration));
          if (job.telco_duration_ms == 0) {
            job.telco_duration_ms = static_cast<std::uint32_t>(duration * 1000.0);
          }
          orchestrator::RunStats stats;
          const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
          cli::Rfc2544Trial trial;
          trial.rate_rps = (stats.actual_rps > 0.0) ? stats.actual_rps : trial_rps;
          trial.sent_packets = stats.attempted;
          trial.received_packets = (stats.sent >= stats.errors) ? (stats.sent - stats.errors) : 0;
          trial.loss_pct = (rc != 0 || stats.attempted == 0)
                               ? 100.0
                               : std::clamp(stats.wire_loss_est_pct, 0.0, 100.0);
          return trial;
        };

        cps_runner = [sup_cfg, opt, &rfc_pool](double target_cps) -> cli::Rfc3511Sample {
          orchestrator::JobOptions job = opt.job;
          job.target_rps = target_cps;
          job.pacing_mode = target_cps > 0.0 ? 1u : 0u;
          job.packet_count = static_cast<uint32_t>(std::max(1.0, target_cps * 2.0));
          job.telco_rate_cps = static_cast<std::uint32_t>(std::max(1.0, target_cps));
          orchestrator::RunStats stats;
          const auto t0 = std::chrono::steady_clock::now();
          const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
          const double elapsed_ms =
              std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
          cli::Rfc3511Sample sample;
          sample.ok = (rc == 0 && stats.attempted > 0);
          sample.achieved_cps =
              (stats.telco_current_cps > 0) ? static_cast<double>(stats.telco_current_cps) : stats.actual_rps;
          if (stats.l7_request_latency_p99_ms > 0.0) {
            sample.p99_latency_ms = stats.l7_request_latency_p99_ms;
          } else if (stats.telco_p99_setup_latency_us > 0) {
            sample.p99_latency_ms = static_cast<double>(stats.telco_p99_setup_latency_us) / 1000.0;
          } else if (stats.telco_avg_setup_latency_us > 0) {
            sample.p99_latency_ms = static_cast<double>(stats.telco_avg_setup_latency_us) / 1000.0;
          } else {
            sample.p99_latency_ms = elapsed_ms / static_cast<double>(std::max<std::uint64_t>(1, stats.sent));
          }
          if (opt.job.concurrency > 1) {
            sample.max_concurrency = opt.job.concurrency;
          } else if (opt.worker_name == "telco" && opt.job.telco_subscribers > 0) {
            sample.max_concurrency = opt.job.telco_subscribers;
          } else {
            sample.max_concurrency = static_cast<uint32_t>(std::min<std::uint64_t>(
                stats.sent, static_cast<std::uint64_t>(UINT32_MAX)));
          }
          return sample;
        };

        inspection_runner = [sup_cfg, opt, &rfc_pool](double) -> cli::Rfc8219Sample {
          orchestrator::JobOptions job = opt.job;
          orchestrator::RunStats stats;
          const auto t0 = std::chrono::steady_clock::now();
          const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
          const double elapsed_s = std::max(
              1e-6, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
          cli::Rfc8219Sample sample;
          sample.ok = (rc == 0 && stats.attempted > 0);
          sample.inspection_pass_rate_pct =
              sample.ok ? std::clamp(100.0 - stats.wire_loss_est_pct, 0.0, 100.0) : 0.0;
          if (stats.bytes_sent > 0) {
            sample.measured_gbps = (static_cast<double>(stats.bytes_sent) * 8.0) / (elapsed_s * 1e9);
          } else {
            sample.measured_gbps = (stats.actual_rps * static_cast<double>(opt.job.packet_size) * 8.0) / 1e9;
          }
          return sample;
        };
      } else {
        live_dataplane = false;
      }
    }

    const cli::RfcSuiteResult res = cli::RfcSuiteEngine::RunAllMeasured(
        c2544, c3511, c8219, trial_runner, cps_runner, inspection_runner, live_dataplane);
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
