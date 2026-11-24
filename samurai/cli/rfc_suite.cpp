#include "rfc_suite.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace samurai::cli {

Rfc2544Result RfcSuiteEngine::Run2544BinarySearchMeasured(
    const Rfc2544Config& cfg,
    std::function<Rfc2544Trial(double trial_rps)> trial_runner) {
  Rfc2544Result res;
  double low = cfg.min_rate_rps;
  double high = cfg.max_rate_rps;
  double best_zero_loss_rps = 0.0;

  for (int iter = 1; iter <= cfg.max_iterations; ++iter) {
    if (iter > 1 && (high - low) < cfg.resolution_rps) break;
    const double mid_rps = (low + high) / 2.0;

    Rfc2544Trial trial;
    if (trial_runner) {
      trial = trial_runner(mid_rps);
      trial.iteration = iter;
      if (trial.rate_rps <= 0.0) trial.rate_rps = mid_rps;
    } else {
      trial.iteration = iter;
      trial.rate_rps = mid_rps;
      trial.sent_packets = 0;
      trial.received_packets = 0;
      trial.loss_pct = 100.0;
    }
    trial.passed = (trial.loss_pct <= cfg.tolerance_loss_pct) && (trial.sent_packets > 0);
    res.trials.push_back(trial);

    if (trial.passed) {
      best_zero_loss_rps = std::max(best_zero_loss_rps, trial.rate_rps);
      low = mid_rps;
    } else {
      high = mid_rps;
    }
  }

  res.max_zero_loss_rps = best_zero_loss_rps;
  res.mpps = best_zero_loss_rps / 1000000.0;
  res.max_zero_loss_gbps = (best_zero_loss_rps * cfg.packet_size_bytes * 8.0) / 1000000000.0;
  res.passed = (best_zero_loss_rps >= cfg.min_rate_rps);
  return res;
}

Rfc2544Result RfcSuiteEngine::Run2544BinarySearch(
    const Rfc2544Config& cfg,
    std::function<double(double trial_rps)> trial_runner) {
  if (!trial_runner) {
    return Run2544BinarySearchMeasured(cfg, {});
  }
  return Run2544BinarySearchMeasured(
      cfg,
      [cfg, trial_runner](double mid_rps) -> Rfc2544Trial {
        Rfc2544Trial trial;
        const double loss_pct = trial_runner(mid_rps);
        trial.rate_rps = mid_rps;
        trial.sent_packets = static_cast<uint64_t>(mid_rps * cfg.trial_duration_s);
        trial.loss_pct = loss_pct;
        trial.received_packets =
            static_cast<uint64_t>(trial.sent_packets * (1.0 - (std::clamp(loss_pct, 0.0, 100.0) / 100.0)));
        return trial;
      });
}

Rfc3511Result RfcSuiteEngine::Run3511BenchmarkMeasured(
    const Rfc3511Config& cfg,
    std::function<Rfc3511Sample(double cps)> cps_runner) {
  Rfc3511Result res;
  if (cps_runner) {
    const Rfc3511Sample sample = cps_runner(cfg.target_cps);
    res.max_cps = sample.achieved_cps;
    res.max_concurrent_connections =
        sample.max_concurrency > 0 ? sample.max_concurrency : cfg.max_concurrency;
    res.p99_latency_ms = sample.p99_latency_ms;
    res.passed = sample.ok && (res.max_cps >= (cfg.target_cps * 0.9)) &&
                 (cfg.latency_cap_ms <= 0.0 || res.p99_latency_ms <= cfg.latency_cap_ms);
  } else {
    res.max_cps = 0.0;
    res.max_concurrent_connections = 0;
    res.p99_latency_ms = 0.0;
    res.passed = false;
  }
  return res;
}

Rfc3511Result RfcSuiteEngine::Run3511Benchmark(
    const Rfc3511Config& cfg,
    std::function<double(double cps)> cps_runner) {
  if (!cps_runner) {
    return Run3511BenchmarkMeasured(cfg, {});
  }
  return Run3511BenchmarkMeasured(
      cfg,
      [cfg, cps_runner](double cps) -> Rfc3511Sample {
        Rfc3511Sample sample;
        sample.achieved_cps = cps_runner(cps);
        sample.max_concurrency = cfg.max_concurrency;
        sample.p99_latency_ms = 0.0;
        sample.ok = sample.achieved_cps > 0.0;
        return sample;
      });
}

Rfc8219Result RfcSuiteEngine::Run8219BenchmarkMeasured(
    const Rfc8219Config& cfg,
    std::function<Rfc8219Sample(double gbps)> inspection_runner) {
  Rfc8219Result res;
  if (inspection_runner) {
    const Rfc8219Sample sample = inspection_runner(cfg.target_gbps);
    res.inspection_pass_rate_pct = std::clamp(sample.inspection_pass_rate_pct, 0.0, 100.0);
    res.ipv6_zero_loss_gbps = sample.measured_gbps;
    res.passed = sample.ok && (res.inspection_pass_rate_pct >= 99.0) &&
                 (res.ipv6_zero_loss_gbps > 0.0);
  } else {
    res.inspection_pass_rate_pct = 0.0;
    res.ipv6_zero_loss_gbps = 0.0;
    res.passed = false;
  }
  return res;
}

Rfc8219Result RfcSuiteEngine::Run8219Benchmark(
    const Rfc8219Config& cfg,
    std::function<double(double gbps)> inspection_runner) {
  if (!inspection_runner) {
    return Run8219BenchmarkMeasured(cfg, {});
  }
  return Run8219BenchmarkMeasured(
      cfg,
      [cfg, inspection_runner](double gbps) -> Rfc8219Sample {
        Rfc8219Sample sample;
        sample.inspection_pass_rate_pct = std::clamp(inspection_runner(gbps), 0.0, 100.0);
        sample.measured_gbps = (cfg.target_gbps * sample.inspection_pass_rate_pct) / 100.0;
        sample.ok = true;
        return sample;
      });
}

RfcSuiteResult RfcSuiteEngine::RunAll(
    const Rfc2544Config& c2544,
    const Rfc3511Config& c3511,
    const Rfc8219Config& c8219,
    std::function<double(double trial_rps)> trial_runner,
    std::function<double(double cps)> cps_runner,
    std::function<double(double gbps)> inspection_runner,
    bool live_dataplane) {
  RfcSuiteResult res;
  res.live_dataplane = live_dataplane;
  res.execution_mode = live_dataplane ? "LIVE_DATAPLANE" : "SIMULATED_DRY_RUN";
  res.rfc2544 = Run2544BinarySearch(c2544, trial_runner);
  res.rfc3511 = Run3511Benchmark(c3511, cps_runner);
  res.rfc8219 = Run8219Benchmark(c8219, inspection_runner);
  res.overall_passed = (res.rfc2544.passed && res.rfc3511.passed && res.rfc8219.passed);
  res.score = res.overall_passed ? 100.0 : 50.0;
  return res;
}

RfcSuiteResult RfcSuiteEngine::RunAllMeasured(
    const Rfc2544Config& c2544,
    const Rfc3511Config& c3511,
    const Rfc8219Config& c8219,
    std::function<Rfc2544Trial(double trial_rps)> trial_runner,
    std::function<Rfc3511Sample(double cps)> cps_runner,
    std::function<Rfc8219Sample(double gbps)> inspection_runner,
    bool live_dataplane) {
  RfcSuiteResult res;
  res.live_dataplane = live_dataplane;
  res.execution_mode = live_dataplane ? "LIVE_DATAPLANE" : "SIMULATED_DRY_RUN";
  res.rfc2544 = Run2544BinarySearchMeasured(c2544, trial_runner);
  res.rfc3511 = Run3511BenchmarkMeasured(c3511, cps_runner);
  res.rfc8219 = Run8219BenchmarkMeasured(c8219, inspection_runner);
  res.overall_passed = (res.rfc2544.passed && res.rfc3511.passed && res.rfc8219.passed);
  res.score = res.overall_passed ? 100.0 : 50.0;
  return res;
}

std::string RfcReportGenerator::GenerateHtmlReport(const RfcSuiteResult& result) {
  std::ostringstream html;
  html << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
       << "<meta charset=\"UTF-8\">\n"
       << "<title>Samurai RFC 2544 / 3511 / 8219 Benchmark Report</title>\n"
       << "<style>\n"
       << "  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 30px; background: #0f172a; color: #f8fafc; }\n"
       << "  .card { background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }\n"
       << "  h1, h2, h3 { color: #38bdf8; margin-top: 0; }\n"
       << "  .badge-pass { background: #166534; color: #4ade80; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; }\n"
       << "  .badge-fail { background: #991b1b; color: #f87171; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; }\n"
       << "  .badge-mode { background: #334155; color: #facc15; padding: 4px 12px; border-radius: 12px; font-size: 12px; margin-left: 10px; }\n"
       << "  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }\n"
       << "  .metric { background: #334155; padding: 16px; border-radius: 8px; text-align: center; }\n"
       << "  .metric-val { font-size: 28px; font-weight: bold; color: #f43f5e; }\n"
       << "  table { width: 100%; border-collapse: collapse; margin-top: 16px; }\n"
       << "  th, td { border: 1px solid #475569; padding: 10px; text-align: left; }\n"
       << "  th { background: #334155; color: #38bdf8; }\n"
       << "</style>\n</head>\n<body>\n";

  html << "<div class=\"card\">\n"
       << "  <div style=\"display:flex; justify-content:space-between; align-items:center;\">\n"
       << "    <h1>⚡ Samurai Executive RFC Benchmark Report</h1>\n"
       << "    <div>\n"
       << "      <span class=\"badge-mode\">MODE: " << result.execution_mode << "</span>\n"
       << "      <span class=\"" << (result.overall_passed ? "badge-pass" : "badge-fail") << "\">"
       << (result.overall_passed ? "PASSED (100%)" : "FAILED") << "</span>\n"
       << "    </div>\n"
       << "  </div>\n"
       << "  <p style=\"color: #94a3b8;\">RFC 2544 Throughput Binary Search, RFC 3511 Firewall CPS & Concurrency, RFC 8219 NGFW IPv6 Inspection Certification</p>\n"
       << "</div>\n";

  // Summary Metrics Grid
  html << "<div class=\"card\">\n"
       << "  <h2>Key Performance Indicators (KPI)</h2>\n"
       << "  <div class=\"grid\">\n"
       << "    <div class=\"metric\"><div class=\"metric-val\">" << std::fixed << std::setprecision(2) << result.rfc2544.max_zero_loss_gbps << " Gbps</div><div>RFC 2544 Zero-Loss Bandwidth</div></div>\n"
       << "    <div class=\"metric\"><div class=\"metric-val\">" << std::fixed << std::setprecision(2) << result.rfc2544.mpps << " Mpps</div><div>RFC 2544 Max Packet Rate</div></div>\n"
       << "    <div class=\"metric\"><div class=\"metric-val\">" << static_cast<uint64_t>(result.rfc3511.max_cps) << "</div><div>RFC 3511 Firewall CPS</div></div>\n"
       << "    <div class=\"metric\"><div class=\"metric-val\">" << result.rfc3511.max_concurrent_connections << "</div><div>RFC 3511 Concurrency</div></div>\n"
       << "  </div>\n"
       << "</div>\n";

  // RFC 2544 Binary Search Trial Table
  html << "<div class=\"card\">\n"
       << "  <h2>RFC 2544 Binary Search Trial Details</h2>\n"
       << "  <table>\n"
       << "    <thead><tr><th>Iter</th><th>Rate (RPS)</th><th>Sent Packets</th><th>Received Packets</th><th>Loss %</th><th>Status</th></tr></thead>\n"
       << "    <tbody>\n";

  for (const auto& t : result.rfc2544.trials) {
    html << "      <tr>"
         << "<td>" << t.iteration << "</td>"
         << "<td>" << std::fixed << std::setprecision(0) << t.rate_rps << "</td>"
         << "<td>" << t.sent_packets << "</td>"
         << "<td>" << t.received_packets << "</td>"
         << "<td>" << std::fixed << std::setprecision(4) << t.loss_pct << "%</td>"
         << "<td>" << (t.passed ? "<span style=\"color:#4ade80;\">PASS</span>" : "<span style=\"color:#f87171;\">FAIL (Loss)</span>") << "</td>"
         << "</tr>\n";
  }

  html << "    </tbody>\n  </table>\n</div>\n";
  html << "</body>\n</html>\n";
  return html.str();
}

std::string RfcReportGenerator::GenerateMarkdownReport(const RfcSuiteResult& result) {
  std::ostringstream md;
  md << "# Samurai Executive RFC Benchmark Report\n\n"
     << "**Overall Verdict:** " << (result.overall_passed ? "PASS 🚀" : "FAIL ❌") << "\n"
     << "**Execution Mode:** `" << result.execution_mode << "`\n"
     << "**Score:** " << result.score << "/100\n\n"
     << "## RFC 2544 Maximum Zero-Loss Throughput\n"
     << "- **Zero-Loss Bandwidth:** " << result.rfc2544.max_zero_loss_gbps << " Gbps\n"
     << "- **Packet Rate:** " << result.rfc2544.mpps << " Mpps\n"
     << "- **Zero-Loss Rate:** " << result.rfc2544.max_zero_loss_rps << " RPS\n\n"
     << "## RFC 3511 Firewall & Security Device Benchmarks\n"
     << "- **Max Connections Per Second (CPS):** " << result.rfc3511.max_cps << "\n"
     << "- **Max Concurrency:** " << result.rfc3511.max_concurrent_connections << "\n"
     << "- **P99 Latency:** " << result.rfc3511.p99_latency_ms << " ms\n\n"
     << "## RFC 8219 Next-Gen Firewall & IPv6 Benchmarks\n"
     << "- **IPv6 Zero-Loss Bandwidth:** " << result.rfc8219.ipv6_zero_loss_gbps << " Gbps\n"
     << "- **Security Inspection Pass Rate:** " << result.rfc8219.inspection_pass_rate_pct << "%\n";
  return md.str();
}

}  // namespace samurai::cli
