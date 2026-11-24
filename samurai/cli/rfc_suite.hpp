#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::cli {

struct Rfc2544Config {
  double min_rate_rps = 1000.0;
  double max_rate_rps = 1000000.0;
  double tolerance_loss_pct = 0.0;     // Default 0.0% loss tolerance for throughput
  double trial_duration_s = 5.0;
  int max_iterations = 10;
  double resolution_rps = 100.0;
  uint32_t packet_size_bytes = 64;
};

struct Rfc2544Trial {
  int iteration = 0;
  double rate_rps = 0.0;
  uint64_t sent_packets = 0;
  uint64_t received_packets = 0;
  double loss_pct = 0.0;
  bool passed = false;
};

struct Rfc2544Result {
  double max_zero_loss_rps = 0.0;
  double max_zero_loss_gbps = 0.0;
  double mpps = 0.0;
  std::vector<Rfc2544Trial> trials;
  bool passed = false;
};

struct Rfc3511Config {
  double target_cps = 50000.0;
  uint32_t max_concurrency = 100000;
  double latency_cap_ms = 50.0;
};

struct Rfc3511Result {
  double max_cps = 0.0;
  uint32_t max_concurrent_connections = 0;
  double p99_latency_ms = 0.0;
  bool passed = false;
};

struct Rfc3511Sample {
  double achieved_cps = 0.0;
  double p99_latency_ms = 0.0;
  uint32_t max_concurrency = 0;
  bool ok = true;
};

struct Rfc8219Config {
  bool ipv6_enabled = true;
  bool deep_inspection_enabled = true;
  double target_gbps = 10.0;
};

struct Rfc8219Result {
  double ipv6_zero_loss_gbps = 0.0;
  double inspection_pass_rate_pct = 100.0;
  bool passed = false;
};

struct Rfc8219Sample {
  double inspection_pass_rate_pct = 0.0;
  double measured_gbps = 0.0;
  bool ok = true;
};

struct RfcSuiteResult {
  Rfc2544Result rfc2544;
  Rfc3511Result rfc3511;
  Rfc8219Result rfc8219;
  double score = 0.0;
  bool overall_passed = false;
  bool live_dataplane = false;
  std::string suite = "all";
  std::string execution_mode = "REQUIRES_LIVE_TARGET";
};

class RfcSuiteEngine {
 public:
  static Rfc2544Result Run2544BinarySearch(
      const Rfc2544Config& cfg,
      std::function<double(double trial_rps)> trial_runner = {});

  static Rfc2544Result Run2544BinarySearchMeasured(
      const Rfc2544Config& cfg,
      std::function<Rfc2544Trial(double trial_rps)> trial_runner);

  static Rfc3511Result Run3511Benchmark(
      const Rfc3511Config& cfg,
      std::function<double(double cps)> cps_runner = {});

  static Rfc3511Result Run3511BenchmarkMeasured(
      const Rfc3511Config& cfg,
      std::function<Rfc3511Sample(double cps)> cps_runner);

  static Rfc8219Result Run8219Benchmark(
      const Rfc8219Config& cfg,
      std::function<double(double gbps)> inspection_runner = {});

  static Rfc8219Result Run8219BenchmarkMeasured(
      const Rfc8219Config& cfg,
      std::function<Rfc8219Sample(double gbps)> inspection_runner);

  static RfcSuiteResult RunAll(
      const Rfc2544Config& c2544,
      const Rfc3511Config& c3511,
      const Rfc8219Config& c8219,
      std::function<double(double trial_rps)> trial_runner = {},
      std::function<double(double cps)> cps_runner = {},
      std::function<double(double gbps)> inspection_runner = {},
      bool live_dataplane = false);

  static RfcSuiteResult RunAllMeasured(
      const Rfc2544Config& c2544,
      const Rfc3511Config& c3511,
      const Rfc8219Config& c8219,
      std::function<Rfc2544Trial(double trial_rps)> trial_runner,
      std::function<Rfc3511Sample(double cps)> cps_runner,
      std::function<Rfc8219Sample(double gbps)> inspection_runner,
      bool live_dataplane = true,
      const std::string& suite = "all");
};

class RfcReportGenerator {
 public:
  static std::string GenerateHtmlReport(const RfcSuiteResult& result);
  static std::string GenerateMarkdownReport(const RfcSuiteResult& result);
};

}  // namespace samurai::cli
