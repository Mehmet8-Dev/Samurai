#pragma once

// SUT-correlation probe (#3). During a load run the master scrapes the
// system-under-test's own observability so a run can be explained in terms of
// the target's behaviour ("at 240k rps the DB pool saturates and p99 explodes"),
// not just the generator's counters. v1 source: a Prometheus HTTP API
// (/api/v1/query, PromQL instant queries).
//
// The primary tie-in is the closed-loop controller: the p99-latency query feeds
// LoadSample::latency_p99_ms, which activates the otherwise-inert latency SLO so
// the autopilot searches for "max rps with SUT p99 < X". Extra queries (CPU,
// error rate, pool usage, ...) are surfaced for the correlation report.
//
// Uses the shared samurai_core HTTP(S) client; no extra dependency.

#include <map>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

struct SutQuery {
  std::string name;    // label in the sample/report, e.g. "cpu_pct"
  std::string promql;  // PromQL instant query
};

struct SutProbeConfig {
  bool enabled = false;
  std::string prometheus_url;     // e.g. http://127.0.0.1:9090
  std::string latency_p99_query;  // PromQL returning p99 latency in ms (drives the SLO)
  std::vector<SutQuery> extra;    // additional correlation metrics
  bool insecure = false;          // skip TLS verify (dev)
  int timeout_s = 5;
};

struct SutSample {
  bool ok = false;                       // at least one query returned a value
  double latency_p99_ms = -1.0;          // -1 => not queried / not found
  std::map<std::string, double> metrics; // name -> value (includes latency_p99_ms when present)
  std::string error;                     // populated when a query failed
};

// Parse a Prometheus /api/v1/query response body into a single scalar (the first
// vector result's value, or a scalar result). Exposed for unit tests (no
// network). Returns false with `err` set when no numeric value is present.
bool ParsePromInstantScalar(const std::string& json_body, double& out, std::string& err);

// Build a /api/v1/query URL for `promql` against `base` (URL-encoded query).
std::string BuildPromQueryUrl(const std::string& base, const std::string& promql);

class SutProbe {
 public:
  explicit SutProbe(const SutProbeConfig& cfg) : cfg_(cfg) {}
  bool enabled() const { return cfg_.enabled && !cfg_.prometheus_url.empty(); }

  // Run every configured query and merge the results into one sample.
  SutSample Scrape() const;

  const SutProbeConfig& config() const { return cfg_; }

  // Serialize a sample as a JSON object for the run report / closed_loop state.
  static samurai::core::json::Value SampleJson(const SutSample& s);

 private:
  SutProbeConfig cfg_;
};

}  // namespace samurai::control
