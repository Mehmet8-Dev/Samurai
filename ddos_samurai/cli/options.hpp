#pragma once

// Parsed command-line options for the native Samurai CLI.
//
// This is the C/C++ replacement for the Python ddos_samurai/cli package. The
// argument surface is parsed into this struct (args.*), validated
// (validation.*), and handed to the orchestrator. Extend CliOptions/JobOptions
// together as more of the former Python CLI flags are ported.

#include <string>
#include <vector>

#include "job_builder.hpp"  // samurai::orchestrator::JobOptions
#include "kpi_gate.hpp"      // samurai::cli::KpiThresholds

namespace samurai::cli {

struct CliOptions {
  std::string worker_name;              // required: cpu/gpu/dpdk/afxdp/doca/l7/defense/scenario
  std::string worker_dir = ".";         // directory containing the worker binaries
  int timeout_ms = 5000;                // per-recv timeout on the events channel
  samurai::orchestrator::JobOptions job;  // maps onto the wire JobEnvelopeV1/V2
  bool show_help = false;
  bool list_profiles = false;             // --list-profiles: print and exit
  KpiThresholds kpi;                      // KPI-gate thresholds (--kpi-*)
  std::string report_json_path;           // --report-json PATH (empty = off)
  std::string report_text_path;           // --report-text PATH (empty = off)
  std::string run_rfc_suite;              // --run-rfc-suite rfc2544|rfc3511|rfc8219|all
  std::string rfc_report_out;             // --rfc-report-out PATH (empty = off)
  // Target-safety gate (core::ValidateTargetSafety).
  bool allow_public = false;              // --allow-public-target
  std::vector<std::string> allow_targets;  // --allow-target IP|CIDR (repeatable)
  std::vector<std::string> deny_targets;   // --deny-target IP|CIDR (repeatable)
  std::string license_key;                 // --license-key KEY
  std::string license_file;                // --license-file PATH
  bool confirm = false;                    // --confirm: confirm live dataplane execution
};

}  // namespace samurai::cli
