#pragma once

// Parsed command-line options for the native Samurai CLI.
//
// This is the C/C++ replacement for the Python ddos_samurai/cli package. The
// argument surface is parsed into this struct (args.*), validated
// (validation.*), and handed to the orchestrator. Extend CliOptions/JobOptions
// together as more of the former Python CLI flags are ported.

#include <string>

#include "job_builder.hpp"  // samurai::orchestrator::JobOptions

namespace samurai::cli {

struct CliOptions {
  std::string worker_name;              // required: cpu/gpu/dpdk/afxdp/doca/l7/defense/scenario
  std::string worker_dir = ".";         // directory containing the worker binaries
  int timeout_ms = 5000;                // per-recv timeout on the events channel
  samurai::orchestrator::JobOptions job;  // maps onto the wire JobEnvelopeV1
  bool show_help = false;
  bool list_profiles = false;             // --list-profiles: print and exit
};

}  // namespace samurai::cli
