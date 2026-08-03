#pragma once

// Native worker supervisor: spawns a compiled worker daemon and drives a single
// job over the shared ZMQ wire protocol, then shuts the worker down cleanly.
//
// This is the native-C++ core of what the Python orchestrator used to do in
// `start_worker_zmq`: pick a worker, hand it a job envelope, collect its metric
// snapshots, and tear it down. It links only libzmq + the shared wire headers.

#include <cstdint>
#include <string>

#include "job_builder.hpp"
#include "run_summary.hpp"
#include "wire_protocol.h"
#include "worker_registry.hpp"

namespace samurai::orchestrator {

struct SupervisorConfig {
  WorkerEntry worker;                 // which worker binary to spawn
  std::string worker_dir = ".";       // directory containing the worker binary
  std::string jobs_endpoint;          // ipc/tcp endpoint for the jobs channel
  std::string events_endpoint;        // ipc/tcp endpoint for the events channel
  int recv_timeout_ms = 5000;         // per-recv timeout on the events socket
  int max_idle_recvs = 24;            // give up after this many empty recvs
};

// Runs one job end-to-end. Returns the worker process exit status (0 on a clean
// JOB_DONE), or a negative value on a supervisor-side error. The aggregated
// run statistics are written to `out_stats` for reporting / KPI gating.
int RunJob(const SupervisorConfig& cfg, const JobOptions& job, RunStats& out_stats);

}  // namespace samurai::orchestrator
