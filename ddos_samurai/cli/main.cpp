// samurai — native CLI entrypoint.
//
// Native replacement for ddos_samurai/cli/__main__.py + app.py. Thin driver:
// parse (args) -> validate (validation) -> run the job via the orchestrator's
// ZMQ supervisor. The CLI surface grows toward parity with the former Python
// cli/ package.

#include <cstdio>
#include <string>

#include <unistd.h>

#include "args.hpp"
#include "options.hpp"
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

  return orchestrator::RunJob(cfg, opt.job);
}
