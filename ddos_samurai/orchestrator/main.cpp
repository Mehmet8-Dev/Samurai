// samurai — native orchestrator/CLI entrypoint.
//
// Thin driver: parse (cli/cli_parser) -> validate (cli/cli_validate) -> run the
// job via the ZMQ supervisor. This is the seed of the native CLI/orchestrator
// that replaces the Python entrypoint; the CLI surface lives in cli/ and grows
// toward parity with ddos_samurai/cli/.

#include <cstdio>
#include <string>

#include <unistd.h>

#include "cli/cli_options.hpp"
#include "cli/cli_parser.hpp"
#include "cli/cli_validate.hpp"
#include "supervisor.hpp"
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
