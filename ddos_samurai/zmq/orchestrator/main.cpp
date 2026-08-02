// samurai — native orchestrator/CLI entrypoint.
//
// Minimal native front-end that selects a worker, builds a job envelope from CLI
// flags, and drives one job to completion via the ZMQ supervisor. This is the
// seed of the native CLI/orchestrator that replaces the Python entrypoint; the
// argument surface grows as more of the Python CLI is ported.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <unistd.h>

#include "job_builder.hpp"
#include "supervisor.hpp"
#include "worker_registry.hpp"

namespace {

using namespace samurai::orchestrator;

void PrintUsage(const char* argv0) {
  std::printf(
      "usage: %s --worker <cpu|gpu|dpdk|afxdp|doca|l7|defense|scenario> [options]\n"
      "\n"
      "options:\n"
      "  --worker NAME       worker backend to run (required)\n"
      "  --worker-dir DIR    directory containing the worker binaries (default: .)\n"
      "  --target IP         target IPv4 address (default: 127.0.0.1)\n"
      "  --port N            target port (default: 80)\n"
      "  --count N           packet count (default: 1000)\n"
      "  --size N            packet size in bytes (default: 64)\n"
      "  --rps F             target rate; 0 = as fast as possible (default: 0)\n"
      "  --protocol NAME     l4 protocol, e.g. udp/tcp (default: udp)\n"
      "  --vector NAME       attack vector label (default: flood)\n"
      "  --pin-cpu N         pin worker to CPU core (default: -1 = none)\n"
      "  --timeout-ms N      per-recv timeout on the events channel (default: 5000)\n"
      "  -h, --help          show this help\n",
      argv0);
}

bool NeedsValue(int i, int argc, const char* flag) {
  if (i + 1 >= argc) {
    std::fprintf(stderr, "samurai: missing value for %s\n", flag);
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string worker_name;
  std::string worker_dir = ".";
  int timeout_ms = 5000;
  JobOptions job;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      PrintUsage(argv[0]);
      return 0;
    } else if (a == "--worker") {
      if (!NeedsValue(i, argc, "--worker")) return 2;
      worker_name = argv[++i];
    } else if (a == "--worker-dir") {
      if (!NeedsValue(i, argc, "--worker-dir")) return 2;
      worker_dir = argv[++i];
    } else if (a == "--target") {
      if (!NeedsValue(i, argc, "--target")) return 2;
      job.target_ip = argv[++i];
    } else if (a == "--port") {
      if (!NeedsValue(i, argc, "--port")) return 2;
      job.target_port = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--count") {
      if (!NeedsValue(i, argc, "--count")) return 2;
      job.packet_count = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--size") {
      if (!NeedsValue(i, argc, "--size")) return 2;
      job.packet_size = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--rps") {
      if (!NeedsValue(i, argc, "--rps")) return 2;
      job.target_rps = std::strtod(argv[++i], nullptr);
      job.pacing_mode = job.target_rps > 0.0 ? 1u : 0u;
    } else if (a == "--protocol") {
      if (!NeedsValue(i, argc, "--protocol")) return 2;
      job.protocol = argv[++i];
    } else if (a == "--vector") {
      if (!NeedsValue(i, argc, "--vector")) return 2;
      job.attack_vector = argv[++i];
    } else if (a == "--pin-cpu") {
      if (!NeedsValue(i, argc, "--pin-cpu")) return 2;
      job.pin_cpu = static_cast<std::int32_t>(std::strtol(argv[++i], nullptr, 10));
    } else if (a == "--timeout-ms") {
      if (!NeedsValue(i, argc, "--timeout-ms")) return 2;
      timeout_ms = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
    } else {
      std::fprintf(stderr, "samurai: unknown argument: %s\n", a.c_str());
      PrintUsage(argv[0]);
      return 2;
    }
  }

  if (worker_name.empty()) {
    std::fprintf(stderr, "samurai: --worker is required\n");
    PrintUsage(argv[0]);
    return 2;
  }

  const auto entry = LookupWorker(worker_name);
  if (!entry) {
    std::fprintf(stderr, "samurai: unknown worker: %s\n", worker_name.c_str());
    return 2;
  }

  const std::string suffix = std::to_string(static_cast<long>(getpid()));
  SupervisorConfig cfg;
  cfg.worker = *entry;
  cfg.worker_dir = worker_dir;
  cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_" + suffix;
  cfg.events_endpoint = "ipc:///tmp/samurai_events_" + suffix;
  cfg.recv_timeout_ms = timeout_ms;

  return RunJob(cfg, job);
}
