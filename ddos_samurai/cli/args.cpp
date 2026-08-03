#include "args.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace samurai::cli {

namespace {

bool NeedsValue(int i, int argc, const char* flag) {
  if (i + 1 >= argc) {
    std::fprintf(stderr, "samurai: missing value for %s\n", flag);
    return false;
  }
  return true;
}

}  // namespace

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

ParseStatus ParseArgs(int argc, char** argv, CliOptions& out) {
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      out.show_help = true;
      return ParseStatus::kHelp;
    } else if (a == "--worker") {
      if (!NeedsValue(i, argc, "--worker")) return ParseStatus::kError;
      out.worker_name = argv[++i];
    } else if (a == "--worker-dir") {
      if (!NeedsValue(i, argc, "--worker-dir")) return ParseStatus::kError;
      out.worker_dir = argv[++i];
    } else if (a == "--target") {
      if (!NeedsValue(i, argc, "--target")) return ParseStatus::kError;
      out.job.target_ip = argv[++i];
    } else if (a == "--port") {
      if (!NeedsValue(i, argc, "--port")) return ParseStatus::kError;
      out.job.target_port = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--count") {
      if (!NeedsValue(i, argc, "--count")) return ParseStatus::kError;
      out.job.packet_count = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--size") {
      if (!NeedsValue(i, argc, "--size")) return ParseStatus::kError;
      out.job.packet_size = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--rps") {
      if (!NeedsValue(i, argc, "--rps")) return ParseStatus::kError;
      out.job.target_rps = std::strtod(argv[++i], nullptr);
      out.job.pacing_mode = out.job.target_rps > 0.0 ? 1u : 0u;
    } else if (a == "--protocol") {
      if (!NeedsValue(i, argc, "--protocol")) return ParseStatus::kError;
      out.job.protocol = argv[++i];
    } else if (a == "--vector") {
      if (!NeedsValue(i, argc, "--vector")) return ParseStatus::kError;
      out.job.attack_vector = argv[++i];
    } else if (a == "--pin-cpu") {
      if (!NeedsValue(i, argc, "--pin-cpu")) return ParseStatus::kError;
      out.job.pin_cpu = static_cast<std::int32_t>(std::strtol(argv[++i], nullptr, 10));
    } else if (a == "--timeout-ms") {
      if (!NeedsValue(i, argc, "--timeout-ms")) return ParseStatus::kError;
      out.timeout_ms = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
    } else {
      std::fprintf(stderr, "samurai: unknown argument: %s\n", a.c_str());
      return ParseStatus::kError;
    }
  }
  return ParseStatus::kOk;
}

}  // namespace samurai::cli
