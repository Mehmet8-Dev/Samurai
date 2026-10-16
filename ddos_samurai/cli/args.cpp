#include "args.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "profiles.hpp"

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
      "usage: %s --worker <cpu|gpu|dpdk|afxdp|afpacket|doca|l7|defense|scenario> [options]\n"
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
      "  --profile NAME      apply a named workload profile (put before overrides)\n"
      "  --l7-protocol NAME  L7 protocol: http1|http2|quic|dns (default: http1)\n"
      "  --l7-profile-file PATH  L7 JSON profile used as the emu scenario (scenario_payload_ref)\n"
      "  --l7-payload-file PATH  raw request bytes file (payload_ref)\n"
      "  --concurrency N     L7 parallel lanes/threads (default: 1)\n"
      "  --max-connections N L7 connection pool size (default: 1)\n"
      "  --max-streams N     L7 H2/H3 streams per connection (default: 1)\n"
      "  --scheme NAME       L7 scheme http|https (default: derived from protocol)\n"
      "  --verify-tls        verify the peer TLS certificate (default: off)\n"
      "  --keepalive         reuse L7 connections across requests (default: off)\n"
      "  --host-header NAME  L7 Host/SNI override (default: target IP)\n"
      "  --l7-timeout-ms N   L7 per-request timeout ms (default: 5000)\n"
      "  --list-profiles     list the available workload profiles and exit\n"
      "  --allow-public-target        permit non-private/loopback targets\n"
      "  --allow-target IP|CIDR       allowlist a target (repeatable)\n"
      "  --deny-target IP|CIDR        denylist a target; always wins (repeatable)\n"
      "  --license-key KEY            license key (or set SAMURAI_LICENSE_KEY)\n"
      "  --license-file PATH          path to file containing license key\n"
      "  --report-json PATH  write the run report as JSON to PATH\n"
      "  --report-text PATH  write the run report as text to PATH\n"
      "  --kpi-min-rate-accuracy PCT  gate: rate_accuracy_pct must be >= PCT\n"
      "  --kpi-max-loss-pct PCT       gate: wire_loss_est_pct must be <= PCT\n"
      "  --kpi-max-errors N           gate: errors must be <= N\n"
      "  --kpi-min-sent N             gate: sent must be >= N\n"
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
    } else if (a == "--l7-protocol") {
      if (!NeedsValue(i, argc, "--l7-protocol")) return ParseStatus::kError;
      out.job.protocol = argv[++i];
    } else if (a == "--l7-profile-file") {
      if (!NeedsValue(i, argc, "--l7-profile-file")) return ParseStatus::kError;
      out.job.l7_profile_file = argv[++i];
    } else if (a == "--l7-payload-file") {
      if (!NeedsValue(i, argc, "--l7-payload-file")) return ParseStatus::kError;
      out.job.l7_payload_file = argv[++i];
    } else if (a == "--concurrency") {
      if (!NeedsValue(i, argc, "--concurrency")) return ParseStatus::kError;
      out.job.concurrency = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--max-connections") {
      if (!NeedsValue(i, argc, "--max-connections")) return ParseStatus::kError;
      out.job.max_connections = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--max-streams") {
      if (!NeedsValue(i, argc, "--max-streams")) return ParseStatus::kError;
      out.job.max_streams_per_connection = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--scheme") {
      if (!NeedsValue(i, argc, "--scheme")) return ParseStatus::kError;
      out.job.scheme = argv[++i];
    } else if (a == "--verify-tls") {
      out.job.verify_tls = 1;
    } else if (a == "--keepalive") {
      out.job.keepalive = 1;
    } else if (a == "--host-header") {
      if (!NeedsValue(i, argc, "--host-header")) return ParseStatus::kError;
      out.job.host_header = argv[++i];
    } else if (a == "--l7-timeout-ms") {
      if (!NeedsValue(i, argc, "--l7-timeout-ms")) return ParseStatus::kError;
      out.job.l7_timeout_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--vector") {
      if (!NeedsValue(i, argc, "--vector")) return ParseStatus::kError;
      out.job.attack_vector = argv[++i];
    } else if (a == "--pin-cpu") {
      if (!NeedsValue(i, argc, "--pin-cpu")) return ParseStatus::kError;
      out.job.pin_cpu = static_cast<std::int32_t>(std::strtol(argv[++i], nullptr, 10));
    } else if (a == "--timeout-ms") {
      if (!NeedsValue(i, argc, "--timeout-ms")) return ParseStatus::kError;
      out.timeout_ms = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
    } else if (a == "--list-profiles") {
      out.list_profiles = true;
      return ParseStatus::kOk;
    } else if (a == "--profile") {
      if (!NeedsValue(i, argc, "--profile")) return ParseStatus::kError;
      if (const auto err = ApplyProfile(argv[++i], out)) {
        std::fprintf(stderr, "samurai: %s\n", err->c_str());
        return ParseStatus::kError;
      }
    } else if (a == "--report-json") {
      if (!NeedsValue(i, argc, "--report-json")) return ParseStatus::kError;
      out.report_json_path = argv[++i];
    } else if (a == "--report-text") {
      if (!NeedsValue(i, argc, "--report-text")) return ParseStatus::kError;
      out.report_text_path = argv[++i];
    } else if (a == "--run-rfc-suite") {
      if (!NeedsValue(i, argc, "--run-rfc-suite")) return ParseStatus::kError;
      out.run_rfc_suite = argv[++i];
    } else if (a == "--rfc-report-out") {
      if (!NeedsValue(i, argc, "--rfc-report-out")) return ParseStatus::kError;
      out.rfc_report_out = argv[++i];
    } else if (a == "--kpi-min-rate-accuracy") {
      if (!NeedsValue(i, argc, "--kpi-min-rate-accuracy")) return ParseStatus::kError;
      out.kpi.min_rate_accuracy_pct = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-max-loss-pct") {
      if (!NeedsValue(i, argc, "--kpi-max-loss-pct")) return ParseStatus::kError;
      out.kpi.max_wire_loss_pct = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-max-errors") {
      if (!NeedsValue(i, argc, "--kpi-max-errors")) return ParseStatus::kError;
      out.kpi.max_errors = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-min-sent") {
      if (!NeedsValue(i, argc, "--kpi-min-sent")) return ParseStatus::kError;
      out.kpi.min_sent = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-min-tls-handshakes") {
      if (!NeedsValue(i, argc, "--kpi-min-tls-handshakes")) return ParseStatus::kError;
      out.kpi.min_tls_handshakes = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-min-dns-queries") {
      if (!NeedsValue(i, argc, "--kpi-min-dns-queries")) return ParseStatus::kError;
      out.kpi.min_dns_queries = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-min-dhcp-leases") {
      if (!NeedsValue(i, argc, "--kpi-min-dhcp-leases")) return ParseStatus::kError;
      out.kpi.min_dhcp_leases = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-min-zc-tx-bytes") {
      if (!NeedsValue(i, argc, "--kpi-min-zc-tx-bytes")) return ParseStatus::kError;
      out.kpi.min_zc_tx_bytes = std::strtod(argv[++i], nullptr);
    } else if (a == "--kpi-max-tcp-overflows") {
      if (!NeedsValue(i, argc, "--kpi-max-tcp-overflows")) return ParseStatus::kError;
      out.kpi.max_tcp_overflows = std::strtod(argv[++i], nullptr);
    } else if (a == "--allow-public-target") {
      out.allow_public = true;
    } else if (a == "--allow-target") {
      if (!NeedsValue(i, argc, "--allow-target")) return ParseStatus::kError;
      out.allow_targets.emplace_back(argv[++i]);
    } else if (a == "--deny-target") {
      if (!NeedsValue(i, argc, "--deny-target")) return ParseStatus::kError;
      out.deny_targets.emplace_back(argv[++i]);
    } else if (a == "--license-key") {
      if (!NeedsValue(i, argc, "--license-key")) return ParseStatus::kError;
      out.license_key = argv[++i];
    } else if (a == "--license-file") {
      if (!NeedsValue(i, argc, "--license-file")) return ParseStatus::kError;
      out.license_file = argv[++i];
    } else if (a == "--confirm") {
      out.confirm = true;
    } else {
      std::fprintf(stderr, "samurai: unknown argument: %s\n", a.c_str());
      return ParseStatus::kError;
    }
  }
  return ParseStatus::kOk;
}

}  // namespace samurai::cli
