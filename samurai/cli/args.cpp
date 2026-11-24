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
      "usage: %s --worker <cpu|afpacket|afxdp|dpdk|gpu|doca|l7|scenario|telco|defense> [options]\n"
      "       %s mcp <doctor|setup> [options]\n"
      "       %s build [--source DIR] [--build-dir DIR] [--prefix DIR] [--jobs N] [--portable]\n"
      "       %s --run-rfc-suite <rfc2544|rfc3511|rfc8219|all> [options]\n"
      "\n"
      "Core & Targeting:\n"
      "  --worker NAME               worker backend to run (required)\n"
      "  --worker-dir DIR            directory containing worker binaries (default: auto-detect)\n"
      "  --target IP                 target IPv4 address (default: 127.0.0.1)\n"
      "  --port N                    target port (default: 80)\n"
      "  --count N                   packet/request count (default: 1000)\n"
      "  --size N                    packet size in bytes (default: 64)\n"
      "  --rps F                     target rate; 0 = uncapped (default: 0)\n"
      "  --protocol NAME             L4/Telco protocol: udp|tcp|pppoe|dhcp|bfd|gtpu|pfcp|sctp|diameter|sip-rtp\n"
      "  --vector NAME               workload/vector label (default: flood)\n"
      "  --pin-cpu N                 pin worker to CPU core (default: -1 = none)\n"
      "  --timeout-ms N              per-recv timeout on events channel (default: 5000)\n"
      "  --profile NAME              apply a built-in workload profile (put before overrides)\n"
      "  --list-profiles             list all built-in workload profiles and exit\n"
      "  --confirm                   confirm live dataplane execution\n"
      "\n"
      "Dataplane, Transport & Config (CLI > Env > samurai.conf):\n"
      "  --config PATH               load tuning config file (default: ./samurai.conf or ~/.config/samurai/samurai.conf)\n"
      "  --iface NAME                network interface / DPDK port for worker TX/RX\n"
      "  --transport MODE            transport backend (af_packet|dpdk|dpdk_direct|loopback|custom_tcp|kernel_socket|geforce_p2p)\n"
      "  --dpdk-port N               DPDK port ID override\n"
      "  --dpdk-queue N              DPDK TX queue ID override\n"
      "  --log-level LEVEL           log verbosity (trace|debug|info|warn|error)\n"
      "\n"
      "Output & Logging:\n"
      "  --output MODE               auto|pretty|ndjson|quiet (default: auto = pretty on TTY, ndjson on pipe)\n"
      "  -q, --quiet                 alias for --output quiet\n"
      "  --report-json PATH          write final run report as JSON to PATH\n"
      "  --report-text PATH          write final run report as text to PATH\n"
      "\n"
      "L7 / TLS / HTTP2 / QUIC:\n"
      "  --l7-protocol NAME          http1|http2|quic|dns (default: http1)\n"
      "  --l7-profile-file PATH      L7 JSON scenario/profile file\n"
      "  --l7-payload-file PATH      raw request bytes file\n"
      "  --concurrency N             parallel lanes/threads (default: 1)\n"
      "  --max-connections N         L7 connection pool size (default: 1)\n"
      "  --max-streams N             HTTP/2 or HTTP/3 streams per connection (default: 1)\n"
      "  --scheme NAME               http|https (default: derived from protocol)\n"
      "  --verify-tls                verify peer TLS certificate (default: off)\n"
      "  --keepalive                 reuse L7 connections across requests (default: off)\n"
      "  --host-header NAME          Host/SNI override (default: target IP)\n"
      "  --l7-timeout-ms N           per-request timeout in ms (default: 5000)\n"
      "\n"
      "Carrier 4G/5G Telecom & GTP-U:\n"
      "  --telco-subscribers N       subscriber count (alias: --subscriber-count, default: 100)\n"
      "  --telco-subscriber-start N  starting subscriber index (alias: --subscriber-start, default: 0)\n"
      "  --telco-cps N               subscriber/setup rate CPS (alias: --cps, default: 50)\n"
      "  --telco-duration-ms N       bounded run duration in ms (default: 5000)\n"
      "  --vlan-s N                  outer QinQ S-VLAN base (default: 100)\n"
      "  --vlan-c N                  inner C-VLAN base (default: 100)\n"
      "  --telco-base-ip IP          subscriber pool base IPv4\n"
      "  --telco-gateway-ip IP       gateway/UPF peer IPv4\n"
      "  --db-port N                 Telco DB/control port\n"
      "  --sctp-rate N               SCTP association/chunk rate\n"
      "  --diameter-rate N           Diameter CCR transaction rate (alias: --diameter-ccr-rate)\n"
      "  --sip-rate N                SIP call rate\n"
      "  --enable-srtp               enable SRTP encrypted media stream\n"
      "  --teid-start N              GTP-U starting TEID\n"
      "  --teid-count N              GTP-U TEID sweep count\n"
      "  --qfi N                     5G NR QFI (QoS Flow Identifier)\n"
      "  --ue-subnet CIDR            UE source IPv4 subnet for GTP-U inner packets\n"
      "  --gtpu-vlan S[:C]           QinQ / VLAN tag for GTP-U frames\n"
      "  --gtpu-inner-proto NAME     udp|tcp|icmp\n"
      "\n"
      "GPU CUDA / GeForce BAR1 P2P:\n"
      "  --gpu-bar1-p2p              enable consumer/enterprise BAR1 P2P DMA path\n"
      "  --gpu-persistent            enable persistent VRAM dataplane kernel\n"
      "\n"
      "IPFIX / NetFlow Telemetry:\n"
      "  --ipfix-enabled             enable live IPFIX/NetFlow UDP telemetry export\n"
      "  --ipfix-collector IP        collector IPv4 (default: 127.0.0.1)\n"
      "  --ipfix-port N              collector UDP port (default: 4739)\n"
      "  --ipfix-sample-rate N       1-in-N packet sampling rate (default: 1000)\n"
      "  --ipfix-netflow-v9          emit NetFlow v9 instead of IPFIX v10\n"
      "  --ipfix-domain-id N         observation domain ID (default: 1)\n"
      "  --ipfix-export-interval-ms N export flush interval in ms\n"
      "\n"
      "KPI Pass/Fail Gates & RFC Compliance:\n"
      "  --kpi-min-rate-accuracy PCT gate: rate_accuracy_pct >= PCT\n"
      "  --kpi-max-loss-pct PCT      gate: wire_loss_est_pct <= PCT\n"
      "  --kpi-max-errors N          gate: errors <= N\n"
      "  --kpi-min-sent N            gate: sent >= N\n"
      "  --kpi-min-tls-handshakes N  gate: l7_tls_handshakes >= N\n"
      "  --kpi-min-dns-queries N     gate: l7_dns_queries >= N\n"
      "  --kpi-min-dhcp-leases N     gate: dhcp_leases >= N\n"
      "  --kpi-min-zc-tx-bytes N     gate: zero-copy TX bytes >= N\n"
      "  --kpi-max-tcp-overflows N   gate: tcp_overflows <= N\n"
      "  --run-rfc-suite SUITE       run RFC 2544 / 3511 / 8219 suite (rfc2544|rfc3511|rfc8219|all)\n"
      "  --rfc-report-out PATH       write RFC compliance HTML report to PATH\n"
      "\n"
      "Target Safety Gates:\n"
      "  --allow-public-target       permit non-private/loopback targets (explicit opt-in)\n"
      "  --allow-target IP|CIDR      allowlist a target (repeatable)\n"
      "  --deny-target IP|CIDR       denylist a target; always wins (repeatable)\n"
      "  -h, --help                  show this help\n",
      argv0,
      argv0,
      argv0,
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
      out.vector_explicit = true;
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
    } else if (a == "--confirm") {
      out.confirm = true;
    } else if (a == "--sctp-rate") {
      if (!NeedsValue(i, argc, "--sctp-rate")) return ParseStatus::kError;
      out.sctp_rate = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
      out.job.sctp_rate = out.sctp_rate;
    } else if (a == "--diameter-rate" || a == "--diameter-ccr-rate") {
      if (!NeedsValue(i, argc, a.c_str())) return ParseStatus::kError;
      out.diameter_rate = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
      out.job.diameter_rate = out.diameter_rate;
    } else if (a == "--sip-rate") {
      if (!NeedsValue(i, argc, "--sip-rate")) return ParseStatus::kError;
      out.sip_rate = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
      out.job.sip_rate = out.sip_rate;
    } else if (a == "--enable-srtp") {
      out.enable_srtp = true;
      out.job.enable_srtp = true;
    } else if (a == "--telco-subscribers" || a == "--subscriber-count") {
      if (!NeedsValue(i, argc, a.c_str())) return ParseStatus::kError;
      out.job.telco_subscribers = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--telco-subscriber-start" || a == "--subscriber-start") {
      if (!NeedsValue(i, argc, a.c_str())) return ParseStatus::kError;
      out.job.telco_subscriber_start = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--telco-cps" || a == "--cps") {
      if (!NeedsValue(i, argc, a.c_str())) return ParseStatus::kError;
      out.job.telco_rate_cps = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--telco-duration-ms") {
      if (!NeedsValue(i, argc, "--telco-duration-ms")) return ParseStatus::kError;
      out.job.telco_duration_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--vlan-s") {
      if (!NeedsValue(i, argc, "--vlan-s")) return ParseStatus::kError;
      out.job.telco_base_vlan_s = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--vlan-c") {
      if (!NeedsValue(i, argc, "--vlan-c")) return ParseStatus::kError;
      out.job.telco_base_vlan_c = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--telco-base-ip") {
      if (!NeedsValue(i, argc, "--telco-base-ip")) return ParseStatus::kError;
      out.job.telco_base_ip = argv[++i];
    } else if (a == "--telco-gateway-ip") {
      if (!NeedsValue(i, argc, "--telco-gateway-ip")) return ParseStatus::kError;
      out.job.telco_gateway_ip = argv[++i];
    } else if (a == "--db-port") {
      if (!NeedsValue(i, argc, "--db-port")) return ParseStatus::kError;
      out.job.telco_db_port = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--ipfix-enabled") {
      out.job.ipfix_enabled = true;
    } else if (a == "--ipfix-collector") {
      if (!NeedsValue(i, argc, "--ipfix-collector")) return ParseStatus::kError;
      out.job.ipfix_collector = argv[++i];
    } else if (a == "--ipfix-port") {
      if (!NeedsValue(i, argc, "--ipfix-port")) return ParseStatus::kError;
      out.job.ipfix_port = static_cast<std::uint16_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--ipfix-sample-rate") {
      if (!NeedsValue(i, argc, "--ipfix-sample-rate")) return ParseStatus::kError;
      out.job.ipfix_sample_rate = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--ipfix-netflow-v9") {
      out.job.ipfix_netflow_v9 = true;
    } else if (a == "--ipfix-domain-id") {
      if (!NeedsValue(i, argc, "--ipfix-domain-id")) return ParseStatus::kError;
      out.job.ipfix_domain_id = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--ipfix-export-interval-ms") {
      if (!NeedsValue(i, argc, "--ipfix-export-interval-ms")) return ParseStatus::kError;
      out.job.ipfix_export_interval_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--teid-start") {
      if (!NeedsValue(i, argc, "--teid-start")) return ParseStatus::kError;
      out.job.teid_start = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--teid-count") {
      if (!NeedsValue(i, argc, "--teid-count")) return ParseStatus::kError;
      out.job.teid_count = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--qfi") {
      if (!NeedsValue(i, argc, "--qfi")) return ParseStatus::kError;
      out.job.qfi = static_cast<std::uint8_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--ue-subnet") {
      if (!NeedsValue(i, argc, "--ue-subnet")) return ParseStatus::kError;
      out.job.spoof_mode = argv[++i];
    } else if (a == "--gtpu-vlan") {
      if (!NeedsValue(i, argc, "--gtpu-vlan")) return ParseStatus::kError;
      std::string vlan_str = argv[++i];
      auto colon = vlan_str.find(':');
      if (colon != std::string::npos) {
        out.job.svlan_tci = static_cast<std::uint16_t>(std::strtoul(vlan_str.substr(0, colon).c_str(), nullptr, 10));
        out.job.cvlan_tci = static_cast<std::uint16_t>(std::strtoul(vlan_str.substr(colon + 1).c_str(), nullptr, 10));
        out.job.vlan_depth = 2;
      } else {
        out.job.svlan_tci = static_cast<std::uint16_t>(std::strtoul(vlan_str.c_str(), nullptr, 10));
        out.job.vlan_depth = 1;
      }
    } else if (a == "--gtpu-inner-proto") {
      if (!NeedsValue(i, argc, "--gtpu-inner-proto")) return ParseStatus::kError;
      std::string p = argv[++i];
      if (p == "tcp") out.job.inner_proto = 6;
      else if (p == "icmp") out.job.inner_proto = 1;
      else out.job.inner_proto = 17;
    } else if (a == "--gpu-bar1-p2p") {
      out.job.gpu_bar1_p2p = true;
    } else if (a == "--gpu-persistent") {
      out.job.gpu_persistent = true;
    } else if (a == "--config") {
      if (!NeedsValue(i, argc, "--config")) return ParseStatus::kError;
      out.config_path = argv[++i];
    } else if (a == "--iface") {
      if (!NeedsValue(i, argc, "--iface")) return ParseStatus::kError;
      out.iface = argv[++i];
    } else if (a == "--transport") {
      if (!NeedsValue(i, argc, "--transport")) return ParseStatus::kError;
      out.transport = argv[++i];
    } else if (a == "--dpdk-port") {
      if (!NeedsValue(i, argc, "--dpdk-port")) return ParseStatus::kError;
      out.dpdk_port = std::stoi(argv[++i]);
    } else if (a == "--dpdk-queue") {
      if (!NeedsValue(i, argc, "--dpdk-queue")) return ParseStatus::kError;
      out.dpdk_queue = std::stoi(argv[++i]);
    } else if (a == "--log-level") {
      if (!NeedsValue(i, argc, "--log-level")) return ParseStatus::kError;
      out.log_level = argv[++i];
    } else if (a == "-q" || a == "--quiet") {
      out.output_mode = samurai::orchestrator::OutputMode::kQuiet;
    } else if (a == "--output") {
      if (!NeedsValue(i, argc, "--output")) return ParseStatus::kError;
      const std::string mode = argv[++i];
      if (mode == "auto") {
        out.output_mode = samurai::orchestrator::OutputMode::kAuto;
      } else if (mode == "pretty") {
        out.output_mode = samurai::orchestrator::OutputMode::kPretty;
      } else if (mode == "ndjson" || mode == "json") {
        out.output_mode = samurai::orchestrator::OutputMode::kNdjson;
      } else if (mode == "quiet") {
        out.output_mode = samurai::orchestrator::OutputMode::kQuiet;
      } else {
        std::fprintf(stderr, "samurai: invalid --output mode '%s' (expected auto|pretty|ndjson|quiet)\n",
                     mode.c_str());
        return ParseStatus::kError;
      }
    } else {
      std::fprintf(stderr, "samurai: unknown argument: %s\n", a.c_str());
      return ParseStatus::kError;
    }
  }
  return ParseStatus::kOk;
}

}  // namespace samurai::cli
