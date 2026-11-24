#pragma once

// Lightweight INI / key=value config loader for Samurai.
//
// Precedence (highest to lowest):
//   1. Explicit CLI flags (--iface, --transport, --dpdk-port, --log-level, ...)
//   2. Existing process environment variables (SAMURAI_*)
//   3. Config file (--config PATH, $SAMURAI_CONFIG, ./samurai.conf,
//      ~/.config/samurai/samurai.conf, /etc/samurai/samurai.conf)
//   4. Compiled worker/kernel defaults
//
// Config entries are applied via setenv(key, value, /*overwrite=*/0) so user-
// exported environment variables always take precedence over the config file.

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>

namespace samurai::cli {

namespace detail {

inline std::string Trim(std::string s) {
  std::size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

inline std::string ToUpperAscii(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return s;
}

inline std::string ToLowerAscii(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

inline std::string StripInlineComment(const std::string& s) {
  bool in_quotes = false;
  char quote_ch = '\0';
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (in_quotes) {
      if (c == quote_ch) in_quotes = false;
    } else if (c == '"' || c == '\'') {
      in_quotes = true;
      quote_ch = c;
    } else if (c == '#' || c == ';') {
      return s.substr(0, i);
    }
  }
  return s;
}

inline std::string Unquote(std::string s) {
  s = Trim(std::move(s));
  if (s.size() >= 2 &&
      ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
    return s.substr(1, s.size() - 2);
  }
  return s;
}

// Maps [section] + key -> SAMURAI_* environment variable name.
// Raw SAMURAI_* keys are accepted in any section.
inline std::string MapConfigKeyToEnv(const std::string& section, const std::string& key) {
  const std::string upper_key = ToUpperAscii(key);
  if (upper_key.rfind("SAMURAI_", 0) == 0) {
    return upper_key;
  }

  const std::string sec = ToLowerAscii(section);
  const std::string k = ToLowerAscii(key);

  static const std::unordered_map<std::string, std::string> kSectionMap = {
      // [logging] / [general]
      {"logging.level", "SAMURAI_LOG_LEVEL"},
      {"general.log_level", "SAMURAI_LOG_LEVEL"},
      {"general.warm_workers", "SAMURAI_WARM_WORKERS"},
      {"general.wire_abi", "SAMURAI_WIRE_ABI"},
      // [pacing]
      {"pacing.use_tsc", "SAMURAI_PACING_USE_TSC"},
      // [af_packet]
      {"af_packet.iface", "SAMURAI_AFPACKET_IFACE"},
      {"af_packet.block_size_kb", "SAMURAI_AF_PACKET_BLOCK_SIZE_KB"},
      {"af_packet.frames_per_block", "SAMURAI_AF_PACKET_FRAMES_PER_BLOCK"},
      {"af_packet.frame_size", "SAMURAI_AF_PACKET_FRAME_SIZE"},
      {"af_packet.ring_target_mb", "SAMURAI_AF_PACKET_RING_TARGET_MB"},
      {"af_packet.mlock_ring", "SAMURAI_AF_PACKET_MLOCK_RING"},
      {"af_packet.prefault_ring", "SAMURAI_AF_PACKET_PREFAULT_RING"},
      {"af_packet.qdisc_bypass", "SAMURAI_AF_PACKET_QDISC_BYPASS"},
      {"af_packet.hugepage_mode", "SAMURAI_AF_PACKET_HUGEPAGE_MODE"},
      {"af_packet.hugepage_size_kb", "SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB"},
      {"af_packet.busy_poll_us", "SAMURAI_AF_PACKET_BUSY_POLL_US"},
      {"af_packet.poll_timeout_ms", "SAMURAI_AF_PACKET_POLL_TIMEOUT_MS"},
      {"af_packet.spin_limit", "SAMURAI_AF_PACKET_SPIN_LIMIT"},
      {"af_packet.txring_adaptive", "SAMURAI_TXRING_ADAPTIVE"},
      {"af_packet.txring_flush_mode", "SAMURAI_TXRING_FLUSH_MODE"},
      // [af_xdp]
      {"af_xdp.iface", "SAMURAI_XDP_IFACE"},
      // [dpdk]
      {"dpdk.eal_args", "SAMURAI_DPDK_EAL_ARGS"},
      {"dpdk.port_id", "SAMURAI_DPDK_PORT_ID"},
      {"dpdk.queue_id", "SAMURAI_DPDK_QUEUE_ID"},
      {"dpdk.tx_queues", "SAMURAI_DPDK_TX_QUEUES"},
      {"dpdk.base_core", "SAMURAI_DPDK_BASE_CORE"},
      {"dpdk.gpu_p2p", "SAMURAI_DPDK_GPU_P2P"},
      {"dpdk.vdev", "SAMURAI_DPDK_VDEV"},
      // [telco]
      {"telco.iface", "SAMURAI_TELCO_IFACE"},
      {"telco.transport", "SAMURAI_TELCO_TRANSPORT"},
      {"telco.cups_contract_path", "SAMURAI_CUPS_CONTRACT_PATH"},
      {"telco.cups_gpu_endpoint", "SAMURAI_CUPS_GPU_ENDPOINT"},
      // [l7] / [custom_tcp]
      {"l7.transport", "SAMURAI_L7_TRANSPORT"},
      {"custom_tcp.mode", "SAMURAI_CUSTOM_TCP_MODE"},
      {"custom_tcp.src_ip", "SAMURAI_CUSTOM_TCP_SRC_IP"},
      {"custom_tcp.connect_timeout_ms", "SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS"},
      {"custom_tcp.idle_timeout_ms", "SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS"},
      {"custom_tcp.initial_rto_ms", "SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS"},
      {"custom_tcp.max_retransmits", "SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS"},
      {"custom_tcp.busy_poll", "SAMURAI_FASTPATH_BUSY_POLL"},
      {"custom_tcp.drain_ms", "SAMURAI_FASTPATH_DRAIN_MS"},
      // [gpu_p2p]
      {"gpu_p2p.tx_backend", "SAMURAI_GPU_TX_BACKEND"},
      {"gpu_p2p.bar1_p2p", "SAMURAI_GPU_PACKET_BAR1_P2P_OUTPUT"},
      {"gpu_p2p.geforce_p2p", "SAMURAI_DPU_GEFORCE_P2P"},
      {"gpu_p2p.gpu_bdf", "SAMURAI_GEFORCE_P2P_GPU_BDF"},
      {"gpu_p2p.nic_bdf", "SAMURAI_GEFORCE_P2P_NIC_BDF"},
      {"gpu_p2p.dpdk_port", "SAMURAI_GEFORCE_P2P_DPDK_PORT"},
      // [doca]
      {"doca.enable", "SAMURAI_GPU_DOCA_ENABLE"},
      {"doca.device", "SAMURAI_GPU_DOCA_DEVICE"},
      {"doca.iface", "SAMURAI_GPU_DOCA_IFACE"},
      {"doca.gpu_bus_id", "SAMURAI_GPU_DOCA_GPU_BUS_ID"},
      {"doca.task_slots", "SAMURAI_GPU_DOCA_TASK_SLOTS"},
      {"doca.progress_loops", "SAMURAI_GPU_DOCA_PROGRESS_LOOPS"},
      // [telemetry]
      {"telemetry.ipfix_enabled", "SAMURAI_IPFIX_ENABLED"},
      {"telemetry.ipfix_collector", "SAMURAI_IPFIX_COLLECTOR"},
      {"telemetry.ipfix_port", "SAMURAI_IPFIX_PORT"},
      {"telemetry.ipfix_sample_rate", "SAMURAI_IPFIX_SAMPLE_RATE"},
      {"telemetry.ipfix_domain_id", "SAMURAI_IPFIX_DOMAIN_ID"},
      {"telemetry.ipfix_export_interval_ms", "SAMURAI_IPFIX_EXPORT_INTERVAL_MS"},
      {"telemetry.ipfix_flow_capacity", "SAMURAI_IPFIX_FLOW_CAPACITY"},
      {"telemetry.ipfix_netflow_v9", "SAMURAI_IPFIX_NETFLOW_V9"},
      // [cluster]
      {"cluster.secret", "SAMURAI_CLUSTER_SECRET"},
      {"cluster.curve_server_secret", "SAMURAI_CURVE_SERVER_SECRET"},
      {"cluster.rl_policy", "SAMURAI_RL_POLICY"},
  };

  if (!sec.empty()) {
    const auto it = kSectionMap.find(sec + "." + k);
    if (it != kSectionMap.end()) return it->second;
  }
  return "SAMURAI_" + ToUpperAscii(sec.empty() ? k : (sec + "_" + k));
}

}  // namespace detail

struct ConfigLoadResult {
  bool loaded = false;
  bool error = false;
  std::string path;
  std::size_t keys_applied = 0;
  std::string error_msg;
};

// Loads config from `explicit_path` (required to exist if non-empty) or
// auto-discovers $SAMURAI_CONFIG -> ./samurai.conf -> ~/.config/samurai/samurai.conf
// -> /etc/samurai/samurai.conf. Applies values with setenv(..., overwrite=0) so
// existing user environment variables always win.
inline ConfigLoadResult LoadConfigFile(const std::string& explicit_path) {
  namespace fs = std::filesystem;
  ConfigLoadResult res;
  std::error_code ec;

  std::string chosen = explicit_path;
  if (chosen.empty()) {
    if (const char* env_cfg = std::getenv("SAMURAI_CONFIG"); env_cfg && env_cfg[0] != '\0') {
      chosen = env_cfg;
    }
  }

  if (!chosen.empty()) {
    if (!fs::is_regular_file(chosen, ec)) {
      res.error = true;
      res.path = chosen;
      res.error_msg = "config file not found: " + chosen;
      return res;
    }
  } else {
    std::string home_cfg;
    if (const char* home = std::getenv("HOME"); home && home[0] != '\0') {
      home_cfg = std::string(home) + "/.config/samurai/samurai.conf";
    }
    const char* candidates[] = {
        "./samurai.conf",
        home_cfg.empty() ? nullptr : home_cfg.c_str(),
        "/etc/samurai/samurai.conf",
    };
    for (const char* c : candidates) {
      if (c && fs::is_regular_file(c, ec)) {
        chosen = c;
        break;
      }
    }
    if (chosen.empty()) {
      return res;  // No default config file present; silently use env/defaults.
    }
  }

  std::ifstream in(chosen);
  if (!in.is_open()) {
    res.error = true;
    res.path = chosen;
    res.error_msg = "unable to open config file: " + chosen;
    return res;
  }

  res.loaded = true;
  res.path = chosen;

  std::string section;
  std::string line;
  while (std::getline(in, line)) {
    line = detail::Trim(detail::StripInlineComment(line));
    if (line.empty()) continue;

    if (line.front() == '[' && line.back() == ']') {
      section = detail::Trim(line.substr(1, line.size() - 2));
      continue;
    }

    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) continue;

    const std::string key = detail::Trim(line.substr(0, eq));
    const std::string val = detail::Unquote(line.substr(eq + 1));
    if (key.empty()) continue;

    const std::string env_name = detail::MapConfigKeyToEnv(section, key);
    if (::setenv(env_name.c_str(), val.c_str(), /*overwrite=*/0) == 0) {
      ++res.keys_applied;
    }
  }

  return res;
}

}  // namespace samurai::cli
