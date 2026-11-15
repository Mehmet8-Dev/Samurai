#pragma once

// Builds a wire JobEnvelopeV1 from a small, orchestrator-level options struct.
//
// The envelope layout itself lives in wire_protocol.h and is shared verbatim
// with every worker, so a job built here is binary-compatible with the worker
// that consumes it by construction (see the static_asserts in wire_protocol.h).

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>

#include "wire_protocol.h"

namespace samurai::orchestrator {

// Orchestrator-facing job description. Extend this as more of the Python CLI
// surface is ported; every field maps onto a JobEnvelopeV1 member.
struct JobOptions {
  std::string target_ip = "127.0.0.1";
  std::uint16_t target_port = 80;
  std::uint32_t packet_count = 1000;
  std::uint32_t packet_size = 64;
  std::uint8_t pacing_mode = 0;
  double target_rps = 0.0;
  std::uint64_t ipg_ns = 0;
  std::uint32_t burst_size = 1;
  std::uint64_t burst_gap_ns = 0;
  std::int32_t pin_cpu = -1;
  std::string protocol = "udp";
  std::string attack_vector = "flood";
  std::uint8_t ttl = 64;
  bool spoof = false;
  std::string spoof_mode;   // e.g. "random" / "realistic"
  std::string dns_name;
  std::string dns_qtype;

  // L7 stateful-runtime options (wire JobEnvelopeV2). Defaults mirror the
  // l7_emu_native engine defaults so a bare job behaves like today.
  std::uint32_t concurrency = 1;
  std::uint32_t max_connections = 1;
  std::uint32_t max_streams_per_connection = 1;
  std::uint8_t verify_tls = 0;
  std::uint8_t keepalive = 0;
  std::string scheme;        // http | https (empty = derived from protocol)
  std::string host_header;   // Host/SNI override (empty = target_ip)
  std::uint32_t l7_timeout_ms = 5000;
  std::string l7_profile_file;  // scenario_payload_ref (JSON L7 profile)
  std::string l7_payload_file;  // payload_ref (raw request bytes)
  // Mahoraga shaping levers (RL action dims). 0 = baseline / no shaping.
  std::uint32_t request_mix = 0;      // request-variant selector honored by the L7 worker
  std::uint32_t source_rotation = 0;  // client source-identity spread (advisory to the L7 path)
  std::uint32_t auth_mode = 0;        // 0=Anon, 1=Bearer JWT, 2=Cookie
  std::uint32_t evasion_tactic = 0;   // 0=Normal, 1=Path Traversal, 2=URL Encoded, 3=Header Spoof
  std::string auth_payload;           // Dynamic JSON body for login

  // Telecom GTP-U & 5G QFI parameters
  std::uint32_t teid_start = 1;
  std::uint32_t teid_count = 1;
  std::uint32_t ue_src_ip_start = 0;
  std::uint32_t ue_src_ip_count = 1;
  std::uint32_t inner_dst_ip = 0;
  std::uint16_t inner_src_port = 0;
  std::uint16_t inner_dst_port = 80;
  std::uint16_t svlan_tci = 0;
  std::uint16_t cvlan_tci = 0;
  std::uint8_t  qfi = 9;
  std::uint8_t  pdu_type = 1;
  std::uint8_t  inner_proto = 17;
  std::uint8_t  vlan_depth = 0;
  std::uint8_t  with_seq = 1;
  std::uint8_t  with_qfi_ext = 1;
  std::uint8_t  echo_mode = 0;
  bool gpu_bar1_p2p = false;
  bool gpu_persistent = false;

  // Production telemetry / IPFIX exporter options (delivered via SET_TELEMETRY)
  bool ipfix_enabled = false;
  std::string ipfix_collector = "127.0.0.1";
  std::uint16_t ipfix_port = 4739;
  std::uint32_t ipfix_sample_rate = 1000;
  bool ipfix_netflow_v9 = false;
  std::uint32_t ipfix_domain_id = 1;
  std::uint32_t ipfix_export_interval_ms = 1000;

  // Distributed Telco control & user plane options (TelcoJobEnvelopeV1)
  std::uint32_t telco_subscriber_start = 0;
  std::uint32_t telco_subscribers = 100;
  std::uint32_t telco_rate_cps = 50;
  std::uint16_t telco_base_vlan_s = 100;
  std::uint16_t telco_base_vlan_c = 100;
  std::string telco_base_ip = "10.0.0.1";
  std::string telco_gateway_ip;  // empty => fall back to target_ip (or 10.0.0.254)
  std::uint32_t telco_duration_ms = 5000;
  std::uint32_t sctp_rate = 0;
  std::uint32_t diameter_rate = 0;
  std::uint32_t sip_rate = 0;
  bool enable_srtp = false;
  std::uint16_t telco_db_port = 5099;
  std::string telco_username = "samurai";
  std::string telco_password = "pass";
  std::array<std::uint8_t, 6> telco_base_mac = {0x02, 0x1a, 0x2b, 0x3c, 0x00, 0x01};
};

// Copies a std::string into a fixed-size char buffer, always NUL-terminating and
// never overrunning (the trailing byte is reserved for the NUL).
inline void CopyFixed(char* dst, std::size_t cap, const std::string& src) {
  std::memset(dst, 0, cap);
  if (cap == 0) {
    return;
  }
  const std::size_t n = std::min(src.size(), cap - 1);
  std::memcpy(dst, src.data(), n);
}

inline samurai::wire::JobEnvelopeV1 BuildJobEnvelope(const JobOptions& opt) {
  samurai::wire::JobEnvelopeV1 env{};
  CopyFixed(env.target_ip, sizeof(env.target_ip), opt.target_ip);
  env.target_port = opt.target_port;
  env.packet_count = opt.packet_count;
  env.packet_size = opt.packet_size;
  env.pacing_mode = opt.pacing_mode;
  env.target_rps = opt.target_rps;
  env.ipg_ns = opt.ipg_ns;
  env.burst_size = opt.burst_size > 0u ? opt.burst_size : 1u;
  env.burst_gap_ns = opt.burst_gap_ns;
  env.pin_cpu = opt.pin_cpu;
  CopyFixed(env.protocol, sizeof(env.protocol), opt.protocol);
  CopyFixed(env.attack_vector, sizeof(env.attack_vector), opt.attack_vector);
  env.ttl = opt.ttl;
  env.spoof_enabled = opt.spoof ? 1u : 0u;
  CopyFixed(env.spoof_mode, sizeof(env.spoof_mode), opt.spoof_mode);
  CopyFixed(env.dns_name, sizeof(env.dns_name), opt.dns_name);
  CopyFixed(env.dns_qtype, sizeof(env.dns_qtype), opt.dns_qtype);
  CopyFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref), opt.l7_profile_file);
  CopyFixed(env.payload_ref, sizeof(env.payload_ref), opt.l7_payload_file);
  env.has_payload = opt.l7_payload_file.empty() ? 0u : 1u;
  return env;
}

// Builds the V2 envelope used by the L7 worker. `base` carries the same fields
// as V1 plus the scenario/payload refs; the tail adds the stateful-runtime knobs.
inline samurai::wire::JobEnvelopeV2 BuildJobEnvelopeV2(const JobOptions& opt) {
  samurai::wire::JobEnvelopeV2 env{};
  env.base = BuildJobEnvelope(opt);
  env.concurrency = std::max(1u, opt.concurrency);
  env.max_connections = std::max(1u, opt.max_connections);
  env.max_streams_per_connection = std::max(1u, opt.max_streams_per_connection);
  env.verify_tls = opt.verify_tls != 0u ? 1u : 0u;
  env.keepalive = opt.keepalive != 0u ? 1u : 0u;
  CopyFixed(env.scheme, sizeof(env.scheme), opt.scheme);
  CopyFixed(env.host_header, sizeof(env.host_header), opt.host_header);
  env.l7_timeout_ms = opt.l7_timeout_ms > 0u ? opt.l7_timeout_ms : 5000u;
  env.request_mix = opt.request_mix;
  env.source_rotation = opt.source_rotation;
  env.auth_mode = opt.auth_mode;
  env.evasion_tactic = opt.evasion_tactic;
  CopyFixed(env.auth_payload, sizeof(env.auth_payload), opt.auth_payload);
  return env;
}

inline bool IsTelcoGtpuProtocol(const std::string& proto) {
  return proto == "gtpu" || proto == "gtp-u" || proto == "GTPU" || proto == "GTP-U" || proto == "5g-gtpu";
}

inline samurai::wire::TelcoGpuJobEnvelopeV1 BuildTelcoGpuJobEnvelope(const JobOptions& opt) {
  samurai::wire::TelcoGpuJobEnvelopeV1 env{};
  env.base = BuildJobEnvelope(opt);
  env.teid_start = opt.teid_start;
  env.teid_count = opt.teid_count;
  env.ue_src_ip_start = opt.ue_src_ip_start;
  env.ue_src_ip_count = opt.ue_src_ip_count;
  env.inner_dst_ip = opt.inner_dst_ip;
  env.inner_src_port = opt.inner_src_port;
  env.inner_dst_port = opt.inner_dst_port;
  env.svlan_tci = opt.svlan_tci;
  env.cvlan_tci = opt.cvlan_tci;
  env.qfi = opt.qfi;
  env.pdu_type = opt.pdu_type;
  env.inner_proto = opt.inner_proto;
  env.vlan_depth = opt.vlan_depth;
  env.with_seq = opt.with_seq;
  env.with_qfi_ext = opt.with_qfi_ext;
  env.echo_mode = opt.echo_mode;
  std::uint8_t fl = samurai::wire::kTelcoGpuJobFlagNone;
  if (opt.gpu_bar1_p2p) fl |= samurai::wire::kTelcoGpuJobFlagBar1P2p;
  if (opt.gpu_persistent) fl |= samurai::wire::kTelcoGpuJobFlagPersistent;
  env.flags = fl;
  return env;
}

inline std::uint32_t ParseIpv4HostOrder(const std::string& ip, std::uint32_t fallback) {
  std::uint32_t parts[4] = {0, 0, 0, 0};
  int part_idx = 0;
  std::uint32_t cur = 0;
  bool has_digit = false;
  for (char c : ip) {
    if (c >= '0' && c <= '9') {
      cur = cur * 10u + static_cast<std::uint32_t>(c - '0');
      if (cur > 255u) return fallback;
      has_digit = true;
    } else if (c == '.') {
      if (!has_digit || part_idx >= 3) return fallback;
      parts[part_idx++] = cur;
      cur = 0;
      has_digit = false;
    } else {
      return fallback;
    }
  }
  if (!has_digit || part_idx != 3) return fallback;
  parts[3] = cur;
  return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

inline samurai::wire::TelcoProtocolKind ResolveTelcoProtocolKind(const std::string& proto) {
  std::string lower;
  lower.reserve(proto.size());
  for (unsigned char c : proto) {
    lower.push_back(static_cast<char>(std::tolower(c)));
  }
  if (lower == "pppoe") return samurai::wire::TelcoProtocolKind::PPPOE;
  if (lower == "dhcp" || lower == "dhcpv4") return samurai::wire::TelcoProtocolKind::DHCP;
  if (lower == "bfd") return samurai::wire::TelcoProtocolKind::BFD;
  if (lower == "gtpu" || lower == "gtp-u" || lower == "5g-gtpu") return samurai::wire::TelcoProtocolKind::GTPU;
  if (lower == "qinq") return samurai::wire::TelcoProtocolKind::QINQ;
  if (lower == "arp") return samurai::wire::TelcoProtocolKind::ARP;
  if (lower == "pfcp" || lower == "cups") return samurai::wire::TelcoProtocolKind::PFCP;
  if (lower == "sctp") return samurai::wire::TelcoProtocolKind::SCTP;
  if (lower == "diameter") return samurai::wire::TelcoProtocolKind::DIAMETER;
  if (lower == "sip" || lower == "rtp" || lower == "sip-rtp" || lower == "sip_rtp") {
    return samurai::wire::TelcoProtocolKind::SIP_RTP;
  }
  return samurai::wire::TelcoProtocolKind::MULTI;
}

inline samurai::wire::TelemetryConfigV1 BuildTelemetryConfig(const JobOptions& opt) {
  samurai::wire::TelemetryConfigV1 cfg{};
  cfg.enabled = opt.ipfix_enabled ? 1u : 0u;
  cfg.netflow_v9 = opt.ipfix_netflow_v9 ? 1u : 0u;
  cfg.collector_port = opt.ipfix_port > 0 ? opt.ipfix_port : 4739u;
  cfg.sample_rate = opt.ipfix_sample_rate > 0 ? opt.ipfix_sample_rate : 1u;
  cfg.domain_id = opt.ipfix_domain_id;
  cfg.export_interval_ms = opt.ipfix_export_interval_ms > 0 ? opt.ipfix_export_interval_ms : 1000u;
  CopyFixed(cfg.collector_ip, sizeof(cfg.collector_ip),
            opt.ipfix_collector.empty() ? std::string("127.0.0.1") : opt.ipfix_collector);
  return cfg;
}

inline samurai::wire::TelcoJobEnvelopeV1 BuildTelcoJobEnvelope(const JobOptions& opt) {
  samurai::wire::TelcoJobEnvelopeV1 env{};
  env.base = BuildJobEnvelope(opt);
  env.subscriber_start_idx = opt.telco_subscriber_start;
  env.subscriber_count = std::max(1u, opt.telco_subscribers);
  env.rate_cps = std::max(1u, opt.telco_rate_cps);
  env.sctp_rate = opt.sctp_rate;
  env.diameter_rate = opt.diameter_rate;
  env.sip_rate = opt.sip_rate;
  env.teid_start = opt.teid_start;
  env.teid_count = std::max(1u, opt.teid_count);
  env.base_client_ip = ParseIpv4HostOrder(opt.telco_base_ip, 0x0A000001u);
  const std::string& gw = opt.telco_gateway_ip.empty() ? opt.target_ip : opt.telco_gateway_ip;
  env.gateway_ip = ParseIpv4HostOrder(gw, 0x0A0000FEu);
  env.duration_ms = opt.telco_duration_ms;
  env.base_vlan_s = opt.svlan_tci > 0 ? opt.svlan_tci : opt.telco_base_vlan_s;
  env.base_vlan_c = opt.cvlan_tci > 0 ? opt.cvlan_tci : opt.telco_base_vlan_c;
  env.db_port = opt.telco_db_port > 0 ? opt.telco_db_port : 5099u;
  env.qfi = opt.qfi;
  env.inner_proto = opt.inner_proto;
  env.enable_srtp = opt.enable_srtp ? 1u : 0u;
  const auto kind = ResolveTelcoProtocolKind(opt.protocol);
  env.telco_protocol_kind = static_cast<std::uint8_t>(kind);
  std::memcpy(env.base_mac, opt.telco_base_mac.data(), 6);
  CopyFixed(env.telco_protocol_name, sizeof(env.telco_protocol_name), opt.protocol);
  CopyFixed(env.auth_username, sizeof(env.auth_username), opt.telco_username);
  CopyFixed(env.auth_password, sizeof(env.auth_password), opt.telco_password);
  return env;
}

}  // namespace samurai::orchestrator
