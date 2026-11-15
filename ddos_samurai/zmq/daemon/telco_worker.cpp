#include "wire_protocol.h"
#include "worker_common.hpp"
#include "zmq_worker_base.hpp"
#include "ddos_samurai/samurai_tsc.h"
#include "ddos_samurai/telecom/core/fastpath_classifier.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/core/telco_packet_transport.hpp"
#include "ddos_samurai/telecom/protocols/stateful/pppoe/pppoe_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/dhcp/dhcp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/bfd/bfd_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/pfcp_engine.hpp"
#include "ddos_samurai/telecom/cups/dpu_arm_cups_bridge.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sctp/sctp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sip_rtp/sip_rtp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateless/gtpu_gen/stateless_gtpu_generator.hpp"
#include "ddos_samurai/telecom/protocols/stateless/qinq_sweep/qinq_generator.hpp"
#include "ddos_samurai/telecom/protocols/stateless/arp_gen/stateless_arp_generator.hpp"

#include <zmq.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace samurai::wire;
using namespace samurai::daemon;
using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::pppoe;
using namespace ddos_samurai::telecom::dhcp;
using namespace ddos_samurai::telecom::bfd;
using namespace ddos_samurai::telecom::mobile;
using namespace ddos_samurai::telecom::sctp;
using namespace ddos_samurai::telecom::diameter;
using namespace ddos_samurai::telecom::sip_rtp;
using namespace ddos_samurai::telecom::stateless;

namespace {

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_telco";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_telco";
constexpr std::uint16_t kDefaultDbPort = 5099;

bool g_worker_running = true;
void SignalHandler(int) {
  g_worker_running = false;
}

void ApplyAffinity(std::int32_t pin_cpu) {
  if (pin_cpu < 0) return;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(static_cast<unsigned>(pin_cpu), &cpuset);
  (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

std::string ToLower(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string FormatHostIpv4(std::uint32_t ip) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                (ip >> 24) & 0xFFu,
                (ip >> 16) & 0xFFu,
                (ip >> 8) & 0xFFu,
                ip & 0xFFu);
  return std::string(buf);
}

std::uint32_t ParseIpv4Host(const char* ip, std::uint32_t fallback) {
  if (!ip || !ip[0]) return fallback;
  struct in_addr addr{};
  if (::inet_pton(AF_INET, ip, &addr) == 1) {
    return ntohl(addr.s_addr);
  }
  return fallback;
}

std::string ProtocolNameFromKind(std::uint8_t kind, const std::string& fallback) {
  switch (static_cast<TelcoProtocolKind>(kind)) {
    case TelcoProtocolKind::PPPOE: return "pppoe";
    case TelcoProtocolKind::DHCP: return "dhcp";
    case TelcoProtocolKind::BFD: return "bfd";
    case TelcoProtocolKind::GTPU: return "gtpu";
    case TelcoProtocolKind::QINQ: return "qinq";
    case TelcoProtocolKind::ARP: return "arp";
    case TelcoProtocolKind::PFCP: return "pfcp";
    case TelcoProtocolKind::SCTP: return "sctp";
    case TelcoProtocolKind::DIAMETER: return "diameter";
    case TelcoProtocolKind::SIP_RTP: return "sip-rtp";
    case TelcoProtocolKind::MULTI: return "telco-full";
    default: return fallback;
  }
}

struct TelcoJobSpec {
  std::uint32_t sub_start = 0;
  std::uint32_t sub_count = 100;
  std::uint32_t rate_cps = 5000;
  std::uint32_t sctp_rate = 0;
  std::uint32_t diameter_rate = 0;
  std::uint32_t sip_rate = 0;
  std::uint32_t teid_start = 1;
  std::uint32_t teid_count = 1;
  std::uint32_t base_client_ip = 0x0A000001u;
  std::uint32_t gateway_ip = 0x0A0000FEu;
  std::uint32_t packet_count = 0;
  std::uint32_t duration_ms = 0;
  std::uint16_t base_vlan_s = 100;
  std::uint16_t base_vlan_c = 10;
  std::uint16_t db_port = kDefaultDbPort;
  std::uint8_t qfi = 9;
  std::uint8_t inner_proto = 17;
  bool enable_srtp = false;
  std::int32_t pin_cpu = -1;
  std::uint8_t pacing_mode = 1;
  double target_rps = 0.0;
  std::uint64_t ipg_ns = 0;
  std::uint32_t burst_size = 1;
  std::array<std::uint8_t, 6> base_mac{0x02, 0x00, 0x5E, 0x00, 0x00, 0x01};
  std::string protocol = "pppoe";
  std::string target_ip = "10.0.0.254";
  std::uint16_t target_port = 2152;
};

// Strictly parses START_JOB payload by exact wire envelope size rather than
// performing an unsafe >= sizeof(TelcoJobPayload) cast.
bool ParseStartJobSpec(
    const std::uint8_t* payload,
    std::size_t payload_len,
    const TelcoJobSpec& defaults,
    TelcoJobSpec& out) {
  out = defaults;
  if (!payload || payload_len == 0) {
    return true;
  }

  auto apply_protocol_rate = [&](TelcoJobSpec& s) {
    const std::string p = ToLower(s.protocol);
    if ((p == "sctp" || p == "sctp-flood") && s.sctp_rate > 0) {
      s.rate_cps = s.sctp_rate;
    } else if ((p == "diameter" || p == "diameter-ccr") && s.diameter_rate > 0) {
      s.rate_cps = s.diameter_rate;
    } else if ((p == "sip" || p == "rtp" || p == "sip-rtp" || p == "sip_rtp" || p == "sip-storm") &&
               s.sip_rate > 0) {
      s.rate_cps = s.sip_rate;
    }
  };

  if (payload_len == sizeof(TelcoJobEnvelopeV1)) {
    TelcoJobEnvelopeV1 te{};
    std::memcpy(&te, payload, sizeof(te));
    out.target_ip = ReadFixed(te.base.target_ip, sizeof(te.base.target_ip));
    if (out.target_ip.empty()) out.target_ip = defaults.target_ip;
    out.target_port = te.base.target_port > 0 ? te.base.target_port : defaults.target_port;
    out.packet_count = te.base.packet_count;
    out.pacing_mode = te.base.pacing_mode;
    out.target_rps = te.base.target_rps;
    out.ipg_ns = te.base.ipg_ns;
    out.burst_size = te.base.burst_size > 0 ? te.base.burst_size : 1u;
    if (te.base.pin_cpu >= 0) out.pin_cpu = te.base.pin_cpu;

    out.sub_start = te.subscriber_start_idx;
    out.sub_count = std::max<std::uint32_t>(1u, te.subscriber_count);
    out.rate_cps = te.rate_cps > 0 ? te.rate_cps : defaults.rate_cps;
    out.sctp_rate = te.sctp_rate;
    out.diameter_rate = te.diameter_rate;
    out.sip_rate = te.sip_rate;
    out.teid_start = te.teid_start > 0 ? te.teid_start : 1u;
    out.teid_count = te.teid_count > 0 ? te.teid_count : out.sub_count;
    out.base_client_ip = te.base_client_ip != 0 ? te.base_client_ip : defaults.base_client_ip;
    out.gateway_ip = te.gateway_ip != 0
                         ? te.gateway_ip
                         : ParseIpv4Host(out.target_ip.c_str(), defaults.gateway_ip);
    out.duration_ms = te.duration_ms;
    out.base_vlan_s = te.base_vlan_s > 0 ? te.base_vlan_s : defaults.base_vlan_s;
    out.base_vlan_c = te.base_vlan_c > 0 ? te.base_vlan_c : defaults.base_vlan_c;
    out.db_port = te.db_port > 0 ? te.db_port : defaults.db_port;
    out.qfi = te.qfi;
    out.inner_proto = te.inner_proto;
    out.enable_srtp = (te.enable_srtp != 0);

    bool non_zero_mac = false;
    for (auto b : te.base_mac) {
      if (b != 0) non_zero_mac = true;
    }
    if (non_zero_mac) {
      std::memcpy(out.base_mac.data(), te.base_mac, 6);
    }

    const std::string tname = ToLower(ReadFixed(te.telco_protocol_name, sizeof(te.telco_protocol_name)));
    const std::string bname = ToLower(ReadFixed(te.base.protocol, sizeof(te.base.protocol)));
    if (!tname.empty() && tname != "udp") {
      out.protocol = tname;
    } else if (!bname.empty() && bname != "udp") {
      out.protocol = bname;
    } else if (te.telco_protocol_kind != 0) {
      out.protocol = ProtocolNameFromKind(te.telco_protocol_kind, defaults.protocol);
    }
    apply_protocol_rate(out);
    return true;
  }

  if (payload_len == sizeof(TelcoGpuJobEnvelopeV1)) {
    TelcoGpuJobEnvelopeV1 tge{};
    std::memcpy(&tge, payload, sizeof(tge));
    out.target_ip = ReadFixed(tge.base.target_ip, sizeof(tge.base.target_ip));
    if (out.target_ip.empty()) out.target_ip = defaults.target_ip;
    out.target_port = tge.base.target_port > 0 ? tge.base.target_port : 2152u;
    out.packet_count = tge.base.packet_count;
    out.pacing_mode = tge.base.pacing_mode;
    out.target_rps = tge.base.target_rps;
    out.ipg_ns = tge.base.ipg_ns;
    out.burst_size = tge.base.burst_size > 0 ? tge.base.burst_size : 1u;
    if (tge.base.pin_cpu >= 0) out.pin_cpu = tge.base.pin_cpu;
    if (tge.teid_count > 0) {
      out.teid_start = tge.teid_start > 0 ? tge.teid_start : 1u;
      out.teid_count = tge.teid_count;
      out.sub_count = std::max<std::uint32_t>(1u, tge.teid_count);
    }
    if (tge.ue_src_ip_start != 0) out.base_client_ip = tge.ue_src_ip_start;
    out.gateway_ip = ParseIpv4Host(out.target_ip.c_str(), defaults.gateway_ip);
    if (tge.svlan_tci > 0) out.base_vlan_s = tge.svlan_tci;
    if (tge.cvlan_tci > 0) out.base_vlan_c = tge.cvlan_tci;
    out.qfi = tge.qfi;
    out.inner_proto = tge.inner_proto;
    const std::string p = ToLower(ReadFixed(tge.base.protocol, sizeof(tge.base.protocol)));
    out.protocol = p.empty() ? std::string("gtpu") : p;
    if (tge.base.target_rps > 0.0) {
      out.rate_cps = static_cast<std::uint32_t>(std::max(1.0, tge.base.target_rps));
    }
    return true;
  }

  if (payload_len == sizeof(JobEnvelopeV1) || payload_len == sizeof(JobEnvelopeV2)) {
    JobEnvelopeV1 env{};
    std::memcpy(&env, payload, sizeof(env));
    const std::string tip = ReadFixed(env.target_ip, sizeof(env.target_ip));
    if (!tip.empty()) {
      out.target_ip = tip;
      out.gateway_ip = ParseIpv4Host(tip.c_str(), defaults.gateway_ip);
    }
    if (env.target_port > 0) out.target_port = env.target_port;
    out.packet_count = env.packet_count;
    out.pacing_mode = env.pacing_mode;
    out.target_rps = env.target_rps;
    out.ipg_ns = env.ipg_ns;
    out.burst_size = env.burst_size > 0 ? env.burst_size : 1u;
    if (env.pin_cpu >= 0) out.pin_cpu = env.pin_cpu;
    const std::string p = ToLower(ReadFixed(env.protocol, sizeof(env.protocol)));
    if (!p.empty() && p != "udp") {
      out.protocol = p;
    }
    if (env.target_rps > 0.0) {
      out.rate_cps = static_cast<std::uint32_t>(std::max(1.0, env.target_rps));
    }
    return true;
  }

  if (payload_len == sizeof(TelcoJobPayload)) {
    TelcoJobPayload jp{};
    std::memcpy(&jp, payload, sizeof(jp));
    out.sub_start = jp.subscriber_start_idx;
    out.sub_count = std::max<std::uint32_t>(1u, jp.subscriber_count);
    out.rate_cps = jp.rate_cps > 0 ? jp.rate_cps : defaults.rate_cps;
    out.protocol = ProtocolNameFromKind(jp.protocol_kind, defaults.protocol);
    if (jp.base_vlan_s > 0) out.base_vlan_s = jp.base_vlan_s;
    if (jp.base_vlan_c > 0) out.base_vlan_c = jp.base_vlan_c;
    if (jp.base_client_ip != 0) out.base_client_ip = jp.base_client_ip;
    if (jp.gateway_ip != 0) {
      out.gateway_ip = jp.gateway_ip;
      out.target_ip = FormatHostIpv4(jp.gateway_ip);
    }
    bool non_zero_mac = false;
    for (auto b : jp.base_mac) {
      if (b != 0) non_zero_mac = true;
    }
    if (non_zero_mac) std::memcpy(out.base_mac.data(), jp.base_mac, 6);
    if (jp.pin_cpu >= 0) out.pin_cpu = jp.pin_cpu;
    if (jp.db_port > 0) out.db_port = jp.db_port;
    return true;
  }

  return false;
}

bool ParseStartJobFrame(
    const DecodedWireFrame& frame,
    const TelcoJobSpec& defaults,
    TelcoJobSpec& out,
    samurai::daemon::TelemetrySink* telemetry) {
  if (frame.version == kVersionV3) {
    JobV3Payload v3{};
    if (!ParseJobV3Payload(frame.payload_ptr, frame.actual_payload_len, frame.ext_count, v3)) {
      out = defaults;
      return false;
    }
    if (v3.has_telemetry && telemetry) {
      samurai::daemon::ApplyTelemetrySectionV3(v3.telemetry, telemetry);
    }
    if (v3.has_telco) {
      TelcoJobEnvelopeV1 te = ToTelcoJobEnvelopeV1(v3.base, v3.telco);
      return ParseStartJobSpec(reinterpret_cast<const std::uint8_t*>(&te), sizeof(te), defaults, out);
    }
    JobEnvelopeV1 env = ToJobEnvelopeV1(v3.base);
    return ParseStartJobSpec(reinterpret_cast<const std::uint8_t*>(&env), sizeof(env), defaults, out);
  }
  return ParseStartJobSpec(frame.payload_ptr, frame.actual_payload_len, defaults, out);
}

// ---------------------------------------------------------------------------
// Real Live Wire Network I/O (PF_PACKET SOCK_RAW)
// ---------------------------------------------------------------------------
class TelcoWireIo {
 public:
  TelcoWireIo() = default;
  ~TelcoWireIo() { Close(); }

  bool Open(const std::string& iface_name) {
    if (iface_name.empty()) return false;
    ifname_ = iface_name;

    int fd = ::socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (fd < 0) {
      std::cerr << "[TELCO_WORKER] Warning: raw socket open failed on '"
                << iface_name << "': " << std::strerror(errno) << " (simulation loop active)" << std::endl;
      return false;
    }

    int buf_size = 16 * 1024 * 1024;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

#ifdef PACKET_IGNORE_OUTGOING
    int ignore_out = 1;
    ::setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));
#endif

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
      std::cerr << "[TELCO_WORKER] Warning: ioctl(SIOCGIFINDEX) failed for " << iface_name << std::endl;
      ::close(fd);
      return false;
    }

    struct sockaddr_ll sll{};
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
      std::cerr << "[TELCO_WORKER] Warning: bind failed on " << iface_name << ": "
                << std::strerror(errno) << std::endl;
      ::close(fd);
      return false;
    }

    fd_ = fd;
    ifindex_ = ifr.ifr_ifindex;
    return true;
  }

  void Close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  int fd_{-1};
  int ifindex_{-1};
  std::string ifname_;
};

// ---------------------------------------------------------------------------
// Bounded Setup Latency Tracker (mean + sorted p99 in microseconds)
// ---------------------------------------------------------------------------
class LatencyRing {
 public:
  static constexpr std::size_t kCapacity = 1024;

  void RecordUs(std::uint32_t us) {
    const std::uint32_t val = std::max<std::uint32_t>(1u, us);
    samples_[head_] = val;
    head_ = (head_ + 1u) % kCapacity;
    if (count_ < kCapacity) ++count_;
  }

  void Compute(std::uint32_t& out_avg_us, std::uint32_t& out_p99_us) const {
    if (count_ == 0) {
      out_avg_us = 0;
      out_p99_us = 0;
      return;
    }
    std::uint64_t sum = 0;
    std::vector<std::uint32_t> sorted;
    sorted.reserve(count_);
    for (std::size_t i = 0; i < count_; ++i) {
      const std::uint32_t v = samples_[i];
      sum += v;
      sorted.push_back(v);
    }
    std::sort(sorted.begin(), sorted.end());
    const std::size_t idx = std::min<std::size_t>(
        sorted.size() - 1u, (sorted.size() * 99u) / 100u);
    out_avg_us = static_cast<std::uint32_t>(sum / count_);
    out_p99_us = sorted[idx];
  }

 private:
  std::array<std::uint32_t, kCapacity> samples_{};
  std::size_t head_{0};
  std::size_t count_{0};
};

// ---------------------------------------------------------------------------
// Protocol Lifecycle Driver Interface & Implementations
// ---------------------------------------------------------------------------
class ITelcoProtocolDriver {
 public:
  virtual ~ITelcoProtocolDriver() = default;
  virtual void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) = 0;
  virtual void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                               std::vector<std::vector<uint8_t>>& out_packets) = 0;
  virtual void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                         const PacketMetadata& meta, TelcoFrameType frame_type) = 0;
  virtual void OnTimerTick(uint64_t current_tsc) = 0;
};

void PopulateCommonMacAndVlans(
    TelcoSessionContext* ctx,
    std::uint32_t sub_idx,
    const TelcoJobSpec& spec,
    bool broadcast_peer = false) {
  ctx->session_id = sub_idx + 1;
  ctx->s_vlan = static_cast<uint16_t>(1 + ((std::max<uint16_t>(1, spec.base_vlan_s) - 1 + (sub_idx / 4094)) % 4094));
  ctx->c_vlan = static_cast<uint16_t>(1 + ((std::max<uint16_t>(1, spec.base_vlan_c) - 1 + (sub_idx % 4094)) % 4094));
  std::memcpy(ctx->client_mac, spec.base_mac.data(), 6);
  ctx->client_mac[3] ^= static_cast<uint8_t>((sub_idx >> 16) & 0xFF);
  ctx->client_mac[4] ^= static_cast<uint8_t>((sub_idx >> 8) & 0xFF);
  ctx->client_mac[5] ^= static_cast<uint8_t>(sub_idx & 0xFF);
  if (broadcast_peer) {
    std::memset(ctx->peer_mac, 0xFF, 6);
  } else {
    std::memcpy(ctx->peer_mac, spec.base_mac.data(), 6);
  }
}

class PppoeDriver final : public ITelcoProtocolDriver {
 public:
  explicit PppoeDriver(PppoeEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->ip_proto = 17;
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::PPPOE);
      ctx->state = SessionState::IDLE;
      session_mgr.BindPppoeSession(ctx, ctx->client_mac, static_cast<uint16_t>(ctx->session_id));
      engine_.StartSession(ctx);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      if (ctx->state == SessionState::ESTABLISHED) {
        auto pkt = engine_.BuildLcpEchoReqFrame(ctx);
        if (!pkt.empty()) out_packets.push_back(std::move(pkt));
      } else {
        auto pkt = engine_.BuildPadiFrame(ctx);
        if (!pkt.empty()) out_packets.push_back(std::move(pkt));
      }
    }
  }

  void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                 const PacketMetadata& meta, TelcoFrameType /*frame_type*/) override {
    TelcoSessionContext* session = session_mgr.FindPppoeSession(meta.src_mac, meta.outer_vlan);
    if (!session) session = session_mgr.FindPppoeSession(meta.dst_mac, meta.outer_vlan);
    engine_.ProcessRxFrame(frame, len, session);
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  PppoeEngine& engine_;
};

class DhcpDriver final : public ITelcoProtocolDriver {
 public:
  explicit DhcpDriver(DhcpEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = 0;
      ctx->peer_ip = spec.gateway_ip;
      ctx->client_port = 68;
      ctx->peer_port = 67;
      ctx->ip_proto = 17;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec, /*broadcast_peer=*/true);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DHCPV4);
      ctx->state = SessionState::IDLE;
      uint32_t xid = 0x54454C00u + sub_idx;
      ctx->SetDhcpXid(xid);
      session_mgr.BindDhcpSession(ctx, xid);
      engine_.StartDhcpv4(ctx, xid);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      if (ctx->state == SessionState::ESTABLISHED && ctx->client_ip != 0) {
        auto pkt = engine_.BuildDhcpv4Request(ctx, ctx->client_ip, ctx->peer_ip);
        if (!pkt.empty()) out_packets.push_back(std::move(pkt));
      } else {
        auto pkt = engine_.BuildDhcpv4Discover(ctx);
        if (!pkt.empty()) out_packets.push_back(std::move(pkt));
      }
    }
  }

  void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                 const PacketMetadata& meta, TelcoFrameType /*frame_type*/) override {
    TelcoSessionContext* session = nullptr;
    if (meta.payload_ptr && meta.payload_len >= 8) {
      uint32_t xid = (static_cast<uint32_t>(meta.payload_ptr[4]) << 24) |
                     (static_cast<uint32_t>(meta.payload_ptr[5]) << 16) |
                     (static_cast<uint32_t>(meta.payload_ptr[6]) << 8) |
                     static_cast<uint32_t>(meta.payload_ptr[7]);
      session = session_mgr.FindDhcpSession(xid);
    }
    engine_.ProcessRxFrame(frame, len, session);
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  DhcpEngine& engine_;
};

class BfdDriver final : public ITelcoProtocolDriver {
 public:
  explicit BfdDriver(BfdEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      ctx->client_port = static_cast<uint16_t>(49152u + (sub_idx % 16000u));
      ctx->peer_port = 3784;
      ctx->ip_proto = 17;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::BFD);
      ctx->state = SessionState::IDLE;

      uint32_t disc = 0x80000000u + sub_idx;
      ctx->SetBfdLocalDisc(disc);
      session_mgr.BindBfdSession(ctx, disc);

      BfdConfig bfd_cfg{};
      bfd_cfg.desired_tx_interval_us = 10000;
      bfd_cfg.required_rx_interval_us = 10000;
      bfd_cfg.detect_multiplier = 3;
      bfd_cfg.local_disc = disc;
      engine_.StartSession(ctx, bfd_cfg);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      auto pkt = engine_.BuildBfdControlPacket(ctx, BfdState::Up, BfdDiag::None);
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    BfdControlHeader hdr{};
    uint32_t remote_disc = 0;
    if (BfdEngine::ParseBfdControlPacket(frame, len, hdr, remote_disc)) {
      uint32_t disc = ntohl(hdr.your_discriminator);
      TelcoSessionContext* session = session_mgr.FindBfdSession(disc);
      if (!session) session = session_mgr.FindBfdSession(remote_disc);
      engine_.ProcessRxFrame(frame, len, samurai_rdtsc(), session);
    }
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  BfdEngine& engine_;
};

class GtpuDriver final : public ITelcoProtocolDriver {
 public:
  explicit GtpuDriver(GtpuEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    const uint32_t teid_mod = std::max<uint32_t>(1u, spec.teid_count);
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      ctx->client_port = GTPU_PORT;
      ctx->peer_port = GTPU_PORT;
      ctx->ip_proto = 17;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::GTPU);
      ctx->state = SessionState::IDLE;

      const uint32_t teid_offset = (spec.teid_count > 1) ? (sub_idx % teid_mod) : sub_idx;
      ctx->teid_uplink = spec.teid_start + teid_offset;
      ctx->teid_downlink = spec.teid_start + 0x10000000u + teid_offset;
      session_mgr.BindGtpuSession(ctx, ctx->teid_uplink);

      GtpuTunnelConfig gtp_cfg{};
      gtp_cfg.uplink_teid = ctx->teid_uplink;
      gtp_cfg.downlink_teid = ctx->teid_downlink;
      gtp_cfg.peer_upf_ip = spec.gateway_ip;
      gtp_cfg.local_gnb_ip = ctx->client_ip;
      std::memcpy(gtp_cfg.local_mac, ctx->client_mac, 6);
      std::memcpy(gtp_cfg.peer_mac, ctx->peer_mac, 6);
      engine_.StartSession(ctx, gtp_cfg);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    static const uint8_t inner_payload[28] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0x00, 0x00,
        192, 168, 100, 1, 8, 8, 8, 8,
        0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01
    };

    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      // Use monotonic per-context sequence rather than mutating ctx->retry_count,
      // which tracks real retransmits triggered by timeout/retransmit state.
      const uint16_t seq = static_cast<uint16_t>((ctx->tx_packets + 1u) & 0xFFFFu);
      auto pkt = engine_.Encapsulate(ctx, inner_payload, sizeof(inner_payload), seq);
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    GtpuDecapInfo info{};
    if (GtpuEngine::Decapsulate(frame, len, info)) {
      TelcoSessionContext* session = session_mgr.FindGtpuSession(info.teid);
      engine_.ProcessRxFrame(frame, len, session);
    }
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  GtpuEngine& engine_;
};

class SctpDriver final : public ITelcoProtocolDriver {
 public:
  explicit SctpDriver(SctpEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SCTP);
      ctx->client_port = static_cast<uint16_t>(20000 + (sub_idx % 30000));
      ctx->peer_port = 38412;  // NGAP standard port
      ctx->ip_proto = IP_PROTO_SCTP;
      ctx->state = SessionState::IDLE;

      SctpAssociationConfig sctp_cfg{};
      sctp_cfg.local_ip = ctx->client_ip;
      sctp_cfg.peer_ip = spec.gateway_ip;
      sctp_cfg.local_port = ctx->client_port;
      sctp_cfg.peer_port = ctx->peer_port;
      sctp_cfg.my_vtag = 0x10000000u + sub_idx;
      sctp_cfg.peer_vtag = 0x20000000u + sub_idx;
      sctp_cfg.my_initial_tsn = 1000u + sub_idx;
      sctp_cfg.peer_initial_tsn = 2000u + sub_idx;
      sctp_cfg.vlan_s = ctx->s_vlan;
      sctp_cfg.vlan_c = ctx->c_vlan;
      std::memcpy(sctp_cfg.local_mac, ctx->client_mac, 6);
      std::memcpy(sctp_cfg.peer_mac, ctx->peer_mac, 6);
      engine_.StartAssociation(ctx, sctp_cfg);
      engine_.AddPath(ctx, spec.gateway_ip + 1u, false);
      session_mgr.Bind5Tuple(ctx, ctx->client_ip, ctx->peer_ip, ctx->client_port, ctx->peer_port, IP_PROTO_SCTP);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    static const uint8_t sctp_payload[32] = "NGAP_PDU_INITIAL_UE_MESSAGE_01";
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      auto pkt = engine_.BuildDataPacket(ctx, 60 /* NGAP PPID */, sctp_payload, sizeof(sctp_payload));
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& /*session_mgr*/, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    engine_.ProcessRxFrame(frame, len, samurai_rdtsc());
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  SctpEngine& engine_;
};

class DiameterDriver final : public ITelcoProtocolDriver {
 public:
  explicit DiameterDriver(DiameterEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DIAMETER);
      ctx->client_port = static_cast<uint16_t>(30000 + (sub_idx % 20000));
      ctx->peer_port = 3868;
      ctx->ip_proto = 6;
      ctx->state = SessionState::IDLE;

      DiameterPeerConfig diam_cfg{};
      diam_cfg.origin_host = "client" + std::to_string(sub_idx) + ".epc.mnc001.mcc001.3gppnetwork.org";
      diam_cfg.origin_realm = "epc.mnc001.mcc001.3gppnetwork.org";
      diam_cfg.destination_host = "pcrf.epc.mnc001.mcc001.3gppnetwork.org";
      diam_cfg.destination_realm = "epc.mnc001.mcc001.3gppnetwork.org";
      diam_cfg.local_ip = ctx->client_ip;
      diam_cfg.peer_ip = spec.gateway_ip;
      diam_cfg.local_port = ctx->client_port;
      diam_cfg.peer_port = ctx->peer_port;
      diam_cfg.vlan_s = ctx->s_vlan;
      diam_cfg.vlan_c = ctx->c_vlan;
      std::memcpy(diam_cfg.local_mac, ctx->client_mac, 6);
      std::memcpy(diam_cfg.peer_mac, ctx->peer_mac, 6);
      engine_.StartPeerSession(ctx, diam_cfg);
      session_mgr.Bind5Tuple(ctx, ctx->client_ip, ctx->peer_ip, ctx->client_port, ctx->peer_port, 6);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      std::string sess_id = "subscriber-billing-" + std::to_string(ctx->session_id);
      const uint32_t cc_num = static_cast<uint32_t>(ctx->tx_packets + 1u);
      auto pkt = engine_.BuildDictionaryDrivenCcr(ctx, sess_id, CcRequestType::UPDATE_REQUEST, cc_num);
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& /*session_mgr*/, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    engine_.ProcessRxFrame(frame, len, samurai_rdtsc());
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  DiameterEngine& engine_;
};

class SipRtpDriver final : public ITelcoProtocolDriver {
 public:
  explicit SipRtpDriver(SipRtpEngine& engine) : engine_(engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    const std::string peer_ip_str = FormatHostIpv4(spec.gateway_ip);
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      TelcoSessionContext* ctx = session_mgr.AcquireSession();
      if (!ctx) continue;
      ctx->client_ip = spec.base_client_ip + sub_idx;
      ctx->peer_ip = spec.gateway_ip;
      PopulateCommonMacAndVlans(ctx, sub_idx, spec);
      ctx->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SIP_RTP);
      ctx->client_port = 5060;
      ctx->peer_port = 5060;
      ctx->ip_proto = 17;
      ctx->state = SessionState::IDLE;

      SipCallConfig call_cfg{};
      call_cfg.from_uri = "sip:user" + std::to_string(sub_idx) + "@ims.carrier.net";
      call_cfg.to_uri = "sip:service@ims.carrier.net";
      call_cfg.call_id = "callid-" + std::to_string(sub_idx) + "@carrier.net";
      call_cfg.local_ip_str = FormatHostIpv4(ctx->client_ip);
      call_cfg.peer_ip_str = peer_ip_str;
      call_cfg.local_ip = ctx->client_ip;
      call_cfg.peer_ip = ctx->peer_ip;
      call_cfg.local_sip_port = 5060;
      call_cfg.peer_sip_port = 5060;
      call_cfg.local_rtp_port = static_cast<uint16_t>(10000 + ((sub_idx * 2) % 10000));
      call_cfg.peer_rtp_port = static_cast<uint16_t>(10000 + ((sub_idx * 2) % 10000));
      call_cfg.vlan_s = ctx->s_vlan;
      call_cfg.vlan_c = ctx->c_vlan;
      call_cfg.ssrc = 0x12340000u + sub_idx;
      call_cfg.enable_srtp = spec.enable_srtp;
      std::memcpy(call_cfg.local_mac, ctx->client_mac, 6);
      std::memcpy(call_cfg.peer_mac, ctx->peer_mac, 6);
      engine_.StartCall(ctx, call_cfg);
      session_mgr.Bind5Tuple(ctx, ctx->client_ip, ctx->peer_ip, ctx->client_port, ctx->peer_port, 17);
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    static const uint8_t audio_pcm[160] = {0x55, 0xAA};
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      auto pkt = engine_.BuildRtpPacket(ctx, audio_pcm, sizeof(audio_pcm));
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& /*session_mgr*/, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    engine_.ProcessRxFrame(frame, len, samurai_rdtsc());
  }

  void OnTimerTick(uint64_t current_tsc) override { engine_.OnTimerTick(current_tsc); }

 private:
  SipRtpEngine& engine_;
};

class TelcoFullDriver final : public ITelcoProtocolDriver {
 public:
  TelcoFullDriver(PppoeDriver& pppoe, DhcpDriver& dhcp, BfdDriver& bfd,
                  GtpuDriver& gtpu, SctpDriver& sctp, DiameterDriver& diam,
                  SipRtpDriver& sip)
      : pppoe_(pppoe), dhcp_(dhcp), bfd_(bfd), gtpu_(gtpu),
        sctp_(sctp), diam_(diam), sip_(sip) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      TelcoJobSpec single = spec;
      single.sub_start = spec.sub_start + i;
      single.sub_count = 1;
      switch (single.sub_start % 7) {
        case 0: pppoe_.InitializeSubscribers(session_mgr, single); break;
        case 1: dhcp_.InitializeSubscribers(session_mgr, single); break;
        case 2: bfd_.InitializeSubscribers(session_mgr, single); break;
        case 3: gtpu_.InitializeSubscribers(session_mgr, single); break;
        case 4: sctp_.InitializeSubscribers(session_mgr, single); break;
        case 5: diam_.InitializeSubscribers(session_mgr, single); break;
        case 6: sip_.InitializeSubscribers(session_mgr, single); break;
      }
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      auto pid = static_cast<TelcoProtocolId>(ctx->protocol_id);
      switch (pid) {
        case TelcoProtocolId::PPPOE: pppoe_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::DHCPV4: dhcp_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::BFD: bfd_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::GTPU: gtpu_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::SCTP: sctp_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::DIAMETER: diam_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        case TelcoProtocolId::SIP_RTP: sip_.GenerateTraffic(session_mgr, sub_cursor + i, 1, out_packets); break;
        default: break;
      }
    }
  }

  void ProcessRx(SessionManager& session_mgr, const uint8_t* frame, size_t len,
                 const PacketMetadata& meta, TelcoFrameType frame_type) override {
    switch (frame_type) {
      case TelcoFrameType::PppoeDiscovery:
      case TelcoFrameType::PppoeSession:
        pppoe_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Dhcp:
        dhcp_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Bfd:
        bfd_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Gtpu:
        gtpu_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Sctp:
        sctp_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Diameter:
        diam_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      case TelcoFrameType::Sip:
      case TelcoFrameType::Rtp:
        sip_.ProcessRx(session_mgr, frame, len, meta, frame_type);
        break;
      default:
        break;
    }
  }

  void OnTimerTick(uint64_t current_tsc) override {
    pppoe_.OnTimerTick(current_tsc);
    dhcp_.OnTimerTick(current_tsc);
    bfd_.OnTimerTick(current_tsc);
    gtpu_.OnTimerTick(current_tsc);
    sctp_.OnTimerTick(current_tsc);
    diam_.OnTimerTick(current_tsc);
    sip_.OnTimerTick(current_tsc);
  }

 private:
  PppoeDriver& pppoe_;
  DhcpDriver& dhcp_;
  BfdDriver& bfd_;
  GtpuDriver& gtpu_;
  SctpDriver& sctp_;
  DiameterDriver& diam_;
  SipRtpDriver& sip_;
};

class CupsDriver final : public ITelcoProtocolDriver {
 public:
  CupsDriver(samurai::telecom::cups::DpuArmCupsSessionController& controller,
             PfcpEngine& pfcp_engine)
      : controller_(controller), pfcp_engine_(pfcp_engine) {}

  void InitializeSubscribers(SessionManager& session_mgr, const TelcoJobSpec& spec) override {
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      uint32_t sub_idx = spec.sub_start + i;
      samurai::telecom::cups::CupsTunnelParams p{};
      p.uplink_teid = spec.teid_start + sub_idx;
      p.downlink_teid = spec.teid_start + sub_idx + 1000u;
      p.ue_src_ip = spec.base_client_ip + sub_idx;
      p.inner_dst_ip = spec.gateway_ip;
      p.inner_src_port = static_cast<uint16_t>(1024u + (sub_idx % 60000u));
      p.inner_dst_port = spec.target_port;
      p.svlan_tci = spec.base_vlan_s;
      p.cvlan_tci = spec.base_vlan_c;
      p.vlan_depth = (spec.base_vlan_s && spec.base_vlan_c) ? 2 : (spec.base_vlan_s || spec.base_vlan_c ? 1 : 0);
      p.qfi = spec.qfi;
      p.pdu_type = 1;
      p.inner_proto = spec.inner_proto;
      p.with_seq = true;
      p.with_qfi_ext = true;
      controller_.EstablishSubscriberSession(sub_idx, static_cast<uint64_t>(sub_idx + 1u), p, nullptr);

      if (TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(i)) {
        ctx->client_ip = p.ue_src_ip;
        ctx->peer_ip = spec.gateway_ip;
        ctx->client_port = PFCP_PORT;
        ctx->peer_port = PFCP_PORT;
        ctx->ip_proto = 17;
      }
    }
  }

  void GenerateTraffic(SessionManager& session_mgr, uint32_t sub_cursor, uint32_t count,
                       std::vector<std::vector<uint8_t>>& out_packets) override {
    for (uint32_t i = 0; i < count; ++i) {
      TelcoSessionContext* ctx = session_mgr.GetSessionByIndex(sub_cursor + i);
      if (!ctx) continue;
      auto pkt = pfcp_engine_.BuildHeartbeatRequest(++pfcp_seq_);
      if (!pkt.empty()) out_packets.push_back(std::move(pkt));
    }
  }

  void ProcessRx(SessionManager& /*session_mgr*/, const uint8_t* frame, size_t len,
                 const PacketMetadata& /*meta*/, TelcoFrameType /*frame_type*/) override {
    controller_.ProcessInboundPfcpMessage(frame, len, nullptr);
  }

  void OnTimerTick(uint64_t current_tsc) override {
    controller_.UpdateHeartbeat(current_tsc);
  }

 private:
  samurai::telecom::cups::DpuArmCupsSessionController& controller_;
  PfcpEngine& pfcp_engine_;
  std::uint32_t pfcp_seq_{0};
};

// Encapsulates all per-job Telco engines and subscriber sessions so warm
// worker restarts / protocol switches never inherit stale session state.
struct TelcoRuntime {
  uint32_t capacity;
  SessionManager session_mgr;
  HierarchicalTimingWheel timing_wheel;
  PppoeEngine pppoe_engine;
  DhcpEngine dhcp_engine;
  BfdEngine bfd_engine;
  GtpuEngine gtpu_engine;
  PfcpEngine pfcp_engine;
  SctpEngine sctp_engine;
  DiameterEngine diameter_engine;
  SipRtpEngine sip_rtp_engine;
  samurai::telecom::cups::DpuArmCupsSessionController cups_controller;

  PppoeDriver pppoe_driver;
  DhcpDriver dhcp_driver;
  BfdDriver bfd_driver;
  GtpuDriver gtpu_driver;
  CupsDriver cups_driver;
  SctpDriver sctp_driver;
  DiameterDriver diameter_driver;
  SipRtpDriver sip_rtp_driver;
  TelcoFullDriver telco_full_driver;
  ITelcoProtocolDriver* active_driver = &pppoe_driver;

  TelcoRuntime(const TelcoJobSpec& spec, uint64_t tsc_hz, const std::string& cups_shm_path)
      : capacity(std::max<uint32_t>(64u, spec.sub_count)),
        session_mgr(capacity),
        timing_wheel(tsc_hz),
        pppoe_engine(session_mgr, &timing_wheel),
        dhcp_engine(session_mgr, &timing_wheel),
        bfd_engine(session_mgr, &timing_wheel),
        gtpu_engine(session_mgr, &timing_wheel),
        pfcp_engine(session_mgr, &timing_wheel),
        sctp_engine(session_mgr, &timing_wheel),
        diameter_engine(session_mgr, &timing_wheel),
        sip_rtp_engine(session_mgr, &timing_wheel),
        cups_controller(session_mgr, pfcp_engine, capacity),
        pppoe_driver(pppoe_engine),
        dhcp_driver(dhcp_engine),
        bfd_driver(bfd_engine),
        gtpu_driver(gtpu_engine),
        cups_driver(cups_controller, pfcp_engine),
        sctp_driver(sctp_engine),
        diameter_driver(diameter_engine),
        sip_rtp_driver(sip_rtp_engine),
        telco_full_driver(pppoe_driver, dhcp_driver, bfd_driver,
                          gtpu_driver, sctp_driver, diameter_driver, sip_rtp_driver) {
    ProtocolConfig pcfg{};
    pcfg.max_sessions = capacity;
    pcfg.rate_cps = std::max(1u, spec.rate_cps);
    pcfg.retransmit_timeout_ms = 500;
    pcfg.max_retries = 3;

    pppoe_engine.Init(pcfg);
    dhcp_engine.Init(pcfg);
    bfd_engine.Init(pcfg);
    gtpu_engine.Init(pcfg);
    pfcp_engine.Init(pcfg);
    sctp_engine.Init(pcfg);
    diameter_engine.Init(pcfg);
    sip_rtp_engine.Init(pcfg);

    if (!cups_shm_path.empty()) {
      (void)cups_controller.InitializeSharedRegion(cups_shm_path, true);
    }

    const std::string p = ToLower(spec.protocol);
    if (p == "dhcp" || p == "dhcpv4") {
      active_driver = &dhcp_driver;
    } else if (p == "bfd") {
      active_driver = &bfd_driver;
    } else if (p == "gtpu" || p == "gtp-u" || p == "5g-gtpu") {
      active_driver = &gtpu_driver;
    } else if (p == "pfcp" || p == "cups") {
      active_driver = &cups_driver;
    } else if (p == "sctp" || p == "sctp-flood") {
      active_driver = &sctp_driver;
    } else if (p == "diameter" || p == "diameter-ccr") {
      active_driver = &diameter_driver;
    } else if (p == "sip" || p == "rtp" || p == "sip-rtp" || p == "sip_rtp" || p == "sip-storm") {
      active_driver = &sip_rtp_driver;
    } else if (p == "telco-full" || p == "multi" || p == "telco") {
      active_driver = &telco_full_driver;
    } else {
      active_driver = &pppoe_driver;
    }

    active_driver->InitializeSubscribers(session_mgr, spec);
  }

  ~TelcoRuntime() {
    sip_rtp_engine.Shutdown();
    diameter_engine.Shutdown();
    sctp_engine.Shutdown();
    pfcp_engine.Shutdown();
    gtpu_engine.Shutdown();
    bfd_engine.Shutdown();
    dhcp_engine.Shutdown();
    pppoe_engine.Shutdown();
  }
};

struct AggregatedSessionStats {
  uint32_t active_sessions = 0;
  uint32_t established_sessions = 0;
  uint32_t failed_sessions = 0;
  uint64_t retransmit_count = 0;
};

AggregatedSessionStats AggregateSessionsExact(SessionManager& mgr, uint32_t sub_count) {
  AggregatedSessionStats out;
  out.active_sessions = mgr.GetActiveSessionCount();
  const uint32_t n = std::min(sub_count, mgr.GetCapacity());
  for (uint32_t i = 0; i < n; ++i) {
    TelcoSessionContext* ctx = mgr.GetSessionByIndex(i);
    if (!ctx) continue;
    if (ctx->state == SessionState::ESTABLISHED) {
      ++out.established_sessions;
    } else if (ctx->state == SessionState::FAILED) {
      ++out.failed_sessions;
    }
    out.retransmit_count += ctx->retry_count;
  }
  return out;
}

void EmitTelcoSnapshotDelta(
    void* events_sock,
    const std::string& job_id,
    uint64_t corr_id,
    uint64_t tx_packets_total,
    uint64_t rx_packets_total,
    uint64_t tx_bytes_total,
    uint64_t rx_bytes_total,
    uint64_t& last_reported_tx,
    uint64_t& last_reported_bytes,
    uint64_t& last_reported_failed,
    uint32_t active_sessions,
    uint32_t established_sessions,
    uint32_t failed_sessions,
    uint32_t current_cps,
    double actual_rps,
    double rate_accuracy_pct,
    uint32_t avg_setup_latency_us,
    uint32_t p99_setup_latency_us,
    uint32_t retransmit_count,
    uint16_t db_port) {
  const uint64_t delta_tx =
      tx_packets_total >= last_reported_tx ? (tx_packets_total - last_reported_tx) : 0;
  const uint64_t delta_bytes =
      tx_bytes_total >= last_reported_bytes ? (tx_bytes_total - last_reported_bytes) : 0;
  const uint64_t delta_failed =
      failed_sessions >= last_reported_failed ? (failed_sessions - last_reported_failed) : 0;
  last_reported_tx = tx_packets_total;
  last_reported_bytes = tx_bytes_total;
  last_reported_failed = failed_sessions;

  MetricSnapshotV1 snap{};
  snap.timestamp_ns = samurai_pacing_monotonic_now_ns();
  snap.packets_sent = delta_tx;
  snap.packets_errors = delta_failed;
  snap.bytes_sent = delta_bytes;
  snap.actual_rps = actual_rps;
  snap.rate_accuracy_pct = rate_accuracy_pct;

  TelcoStatsPayload stats{};
  stats.active_sessions = active_sessions;
  stats.established_sessions = established_sessions;
  stats.failed_sessions = failed_sessions;
  stats.current_cps = current_cps;
  stats.tx_packets = tx_packets_total;
  stats.rx_packets = rx_packets_total;
  stats.tx_bytes = tx_bytes_total;
  stats.rx_bytes = rx_bytes_total;
  stats.avg_setup_latency_us = avg_setup_latency_us;
  stats.p99_setup_latency_us = p99_setup_latency_us;
  stats.retransmit_count = retransmit_count;
  stats.db_port = db_port;

  std::vector<uint8_t> payload(sizeof(snap) + sizeof(stats));
  std::memcpy(payload.data(), &snap, sizeof(snap));
  std::memcpy(payload.data() + sizeof(snap), &stats, sizeof(stats));
  SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::METRIC_SNAPSHOT),
            corr_id, WorkerKind::TELCO, job_id, payload);
}

std::string BuildTelcoJobDoneJson(
    const char* status,
    const std::string& protocol,
    uint64_t tx_packets,
    uint64_t rx_packets,
    const AggregatedSessionStats& sess,
    uint32_t current_cps,
    uint32_t avg_latency_us,
    uint32_t p99_latency_us,
    const TelemetrySink& telemetry) {
  char buf[1024];
  std::snprintf(
      buf, sizeof(buf),
      "{\"status\":\"%s\",\"protocol\":\"%s\",\"tx_packets\":%llu,\"rx_packets\":%llu,"
      "\"ipfix_exported_packets\":%llu,\"ipfix_exported_records\":%llu,"
      "\"telco_active_sessions\":%u,\"telco_established_sessions\":%u,"
      "\"telco_failed_sessions\":%u,\"telco_current_cps\":%u,"
      "\"telco_avg_setup_latency_us\":%u,\"telco_p99_setup_latency_us\":%u,"
      "\"telco_retransmit_count\":%llu}",
      status,
      protocol.c_str(),
      static_cast<unsigned long long>(tx_packets),
      static_cast<unsigned long long>(rx_packets),
      static_cast<unsigned long long>(telemetry.JobExportedPackets()),
      static_cast<unsigned long long>(telemetry.JobExportedRecords()),
      static_cast<unsigned>(sess.active_sessions),
      static_cast<unsigned>(sess.established_sessions),
      static_cast<unsigned>(sess.failed_sessions),
      static_cast<unsigned>(current_cps),
      static_cast<unsigned>(avg_latency_us),
      static_cast<unsigned>(p99_latency_us),
      static_cast<unsigned long long>(sess.retransmit_count));
  return std::string(buf);
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, SignalHandler);
  std::signal(SIGTERM, SignalHandler);

  std::string jobs_endpoint = kDefaultJobs;
  std::string events_endpoint = kDefaultEvents;
  std::string iface_name;
  std::string transport_mode = "af_packet";
  TelcoJobSpec cli_defaults;
  std::string cups_shm_path;
  if (const char* env_cups = std::getenv("SAMURAI_CUPS_CONTRACT_PATH"); env_cups && env_cups[0]) {
    cups_shm_path = env_cups;
  }
  std::string cups_gpu_endpoint;
  if (const char* env_gep = std::getenv("SAMURAI_CUPS_GPU_ENDPOINT"); env_gep && env_gep[0]) {
    cups_gpu_endpoint = env_gep;
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--job-endpoint" && i + 1 < argc) {
      jobs_endpoint = argv[++i];
    } else if (arg == "--event-endpoint" && i + 1 < argc) {
      events_endpoint = argv[++i];
    } else if (arg == "--iface" && i + 1 < argc) {
      iface_name = argv[++i];
    } else if (arg == "--transport" && i + 1 < argc) {
      transport_mode = ToLower(argv[++i]);
    } else if (arg == "--pin-cpu" && i + 1 < argc) {
      cli_defaults.pin_cpu = std::stoi(argv[++i]);
    } else if (arg == "--subscriber-start" && i + 1 < argc) {
      cli_defaults.sub_start = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--subscriber-count" && i + 1 < argc) {
      cli_defaults.sub_count = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--protocol" && i + 1 < argc) {
      cli_defaults.protocol = ToLower(argv[++i]);
    } else if (arg == "--cps" && i + 1 < argc) {
      cli_defaults.rate_cps = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--sctp-rate" && i + 1 < argc) {
      cli_defaults.sctp_rate = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if ((arg == "--diameter-ccr-rate" || arg == "--diameter-rate") && i + 1 < argc) {
      cli_defaults.diameter_rate = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--sip-rate" && i + 1 < argc) {
      cli_defaults.sip_rate = static_cast<uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--enable-srtp") {
      cli_defaults.enable_srtp = true;
    } else if (arg == "--vlan-s" && i + 1 < argc) {
      cli_defaults.base_vlan_s = static_cast<uint16_t>(std::stoul(argv[++i]));
    } else if (arg == "--vlan-c" && i + 1 < argc) {
      cli_defaults.base_vlan_c = static_cast<uint16_t>(std::stoul(argv[++i]));
    } else if (arg == "--db-port" && i + 1 < argc) {
      cli_defaults.db_port = static_cast<uint16_t>(std::stoul(argv[++i]));
    } else if (arg == "--cups-shm-path" && i + 1 < argc) {
      cups_shm_path = argv[++i];
    } else if (arg == "--cups-gpu-endpoint" && i + 1 < argc) {
      cups_gpu_endpoint = argv[++i];
    }
  }

  if (iface_name.empty()) {
    if (const char* env_if = std::getenv("SAMURAI_TELCO_IFACE"); env_if && env_if[0]) {
      iface_name = env_if;
    }
  }
  if (const char* env_tr = std::getenv("SAMURAI_TELCO_TRANSPORT"); env_tr && env_tr[0]) {
    transport_mode = ToLower(env_tr);
  }
  if (cli_defaults.pin_cpu >= 0) {
    ApplyAffinity(cli_defaults.pin_cpu);
  }

  uint64_t tsc_hz = HierarchicalTimingWheel::CalibrateTscHz();
  if (tsc_hz == 0) tsc_hz = 2000000000ULL;

  std::unique_ptr<ITelcoPacketTransport> packet_transport = CreateTelcoPacketTransport(transport_mode);
  if (!iface_name.empty() || transport_mode == "loopback" || transport_mode == "dpdk" ||
      transport_mode == "dpdk_direct") {
    if (!packet_transport->Open(iface_name)) {
      if (transport_mode == "dpdk" || transport_mode == "dpdk_direct") {
        std::cerr << "[TELCO_WORKER] FATAL: DPDK transport requested (--transport " << transport_mode
                  << ") but initialization failed." << std::endl;
        return 2;
      }
    }
  }

  void* zmq_ctx = zmq_ctx_new();
  void* jobs_sock = zmq_socket(zmq_ctx, ZMQ_PULL);
  void* events_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);
  int linger = 200;
  zmq_setsockopt(events_sock, ZMQ_LINGER, &linger, sizeof(linger));
  int recv_to = 100;
  zmq_setsockopt(jobs_sock, ZMQ_RCVTIMEO, &recv_to, sizeof(recv_to));

  if (zmq_bind(jobs_sock, jobs_endpoint.c_str()) != 0) {
    zmq_connect(jobs_sock, jobs_endpoint.c_str());
  }
  zmq_connect(events_sock, events_endpoint.c_str());

  void* cups_gpu_sock = nullptr;
  if (!cups_gpu_endpoint.empty()) {
    cups_gpu_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);
    if (cups_gpu_sock) {
      zmq_connect(cups_gpu_sock, cups_gpu_endpoint.c_str());
    }
  }

  TelemetrySink telemetry;
  std::unique_ptr<TelcoRuntime> runtime;

  while (g_worker_running) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    const int n = zmq_msg_recv(&msg, jobs_sock, 0);
    if (n < 0) {
      zmq_msg_close(&msg);
      continue;
    }

    const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
    DecodedWireFrame frame{};
    if (!DecodeWireFrame(zmq_msg_data(&msg), sz, frame)) {
      zmq_msg_close(&msg);
      continue;
    }

    const std::string& job_id = frame.job_id;
    const auto& hdr = frame.as_v1_header;

    if (HandleCommonIdleMessage(events_sock, WorkerKind::TELCO, frame, telemetry, g_worker_running)) {
      zmq_msg_close(&msg);
      continue;
    }

    if (static_cast<MessageType>(frame.msg_type) != MessageType::START_JOB) {
      zmq_msg_close(&msg);
      continue;
    }

    TelcoJobSpec spec;
    if (!ParseStartJobFrame(frame, cli_defaults, spec, &telemetry)) {
      zmq_msg_close(&msg);
      SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::ERROR),
                frame.correlation_id, WorkerKind::TELCO, job_id,
                JsonError("telco_envelope_size_mismatch"));
      continue;
    }
    const std::uint64_t start_corr = frame.correlation_id;
    zmq_msg_close(&msg);

    if (spec.pin_cpu >= 0) {
      ApplyAffinity(spec.pin_cpu);
    }

    runtime.reset();
    runtime = std::make_unique<TelcoRuntime>(spec, tsc_hz, cups_shm_path);
    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      if (TelcoSessionContext* ctx = runtime->session_mgr.GetSessionByIndex(i)) {
        ctx->state = SessionState::ESTABLISHED;
      }
    }

    if (cups_gpu_sock && runtime->cups_controller.GetActiveSessions() > 0) {
      std::vector<uint8_t> upsert_payload = runtime->cups_controller.BuildZmqUpsertPayload(
          spec.sub_start, spec.sub_count, samurai::wire::kTelcoTunnelUpsertFlagClearBeforeUpsert);
      if (!upsert_payload.empty()) {
        SendFrame(cups_gpu_sock, static_cast<std::uint8_t>(MessageType::TELCO_TUNNEL_UPSERT),
                  start_corr, WorkerKind::TELCO, job_id, upsert_payload);
      }
    }

    SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::ACK),
              start_corr, WorkerKind::TELCO, job_id);

    telemetry.BeginJob();

    double eff_rps = spec.target_rps > 0.0
                         ? spec.target_rps
                         : static_cast<double>(std::max<uint32_t>(1u, spec.rate_cps));
    samurai_pacing_config_t pace_cfg{};
    pace_cfg.mode = spec.ipg_ns > 0 ? SAMURAI_PACING_IPG : SAMURAI_PACING_RPS;
    pace_cfg.target_rps = eff_rps;
    pace_cfg.ipg_ns = spec.ipg_ns;
    pace_cfg.burst_size = std::max<uint32_t>(1u, spec.burst_size);
    pace_cfg.jitter_model = SAMURAI_JITTER_NONE;
    pace_cfg.disable_busywait = 1;
    samurai_pacing_state_t pace_state{};
    samurai_pacing_init(&pace_state, &pace_cfg);

    const std::uint64_t job_start_ns = samurai_pacing_monotonic_now_ns();
    const std::uint64_t duration_limit_ns =
        spec.duration_ms > 0 ? static_cast<std::uint64_t>(spec.duration_ms) * 1000000ULL : 0ULL;

    uint64_t tx_packets_total = 0;
    uint64_t rx_packets_total = 0;
    uint64_t tx_bytes_total = 0;
    uint64_t rx_bytes_total = 0;
    uint64_t last_reported_tx = 0;
    uint64_t last_reported_bytes = 0;
    uint64_t last_reported_failed = 0;
    uint32_t active_sub_cursor = 0;
    uint64_t last_snapshot_ns = job_start_ns;
    LatencyRing latency_ring;
    std::vector<std::vector<uint8_t>> tx_packets_batch;
    tx_packets_batch.reserve(512);

    bool stopped_by_cmd = false;
    while (g_worker_running) {
      ControlPollState cstate;
      PollControlNonBlocking(jobs_sock, events_sock, WorkerKind::TELCO, &telemetry, cstate);
      if (cstate.reconfigure) {
        std::uint32_t new_cps = spec.rate_cps;
        ApplyReconfigureWindow(
            reinterpret_cast<const std::uint8_t*>(&cstate.reconf),
            sizeof(cstate.reconf),
            pace_cfg,
            pace_state,
            nullptr,
            nullptr,
            &new_cps);
        if (cstate.reconf.flags & samurai::wire::ReconfigureFlag::kTelcoCps) {
          spec.rate_cps = std::max<std::uint32_t>(1u, new_cps);
          if ((cstate.reconf.flags & samurai::wire::ReconfigureFlag::kRps) == 0) {
            pace_cfg.mode = SAMURAI_PACING_RPS;
            pace_cfg.target_rps = static_cast<double>(spec.rate_cps);
            samurai_pacing_reconfigure(&pace_state, &pace_cfg);
          }
        } else if (cstate.reconf.flags & samurai::wire::ReconfigureFlag::kRps) {
          spec.rate_cps = static_cast<std::uint32_t>(std::max(1.0, pace_cfg.target_rps));
        }
      }
      if (cstate.shutdown) {
        g_worker_running = false;
        stopped_by_cmd = true;
        break;
      }
      if (cstate.stop_job) {
        stopped_by_cmd = true;
        break;
      }

      const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
      if (spec.packet_count > 0 && tx_packets_total >= spec.packet_count) {
        break;
      }
      if (duration_limit_ns > 0 && (now_ns - job_start_ns) >= duration_limit_ns) {
        break;
      }

      const uint64_t now_tsc = samurai_rdtsc();
      runtime->active_driver->OnTimerTick(now_tsc);

      if (packet_transport && packet_transport->IsOpen()) {
        uint8_t rx_buffer[2048];
        for (int r = 0; r < 64; ++r) {
          ssize_t rlen = packet_transport->Receive(rx_buffer, sizeof(rx_buffer));
          if (rlen <= 0) break;
          ++rx_packets_total;
          rx_bytes_total += static_cast<uint64_t>(rlen);
          PacketMetadata meta{};
          TelcoFrameType ftype = TelcoFrameType::Unknown;
          if (FastpathClassifier::Classify(rx_buffer, static_cast<size_t>(rlen), meta, ftype)) {
            runtime->active_driver->ProcessRx(
                runtime->session_mgr, rx_buffer, static_cast<size_t>(rlen), meta, ftype);
          }
        }
      }

      uint32_t batch_limit = std::min<uint32_t>(
          std::max<uint32_t>(1u, spec.rate_cps / 50u + 1u),
          std::min<uint32_t>(spec.sub_count, 64u));
      if (spec.packet_count > 0) {
        const uint64_t rem = spec.packet_count - tx_packets_total;
        batch_limit = static_cast<uint32_t>(std::min<uint64_t>(batch_limit, rem));
      }

      const auto t_gen0 = std::chrono::steady_clock::now();
      tx_packets_batch.clear();
      runtime->active_driver->GenerateTraffic(
          runtime->session_mgr, active_sub_cursor, batch_limit, tx_packets_batch);
      const auto t_gen1 = std::chrono::steady_clock::now();
      const uint32_t gen_us = static_cast<uint32_t>(std::max<long long>(
          1, std::chrono::duration_cast<std::chrono::microseconds>(t_gen1 - t_gen0).count()));
      latency_ring.RecordUs(gen_us);

      if (packet_transport && packet_transport->IsOpen()) {
        std::vector<const uint8_t*> ptrs;
        std::vector<uint16_t> lens;
        ptrs.reserve(tx_packets_batch.size());
        lens.reserve(tx_packets_batch.size());
        for (const auto& pkt : tx_packets_batch) {
          if (pkt.empty() || pkt.size() > 65535u) continue;
          ptrs.push_back(pkt.data());
          lens.push_back(static_cast<uint16_t>(pkt.size()));
        }
        const size_t sent = packet_transport->TransmitBurst(ptrs.data(), lens.data(), ptrs.size());
        for (size_t i = 0; i < sent; ++i) {
          ++tx_packets_total;
          tx_bytes_total += lens[i];
          if (telemetry.Enabled()) {
            const uint32_t sidx = (active_sub_cursor + static_cast<uint32_t>(i)) % spec.sub_count;
            if (TelcoSessionContext* c = runtime->session_mgr.GetSessionByIndex(sidx)) {
              telemetry.RecordPacketHost(c->client_ip, c->peer_ip, c->client_port, c->peer_port,
                                         c->ip_proto, lens[i], 0x10u, c->s_vlan, now_ns);
            }
          }
        }
      } else {
        for (size_t i = 0; i < tx_packets_batch.size(); ++i) {
          const auto& pkt = tx_packets_batch[i];
          if (pkt.empty()) continue;
          ++tx_packets_total;
          tx_bytes_total += pkt.size();
          if (telemetry.Enabled()) {
            const uint32_t sidx = (active_sub_cursor + static_cast<uint32_t>(i)) % spec.sub_count;
            if (TelcoSessionContext* c = runtime->session_mgr.GetSessionByIndex(sidx)) {
              telemetry.RecordPacketHost(c->client_ip, c->peer_ip, c->client_port, c->peer_port,
                                         c->ip_proto, static_cast<uint32_t>(pkt.size()),
                                         0x10u, c->s_vlan, now_ns);
            }
          }
        }
      }

      if (spec.sub_count > 0) {
        active_sub_cursor = (active_sub_cursor + std::max<uint32_t>(1u, batch_limit)) % spec.sub_count;
      }

      telemetry.TickExport(now_ns);

      if (now_ns - last_snapshot_ns >= 1000000000ULL) {
        const AggregatedSessionStats sess = AggregateSessionsExact(runtime->session_mgr, spec.sub_count);
        uint32_t avg_us = 0, p99_us = 0;
        latency_ring.Compute(avg_us, p99_us);
        const double elapsed_s = std::max(1e-6, static_cast<double>(now_ns - job_start_ns) / 1e9);
        const double actual_rps = static_cast<double>(tx_packets_total) / elapsed_s;
        const double target = std::max(1.0, pace_cfg.target_rps);
        const double acc = std::min(100.0, (actual_rps / target) * 100.0);

        EmitTelcoSnapshotDelta(
            events_sock, job_id, start_corr,
            tx_packets_total, rx_packets_total, tx_bytes_total, rx_bytes_total,
            last_reported_tx, last_reported_bytes, last_reported_failed,
            sess.active_sessions, sess.established_sessions, sess.failed_sessions,
            spec.rate_cps, actual_rps, acc,
            avg_us, p99_us,
            static_cast<uint32_t>(std::min<uint64_t>(sess.retransmit_count, 0xFFFFFFFFULL)),
            spec.db_port);
        last_snapshot_ns = now_ns;
      }

      const std::size_t tx_this_batch = tx_packets_batch.size();
      for (std::size_t k = 0; k < tx_this_batch; ++k) {
        samurai_pacing_wait_next(&pace_state, &pace_cfg);
        if ((k & 7u) == 7u) {
          ControlPollState mid_state;
          PollControlNonBlocking(jobs_sock, events_sock, WorkerKind::TELCO, &telemetry, mid_state);
          if (mid_state.reconfigure) {
            std::uint32_t new_cps = spec.rate_cps;
            ApplyReconfigureWindow(
                reinterpret_cast<const std::uint8_t*>(&mid_state.reconf),
                sizeof(mid_state.reconf),
                pace_cfg,
                pace_state,
                nullptr,
                nullptr,
                &new_cps);
            if (mid_state.reconf.flags & samurai::wire::ReconfigureFlag::kTelcoCps) {
              spec.rate_cps = std::max<std::uint32_t>(1u, new_cps);
              if ((mid_state.reconf.flags & samurai::wire::ReconfigureFlag::kRps) == 0) {
                pace_cfg.mode = SAMURAI_PACING_RPS;
                pace_cfg.target_rps = static_cast<double>(spec.rate_cps);
                samurai_pacing_reconfigure(&pace_state, &pace_cfg);
              }
            } else if (mid_state.reconf.flags & samurai::wire::ReconfigureFlag::kRps) {
              spec.rate_cps = static_cast<std::uint32_t>(std::max(1.0, pace_cfg.target_rps));
            }
          }
          if (mid_state.shutdown) {
            g_worker_running = false;
            stopped_by_cmd = true;
            break;
          }
          if (mid_state.stop_job) {
            stopped_by_cmd = true;
            break;
          }
        }
      }
      if (stopped_by_cmd) break;
    }

    const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
    telemetry.FlushEnd(end_ns);

    const AggregatedSessionStats final_sess = AggregateSessionsExact(runtime->session_mgr, spec.sub_count);
    uint32_t final_avg_us = 0, final_p99_us = 0;
    latency_ring.Compute(final_avg_us, final_p99_us);
    const double total_elapsed_s = std::max(1e-6, static_cast<double>(end_ns - job_start_ns) / 1e9);
    const double final_actual_rps = static_cast<double>(tx_packets_total) / total_elapsed_s;
    const double final_target = std::max(1.0, pace_cfg.target_rps);
    const double final_acc = std::min(100.0, (final_actual_rps / final_target) * 100.0);

    EmitTelcoSnapshotDelta(
        events_sock, job_id, start_corr,
        tx_packets_total, rx_packets_total, tx_bytes_total, rx_bytes_total,
        last_reported_tx, last_reported_bytes, last_reported_failed,
        final_sess.active_sessions, final_sess.established_sessions, final_sess.failed_sessions,
        spec.rate_cps, final_actual_rps, final_acc,
        final_avg_us, final_p99_us,
        static_cast<uint32_t>(std::min<uint64_t>(final_sess.retransmit_count, 0xFFFFFFFFULL)),
        spec.db_port);

    for (uint32_t i = 0; i < spec.sub_count; ++i) {
      if (TelcoSessionContext* ctx = runtime->session_mgr.GetSessionByIndex(i)) {
        ctx->state = SessionState::IDLE;
      }
    }

    const std::string detail = BuildTelcoJobDoneJson(
        stopped_by_cmd ? "stopped" : "done",
        spec.protocol,
        tx_packets_total,
        rx_packets_total,
        final_sess,
        spec.rate_cps,
        final_avg_us,
        final_p99_us,
        telemetry);
    SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::JOB_DONE),
              start_corr, WorkerKind::TELCO, job_id,
              std::vector<std::uint8_t>(detail.begin(), detail.end()));
  }

  runtime.reset();
  if (packet_transport) packet_transport->Close();
  if (cups_gpu_sock) zmq_close(cups_gpu_sock);
  zmq_close(jobs_sock);
  zmq_close(events_sock);
  zmq_ctx_term(zmq_ctx);
  return 0;
}
