#pragma once

// Lightweight, zero-overhead-when-disabled production IPFIX/NetFlow telemetry sink
// shared by ZMQ data-plane, L7, scenario, and Telco workers.
//
// Configured either at startup via SAMURAI_IPFIX_* environment variables or
// dynamically at runtime via wire MessageType::SET_TELEMETRY frames. When
// disabled, Enabled() short-circuits with a single predictable branch and no
// heap allocations or sockets are touched.

#include <arpa/inet.h>
#ifdef AF_XDP
#undef AF_XDP
#endif
#ifdef AF_PACKET
#undef AF_PACKET
#endif
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include "flow_cache.hpp"
#include "ipfix_exporter.hpp"
#include "ipfix_types.hpp"
#include "packet_sampler.hpp"
#include "wire_protocol.h"

namespace samurai::daemon {

class TelemetrySink {
 public:
  TelemetrySink() { LoadFromEnv(); }

  ~TelemetrySink() = default;
  TelemetrySink(const TelemetrySink&) = delete;
  TelemetrySink& operator=(const TelemetrySink&) = delete;

  inline bool Enabled() const noexcept { return enabled_; }

  void BeginJob() {
    job_base_packets_ = TotalExportedPackets();
    job_base_records_ = TotalExportedRecords();
    last_export_ns_ = 0;
    if (table_) {
      table_->Clear();
    }
  }

  void ApplyWireConfig(const samurai::wire::TelemetryConfigV1& cfg, uint64_t now_ns = 0) {
    if (cfg.enabled == 0u) {
      if (enabled_ && table_ && exporter_) {
        FlushEnd(now_ns > 0 ? now_ns : MonotonicNs());
      }
      enabled_ = false;
      return;
    }

    const uint32_t sample_rate = cfg.sample_rate > 0u ? cfg.sample_rate : 1u;
    const std::string collector =
        cfg.collector_ip[0] != '\0'
            ? std::string(cfg.collector_ip, strnlen(cfg.collector_ip, sizeof(cfg.collector_ip)))
            : std::string("127.0.0.1");
    const uint16_t port = cfg.collector_port > 0u ? cfg.collector_port : 4739u;
    const bool netflow_v9 = cfg.netflow_v9 != 0u;
    const uint32_t domain_id = cfg.domain_id > 0u ? cfg.domain_id : 1u;
    const uint32_t interval_ms = cfg.export_interval_ms > 0u ? cfg.export_interval_ms : 1000u;

    ApplySettings(true, collector, port, sample_rate, netflow_v9, domain_id, interval_ms,
                  flow_capacity_);
  }

  // Record a packet whose addresses/ports are already in network byte order.
  inline void RecordPacketNet(uint32_t src_ip_be, uint32_t dst_ip_be, uint16_t src_port_be,
                              uint16_t dst_port_be, uint8_t proto, uint32_t bytes,
                              uint8_t tcp_flags, uint16_t vlan_id, uint64_t now_ns) noexcept {
    if (__builtin_expect(!enabled_ || !table_, 1)) {
      return;
    }
    if (!sampler_.ShouldSample()) {
      return;
    }
    samurai::telemetry::SamuraiFlowKey key{};
    key.src_ip = src_ip_be;
    key.dst_ip = dst_ip_be;
    key.src_port = src_port_be;
    key.dst_port = dst_port_be;
    key.protocol = proto;
    key.pad0 = 0;
    key.vlan_id = vlan_id;
    bool is_new = false;
    auto* rec = table_->LookupOrInsert(key, now_ns, is_new);
    if (rec) {
      samurai::telemetry::FlowTableShard::UpdateStats(rec, bytes, tcp_flags, now_ns);
    }
  }

  // Record a packet whose ports/IPs (uint32 host order IPs + host ports) need byte-swapping
  // only if sampling selects the packet.
  inline void RecordPacketHost(uint32_t src_ip_host, uint32_t dst_ip_host, uint16_t src_port_host,
                               uint16_t dst_port_host, uint8_t proto, uint32_t bytes,
                               uint8_t tcp_flags, uint16_t vlan_id, uint64_t now_ns) noexcept {
    if (__builtin_expect(!enabled_ || !table_, 1)) {
      return;
    }
    if (!sampler_.ShouldSample()) {
      return;
    }
    samurai::telemetry::SamuraiFlowKey key{};
    key.src_ip = htonl(src_ip_host);
    key.dst_ip = htonl(dst_ip_host);
    key.src_port = htons(src_port_host);
    key.dst_port = htons(dst_port_host);
    key.protocol = proto;
    key.pad0 = 0;
    key.vlan_id = vlan_id;
    bool is_new = false;
    auto* rec = table_->LookupOrInsert(key, now_ns, is_new);
    if (rec) {
      samurai::telemetry::FlowTableShard::UpdateStats(rec, bytes, tcp_flags, now_ns);
    }
  }

  void TickExport(uint64_t now_ns) {
    if (!enabled_ || !table_ || !exporter_) {
      return;
    }
    if (last_export_ns_ != 0 && (now_ns - last_export_ns_) < export_interval_ns_) {
      return;
    }
    last_export_ns_ = now_ns;
    export_buf_.clear();
    table_->EvictTimedOut(now_ns, active_timeout_ns_, inactive_timeout_ns_, export_buf_, 256);
    if (!export_buf_.empty()) {
      const uint32_t now_s = static_cast<uint32_t>(std::time(nullptr));
      const uint32_t up_ms = static_cast<uint32_t>((now_ns / 1000000ULL) & 0xFFFFFFFFULL);
      exporter_->ExportRecords(export_buf_.data(), export_buf_.size(), now_s, up_ms);
      export_buf_.clear();
    }
  }

  void FlushEnd(uint64_t now_ns) {
    if (!enabled_ || !table_ || !exporter_) {
      return;
    }
    const uint32_t now_s = static_cast<uint32_t>(std::time(nullptr));
    const uint32_t up_ms = static_cast<uint32_t>((now_ns / 1000000ULL) & 0xFFFFFFFFULL);
    while (table_->active_flow_count() > 0) {
      export_buf_.clear();
      const size_t n = table_->FlushActive(export_buf_, 1024);
      if (n == 0) {
        break;
      }
      exporter_->ExportRecords(export_buf_.data(), n, now_s, up_ms);
    }
    export_buf_.clear();
  }

  uint64_t JobExportedPackets() const noexcept {
    const uint64_t tot = TotalExportedPackets();
    return tot >= job_base_packets_ ? (tot - job_base_packets_) : 0;
  }

  uint64_t JobExportedRecords() const noexcept {
    const uint64_t tot = TotalExportedRecords();
    return tot >= job_base_records_ ? (tot - job_base_records_) : 0;
  }

  uint64_t TotalExportedPackets() const noexcept {
    return retired_packets_ + (exporter_ ? exporter_->exported_packets() : 0ULL);
  }

  uint64_t TotalExportedRecords() const noexcept {
    return retired_records_ + (exporter_ ? exporter_->exported_records() : 0ULL);
  }

  static uint32_t ParseIpBe(const std::string& ip, uint32_t fallback_be = htonl(0x7F000001u)) noexcept {
    in_addr addr{};
    if (!ip.empty() && inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
      return addr.s_addr;
    }
    return fallback_be;
  }

  static uint8_t ProtoFromName(const std::string& proto) noexcept {
    std::string lower;
    lower.reserve(proto.size());
    for (unsigned char c : proto) {
      lower.push_back(static_cast<char>(std::tolower(c)));
    }
    if (lower == "tcp" || lower == "syn" || lower == "ack" || lower == "rst" ||
        lower == "http" || lower == "https" || lower == "h1" || lower == "h2" ||
        lower == "h3" || lower == "websocket" || lower == "diameter") {
      return 6;
    }
    if (lower == "icmp") {
      return 1;
    }
    if (lower == "sctp") {
      return 132;
    }
    return 17;
  }

 private:
  static bool EnvTruthy(const char* val) {
    if (!val || val[0] == '\0') return false;
    return val[0] == '1' || val[0] == 't' || val[0] == 'T' || val[0] == 'y' || val[0] == 'Y';
  }

  static uint64_t MonotonicNs() noexcept {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
  }

  void LoadFromEnv() {
    const char* en = std::getenv("SAMURAI_IPFIX_ENABLED");
    if (!EnvTruthy(en)) {
      return;
    }
    const char* coll = std::getenv("SAMURAI_IPFIX_COLLECTOR");
    const char* port_s = std::getenv("SAMURAI_IPFIX_PORT");
    const char* sr_s = std::getenv("SAMURAI_IPFIX_SAMPLE_RATE");
    const char* nf9_s = std::getenv("SAMURAI_IPFIX_NETFLOW_V9");
    const char* dom_s = std::getenv("SAMURAI_IPFIX_DOMAIN_ID");
    const char* int_s = std::getenv("SAMURAI_IPFIX_EXPORT_INTERVAL_MS");
    const char* cap_s = std::getenv("SAMURAI_IPFIX_FLOW_CAPACITY");

    const std::string collector = (coll && coll[0] != '\0') ? std::string(coll) : std::string("127.0.0.1");
    const uint16_t port = (port_s && std::strtoul(port_s, nullptr, 10) > 0)
                              ? static_cast<uint16_t>(std::strtoul(port_s, nullptr, 10))
                              : 4739u;
    const uint32_t sample_rate = (sr_s && std::strtoul(sr_s, nullptr, 10) > 0)
                                     ? static_cast<uint32_t>(std::strtoul(sr_s, nullptr, 10))
                                     : 1000u;
    const bool nf9 = EnvTruthy(nf9_s);
    const uint32_t domain_id = (dom_s && std::strtoul(dom_s, nullptr, 10) > 0)
                                   ? static_cast<uint32_t>(std::strtoul(dom_s, nullptr, 10))
                                   : 1u;
    const uint32_t interval_ms = (int_s && std::strtoul(int_s, nullptr, 10) > 0)
                                     ? static_cast<uint32_t>(std::strtoul(int_s, nullptr, 10))
                                     : 1000u;
    const size_t cap = (cap_s && std::strtoull(cap_s, nullptr, 10) >= 64)
                           ? static_cast<size_t>(std::strtoull(cap_s, nullptr, 10))
                           : flow_capacity_;
    ApplySettings(true, collector, port, sample_rate, nf9, domain_id, interval_ms, cap);
  }

  void ApplySettings(bool enable, const std::string& collector, uint16_t port,
                     uint32_t sample_rate, bool netflow_v9, uint32_t domain_id,
                     uint32_t interval_ms, size_t capacity) {
    sampler_.set_sampling_rate(sample_rate);
    export_interval_ns_ = static_cast<uint64_t>(interval_ms) * 1000000ULL;
    flow_capacity_ = capacity;

    if (!table_ || table_->capacity() < flow_capacity_) {
      table_ = std::make_unique<samurai::telemetry::FlowTableShard>(flow_capacity_);
    }

    const bool need_new_exporter =
        !exporter_ || cfg_.collector_ip != collector || cfg_.collector_port != port ||
        cfg_.enable_netflow_v9 != netflow_v9 || cfg_.observation_domain_id != domain_id;

    if (need_new_exporter) {
      if (exporter_) {
        retired_packets_ += exporter_->exported_packets();
        retired_records_ += exporter_->exported_records();
        exporter_->CloseSocket();
        exporter_.reset();
      }
      cfg_.collector_ip = collector;
      cfg_.collector_port = port;
      cfg_.enable_netflow_v9 = netflow_v9;
      cfg_.observation_domain_id = domain_id;
      cfg_.template_id = 256;
      auto exp = std::make_unique<samurai::telemetry::IpfixExporter>(cfg_);
      if (!exp->InitSocket()) {
        enabled_ = false;
        return;
      }
      exporter_ = std::move(exp);
      export_buf_.reserve(1024);
    }
    enabled_ = enable;
  }

  bool enabled_{false};
  size_t flow_capacity_{16384};
  uint64_t export_interval_ns_{1000000000ULL};
  uint64_t active_timeout_ns_{30000000000ULL};
  uint64_t inactive_timeout_ns_{5000000000ULL};
  uint64_t last_export_ns_{0};

  samurai::telemetry::SamplerMode sampler_mode_{
      samurai::telemetry::SamplerMode::Deterministic1ofN};
  samurai::telemetry::PacketSampler sampler_{1000, sampler_mode_};
  samurai::telemetry::ExporterConfig cfg_{};
  std::unique_ptr<samurai::telemetry::FlowTableShard> table_;
  std::unique_ptr<samurai::telemetry::IpfixExporter> exporter_;
  std::vector<samurai::telemetry::SamuraiFlowRecord> export_buf_;

  uint64_t retired_packets_{0};
  uint64_t retired_records_{0};
  uint64_t job_base_packets_{0};
  uint64_t job_base_records_{0};
};

}  // namespace samurai::daemon
