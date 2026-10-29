#pragma once

// Shard-split helpers for distributed jobs. Pure logic: given a total packet
// count or subscriber count and a set of workers, split the work across shards
// by an equal / capability / region-weighted or subscriber-partitioned strategy.
// No I/O, no transport.

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

// Worker capabilities used to weight shard assignment. Mirrors the string-keyed
// capability dict in the Python implementation.
struct WorkerCapabilities {
  bool gpu_available = false;
  bool xdp_available = false;
  int capacity_score = 0;   // >= 1 overrides the derived weight; 0 = unset
  std::string region;       // for the "region" strategy
};

struct Shard {
  std::string shard_id;      // "shard-<n>"
  std::string worker_id;
  std::uint64_t packet_count = 0;
};

// Split `total_count` packets across `worker_ids`. Blank worker ids are dropped.
// strategy: "equal" (default), "capability", or "region" (needs target_region).
std::vector<Shard> SplitJobToShards(
    std::uint64_t total_count,
    const std::vector<std::string>& worker_ids,
    const std::string& strategy = "equal",
    const std::map<std::string, WorkerCapabilities>& worker_capabilities = {},
    const std::string& target_region = "");

// =============================================================================
// Telecom Subscriber Sharding Specifications
// =============================================================================

struct SubscriberRange {
  std::uint32_t start_idx = 0;
  std::uint32_t count = 0;
  std::uint16_t base_vlan_s = 100;  // 802.1ad Service Outer VLAN
  std::uint16_t base_vlan_c = 10;   // 802.1Q Customer Inner VLAN
  std::uint16_t vlan_step = 1;
  std::uint8_t  base_mac[6] = {0x02, 0x00, 0x5E, 0x00, 0x00, 0x01};
  std::uint32_t base_ip = 0x0A000001;     // 10.0.0.1
  std::uint32_t gateway_ip = 0x0A0000FE;  // 10.0.0.254

  inline bool Contains(std::uint32_t sub_idx) const noexcept {
    return sub_idx >= start_idx && sub_idx < (start_idx + count);
  }

  inline void GetMacFor(std::uint32_t sub_idx, std::uint8_t out_mac[6]) const noexcept {
    std::memcpy(out_mac, base_mac, 6);
    out_mac[3] ^= static_cast<std::uint8_t>((sub_idx >> 16) & 0xFF);
    out_mac[4] ^= static_cast<std::uint8_t>((sub_idx >> 8) & 0xFF);
    out_mac[5] ^= static_cast<std::uint8_t>(sub_idx & 0xFF);
  }

  inline std::uint32_t GetIpFor(std::uint32_t sub_idx) const noexcept {
    return base_ip + sub_idx;
  }

  inline std::uint16_t GetVlanSFor(std::uint32_t sub_idx) const noexcept {
    return static_cast<std::uint16_t>(base_vlan_s + (sub_idx / 4096));
  }

  inline std::uint16_t GetVlanCFor(std::uint32_t sub_idx) const noexcept {
    return static_cast<std::uint16_t>(base_vlan_c + (sub_idx % 4096));
  }
};

struct TelcoShardSpec {
  std::string shard_id;
  std::string worker_id;
  std::string protocol = "pppoe";  // "pppoe", "dhcp", "gtpu", "bfd", "qinq", "arp"
  SubscriberRange range;
  std::uint32_t target_cps = 5000;
  std::uint32_t max_retries = 3;
  std::uint32_t timeout_ms = 500;
  int db_port = 5099;

  samurai::core::json::Value ToJson() const;
  static TelcoShardSpec FromJson(const samurai::core::json::Value& val);
};

// Partition total_subscribers into disjoint, non-overlapping subscriber ranges
// across available worker nodes.
std::vector<TelcoShardSpec> SplitTelcoSubscribers(
    std::uint32_t total_subscribers,
    const std::vector<std::string>& worker_ids,
    const std::string& protocol = "pppoe",
    std::uint32_t target_cps = 5000,
    std::uint16_t base_vlan_s = 100,
    std::uint16_t base_vlan_c = 10,
    const std::uint8_t base_mac[6] = nullptr,
    std::uint32_t base_ip = 0x0A000001,
    std::uint32_t gateway_ip = 0x0A0000FE);

}  // namespace samurai::control

