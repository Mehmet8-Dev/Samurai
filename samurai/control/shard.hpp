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
  std::string region;       // for the "region" strategy (e.g. "tr-ist", "tr-ank")
};

// Convert string-keyed worker registration capabilities into WorkerCapabilities.
WorkerCapabilities CapabilitiesFromStrings(const std::map<std::string, std::string>& caps);

// Hierarchical region topology & ASN-to-PoP map for locality-aware sharding.
// Canonical regions use optional macro-country prefixes (e.g. "tr-ist",
// "tr-ank", "eu-central") so same-country PoPs outrank cross-region nodes when
// an exact PoP match is saturated or absent.
struct RegionTopology {
  std::map<std::uint32_t, std::string> asn_to_region;
  std::map<std::string, std::string> region_aliases;

  std::string CanonicalRegion(const std::string& raw) const;
  std::string ResolveRegion(std::uint32_t target_asn,
                            const std::string& explicit_region = "") const;
  // +5 exact PoP match, +2 same macro/country prefix ("tr-ist" vs "tr-ank"),
  // -1 unrelated non-empty regions, 0 when unset.
  int AffinityDelta(const std::string& worker_region,
                    const std::string& target_region) const;

  samurai::core::json::Value ToJson() const;
  static bool FromJson(const samurai::core::json::Value& val,
                       RegionTopology& out, std::string& err);
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
    const std::string& target_region = "",
    const RegionTopology* topology = nullptr);

// =============================================================================
// Telecom Subscriber Sharding Specifications & Lab Pool Sizing
// =============================================================================

// True iff `host_ip` lies inside isolated lab/CGNAT/private IPv4 ranges
// (RFC 1918, RFC 6598 100.64.0.0/10, RFC 2544 198.18.0.0/15, loopback 127/8).
bool IsSafeTelcoLabIpv4(std::uint32_t host_ip) noexcept;
bool IsSafeTelcoLabSubnet(std::uint32_t network_ip, std::uint8_t prefix_len) noexcept;

// One homogeneous bucket of disjoint /prefix_len blocks within an isolated
// RFC 1918 / RFC 6598 / RFC 2544 address space, used to model realistic BNG /
// CGNAT / UPF FIB & NAT table distribution in the lab without touching public IPs.
struct TelcoPoolBucket {
  std::uint32_t base_ip = 0x64400000u;     // 100.64.0.0 (RFC 6598 CGNAT)
  std::uint8_t  prefix_len = 22;           // [8..30]
  std::uint32_t subnet_count = 1;          // number of consecutive /prefix_len blocks
  std::uint32_t hosts_per_subnet = 0;      // 0 => 2^(32-prefix_len) - 2 usable hosts

  std::uint32_t HostsPerSubnet() const noexcept;
  std::uint64_t TotalCapacity() const noexcept;
  std::uint32_t Ipv4ForOffset(std::uint64_t local_idx) const noexcept;
};

struct TelcoLabSizingProfile {
  std::string name = "linear";
  std::vector<TelcoPoolBucket> buckets;

  std::uint32_t RouteCount() const noexcept;
  std::uint64_t TotalCapacity() const noexcept;
  std::uint32_t Ipv4ForIndex(std::uint32_t sub_idx,
                             std::uint32_t fallback_base_ip) const noexcept;

  static TelcoLabSizingProfile Preset(const std::string& profile_name);
  static bool FromJson(const samurai::core::json::Value& val,
                       TelcoLabSizingProfile& out, std::string& err);
  samurai::core::json::Value ToJson() const;
};

struct SubscriberRange {
  std::uint32_t start_idx = 0;
  std::uint32_t count = 0;
  std::uint16_t base_vlan_s = 100;  // 802.1ad Service Outer VLAN
  std::uint16_t base_vlan_c = 10;   // 802.1Q Customer Inner VLAN
  std::uint16_t vlan_step = 1;
  std::uint8_t  base_mac[6] = {0x02, 0x00, 0x5E, 0x00, 0x00, 0x01};
  std::uint32_t base_ip = 0x0A000001;     // 10.0.0.1
  std::uint32_t gateway_ip = 0x0A0000FE;  // 10.0.0.254
  std::vector<TelcoPoolBucket> pools;     // Optional fragmented CGNAT/BNG lab pools

  inline bool Contains(std::uint32_t sub_idx) const noexcept {
    return sub_idx >= start_idx && sub_idx < (start_idx + count);
  }

  inline void GetMacFor(std::uint32_t sub_idx, std::uint8_t out_mac[6]) const noexcept {
    std::memcpy(out_mac, base_mac, 6);
    out_mac[3] ^= static_cast<std::uint8_t>((sub_idx >> 16) & 0xFF);
    out_mac[4] ^= static_cast<std::uint8_t>((sub_idx >> 8) & 0xFF);
    out_mac[5] ^= static_cast<std::uint8_t>(sub_idx & 0xFF);
  }

  std::uint32_t GetIpFor(std::uint32_t sub_idx) const noexcept;
  std::uint32_t PoolRouteCount() const noexcept;
  std::uint64_t EstimatedNatTableEntries(std::uint16_t ports_per_subscriber = 64) const noexcept;

  inline std::uint16_t GetVlanSFor(std::uint32_t sub_idx) const noexcept {
    return static_cast<std::uint16_t>(1 + ((base_vlan_s - 1 + (sub_idx / 4094)) % 4094));
  }

  inline std::uint16_t GetVlanCFor(std::uint32_t sub_idx) const noexcept {
    return static_cast<std::uint16_t>(1 + ((base_vlan_c - 1 + (sub_idx % 4094)) % 4094));
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
// across available worker nodes (equal baseline split).
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

// Region/capability-weighted subscriber partitioning with optional isolated
// multi-pool CGNAT/BNG FIB sizing layout.
std::vector<TelcoShardSpec> SplitTelcoSubscribers(
    std::uint32_t total_subscribers,
    const std::vector<std::string>& worker_ids,
    const std::map<std::string, WorkerCapabilities>& worker_capabilities,
    const std::string& target_region = "",
    const std::string& strategy = "region",
    const std::string& protocol = "pppoe",
    std::uint32_t target_cps = 5000,
    std::uint16_t base_vlan_s = 100,
    std::uint16_t base_vlan_c = 10,
    const std::uint8_t base_mac[6] = nullptr,
    std::uint32_t base_ip = 0x0A000001,
    std::uint32_t gateway_ip = 0x0A0000FE,
    const TelcoLabSizingProfile* pool_profile = nullptr,
    const RegionTopology* topology = nullptr);

}  // namespace samurai::control

