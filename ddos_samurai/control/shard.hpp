#pragma once

// Shard-split helpers for distributed jobs — native C++ port of
// ddos_samurai/control/shard.py. Pure logic: given a total packet count and a
// set of workers, split the work across shards by an equal / capability /
// region-weighted strategy. No I/O, no transport.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

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

}  // namespace samurai::control
