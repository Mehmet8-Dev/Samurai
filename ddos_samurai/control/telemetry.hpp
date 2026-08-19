#pragma once

// Distributed telemetry aggregation (DistributedAggregator). Pure logic: fold a
// stream of per-update telemetry items (JSON objects) into a rolled-up snapshot
// (totals, per-shard/worker/region rollups, top-error shards). No I/O.
//
// Items and the snapshot are core::json::Value objects so arbitrary numeric
// fields flow through to numeric_totals exactly as the Python dict did.

#include <vector>

#include "json.hpp"  // samurai::core::json::Value

namespace samurai::control {

class DistributedAggregator {
 public:
  // Append a telemetry item (a JSON object). Non-object items contribute
  // nothing, matching dict(item or {}).
  void Add(const samurai::core::json::Value& item);

  // Aggregate everything added so far into a snapshot object with the same
  // shape/ordering rules as the Python implementation.
  samurai::core::json::Value Snapshot() const;

  static void CalculateLatencyPercentiles(std::vector<double> latencies_ms,
                                           double& out_p50,
                                           double& out_p95,
                                           double& out_p99);

  std::size_t size() const { return items_.size(); }

 private:
  std::vector<samurai::core::json::Value> items_;
};

}  // namespace samurai::control
