#pragma once

// Cross-run persistence for the per-target persistent-ban (ban_pressure) state.
//
// The serving loop folds the flow-level conn_drop reaction into a causal EWMA
// (ban_pressure) so a ban-aware policy conditions on a fail2ban/IPS ban that
// PERSISTS. That EWMA dies with the process, so a fresh run against an already-banned
// target would start from "no ban known" and pay windows to rediscover it — the same
// non-stationarity the feature exists to fix. This store persists the last folded
// ban_pressure keyed by target identity ("host:port"), so the next run WARM-STARTS
// the EWMA (and thus the policy's ban state feature) from what the last run saw.
//
// Format is a flat JSON object: { "host:port": pressure, ... } — one scalar per
// target, value = ban_pressure in [0,1] (or < 0 for never observed). Header-only +
// dependency-free (core/json), mirroring variant_memory.hpp so no build wiring
// changes.

#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../core/json.hpp"

namespace samurai::control {

class BanMemory {
 public:
  // Load the store from disk. A missing or unparseable file yields an empty store
  // (a first run, or a corrupt file, must not abort the load test / master).
  static BanMemory Load(const std::string& path) {
    BanMemory m;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return m;
    std::ostringstream ss;
    ss << in.rdbuf();
    const auto parsed = core::json::Parse(ss.str());
    if (!parsed.ok || !parsed.value.is_object()) return m;
    for (const auto& [key, val] : parsed.value.members()) {
      if (!val.is_number()) continue;
      m.entries_.emplace_back(key, val.as_double(-1.0));
    }
    return m;
  }

  // Last folded ban_pressure for a target key (-1 if never stored).
  double Get(const std::string& key) const {
    for (const auto& [k, v] : entries_) {
      if (k == key) return v;
    }
    return -1.0;
  }

  // Insert or replace the ban_pressure for a target key.
  void Put(const std::string& key, double pressure) {
    for (auto& [k, v] : entries_) {
      if (k == key) { v = pressure; return; }
    }
    entries_.emplace_back(key, pressure);
  }

  // Persist atomically: write a temp file then rename over the target, so a crash
  // mid-write can never leave a truncated store. Returns false on any I/O error.
  bool Save(const std::string& path) const {
    core::json::Value root = core::json::Value::Object();
    for (const auto& [k, v] : entries_) root.set(k, core::json::Value::Double(v));
    const std::string tmp = path + ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      if (!out.is_open()) return false;
      out << root.dump(/*sort_keys=*/true);
      if (!out.good()) return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
  }

  std::size_t size() const { return entries_.size(); }

 private:
  std::vector<std::pair<std::string, double>> entries_;
};

}  // namespace samurai::control
