#pragma once

// Cross-episode persistence for the per-target variant-block memory.
//
// The LeverShield learns, within one episode, which request_mix variants a target
// path-blocks (served ~0). That knowledge dies with the process, so every new run
// rediscovers the same walls from scratch. This store persists the per-variant
// best-observed-success snapshot keyed by target identity ("host:port"), so a fresh
// episode can WARM-START the shield (and thus the policy's block state feature) from
// what the last run against that target already learned.
//
// Format is a flat JSON object: { "host:port": [best0, best1, ...], ... } — one
// array per target, indexed by variant, value = best success in [0,1] (or < 0 for
// a variant never observed). Header-only + dependency-free (core/json), matching
// lever_shield.hpp so no build wiring changes.

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../core/json.hpp"

namespace samurai::control {

class VariantMemory {
 public:
  // Load the store from disk. A missing or unparseable file yields an empty store
  // (a first run, or a corrupt file, must not abort the load test / master).
  static VariantMemory Load(const std::string& path) {
    VariantMemory m;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return m;
    std::ostringstream ss;
    ss << in.rdbuf();
    const auto parsed = core::json::Parse(ss.str());
    if (!parsed.ok || !parsed.value.is_object()) return m;
    for (const auto& [key, val] : parsed.value.members()) {
      if (!val.is_array()) continue;
      std::vector<double> best;
      best.reserve(val.elements().size());
      for (const auto& e : val.elements()) best.push_back(e.as_double(-1.0));
      m.entries_.emplace_back(key, std::move(best));
    }
    return m;
  }

  // Per-variant best-success snapshot for a target key (empty if never stored).
  std::vector<double> Get(const std::string& key) const {
    for (const auto& [k, v] : entries_) {
      if (k == key) return v;
    }
    return {};
  }

  // Insert or replace the snapshot for a target key.
  void Put(const std::string& key, const std::vector<double>& best) {
    for (auto& [k, v] : entries_) {
      if (k == key) { v = best; return; }
    }
    entries_.emplace_back(key, best);
  }

  // Persist atomically: write a temp file then rename over the target, so a crash
  // mid-write can never leave a truncated store. Returns false on any I/O error.
  bool Save(const std::string& path) const {
    core::json::Value root = core::json::Value::Object();
    for (const auto& [k, v] : entries_) {
      core::json::Value arr = core::json::Value::Array();
      for (double d : v) arr.push_back(core::json::Value::Double(d));
      root.set(k, std::move(arr));
    }
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
  std::vector<std::pair<std::string, std::vector<double>>> entries_;
};

}  // namespace samurai::control
