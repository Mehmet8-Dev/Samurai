#pragma once

// Serving-time continual fine-tuning with a champion-challenger rollback guard —
// the SLOW half of the Mahoraga wheel. The offline IQL/RL² policy is frozen: its
// deep weights only change by retraining. RL² adapts WITHIN an episode via the GRU;
// this layer adapts ACROSS windows and runs, safely and reversibly, without ever
// touching the frozen network.
//
// It learns a small, bounded, state-conditioned correction to the policy's setpoint:
//
//     applied_rps = proposed_rps * (1 + clamp(w · phi, -max_dev, +max_dev))
//
// where phi is a compact normalized state vector and w is updated ONLINE from the
// served-throughput reward by a one-sample evolution-strategies (zeroth-order policy
// gradient) rule — no backprop, no torch, deterministic. Because it only scales the
// proposal (which the setpoint shield in ClosedLoopController::StepRl still bounds),
// a bad update cannot overdrive the target; because the correction is clamped and the
// weights are norm-capped, it stays a gentle nudge.
//
// The rollback guard is the safety contract. During a warmup the adapter is inert and
// records the frozen policy's reward as a baseline. Once adapting, it tracks the
// adapted reward (EWMA); if that falls below the frozen baseline by a margin for a
// guard window, it ROLLS BACK — zeroes the correction (reverting to the frozen
// policy) and cools down before trying again. So online learning can only help on
// net: any regression is detected and undone. The learned w and baseline persist
// per target (AdapterMemory), so continual improvement carries across runs.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../core/json.hpp"

namespace samurai::control {

class OnlineAdapter {
 public:
  struct Config {
    bool enabled = false;
    double lr = 0.10;            // ES step size for the weight update
    double sigma = 0.05;         // exploration std on the correction each window
    double max_dev = 0.30;       // |correction| clamp: applied in [1-dev, 1+dev]*proposed
    double weight_cap = 5.0;     // L2 cap on w so a noisy window can't blow it up
    int warmup_windows = 3;      // inert warmup: record the frozen-policy baseline
    int guard_window = 5;        // consecutive sub-baseline windows that trigger rollback
    double rollback_margin = 0.03;  // adapted EWMA must stay within margin of baseline
    int cooldown_windows = 5;    // windows to stay reverted after a rollback
    double ewma_alpha = 0.3;     // reward EWMA smoothing
  };

  OnlineAdapter() : OnlineAdapter(Config{}, 1, 0) {}
  OnlineAdapter(Config cfg, int n_features, std::uint64_t seed)
      : cfg_(cfg),
        w_(n_features > 0 ? n_features : 1, 0.0),
        last_phi_(w_.size(), 0.0),
        rng_(seed) {}

  int n_features() const { return static_cast<int>(w_.size()); }

  // Shape the policy's proposed setpoint with the (exploring) correction for THIS
  // window, remembering (phi, eps) so the next Observe can attribute the reward.
  // A non-positive proposal is returned unchanged (nothing to scale).
  double Apply(double proposed_rps, const std::vector<double>& phi) {
    last_phi_.assign(w_.size(), 0.0);
    for (std::size_t i = 0; i < w_.size() && i < phi.size(); ++i) last_phi_[i] = phi[i];

    double base = 0.0;
    for (std::size_t i = 0; i < w_.size(); ++i) base += w_[i] * last_phi_[i];

    // Explore only while actively adapting (not during warmup or cooldown), so the
    // frozen baseline and the reverted state are measured on the un-perturbed policy.
    last_eps_ = 0.0;
    if (adapting()) {
      std::normal_distribution<double> nd(0.0, cfg_.sigma);
      last_eps_ = nd(rng_);
    }
    last_delta_ = Clamp(base + last_eps_, -cfg_.max_dev, cfg_.max_dev);
    have_pending_ = proposed_rps > 0.0;
    return proposed_rps > 0.0 ? proposed_rps * (1.0 + last_delta_) : proposed_rps;
  }

  // Fold the reward observed for the window Apply() just shaped: advance the reward
  // EWMAs, run the rollback guard, and (when adapting) take one ES gradient step.
  void Observe(double reward) {
    ++windows_;
    if (windows_ <= cfg_.warmup_windows) {
      // Inert warmup: establish the frozen-policy baseline.
      frozen_baseline_ = warmup_seen_ ? Ewma(frozen_baseline_, reward) : reward;
      warmup_seen_ = true;
      have_pending_ = false;
      return;
    }

    if (cooldown_ > 0) {
      // Reverted + cooling down: keep the baseline tracking the (now frozen) policy.
      frozen_baseline_ = Ewma(frozen_baseline_, reward);
      --cooldown_;
      have_pending_ = false;
      return;
    }

    // Actively adapting: track adapted reward and check the guard. Seed the EWMA at
    // the frozen baseline (not the first, noisy adapted reward) so a single unlucky
    // window near baseline cannot trip the guard before learning has had a chance.
    if (!adapted_seen_) {
      adapted_ewma_ = frozen_baseline_;
      adapted_seen_ = true;
    }
    adapted_ewma_ = Ewma(adapted_ewma_, reward);

    if (adapted_ewma_ < frozen_baseline_ - cfg_.rollback_margin) {
      if (++guard_bad_ >= cfg_.guard_window) Rollback();
    } else {
      guard_bad_ = 0;
    }

    // One-sample ES / zeroth-order policy-gradient step: nudge w along the exploration
    // that correlated with an above-baseline reward. Advantage centers the signal so a
    // uniformly high/low reward scale does not bias the direction.
    if (have_pending_ && cfg_.sigma > 0.0) {
      const double adv = reward - frozen_baseline_;
      const double scale = cfg_.lr * adv * last_eps_ / (cfg_.sigma * cfg_.sigma);
      for (std::size_t i = 0; i < w_.size(); ++i) w_[i] += scale * last_phi_[i];
      CapWeights();
    }
    have_pending_ = false;
  }

  // Seed from a persisted per-target snapshot (cross-run continual learning).
  void Warm(const std::vector<double>& w, double baseline) {
    for (std::size_t i = 0; i < w_.size() && i < w.size(); ++i) w_[i] = w[i];
    CapWeights();
    if (std::isfinite(baseline)) {
      frozen_baseline_ = baseline;
      warmup_seen_ = true;
    }
  }

  const std::vector<double>& weights() const { return w_; }
  double frozen_baseline() const { return frozen_baseline_; }
  int rollbacks() const { return rollbacks_; }
  double last_delta() const { return last_delta_; }
  bool reverted() const { return cooldown_ > 0; }

 private:
  bool adapting() const { return windows_ >= cfg_.warmup_windows && cooldown_ == 0; }

  double Ewma(double prev, double x) const {
    return cfg_.ewma_alpha * x + (1.0 - cfg_.ewma_alpha) * prev;
  }

  static double Clamp(double v, double lo, double hi) {
    return v < lo ? lo : (v > hi ? hi : v);
  }

  void CapWeights() {
    double n2 = 0.0;
    for (double v : w_) n2 += v * v;
    const double norm = std::sqrt(n2);
    if (norm > cfg_.weight_cap && norm > 0.0) {
      const double s = cfg_.weight_cap / norm;
      for (double& v : w_) v *= s;
    }
  }

  void Rollback() {
    std::fill(w_.begin(), w_.end(), 0.0);
    cooldown_ = cfg_.cooldown_windows;
    guard_bad_ = 0;
    adapted_seen_ = false;
    ++rollbacks_;
  }

  Config cfg_;
  std::vector<double> w_;
  std::vector<double> last_phi_;
  double last_eps_ = 0.0;
  double last_delta_ = 0.0;
  bool have_pending_ = false;

  double frozen_baseline_ = 0.0;
  bool warmup_seen_ = false;
  double adapted_ewma_ = 0.0;
  bool adapted_seen_ = false;

  int windows_ = 0;
  int guard_bad_ = 0;
  int cooldown_ = 0;
  int rollbacks_ = 0;
  std::mt19937_64 rng_;
};

// Cross-run persistence for the per-target online-adapter state. Format is a flat
// JSON object keyed by target ("host:port"): { "host:port": {"w": [...], "baseline":
// x}, ... }. Header-only + dependency-free (core/json), mirroring variant_memory.hpp
// / ban_memory.hpp so no build wiring changes.
class AdapterMemory {
 public:
  struct Entry {
    std::vector<double> w;
    double baseline = 0.0;
    bool has_baseline = false;
  };

  static AdapterMemory Load(const std::string& path) {
    AdapterMemory m;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return m;
    std::ostringstream ss;
    ss << in.rdbuf();
    const auto parsed = core::json::Parse(ss.str());
    if (!parsed.ok || !parsed.value.is_object()) return m;
    for (const auto& [key, val] : parsed.value.members()) {
      if (!val.is_object()) continue;
      Entry e;
      if (const auto* w = val.find("w"); w && w->is_array()) {
        for (const auto& x : w->elements()) e.w.push_back(x.as_double(0.0));
      }
      if (const auto* b = val.find("baseline"); b && b->is_number()) {
        e.baseline = b->as_double(0.0);
        e.has_baseline = true;
      }
      m.entries_.emplace_back(key, std::move(e));
    }
    return m;
  }

  Entry Get(const std::string& key) const {
    for (const auto& [k, v] : entries_) {
      if (k == key) return v;
    }
    return Entry{};
  }

  void Put(const std::string& key, const std::vector<double>& w, double baseline) {
    Entry e{w, baseline, true};
    for (auto& [k, v] : entries_) {
      if (k == key) { v = std::move(e); return; }
    }
    entries_.emplace_back(key, std::move(e));
  }

  bool Save(const std::string& path) const {
    core::json::Value root = core::json::Value::Object();
    for (const auto& [k, v] : entries_) {
      core::json::Value obj = core::json::Value::Object();
      core::json::Value arr = core::json::Value::Array();
      for (double d : v.w) arr.push_back(core::json::Value::Double(d));
      obj.set("w", std::move(arr));
      obj.set("baseline", core::json::Value::Double(v.baseline));
      root.set(k, std::move(obj));
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
  std::vector<std::pair<std::string, Entry>> entries_;
};

}  // namespace samurai::control
