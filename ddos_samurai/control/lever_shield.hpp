#pragma once

// Online reaction memory for a categorical shaping lever (request_mix) — the
// Mahoraga reflex, parallel to the rps AIMD shield in ClosedLoopController::StepRl.
//
// The RL policy proposes a request variant from an AGGREGATE state that cannot tell
// which variant *this* target path-blocks, so a policy trained across defenses
// converges to a marginal that may still propose a variant a given target 403s.
// This shield closes that gap at serving time, model-free: it remembers, per
// episode, which variant the target actually path-BLOCKED (served ~0 => a WAF 403
// on that path, distinct from rate-limiting, which still honors some traffic at low
// rps) and substitutes the best-known honored variant for a blocked proposal.
//
// It is deliberately NOT active during pure corpus capture: exploration must be
// free to hit blocked variants so their reaction is recorded for training. The
// caller gates Govern() on serving (a loaded policy), like the rps shield.

#include <algorithm>
#include <vector>

namespace samurai::control {

class LeverShield {
 public:
  struct Config {
    // Best-observed success below this => the variant is path-blocked (WAF), not
    // merely rate-limited (which always honors some traffic at low enough rps, so
    // its best-case success stays ~1). Matches the fingerprint's block criterion.
    double honored_success_floor = 0.10;
    int variant_count = 5;  // categorical cardinality (== kRequestVariantCount)
  };

  LeverShield() : LeverShield(Config{}) {}
  explicit LeverShield(Config cfg)
      : cfg_(cfg),
        best_success_(cfg.variant_count > 0 ? cfg.variant_count : 1, -1.0) {}

  // Record the reaction to the variant applied in the just-measured window.
  // success_ratio = 2xx / responses for that window; < 0 means unknown (ignored).
  void Observe(int variant, double success_ratio) {
    if (variant < 0 || variant >= static_cast<int>(best_success_.size())) return;
    if (success_ratio < 0.0) return;
    if (success_ratio > best_success_[variant]) best_success_[variant] = success_ratio;
  }

  // True once the variant has been observed and its best-case success is below the
  // honored floor (a persistent path-block, not a transient rate-limit dip).
  bool Blocked(int variant) const {
    if (variant < 0 || variant >= static_cast<int>(best_success_.size())) return false;
    const double b = best_success_[variant];
    return b >= 0.0 && b < cfg_.honored_success_floor;
  }

  // Map the policy/exploration proposal to the variant to actually apply:
  //   - proposal unchanged if it is not known-blocked (includes unobserved ones —
  //     trust the policy and let first-touch discovery happen);
  //   - else the observed variant with the highest best-success (most honored);
  //   - else an unobserved variant (optimistic probe to find an honored one);
  //   - else the proposal unchanged (everything observed and blocked).
  int Govern(int proposed) const {
    if (!Blocked(proposed)) return proposed;
    int best = -1;
    double best_val = cfg_.honored_success_floor;
    for (int v = 0; v < static_cast<int>(best_success_.size()); ++v) {
      if (best_success_[v] > best_val) { best_val = best_success_[v]; best = v; }
    }
    if (best >= 0) return best;
    for (int v = 0; v < static_cast<int>(best_success_.size()); ++v) {
      if (best_success_[v] < 0.0) return v;  // unobserved — probe it
    }
    return proposed;
  }

  void Reset() { std::fill(best_success_.begin(), best_success_.end(), -1.0); }

  // Seed the memory from a persisted per-target snapshot (cross-episode warm start):
  // a value >= 0 pre-populates that variant's best-observed success so the policy's
  // block feature is informed from window 0 instead of rediscovering the target.
  void Warm(const std::vector<double>& best) {
    const std::size_t n = std::min(best.size(), best_success_.size());
    for (std::size_t v = 0; v < n; ++v) {
      if (best[v] >= 0.0 && best[v] > best_success_[v]) best_success_[v] = best[v];
    }
  }

  // The full per-variant best-success vector (-1 = unobserved). Feeds both the
  // RlStateInputs block features and the persistent store.
  const std::vector<double>& snapshot() const { return best_success_; }

  double best_success(int variant) const {
    if (variant < 0 || variant >= static_cast<int>(best_success_.size())) return -1.0;
    return best_success_[variant];
  }

 private:
  Config cfg_;
  std::vector<double> best_success_;  // per-variant best observed success, -1 = unobserved
};

}  // namespace samurai::control
