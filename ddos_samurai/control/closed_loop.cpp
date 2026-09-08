#include "closed_loop.hpp"

#include <algorithm>
#include <cmath>

namespace samurai::control {

namespace {

double Clamp(double v, double lo, double hi) {
  return std::max(lo, std::min(hi, v));
}

}  // namespace

ClosedLoopController::ClosedLoopController(const ClosedLoopConfig& cfg) : cfg_(cfg) {
  enabled_ = cfg_.enabled;

  // Normalize the load band. min <= max, both positive.
  cfg_.min_rps = std::max(1.0, cfg_.min_rps);
  cfg_.max_rps = std::max(cfg_.min_rps, cfg_.max_rps);
  const double span = std::max(1.0, cfg_.max_rps - cfg_.min_rps);

  increase_ = cfg_.aimd_increase_rps > 0.0 ? cfg_.aimd_increase_rps : 0.10 * span;
  backoff_ = (cfg_.aimd_backoff > 0.0 && cfg_.aimd_backoff < 1.0) ? cfg_.aimd_backoff : 0.5;
  tolerance_ = cfg_.binsearch_tolerance_rps > 0.0 ? cfg_.binsearch_tolerance_rps : 0.01 * span;
  // Shield jump factor is a multiplier on the last setpoint; anything < 1 would
  // forbid growth, so floor it at 1.0.
  cfg_.rl_max_jump_factor = std::max(1.0, cfg_.rl_max_jump_factor);

  const double init = cfg_.initial_rps > 0.0 ? cfg_.initial_rps : cfg_.min_rps;
  setpoint_ = Clamp(init, cfg_.min_rps, cfg_.max_rps);

  // Binary search starts with the min assumed sustainable (verified by the first
  // green sample) and no upper bound yet.
  lo_ = cfg_.min_rps;
  hi_ = 0.0;
  bracketed_ = false;
}

bool ClosedLoopController::IsHealthy(const LoadSample& sample, double* out_error_pct) const {
  double err = sample.error_pct;
  if (err < 0.0) {
    err = sample.attempted > 0.0 ? (100.0 * sample.errors / sample.attempted) : 0.0;
  }
  if (out_error_pct) *out_error_pct = err;

  if (cfg_.slo_max_error_pct > 0.0 && err > cfg_.slo_max_error_pct) return false;
  if (cfg_.slo_max_loss_pct > 0.0 && sample.loss_pct >= 0.0 &&
      sample.loss_pct > cfg_.slo_max_loss_pct) {
    return false;
  }
  if (cfg_.slo_min_rate_accuracy_pct > 0.0 && sample.rate_accuracy_pct >= 0.0 &&
      sample.rate_accuracy_pct < cfg_.slo_min_rate_accuracy_pct) {
    return false;
  }
  if (cfg_.slo_max_latency_ms > 0.0 && sample.latency_p99_ms >= 0.0 &&
      sample.latency_p99_ms > cfg_.slo_max_latency_ms) {
    return false;
  }
  if (cfg_.slo_max_pushback_pct > 0.0 && sample.pushback_pct >= 0.0 &&
      sample.pushback_pct > cfg_.slo_max_pushback_pct) {
    return false;
  }
  return true;
}

ClosedLoopDecision ClosedLoopController::Step(const LoadSample& sample) {
  if (!enabled_) {
    ClosedLoopDecision d;
    d.enabled = false;
    d.done = true;
    d.phase = "disabled";
    d.reason = "disabled";
    d.setpoint_rps = setpoint_;
    return d;
  }
  if (done_) {
    ClosedLoopDecision d;
    d.enabled = true;
    d.done = true;
    d.phase = "done";
    d.reason = "converged";
    d.setpoint_rps = best_good_;
    d.best_good_rps = best_good_;
    d.window = window_;
    return d;
  }

  double err_pct = -1.0;
  const bool healthy = IsHealthy(sample, &err_pct);
  ++window_;

  ClosedLoopDecision d;
  switch (cfg_.strategy) {
    case ClosedLoopStrategy::kBinSearch:
      d = StepBinSearch(sample, healthy, err_pct);
      break;
    case ClosedLoopStrategy::kRl:
      d = StepRl(sample, healthy, err_pct);
      break;
    case ClosedLoopStrategy::kAimd:
    default:
      d = StepAimd(sample, healthy, err_pct);
      break;
  }
  d.enabled = true;
  d.last_healthy = healthy;
  d.error_pct = err_pct;
  d.window = window_;
  d.best_good_rps = best_good_;
  d.done = done_;
  return d;
}

ClosedLoopDecision ClosedLoopController::StepAimd(const LoadSample& /*sample*/, bool healthy,
                                                  double /*err_pct*/) {
  ClosedLoopDecision d;
  if (healthy) {
    best_good_ = std::max(best_good_, setpoint_);
    setpoint_ = std::min(cfg_.max_rps, setpoint_ + increase_);
    d.phase = "probe";
    d.reason = "slo-green: increase";
  } else {
    setpoint_ = std::max(cfg_.min_rps, setpoint_ * backoff_);
    d.phase = "backoff";
    d.reason = "slo-violation: backoff";
  }

  if (cfg_.aimd_max_windows > 0 && window_ >= cfg_.aimd_max_windows) {
    done_ = true;
    setpoint_ = best_good_ > 0.0 ? best_good_ : cfg_.min_rps;
    d.phase = "done";
    d.reason = "window budget exhausted";
  }

  d.setpoint_rps = setpoint_;
  return d;
}

ClosedLoopDecision ClosedLoopController::StepRl(const LoadSample& sample, bool healthy,
                                                double /*err_pct*/) {
  // RL as accelerator, AIMD as safety net. The policy proposes; the shield here
  // is the only thing that actually moves the setpoint, so no policy can overdrive
  // the SUT.
  ClosedLoopDecision d;
  const double proposal = sample.rl_action_rps;

  if (!healthy) {
    // SLO red: ignore the policy entirely, force a multiplicative backoff.
    setpoint_ = std::max(cfg_.min_rps, setpoint_ * backoff_);
    d.phase = "backoff";
    d.reason = "shield: slo-violation backoff";
  } else {
    best_good_ = std::max(best_good_, setpoint_);
    if (proposal < 0.0) {
      // No proposal (policy absent/failed): fall back to AIMD additive increase.
      setpoint_ = std::min(cfg_.max_rps, setpoint_ + increase_);
      d.phase = "probe";
      d.reason = "rl: no proposal, aimd fallback";
    } else {
      // Cap the *upward* jump to rl_max_jump_factor x the last setpoint; downward
      // moves (lowering load) are always allowed. Then clamp to the load band.
      const double jump_ceiling =
          setpoint_ > 0.0 ? setpoint_ * cfg_.rl_max_jump_factor : cfg_.max_rps;
      const double capped = std::min(proposal, jump_ceiling);
      setpoint_ = Clamp(capped, cfg_.min_rps, cfg_.max_rps);
      d.phase = "rl";
      d.reason = "rl: shielded proposal";
    }
  }

  // Reuse the AIMD window budget as the soak/stop cap for kRl.
  if (cfg_.aimd_max_windows > 0 && window_ >= cfg_.aimd_max_windows) {
    done_ = true;
    setpoint_ = best_good_ > 0.0 ? best_good_ : cfg_.min_rps;
    d.phase = "done";
    d.reason = "window budget exhausted";
  }

  d.setpoint_rps = setpoint_;
  return d;
}

ClosedLoopDecision ClosedLoopController::StepBinSearch(const LoadSample& /*sample*/, bool healthy,
                                                       double /*err_pct*/) {
  ClosedLoopDecision d;
  const double ran = setpoint_;

  if (healthy) {
    lo_ = ran;
    best_good_ = std::max(best_good_, ran);
    if (!bracketed_) {
      // Exponential bracket: keep doubling until a violation gives us a ceiling
      // or we hit max_rps (in which case max is itself sustainable).
      const double next = std::min(cfg_.max_rps, ran > 0.0 ? ran * 2.0 : cfg_.max_rps);
      if (next <= ran + 1e-9) {
        // Already at the ceiling and still green: max_rps is the answer.
        done_ = true;
        setpoint_ = best_good_;
        d.phase = "converged";
        d.reason = "sustainable at max_rps";
        d.setpoint_rps = setpoint_;
        return d;
      }
      setpoint_ = next;
      d.phase = "bracket";
      d.reason = "slo-green: grow bracket";
    } else {
      setpoint_ = 0.5 * (lo_ + hi_);
      d.phase = "search";
      d.reason = "slo-green: raise floor";
    }
  } else {
    hi_ = ran;
    bracketed_ = true;
    setpoint_ = 0.5 * (lo_ + hi_);
    d.phase = "search";
    d.reason = "slo-violation: lower ceiling";
  }

  // Convergence: bracket collapsed within tolerance, or window budget spent.
  if (bracketed_ && (hi_ - lo_) <= tolerance_) {
    done_ = true;
    setpoint_ = best_good_ > 0.0 ? best_good_ : cfg_.min_rps;
    d.phase = "converged";
    d.reason = "bracket within tolerance";
  } else if (cfg_.binsearch_max_windows > 0 && window_ >= cfg_.binsearch_max_windows) {
    done_ = true;
    setpoint_ = best_good_ > 0.0 ? best_good_ : cfg_.min_rps;
    d.phase = "done";
    d.reason = "window budget exhausted";
  }

  d.setpoint_rps = setpoint_;
  return d;
}

}  // namespace samurai::control
