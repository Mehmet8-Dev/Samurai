#pragma once

// Closed-loop (autopilot) load controller. Drives a load setpoint (target_rps)
// across successive *measured* windows to find and hold the maximum load the
// system-under-test (SUT) can take while staying inside a set of SLO
// thresholds. This is what turns the open-loop "generate N rps" generator into
// a "find the breaking point / hold the ceiling" capacity tool.
//
// Two strategies (selectable via ClosedLoopConfig::strategy):
//   - AIMD (kAimd): TCP-style additive-increase / multiplicative-decrease. While
//     the sample is SLO-green the setpoint climbs by a fixed step; on a violation
//     it is cut by a backoff factor. Converges to and oscillates around the
//     sustainable ceiling. Good for long/open-ended soak runs and wobbly systems.
//   - Binary search (kBinSearch): exponential bracket then bisection. Finds
//     "max rps with SLO still green" deterministically in a bounded number of
//     windows. Ideal for a one-shot capacity report or a CI gate.
//
// The decision state machine is intentionally pure and unit-testable, exactly
// like AutoscaleController / MasterCoordinator: each Step() consumes one already
// measured LoadSample and returns the next setpoint + phase. HOW a window is run
// and HOW the sample is measured is the caller's job (master_main runs a
// RunSingleJob window at the current setpoint and derives the sample from the
// aggregated run snapshot).
//
// SLO signal note: rules whose input is unknown (a negative field on the sample)
// are skipped, never failed. The latency rule therefore stays inert until the
// SUT-correlation feature feeds a real p99 into LoadSample::latency_p99_ms; the
// error / loss / rate-accuracy rules work off the native RunStats today.

#include <cstdint>
#include <string>

namespace samurai::control {

enum class ClosedLoopStrategy : std::uint8_t {
  kAimd = 0,
  kBinSearch = 1,
  kRl = 2,  // learned policy proposes the setpoint; the shield below bounds it
};

struct ClosedLoopConfig {
  bool enabled = false;
  ClosedLoopStrategy strategy = ClosedLoopStrategy::kAimd;

  double min_rps = 1.0;
  double max_rps = 1000000.0;
  double initial_rps = 0.0;  // <=0 => min_rps

  // SLO thresholds. Each rule is enabled only when its knob is > 0 (>= 0 would
  // make "0 errors" impossible to express as disabled, so 0 == disabled). A rule
  // with an unknown sample input (negative field) is skipped, not failed.
  double slo_max_error_pct = 0.0;          // errors/attempted*100 <= X
  double slo_max_loss_pct = 0.0;           // wire_loss_est_pct    <= X
  double slo_min_rate_accuracy_pct = 0.0;  // rate_accuracy_pct    >= X
  double slo_max_latency_ms = 0.0;         // latency_p99_ms       <= X (needs SUT signal)
  // Defense pushback (rate-limit 429 / overload 503 share, %) <= X. A load test whose
  // requests are being rejected is NOT delivering its target load, so sustained
  // pushback is a real SLO breach — without this rule the controller keeps ramping
  // into a rate wall (429s do not raise error_pct), never settling at the honored
  // ceiling. Enables ceiling-finding for AIMD/binsearch and forces the RL shield's
  // backoff on a rejecting window.
  double slo_max_pushback_pct = 0.0;       // 100*(4xx+5xx)/responses_total <= X

  // AIMD params.
  double aimd_increase_rps = 0.0;  // <=0 => 10% of (max_rps - min_rps)
  double aimd_backoff = 0.5;       // multiplicative decrease factor, clamped to (0,1)
  int aimd_max_windows = 0;        // 0 => unbounded soak; >0 => stop after N windows

  // Binary-search params.
  double binsearch_tolerance_rps = 0.0;  // <=0 => 1% of (max_rps - min_rps)
  int binsearch_max_windows = 24;        // hard cap on windows

  // RL (kRl) safety shield. The learned policy only *proposes* the next setpoint
  // (LoadSample::rl_action_rps); the controller enforces these bounds so a bad or
  // untrained policy can never overdrive the SUT:
  //   - an SLO-red window forces a multiplicative backoff (policy ignored), and
  //   - a green window caps the upward jump to rl_max_jump_factor x the last
  //     setpoint (downward moves are unrestricted — lowering load is always safe).
  // A missing proposal (<0, e.g. policy failed to load) falls back to AIMD.
  double rl_max_jump_factor = 2.0;  // clamped to >= 1.0 in the controller
};

// One already-measured window. Fields left < 0 are "unknown" and disable the
// rule that consumes them. error_pct, when < 0, is derived from errors/attempted.
struct LoadSample {
  bool valid = false;
  double actual_rps = 0.0;
  double attempted = 0.0;
  double errors = 0.0;
  double error_pct = -1.0;
  double loss_pct = -1.0;
  double rate_accuracy_pct = -1.0;
  double latency_p99_ms = -1.0;  // unknown until SUT correlation feeds it
  double pushback_pct = -1.0;    // 100*(4xx+5xx)/responses_total; <0 => unknown (rule skipped)
  // kRl only: the policy's proposed setpoint for the NEXT window, computed by the
  // caller from this measured state. < 0 => no proposal (shield falls back to AIMD).
  double rl_action_rps = -1.0;
};

struct ClosedLoopDecision {
  bool enabled = false;
  bool done = false;             // search converged / window budget exhausted
  double setpoint_rps = 0.0;     // setpoint to run the NEXT window at
  double best_good_rps = 0.0;    // best SLO-green setpoint observed so far
  bool last_healthy = false;     // was the sample just fed SLO-green?
  double error_pct = -1.0;       // the error_pct used for the health verdict
  std::string phase;             // "probe"|"bracket"|"search"|"backoff"|"converged"|"done"|"disabled"
  std::string reason;
  int window = 0;                // windows consumed so far
};

class ClosedLoopController {
 public:
  explicit ClosedLoopController(const ClosedLoopConfig& cfg);

  // Setpoint the FIRST window should run at (before any sample is fed).
  double initial_setpoint() const { return setpoint_; }

  // Consume one measured window and advance the state machine. The sample is
  // interpreted as the result of running a window at current_setpoint().
  ClosedLoopDecision Step(const LoadSample& sample);

  // SLO verdict for a sample in isolation (rules with unknown inputs are skipped).
  bool IsHealthy(const LoadSample& sample, double* out_error_pct = nullptr) const;

  double current_setpoint() const { return setpoint_; }
  double best_good_rps() const { return best_good_; }
  bool done() const { return done_; }
  bool enabled() const { return enabled_; }
  const ClosedLoopConfig& config() const { return cfg_; }

 private:
  ClosedLoopDecision StepAimd(const LoadSample& sample, bool healthy, double err_pct);
  ClosedLoopDecision StepBinSearch(const LoadSample& sample, bool healthy, double err_pct);
  ClosedLoopDecision StepRl(const LoadSample& sample, bool healthy, double err_pct);

  ClosedLoopConfig cfg_;
  bool enabled_ = false;

  double setpoint_ = 0.0;    // setpoint currently in effect (produced the next sample)
  double best_good_ = 0.0;   // highest SLO-green setpoint observed
  bool done_ = false;
  int window_ = 0;

  // Derived / normalized params.
  double increase_ = 0.0;
  double backoff_ = 0.5;
  double tolerance_ = 0.0;

  // Binary-search bracket state.
  double lo_ = 0.0;   // last known-good setpoint
  double hi_ = 0.0;   // last known-bad setpoint (0 => not yet bracketed)
  bool bracketed_ = false;
};

}  // namespace samurai::control
