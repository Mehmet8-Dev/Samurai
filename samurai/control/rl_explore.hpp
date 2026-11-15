#pragma once

// Exploration-mode lever perturbation for RL corpus capture.
//
// Offline RL can only learn an action dimension the corpus BOTH varies AND the
// dataplane reacts to. During plain corpus capture (--rl-corpus) with no policy
// driving them, the extra Mahoraga levers (concurrency, request_mix,
// source_rotation, pacing_mode) never move, so those columns are constant and
// unlearnable. This module supplies the "varies" half: a deterministic,
// reproducible per-window perturbation of the extra levers so the captured
// corpus has coverage across the Mahoraga action space. The rps setpoint
// (dim 0) is deliberately NOT perturbed here — the closed-loop strategy
// (AIMD/binary-search) owns the SLO search on rps; exploration rides on top,
// varying the shaping levers while the strategy sweeps rps.
//
// The schedule is a splitmix64 hash of (seed, window, dim): reproducible across
// runs (same seed => same corpus perturbation) and decorrelated across
// dimensions and windows (no lockstep sweep that would confound the levers).

#include <cstdint>
#include <string>
#include <vector>

namespace samurai::control {

// One perturbed dimension. `active` dims are drawn uniformly in [lo, hi]
// (inclusive) each window; inactive dims are left to their spec value.
struct RlExploreLever {
  bool active = false;
  long lo = 0;
  long hi = 0;
};

// Exploration schedule. `levers` is indexed to match kActionFields (rl_policy.hpp):
// index 0 = rps is never perturbed (owned by the strategy); indices 1..N are the
// extra Mahoraga levers. Sized to kActionFields so index k lines up with the
// canonical field name the serving/apply path uses.
struct RlExploreConfig {
  bool enabled = false;
  std::uint64_t seed = 0;
  std::vector<RlExploreLever> levers;  // size == number of kActionFields entries

  // Enable + range for the lever named `field` (must be a kActionFields name
  // other than "rps"). Returns false if the field is unknown or is "rps".
  bool SetLever(const std::string& field, long lo, long hi);
};

// A config pre-populated with sensible defaults for a WAF/rate-limit lab. All
// four extra levers active; ranges chosen so a defended target reacts
// differently across the space (see rl_explore.cpp for the rationale).
RlExploreConfig DefaultExploreConfig(std::uint64_t seed);

// The perturbed lever values for `win`, aligned to kActionFields. Entry k is the
// value for field kActionFields[k], or a negative sentinel (-1) meaning "do not
// perturb this dimension — leave the spec value". Index 0 (rps) is always the
// sentinel. Deterministic in (cfg.seed, win).
std::vector<double> ExploreLevers(int win, const RlExploreConfig& cfg);

}  // namespace samurai::control
