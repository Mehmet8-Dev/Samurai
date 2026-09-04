#pragma once

// Native serving for the offline-trained RL policy (the "brain" of the kRl
// closed-loop strategy). Loads the flat SRLP weight file exported by
// ddos_samurai/models/rl/export.py and runs the MLP forward pass in-process — no
// torch, no Python, no external deps — so the master binary stays self-contained
// and deterministic. Inference is once per closed-loop window (seconds apart), so
// the cost is irrelevant; what matters is that this mirrors the Python
// PolicyArtifact op-for-op, which the selftest golden vector pins.
//
// The policy only *proposes* a setpoint. The safety shield that bounds the
// proposal (jump cap + forced SLO backoff) lives in ClosedLoopController::StepRl,
// keeping brain (this file) and reflex (the controller) cleanly separated.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace samurai::control {

// Canonical action-dimension order — MUST match ddos_samurai/models/rl
// action_spec.MAHORAGA. The serving side applies policy output[k] to this field
// (k=0 is the rps setpoint the shield governs; k>=1 are Mahoraga load-shaping
// levers set on the job spec). A training ActionSpec must be a prefix of this.
inline constexpr const char* kActionFields[] = {
    "rps", "concurrency", "request_mix", "source_rotation", "pacing_mode",
};

// Raw (pre-normalization) state inputs for one window. Fields left < 0 are
// "unknown" and imputed/masked exactly like the Python DefaultFeatureExtractor.
struct RlStateInputs {
  double rps = 0.0;
  double error_pct = -1.0;           // effective (derived) error percent, or -1
  double loss_pct = -1.0;
  double rate_accuracy_pct = -1.0;
  double p99_ms = -1.0;
  int win = 0;
  // Mahoraga defense-reaction derived ratios (UNKNOWN = -1 when not computable).
  double rate_limited_ratio = -1.0;
  double overload_ratio = -1.0;
  double conn_drop_ratio = -1.0;
  double reset_pressure = -1.0;
  double challenge_rate = -1.0;
  // Context used for normalization of the raw features.
  double max_rps = 1.0;
  double step_horizon = 32.0;  // must match RLConfig.step_horizon
};

class RlPolicy {
 public:
  RlPolicy() = default;

  // Load an SRLP file. Returns false (with *err set, if given) on any format or
  // I/O error; the object stays unloaded and Propose*() must not be called.
  bool Load(const std::string& path, std::string* err = nullptr);

  bool loaded() const { return loaded_; }
  int input_dim() const { return in_dim_; }
  int action_dim() const { return action_dim_; }

  // Build the ordered raw feature vector from state inputs. The ordering is fixed
  // and MUST match ddos_samurai/models/rl RLConfig.feature_names + the mask bits:
  //   [0] rps_norm  [1] error_pct  [2] loss_pct  [3] rate_accuracy_pct
  //   [4] p99_ms    [5] step_norm  [6] rate_limited_ratio  [7] overload_ratio
  //   [8] conn_drop_ratio  [9] reset_pressure  [10] challenge_rate
  //   [11..19] known-mask bits for error_pct, loss_pct, rate_accuracy_pct, p99_ms,
  //            rate_limited_ratio, overload_ratio, conn_drop_ratio, reset_pressure,
  //            challenge_rate.
  static std::vector<float> BuildFeatures(const RlStateInputs& in);

  // Forward pass on a raw feature vector -> the full (action_dim) de-normalized
  // action vector. Mirrors PolicyArtifact.act_batch: standardize, ReLU-MLP, linear
  // output per-dim clamped to [0,1], de-normalized with [action_lo, action_hi].
  // Returns empty on unloaded / bad dims. Element 0 is the rps setpoint.
  std::vector<double> Propose(const std::vector<float>& features) const;

  // Convenience: build features from state inputs and run the forward pass.
  std::vector<double> ProposeFor(const RlStateInputs& in) const {
    return Propose(BuildFeatures(in));
  }

 private:
  bool loaded_ = false;
  int in_dim_ = 0;
  int action_dim_ = 0;
  // Dense layers as (W, b): W flattened row-major (out*in), b size out, out_dim.
  struct Layer {
    std::vector<float> w;
    std::vector<float> b;
    int out_dim = 0;
    int in_dim = 0;
  };
  std::vector<Layer> layers_;
  std::vector<float> norm_mean_;
  std::vector<float> norm_std_;
  std::vector<float> action_lo_;  // per-dim
  std::vector<float> action_hi_;  // per-dim
};

}  // namespace samurai::control
