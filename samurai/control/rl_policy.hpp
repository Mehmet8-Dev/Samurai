#pragma once

// Native serving for the offline-trained RL policy (the "brain" of the kRl
// closed-loop strategy). Loads the flat SRLP weight file exported by
// samurai/models/rl/export.py and runs the MLP forward pass in-process — no
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

// Canonical action-dimension order — MUST match samurai/models/rl
// action_spec.MAHORAGA. The serving side applies policy output[k] to this field
// (k=0 is the rps setpoint the shield governs; k>=1 are Mahoraga load-shaping
// levers set on the job spec). A training ActionSpec must be a prefix of this.
inline constexpr const char* kActionFields[] = {
    "rps", "concurrency", "request_mix", "source_rotation", "pacing_mode", "auth_mode", "evasion_tactic",
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
  // Path-aware variant-block memory (RLConfig.variant_block_features). Per-variant
  // best-observed success this episode, -1 = unobserved. When non-empty, BuildFeatures
  // appends 2 features per variant AFTER the mask bits: block ratio (1-best, imputed
  // 0 if unobserved) then a known bit — matching dataset.build_dataset's layout.
  // Empty => legacy 20-dim state (no block features), so old policies still load.
  std::vector<double> variant_block_success;
  // Persistent-defense (ban) state (RLConfig.ban_state_features). When ban_features
  // is set, BuildFeatures appends 2 features AFTER the block features: ban_pressure
  // (a causal EWMA of conn_drop, imputed 0 if never observed) then a ban_known bit.
  // ban_pressure < 0 means "no conn_drop folded yet" (known bit 0). Off by default so
  // block-only / legacy policies keep their exact width.
  bool ban_features = false;
  double ban_pressure = -1.0;
  // Flow-level IPS/NSM state (RLConfig.flow_state_features). When flow_features is
  // set, BuildFeatures appends 5 features AFTER the ban features: four
  // per-connection-attempt flow rates (rst / connect-timeout / retransmit /
  // timeout-close, imputed 0 when < 0) then ONE shared flow_known bit. The bit is
  // set only when this run drives a flow-capable transport (flow_capable) AND at
  // least one rate is measurable — mirroring the dataset's transport-gated encoding,
  // so a kernel-socket serve masks these exactly like the kernel-socket corpus did.
  bool flow_features = false;
  bool flow_capable = false;  // transport actually measures the flow counters
  double rst_rate = -1.0;
  double connect_timeout_rate = -1.0;
  double retransmit_rate = -1.0;
  double timeout_close_rate = -1.0;
};

// EWMA smoothing for ban_pressure — MUST match RLConfig.ban_ewma_alpha (Python).
inline constexpr double kBanEwmaAlpha = 0.5;

class RlPolicy {
 public:
  RlPolicy() = default;

  // Load an SRLP file. Returns false (with *err set, if given) on any format or
  // I/O error; the object stays unloaded and Propose*() must not be called.
  bool Load(const std::string& path, std::string* err = nullptr);

  bool loaded() const { return loaded_; }
  int input_dim() const { return in_dim_; }
  int action_dim() const { return action_dim_; }

  // Whether this is an RL² recurrent policy (SRLP v4): the GRU context encoder runs
  // once per window and its hidden state is carried across the episode, so the same
  // frozen weights adapt as the trajectory unfolds.
  bool recurrent() const { return recurrent_; }

  // Normalized state feature width — the number of features BuildFeatures must emit
  // and the length of the exported normalizer. For a feedforward policy this equals
  // input_dim(); for a recurrent policy the MLP input is [state, hidden] so
  // input_dim() == state_dim() + hidden_dim(). The caller decodes which extra
  // (block/ban) features a feedforward policy wants from state_dim(), NOT input_dim().
  int state_dim() const { return recurrent_ ? state_dim_ : in_dim_; }
  int hidden_dim() const { return hidden_dim_; }

  // Reset the recurrent context to the start of an episode (hidden state -> 0, no
  // prior token). A no-op on a feedforward policy. Call before the first ProposeFor
  // of a new closed-loop run.
  void ResetContext();

  // Build the ordered raw feature vector from state inputs. The ordering is fixed
  // and MUST match samurai/models/rl RLConfig.feature_names + the mask bits:
  //   [0] rps_norm  [1] error_pct  [2] loss_pct  [3] rate_accuracy_pct
  //   [4] p99_ms    [5] step_norm  [6] rate_limited_ratio  [7] overload_ratio
  //   [8] conn_drop_ratio  [9] reset_pressure  [10] challenge_rate
  //   [11..19] known-mask bits for error_pct, loss_pct, rate_accuracy_pct, p99_ms,
  //            rate_limited_ratio, overload_ratio, conn_drop_ratio, reset_pressure,
  //            challenge_rate.
  //   [20..20+V-1]     variant block ratios (1-best success, 0 if unobserved)
  //   [20+V..20+2V-1]  variant known bits   (present only when in.variant_block_success
  //                    is non-empty; V == in.variant_block_success.size()).
  //   [.. , ..+1]      ban_pressure, ban_known (present only when in.ban_features;
  //                    appended AFTER the block features, matching the Python layout).
  static std::vector<float> BuildFeatures(const RlStateInputs& in);

  // Forward pass on a raw (state) feature vector -> the full (action_dim)
  // de-normalized action vector. Mirrors PolicyArtifact.act_batch (feedforward):
  // standardize, ReLU-MLP, per-dim decode (continuous clamp[0,1]+de-normalize;
  // categorical argmax). Returns empty on unloaded / bad dims. Element 0 is rps.
  // For a recurrent policy this treats the state as an isolated first window (zero
  // context); use ProposeFor to carry the episode context that makes it adapt.
  std::vector<double> Propose(const std::vector<float>& features) const;

  // Build features from state inputs and run the forward pass. For a recurrent
  // policy this ADVANCES the carried hidden state with the previous window's token
  // and conditions the action on it (mirrors PolicyArtifact.act_sequence), so it is
  // stateful across calls — hence non-const. Feedforward policies are unaffected.
  std::vector<double> ProposeFor(const RlStateInputs& in);

 private:
  // Standardize the state part (length state_dim_) with the exported normalizer.
  std::vector<float> Standardize(const std::vector<float>& features) const;
  // Run the ReLU-MLP + per-dim decode on a prepared input of width in_dim_.
  std::vector<double> ForwardDecode(const std::vector<float>& mlp_input) const;
  // Normalize a de-normalized action to the per-dim [0,1] token space (mirrors the
  // training A = (action - lo)/span), used to build the GRU token.
  std::vector<float> NormalizeAction(const std::vector<double>& action) const;
  // One torch.nn.GRUCell step (gate order reset, update, new): h' from h and token.
  std::vector<float> GruStep(const std::vector<float>& h,
                             const std::vector<float>& token) const;

  bool loaded_ = false;
  int in_dim_ = 0;
  int action_dim_ = 0;    // number of action DIMENSIONS
  int output_width_ = 0;  // width of the network output (>= action_dim_ with categorical heads)
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

  // RL² recurrent context encoder (SRLP v4). Off for v2/v3.
  bool recurrent_ = false;
  int state_dim_ = 0;    // normalized state width (== in_dim_ when feedforward)
  int hidden_dim_ = 0;   // GRU hidden width H
  int token_dim_ = 0;    // state_dim_ + action_dim_
  std::vector<float> gru_w_ih_;  // (3H * token_dim_) row-major, gate order r,z,n
  std::vector<float> gru_w_hh_;  // (3H * H) row-major
  std::vector<float> gru_b_ih_;  // 3H
  std::vector<float> gru_b_hh_;  // 3H
  // Carried episode context: hidden state, and the previous window's token
  // ([standardized state, action]) folded in on the next ProposeFor.
  std::vector<float> hidden_;      // H (zero at episode start)
  std::vector<float> prev_token_;  // token_dim_ (empty until the first proposal)
  // Per-dim output head. A continuous dim reads one output at out_offset, clamped
  // to [0,1] and de-normalized with [lo, hi]. A categorical dim reads
  // cats.size() outputs as logits starting at out_offset; argmax -> cats[idx].
  struct DimHead {
    bool categorical = false;
    int out_offset = 0;
    float lo = 0.0f;
    float hi = 1.0f;
    std::vector<float> cats;
  };
  std::vector<DimHead> dims_;
};

}  // namespace samurai::control
