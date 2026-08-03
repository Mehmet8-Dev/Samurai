#pragma once

// Autoscale decision controller — native C++ port of the control logic in
// ddos_samurai/control/autoscale.py (K8sAutoscaleController). The scaling
// *decision* state machine (cooldown, step limiting, idle scale-down, desired
// replica computation) is ported here and unit-testable.
//
// The live Kubernetes read/patch calls are deferred to a native k8s client;
// this controller runs in the in-memory mode (the Python `_api is None` path),
// tracking the replica count internally so decisions can be computed and driven
// deterministically. A clock is injectable for testing.

#include <functional>
#include <string>

namespace samurai::control {

struct AutoscaleConfig {
  bool enabled = false;
  std::string namespace_ = "default";
  std::string target_kind = "deployment";  // "deployment" | "statefulset"
  std::string target_name;
  int min_replicas = 1;
  int max_replicas = 100;
  int step = 1;
  double cooldown_s = 15.0;
  int shards_per_worker = 4;
  double idle_scale_down_s = 60.0;
};

struct AutoscaleDecision {
  bool enabled = false;
  bool changed = false;
  std::string reason;   // "disabled" | "cooldown" | "" (when a decision was computed)
  bool has_values = false;  // whether current/desired/applied are meaningful
  int current = 0;
  int desired = 0;
  int applied = 0;
  bool ok = false;
};

class AutoscaleController {
 public:
  // now_fn returns seconds (deltas only). Defaults to a steady monotonic clock.
  explicit AutoscaleController(const AutoscaleConfig& cfg,
                               std::function<double()> now_fn = {});

  // Evaluate and (in in-memory mode) apply one scaling step.
  AutoscaleDecision MaybeScale(int pending_shards, int inflight_shards, int workers_count);

  int current_replicas() const { return current_replicas_; }
  bool enabled() const { return enabled_; }

 private:
  int Desired(int pending_shards, int inflight_shards, int workers_count);

  bool enabled_;
  std::string namespace_;
  std::string target_kind_;
  std::string target_name_;
  int min_replicas_;
  int max_replicas_;
  int step_;
  double cooldown_s_;
  int shards_per_worker_;
  double idle_scale_down_s_;

  std::function<double()> now_fn_;
  double last_scale_ts_ = 0.0;
  double last_busy_ts_ = 0.0;
  int current_replicas_ = 1;
};

}  // namespace samurai::control
