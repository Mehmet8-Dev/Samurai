#pragma once

// Autoscale decision controller. The scaling *decision* state machine (cooldown,
// step limiting, idle scale-down, desired replica computation) is native and
// unit-testable.
//
// The live replica read/patch is pluggable via AutoscaleBackend: when a backend
// is set (the k8s_client wiring in master_main), MaybeScale reads the current
// replica count from the cluster and applies the next step through it; when no
// backend is set it runs in in-memory mode, tracking the replica count
// internally so decisions can still be computed and driven deterministically. A
// clock is injectable for testing.

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

// Live replica backend. Both callbacks return false to signal a transient
// failure, in which case MaybeScale falls back to the in-memory replica value
// for that evaluation (and reports the failure via the decision reason).
struct AutoscaleBackend {
  std::function<bool(int& current_out)> read_replicas;         // GET current
  std::function<bool(int desired, int& applied_out)> patch_replicas;  // PATCH
};

class AutoscaleController {
 public:
  // now_fn returns seconds (deltas only). Defaults to a steady monotonic clock.
  explicit AutoscaleController(const AutoscaleConfig& cfg,
                               std::function<double()> now_fn = {});

  // Install a live backend (k8s). Empty callbacks => stays in in-memory mode.
  void set_backend(AutoscaleBackend backend);

  // Evaluate and apply one scaling step (via the backend if set, else in-memory).
  AutoscaleDecision MaybeScale(int pending_shards, int inflight_shards, int workers_count);

  int current_replicas() const { return current_replicas_; }
  bool enabled() const { return enabled_; }
  bool has_backend() const { return has_backend_; }
  std::string backend_mode() const { return has_backend_ ? "kubernetes" : "in-memory"; }

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

  AutoscaleBackend backend_;
  bool has_backend_ = false;
};

}  // namespace samurai::control
