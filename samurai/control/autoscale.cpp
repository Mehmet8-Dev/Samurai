#include "autoscale.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>

namespace samurai::control {

namespace {

std::string LowerNonEmpty(const std::string& s, const std::string& fallback) {
  std::string t = s;
  const auto first = t.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return fallback;
  const auto last = t.find_last_not_of(" \t\r\n");
  t = t.substr(first, last - first + 1);
  for (char& c : t) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return t.empty() ? fallback : t;
}

std::string StripNonEmpty(const std::string& s, const std::string& fallback) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return fallback;
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

double SteadyNow() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

AutoscaleController::AutoscaleController(const AutoscaleConfig& cfg,
                                        std::function<double()> now_fn)
    : enabled_(cfg.enabled),
      namespace_(LowerNonEmpty(cfg.namespace_, "default")),
      target_kind_(LowerNonEmpty(cfg.target_kind, "deployment")),
      target_name_(StripNonEmpty(cfg.target_name, "")),
      min_replicas_(std::max(1, cfg.min_replicas)),
      max_replicas_(std::max(std::max(1, cfg.min_replicas), cfg.max_replicas)),
      step_(std::max(1, cfg.step)),
      cooldown_s_(std::max(1.0, cfg.cooldown_s)),
      shards_per_worker_(std::max(1, cfg.shards_per_worker)),
      idle_scale_down_s_(std::max(5.0, cfg.idle_scale_down_s)),
      now_fn_(now_fn ? std::move(now_fn) : std::function<double()>(SteadyNow)) {
  current_replicas_ = min_replicas_;
  last_busy_ts_ = now_fn_();
}

void AutoscaleController::set_backend(AutoscaleBackend backend) {
  backend_ = std::move(backend);
  has_backend_ = static_cast<bool>(backend_.read_replicas) &&
                 static_cast<bool>(backend_.patch_replicas);
}

int AutoscaleController::Desired(int pending_shards, int inflight_shards, int workers_count) {
  const int busy = pending_shards + inflight_shards;
  if (busy > 0) {
    last_busy_ts_ = now_fn_();
    int needed = std::max(1, (busy + shards_per_worker_ - 1) / shards_per_worker_);
    needed = std::max(needed, std::max(0, workers_count));
    return std::min(max_replicas_, std::max(min_replicas_, needed));
  }
  if ((now_fn_() - last_busy_ts_) >= idle_scale_down_s_) {
    return min_replicas_;
  }
  const int val = workers_count > 0 ? workers_count : min_replicas_;
  return std::max(min_replicas_, std::min(max_replicas_, val));
}

AutoscaleDecision AutoscaleController::MaybeScale(int pending_shards, int inflight_shards,
                                                 int workers_count) {
  AutoscaleDecision d;
  if (!enabled_ || target_name_.empty()) {
    d.enabled = false;
    d.changed = false;
    d.reason = "disabled";
    return d;
  }

  const double now = now_fn_();
  if ((now - last_scale_ts_) < cooldown_s_) {
    d.enabled = true;
    d.changed = false;
    d.reason = "cooldown";
    return d;
  }

  // Read the current replica count: from the live backend when set (falling back
  // to the in-memory value on a transient read failure), else the in-memory model.
  int cur = current_replicas_;
  if (has_backend_) {
    int live = 0;
    if (backend_.read_replicas(live)) {
      cur = live;
      current_replicas_ = live;
    } else {
      d.reason = "backend-read-failed";  // proceed against the in-memory value
    }
  }
  const int des = Desired(std::max(0, pending_shards), std::max(0, inflight_shards),
                          std::max(0, workers_count));

  d.enabled = true;
  d.has_values = true;
  d.current = cur;
  d.desired = des;

  if (des == cur) {
    d.changed = false;
    return d;
  }

  const int nxt = des > cur ? std::min(des, cur + step_) : std::max(des, cur - step_);
  if (has_backend_) {
    int applied = 0;
    if (!backend_.patch_replicas(nxt, applied)) {
      d.changed = false;
      d.ok = false;
      d.reason = "backend-patch-failed";
      return d;  // no cooldown consumed: retry on the next tick
    }
    current_replicas_ = applied;
    d.applied = applied;
  } else {
    // in-memory patch: always succeeds.
    current_replicas_ = nxt;
    d.applied = nxt;
  }
  last_scale_ts_ = now;
  d.changed = true;
  d.ok = true;
  return d;
}

}  // namespace samurai::control
