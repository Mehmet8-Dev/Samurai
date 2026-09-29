#pragma once

// Open-vocabulary defense detection — the part that notices a phenomenon the frozen
// feature/action space cannot represent. The policy only "sees" defenses along its
// fixed axes (rate-limit 4xx, overload 5xx, conn-drop, stream-reset, WAF challenge).
// A target that defends by an UNMODELLED mechanism — a silent tarpit, a slow-drip,
// a 200-with-wrong-body content block, an application-layer poison — drives success
// down while every known axis stays quiet. A frozen dictionary is blind to it; this
// layer is not.
//
// The honest, model-free discriminator is the UNEXPLAINED success loss:
//
//     unexplained = max(0, (1 - success_ratio) - sum(known defense shares))
//
// When traffic is failing (success well below 1) but no known signal accounts for
// it, `unexplained` is large — the target is doing something outside the dictionary.
// The detector smooths this into a novelty score, and when it persists it records a
// SIGNATURE for the phenomenon in an open vocabulary (new signature strings appear
// as new mechanisms are discovered — that is the "new axis" opening), and raises a
// novelty pressure the serving loop can act on (a cautious backoff: if we cannot
// model why load is failing, do not keep pushing into it).
//
// The new axis is not just NAMED, it is TUNED. A signature that keeps recurring
// GRADUATES from the open vocabulary into a first-class response lever: instead of
// the one fixed global backoff, each discovered mechanism grows its OWN damping
// multiplier, learned online by outcome. While a signature's windows stay novel
// (still-unexplained failure), its lever tightens (more backoff — the fixed space
// could not model this defense, so retreat harder from it); as its windows recover
// (unexplained recedes), the lever relaxes back toward 1. That per-signature lever,
// tuned by the target's reaction and persisted across runs, is the action space
// literally growing a new dimension for a defense the frozen policy never saw.
//
// Header-only + dependency-free (core/json), mirroring ban_memory.hpp /
// online_adapter.hpp so no build wiring changes.

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../core/json.hpp"

namespace samurai::control {

// One window's defense reaction along the known axes. A field < 0 is "unknown" and
// contributes nothing (neither to the explained share nor to a false novelty).
struct NoveltySignals {
  double success_ratio = -1.0;   // 2xx / responses
  double rate_limited = -1.0;    // 4xx share
  double overload = -1.0;        // 5xx share
  double conn_drop = -1.0;       // 1 - established/attempted
  double reset = -1.0;           // stream-reset ratio
  double challenge = -1.0;       // WAF challenge / unexpected-response rate
};

class NoveltyDetector {
 public:
  struct Config {
    bool enabled = false;
    double residual_threshold = 0.35;  // smoothed unexplained loss above this = novel
    double ewma_alpha = 0.3;           // novelty-score smoothing
    double backoff = 0.85;             // default lever for an un-graduated signature
    int warmup_windows = 3;            // observe before flagging (avoid startup noise)
    // Per-signature learned-lever (graduated axis) tuning.
    int promotion_count = 3;    // novel windows before a signature graduates to its own lever
    double min_damping = 0.50;  // floor on a learned lever (never harder backoff than this)
    double damp_lr = 0.20;      // tighten rate while a graduated signature stays novel
    double relax_lr = 0.10;     // relax rate back toward 1.0 on a recovered (non-novel) window
  };

  // A discovered defense mechanism promoted to a first-class, outcome-tuned response
  // lever. `damping` is the setpoint multiplier the serving loop applies while this
  // signature is the active novel regime (only once `graduated`); `resid_ewma` is the
  // smoothed unexplained loss seen under it (telemetry + the learning signal).
  struct Axis {
    std::string signature;
    long count = 0;
    double damping = 0.85;
    double resid_ewma = 0.0;
    bool graduated = false;
  };

  NoveltyDetector() : NoveltyDetector(Config{}) {}
  explicit NoveltyDetector(Config cfg) : cfg_(cfg) {}

  // Fold one window's reaction. Returns the current (smoothed) novelty score in
  // [0,1]. When the score first crosses the threshold in a window, a signature for
  // the phenomenon is minted / counted in the open vocabulary.
  double Observe(const NoveltySignals& s) {
    ++windows_;
    if (s.success_ratio < 0.0) return score_;  // no success signal -> cannot judge

    auto share = [](double v) { return v > 0.0 ? v : 0.0; };
    const double explained = std::min(
        1.0, share(s.rate_limited) + share(s.overload) + share(s.conn_drop) +
                 share(s.reset) + share(s.challenge));
    const double unexplained = std::max(0.0, (1.0 - s.success_ratio) - explained);
    last_unexplained_ = unexplained;

    score_ = seen_ ? cfg_.ewma_alpha * unexplained + (1.0 - cfg_.ewma_alpha) * score_
                   : unexplained;
    seen_ = true;

    novel_now_ = windows_ > cfg_.warmup_windows && score_ >= cfg_.residual_threshold;
    if (novel_now_) {
      last_signature_ = Signature(s, explained);
      Axis& ax = Bump(last_signature_);
      // Learn the axis's lever from the outcome. While this signature keeps failing
      // unexplained, tighten its damping (retreat harder from a defense the fixed
      // space cannot model); floor at min_damping so it stays a nudge, not a stall.
      if (ax.graduated) {
        const double err = std::max(0.0, unexplained - cfg_.residual_threshold);
        ax.damping = std::max(cfg_.min_damping, ax.damping - cfg_.damp_lr * err);
      }
    } else if (windows_ > cfg_.warmup_windows) {
      // A recovered (judged, non-novel) window: relax every graduated lever back
      // toward 1.0, so a defense that has stopped reacting stops being penalized.
      for (Axis& ax : axes_) {
        if (ax.graduated) ax.damping += cfg_.relax_lr * (1.0 - ax.damping);
      }
    }
    return score_;
  }

  double score() const { return score_; }
  bool novel() const { return novel_now_; }
  double last_unexplained() const { return last_unexplained_; }
  const std::string& last_signature() const { return last_signature_; }

  // Cautious setpoint response: while a novel (un-modelled) regime holds, damp the
  // proposal rather than keep pushing into a failure we cannot explain. A graduated
  // signature uses its OWN learned lever; an un-graduated one uses the default
  // backoff. Identity otherwise. The rps shield still bounds the result, so this only
  // ever lowers load.
  double DampSetpoint(double rps) const {
    if (!novel_now_) return rps;
    for (const Axis& ax : axes_) {
      if (ax.signature == last_signature_) {
        return rps * (ax.graduated ? ax.damping : cfg_.backoff);
      }
    }
    return rps * cfg_.backoff;
  }

  // The learned per-signature levers (graduated axes carry a tuned damping). The set
  // grows as new mechanisms appear; that growth IS the new-axis discovery.
  const std::vector<Axis>& axes() const { return axes_; }

  // Back-compat count view: {signature -> times seen}.
  std::vector<std::pair<std::string, long>> vocabulary() const {
    std::vector<std::pair<std::string, long>> v;
    v.reserve(axes_.size());
    for (const Axis& ax : axes_) v.emplace_back(ax.signature, ax.count);
    return v;
  }

  void Warm(const std::vector<Axis>& axes) {
    for (const Axis& a : axes) {
      if (a.count <= 0) continue;
      Axis ax = a;
      ax.graduated = ax.graduated || ax.count >= cfg_.promotion_count;
      if (ax.damping <= 0.0) ax.damping = cfg_.backoff;
      axes_.push_back(ax);
    }
  }

  // Legacy warm path: count-only vocabulary (older novelty-memory files).
  void Warm(const std::vector<std::pair<std::string, long>>& vocab) {
    std::vector<Axis> axes;
    for (const auto& [k, c] : vocab) {
      Axis ax;
      ax.signature = k;
      ax.count = c;
      ax.damping = cfg_.backoff;
      axes.push_back(ax);
    }
    Warm(axes);
  }

  core::json::Value ToJson() const {
    core::json::Value o = core::json::Value::Object();
    o.set("score", core::json::Value::Double(score_));
    o.set("novel", core::json::Value::Bool(novel_now_));
    o.set("unexplained", core::json::Value::Double(last_unexplained_));
    if (!last_signature_.empty()) o.set("signature", core::json::Value::Str(last_signature_));
    core::json::Value v = core::json::Value::Object();
    for (const Axis& ax : axes_) {
      core::json::Value a = core::json::Value::Object();
      a.set("count", core::json::Value::Int(ax.count));
      a.set("damping", core::json::Value::Double(ax.damping));
      a.set("graduated", core::json::Value::Bool(ax.graduated));
      v.set(ax.signature, std::move(a));
    }
    o.set("vocabulary", std::move(v));
    return o;
  }

 private:
  // Classify the novel phenomenon into an open-vocabulary signature. The point is to
  // NAME what the dictionary could not: a total silence (no known axis moved at all)
  // vs. an under-explained regime where a known axis is present but nowhere near
  // enough to account for the failure.
  static std::string Signature(const NoveltySignals& s, double explained) {
    if (explained < 0.10) return "silent-success-loss";  // failing with no known signal
    struct Axis { const char* name; double v; };
    const Axis axes[] = {
        {"rate_limit", s.rate_limited}, {"overload", s.overload},
        {"conn_drop", s.conn_drop},     {"reset", s.reset},
        {"challenge", s.challenge},
    };
    const char* dom = "mixed";
    double best = 0.0;
    for (const Axis& a : axes) {
      if (a.v > best) { best = a.v; dom = a.name; }
    }
    return std::string("under-explained:") + dom;
  }

  // Count the signature, minting its axis on first sight, and promote it to a learned
  // lever once it has recurred enough to be worth a dedicated response dimension.
  Axis& Bump(const std::string& sig) {
    for (Axis& ax : axes_) {
      if (ax.signature == sig) {
        ++ax.count;
        ax.resid_ewma = cfg_.ewma_alpha * last_unexplained_ +
                        (1.0 - cfg_.ewma_alpha) * ax.resid_ewma;
        if (!ax.graduated && ax.count >= cfg_.promotion_count) ax.graduated = true;
        return ax;
      }
    }
    Axis ax;
    ax.signature = sig;
    ax.count = 1;
    ax.damping = cfg_.backoff;
    ax.resid_ewma = last_unexplained_;
    ax.graduated = cfg_.promotion_count <= 1;
    axes_.push_back(std::move(ax));
    return axes_.back();
  }

  Config cfg_;
  double score_ = 0.0;
  bool seen_ = false;
  bool novel_now_ = false;
  int windows_ = 0;
  double last_unexplained_ = 0.0;
  std::string last_signature_;
  std::vector<Axis> axes_;
};

// Cross-run persistence for the per-target discovered novelty vocabulary AND its
// learned levers. Format is a nested JSON object keyed by target, each signature
// carrying its learned response: { "host:port": { "signature": {"count": n,
// "damping": d, "graduated": bool}, ... }, ... }. A legacy plain-integer value
// ({ "signature": count }) is still read (count only, lever defaults on warm).
class NoveltyMemory {
 public:
  using Axis = NoveltyDetector::Axis;

  static NoveltyMemory Load(const std::string& path) {
    NoveltyMemory m;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return m;
    std::ostringstream ss;
    ss << in.rdbuf();
    const auto parsed = core::json::Parse(ss.str());
    if (!parsed.ok || !parsed.value.is_object()) return m;
    for (const auto& [key, val] : parsed.value.members()) {
      if (!val.is_object()) continue;
      std::vector<Axis> axes;
      for (const auto& [sig, entry] : val.members()) {
        Axis ax;
        ax.signature = sig;
        if (entry.is_object()) {
          if (const auto* c = entry.find("count")) ax.count = static_cast<long>(c->as_double(0.0));
          if (const auto* d = entry.find("damping")) ax.damping = d->as_double(0.0);
          if (const auto* g = entry.find("graduated")) ax.graduated = g->as_bool(false);
        } else {
          ax.count = static_cast<long>(entry.as_double(0.0));  // legacy count-only form
        }
        axes.push_back(std::move(ax));
      }
      m.entries_.emplace_back(key, std::move(axes));
    }
    return m;
  }

  std::vector<Axis> Get(const std::string& key) const {
    for (const auto& [k, v] : entries_) {
      if (k == key) return v;
    }
    return {};
  }

  void Put(const std::string& key, const std::vector<Axis>& axes) {
    for (auto& [k, v] : entries_) {
      if (k == key) { v = axes; return; }
    }
    entries_.emplace_back(key, axes);
  }

  bool Save(const std::string& path) const {
    core::json::Value root = core::json::Value::Object();
    for (const auto& [k, axes] : entries_) {
      core::json::Value obj = core::json::Value::Object();
      for (const Axis& ax : axes) {
        core::json::Value a = core::json::Value::Object();
        a.set("count", core::json::Value::Int(ax.count));
        a.set("damping", core::json::Value::Double(ax.damping));
        a.set("graduated", core::json::Value::Bool(ax.graduated));
        obj.set(ax.signature, std::move(a));
      }
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
  std::vector<std::pair<std::string, std::vector<Axis>>> entries_;
};

}  // namespace samurai::control
