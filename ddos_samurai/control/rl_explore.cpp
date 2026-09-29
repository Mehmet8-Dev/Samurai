#include "rl_explore.hpp"

#include <cstddef>

#include "rl_policy.hpp"  // kActionFields — canonical dimension order

namespace samurai::control {

namespace {

constexpr std::size_t kNumFields =
    sizeof(kActionFields) / sizeof(kActionFields[0]);

// splitmix64: a fast, well-distributed finalizer. We use it to turn the tuple
// (seed, window, dim) into an independent uniform draw per dimension per window.
std::uint64_t Splitmix64(std::uint64_t x) {
  x += 0x9E3779B97F4A7C15ull;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
  return x ^ (x >> 31);
}

// Uniform integer in [lo, hi] from a 64-bit hash. Degenerate/empty ranges
// collapse to lo.
long DrawInRange(std::uint64_t h, long lo, long hi) {
  if (hi <= lo) return lo;
  const std::uint64_t span = static_cast<std::uint64_t>(hi - lo) + 1ull;
  return lo + static_cast<long>(h % span);
}

}  // namespace

bool RlExploreConfig::SetLever(const std::string& field, long lo, long hi) {
  if (levers.size() != kNumFields) levers.assign(kNumFields, RlExploreLever{});
  for (std::size_t k = 0; k < kNumFields; ++k) {
    if (field == kActionFields[k]) {
      if (k == 0) return false;  // rps is owned by the strategy, never explored
      if (hi < lo) return false;
      levers[k] = RlExploreLever{true, lo, hi};
      return true;
    }
  }
  return false;
}

RlExploreConfig DefaultExploreConfig(std::uint64_t seed) {
  RlExploreConfig cfg;
  cfg.enabled = true;
  cfg.seed = seed;
  cfg.levers.assign(kNumFields, RlExploreLever{});
  // Ranges tuned for a WAF/rate-limit lab so the defended target's reaction
  // (403 rate, 429/503 rate, conn drops) actually shifts across the space:
  //   concurrency     parallel lanes — pushes limit_conn / backend saturation.
  //   request_mix     which request variant is emitted (path/method) — trips
  //                   different WAF rules; see l7 request-variant table.
  //   source_rotation client source-identity spread — connection-tracking load.
  //   pacing_mode     1=RPS 2=IPG 3=BURST — burstiness the rate-limiter sees.
  cfg.SetLever("concurrency", 1, 16);
  cfg.SetLever("request_mix", 0, 4);
  cfg.SetLever("source_rotation", 1, 8);
  cfg.SetLever("pacing_mode", 1, 3);
  return cfg;
}

std::vector<double> ExploreLevers(int win, const RlExploreConfig& cfg) {
  std::vector<double> out(kNumFields, -1.0);
  if (!cfg.enabled || cfg.levers.size() != kNumFields) return out;
  const std::uint64_t win_h = Splitmix64(static_cast<std::uint64_t>(win));
  for (std::size_t k = 1; k < kNumFields; ++k) {  // k=0 (rps) stays sentinel
    const RlExploreLever& lv = cfg.levers[k];
    if (!lv.active) continue;
    // Mix seed, window and dim so each (win, dim) draw is independent.
    const std::uint64_t h =
        Splitmix64(cfg.seed ^ (win_h + 0x9E3779B97F4A7C15ull * (k + 1)));
    out[k] = static_cast<double>(DrawInRange(h, lv.lo, lv.hi));
  }
  return out;
}

}  // namespace samurai::control
