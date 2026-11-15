#pragma once

#include <cstdint>
#include <cstddef>
#include <random>

namespace samurai::telemetry {

enum class SamplerMode : uint8_t {
  Deterministic1ofN = 0, // Her N pakette tam 1 paket örneklenir (1:N)
  Probabilistic = 1      // 1/N olasılıkla rastgele örneklenir
};

class PacketSampler {
 public:
  explicit PacketSampler(uint32_t sampling_rate = 1, SamplerMode mode = SamplerMode::Deterministic1ofN)
      : sampling_rate_(sampling_rate == 0 ? 1 : sampling_rate),
        mode_(mode),
        counter_(0),
        rng_(1337) {}

  inline bool ShouldSample() noexcept {
    if (sampling_rate_ <= 1) return true; // 1:1 Tam örnekleme

    if (mode_ == SamplerMode::Deterministic1ofN) {
      if (++counter_ >= sampling_rate_) {
        counter_ = 0;
        return true;
      }
      return false;
    } else {
      // Fast LCG pseudo-random for wire-speed probabilistic sampling
      counter_ = counter_ * 6364136223846793005ULL + 1442695040888963407ULL;
      return (counter_ % sampling_rate_) == 0;
    }
  }

  void set_sampling_rate(uint32_t rate) noexcept {
    sampling_rate_ = (rate == 0) ? 1 : rate;
  }

  uint32_t sampling_rate() const noexcept { return sampling_rate_; }
  SamplerMode mode() const noexcept { return mode_; }

 private:
  uint32_t sampling_rate_;
  SamplerMode mode_;
  uint64_t counter_;
  std::mt19937_64 rng_;
};

}  // namespace samurai::telemetry
