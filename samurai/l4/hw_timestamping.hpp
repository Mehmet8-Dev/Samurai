#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace samurai::l4 {

struct HwTimestampConfig {
  bool enable_ptp = true;
  bool enable_so_timestamping = true;
  uint64_t histogram_max_ns = 1000000000ull;  // 1 second max sample
};

struct NanosecondLatencyStats {
  uint64_t samples_count = 0;
  uint64_t min_ns = 0;
  uint64_t max_ns = 0;
  double avg_ns = 0.0;
  double p50_ns = 0.0;
  double p90_ns = 0.0;
  double p95_ns = 0.0;
  double p99_ns = 0.0;
  double p99_9_ns = 0.0;
  double jitter_ns = 0.0;
};

class NanosecondLatencyHistogram {
 public:
  NanosecondLatencyHistogram();

  void AddSample(uint64_t latency_ns);
  NanosecondLatencyStats CalculateStats() const;
  void Reset();

 private:
  mutable std::mutex mu_;
  std::vector<uint64_t> samples_;
  uint64_t min_ns_ = UINT64_MAX;
  uint64_t max_ns_ = 0;
  uint64_t sum_ns_ = 0;
  uint64_t prev_sample_ns_ = 0;
  double sum_jitter_ns_ = 0.0;
};

class HwTimestampEngine {
 public:
  static bool EnableDpdkTimesync(uint16_t port_id);
  static bool ReadRxTimestampDpdk(uint16_t port_id, uint64_t* out_ns);
  static bool ReadTxTimestampDpdk(uint16_t port_id, uint64_t* out_ns);

  static bool EnableSocketTimestamping(int socket_fd);
  static bool ExtractSocketTimestampNs(const void* cmsg_buf, size_t cmsg_len, uint64_t* out_ns);
};

}  // namespace samurai::l4
