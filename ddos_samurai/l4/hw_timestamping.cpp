#include "hw_timestamping.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#if __has_include(<linux/net_tstamp.h>)
#include <linux/net_tstamp.h>
#endif

#ifndef SOF_TIMESTAMPING_RX_HARDWARE
#define SOF_TIMESTAMPING_RX_HARDWARE (1<<2)
#endif
#ifndef SOF_TIMESTAMPING_RAW_HARDWARE
#define SOF_TIMESTAMPING_RAW_HARDWARE (1<<6)
#endif
#ifndef SOF_TIMESTAMPING_SOFTWARE
#define SOF_TIMESTAMPING_SOFTWARE (1<<4)
#endif
#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#endif

#ifdef SAMURAI_WITH_DPDK
extern "C" {
#include <rte_ethdev.h>
#include <rte_time.h>
}
#endif

namespace samurai::l4 {

NanosecondLatencyHistogram::NanosecondLatencyHistogram() {
  samples_.reserve(10000);
}

void NanosecondLatencyHistogram::AddSample(uint64_t latency_ns) {
  std::lock_guard<std::mutex> lock(mu_);
  samples_.push_back(latency_ns);
  if (latency_ns < min_ns_) min_ns_ = latency_ns;
  if (latency_ns > max_ns_) max_ns_ = latency_ns;
  sum_ns_ += latency_ns;

  if (prev_sample_ns_ > 0) {
    const double diff = (latency_ns > prev_sample_ns_)
                            ? static_cast<double>(latency_ns - prev_sample_ns_)
                            : static_cast<double>(prev_sample_ns_ - latency_ns);
    sum_jitter_ns_ += diff;
  }
  prev_sample_ns_ = latency_ns;
}

NanosecondLatencyStats NanosecondLatencyHistogram::CalculateStats() const {
  std::lock_guard<std::mutex> lock(mu_);
  NanosecondLatencyStats stats;
  if (samples_.empty()) return stats;

  stats.samples_count = samples_.size();
  stats.min_ns = min_ns_;
  stats.max_ns = max_ns_;
  stats.avg_ns = static_cast<double>(sum_ns_) / static_cast<double>(stats.samples_count);
  if (stats.samples_count > 1) {
    stats.jitter_ns = sum_jitter_ns_ / static_cast<double>(stats.samples_count - 1);
  }

  std::vector<uint64_t> sorted = samples_;
  std::sort(sorted.begin(), sorted.end());
  const std::size_t n = sorted.size();

  auto percentile = [&](double p) -> double {
    if (n == 0) return 0.0;
    std::size_t idx = static_cast<std::size_t>(p * n);
    if (idx >= n) idx = n - 1;
    return static_cast<double>(sorted[idx]);
  };

  stats.p50_ns = percentile(0.50);
  stats.p90_ns = percentile(0.90);
  stats.p95_ns = percentile(0.95);
  stats.p99_ns = percentile(0.99);
  stats.p99_9_ns = percentile(0.999);
  return stats;
}

void NanosecondLatencyHistogram::Reset() {
  std::lock_guard<std::mutex> lock(mu_);
  samples_.clear();
  min_ns_ = UINT64_MAX;
  max_ns_ = 0;
  sum_ns_ = 0;
  prev_sample_ns_ = 0;
  sum_jitter_ns_ = 0.0;
}

bool HwTimestampEngine::EnableDpdkTimesync(uint16_t port_id) {
#ifdef SAMURAI_WITH_DPDK
  return rte_eth_timesync_enable(port_id) == 0;
#else
  (void)port_id;
  return false;
#endif
}

bool HwTimestampEngine::ReadRxTimestampDpdk(uint16_t port_id, uint64_t* out_ns) {
#ifdef SAMURAI_WITH_DPDK
  if (!out_ns) return false;
  timespec ts{};
  if (rte_eth_timesync_read_rx_timestamp(port_id, &ts, 0) == 0) {
    *out_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
    return true;
  }
#else
  (void)port_id;
  (void)out_ns;
#endif
  return false;
}

bool HwTimestampEngine::ReadTxTimestampDpdk(uint16_t port_id, uint64_t* out_ns) {
#ifdef SAMURAI_WITH_DPDK
  if (!out_ns) return false;
  timespec ts{};
  if (rte_eth_timesync_read_tx_timestamp(port_id, &ts) == 0) {
    *out_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
    return true;
  }
#else
  (void)port_id;
  (void)out_ns;
#endif
  return false;
}

bool HwTimestampEngine::EnableSocketTimestamping(int socket_fd) {
  if (socket_fd < 0) return false;
  int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_SOFTWARE;
  return setsockopt(socket_fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) == 0;
}

bool HwTimestampEngine::ExtractSocketTimestampNs(const void* cmsg_buf, size_t cmsg_len, uint64_t* out_ns) {
  if (!cmsg_buf || cmsg_len < sizeof(cmsghdr) || !out_ns) return false;
  const auto* cm = reinterpret_cast<const cmsghdr*>(cmsg_buf);
  if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMPING) {
    const auto* ts = reinterpret_cast<const timespec*>(CMSG_DATA(cm));
    // Hardware timestamp is in ts[2]
    if (ts[2].tv_sec > 0 || ts[2].tv_nsec > 0) {
      *out_ns = static_cast<uint64_t>(ts[2].tv_sec) * 1000000000ull + static_cast<uint64_t>(ts[2].tv_nsec);
      return true;
    }
    // Software fallback in ts[0]
    if (ts[0].tv_sec > 0 || ts[0].tv_nsec > 0) {
      *out_ns = static_cast<uint64_t>(ts[0].tv_sec) * 1000000000ull + static_cast<uint64_t>(ts[0].tv_nsec);
      return true;
    }
  }
  return false;
}

}  // namespace samurai::l4
