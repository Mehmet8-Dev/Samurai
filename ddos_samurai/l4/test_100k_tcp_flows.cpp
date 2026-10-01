// Test suite for 100,000 active TCP flows & 4-tuple lock shard distribution (TASK-TEST-L2-01).
// Verifies 64-shard hash distribution variance <= 5% and concurrent multithreaded performance.

#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <thread>
#include <vector>

using ddos_samurai::tcpdp::TcpDataplaneCore;
using ddos_samurai::tcpdp::TcpDpConfig;

static int g_fails = 0;
#define CHECK(cond, ...)                                       \
  do {                                                         \
    if (!(cond)) {                                             \
      std::printf("FAIL [%s:%d]: ", __FILE__, __LINE__);       \
      std::printf(__VA_ARGS__);                                \
      std::printf("\n");                                       \
      g_fails++;                                               \
    }                                                          \
  } while (0)

struct SimpleFlowKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
};

static size_t HashFlowKey(const SimpleFlowKey& key) {
  uint64_t h = static_cast<uint64_t>(key.src_ip);
  h ^= (static_cast<uint64_t>(key.dst_ip) << 1);
  h ^= (static_cast<uint64_t>(key.src_port) << 33);
  h ^= (static_cast<uint64_t>(key.dst_port) << 49);
  return static_cast<size_t>(h ^ (h >> 32)) % 64;
}

int main() {
  std::printf("=== TASK-TEST-L2-01: 100K TCP Flow Hash Distribution & Concurrency Test ===\n");

  constexpr size_t kNumFlows = 100000;
  constexpr size_t kNumShards = 64;

  // 1. Hash Distribution Verification
  std::vector<size_t> shard_counts(kNumShards, 0);
  std::vector<uint64_t> flow_ids;
  flow_ids.reserve(kNumFlows);

  TcpDataplaneCore core;
  TcpDpConfig cfg;
  cfg.mode = "test";
  CHECK(core.Configure(cfg), "Failed to configure TcpDataplaneCore");

  const auto start_time = std::chrono::high_resolution_clock::now();

  for (size_t i = 0; i < kNumFlows; ++i) {
    uint32_t src_ip = 0x0A000001 + (i % 256);
    uint32_t dst_ip = 0xC0A80001 + ((i / 256) % 256);
    uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
    uint16_t dst_port = 80;

    SimpleFlowKey key{src_ip, dst_ip, src_port, dst_port};
    size_t shard = HashFlowKey(key);
    shard_counts[shard]++;

    uint64_t fid = core.EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
    flow_ids.push_back(fid);
  }

  const auto end_time = std::chrono::high_resolution_clock::now();
  const double duration_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

  std::printf("[INFO] Enqueued %zu flows in %.2f ms (%.2f flows/sec)\n",
              kNumFlows, duration_ms, (kNumFlows / duration_ms) * 1000.0);

  // Calculate mean, min, max, stddev, and max percentage variance
  const double mean = static_cast<double>(kNumFlows) / kNumShards;
  size_t min_count = kNumFlows;
  size_t max_count = 0;
  double sq_sum = 0.0;

  for (size_t s = 0; s < kNumShards; ++s) {
    if (shard_counts[s] < min_count) min_count = shard_counts[s];
    if (shard_counts[s] > max_count) max_count = shard_counts[s];
    double diff = static_cast<double>(shard_counts[s]) - mean;
    sq_sum += diff * diff;
  }

  const double stddev = std::sqrt(sq_sum / kNumShards);
  const double max_dev = std::max(std::abs(static_cast<double>(max_count) - mean),
                                  std::abs(static_cast<double>(min_count) - mean));
  const double max_variance_pct = (max_dev / mean) * 100.0;

  std::printf("[STATS] Shards: %zu, Mean: %.2f flows/shard\n", kNumShards, mean);
  std::printf("[STATS] Min: %zu, Max: %zu, StdDev: %.2f\n", min_count, max_count, stddev);
  std::printf("[STATS] Max Variance from Mean: %.2f%%\n", max_variance_pct);

  CHECK(max_variance_pct <= 5.0,
        "4-tuple hash distribution variance %.2f%% exceeds 5.0%% threshold!", max_variance_pct);

  // 2. Multithreaded Lock Shard Concurrency & Lookup Stress
  constexpr size_t kNumThreads = 8;
  constexpr size_t kLookupsPerThread = 50000;
  std::atomic<uint64_t> total_found{0};
  std::vector<std::thread> threads;

  const auto mt_start = std::chrono::high_resolution_clock::now();

  for (size_t t = 0; t < kNumThreads; ++t) {
    threads.emplace_back([&core, &flow_ids, &total_found, t]() {
      uint64_t found_count = 0;
      size_t start_idx = (t * kLookupsPerThread) % kNumFlows;
      for (size_t i = 0; i < kLookupsPerThread; ++i) {
        uint64_t fid = flow_ids[(start_idx + i) % kNumFlows];
        auto snap = core.GetFlowLockless(fid);
        if (snap.found) {
          found_count++;
        }
      }
      total_found.fetch_add(found_count, std::memory_order_relaxed);
    });
  }

  for (auto& th : threads) {
    th.join();
  }

  const auto mt_end = std::chrono::high_resolution_clock::now();
  const double mt_duration_ms = std::chrono::duration<double, std::milli>(mt_end - mt_start).count();

  const uint64_t expected_total = kNumThreads * kLookupsPerThread;
  std::printf("[INFO] Completed %" PRIu64 " lockless flow lookups across %zu threads in %.2f ms (%.2f lookups/sec)\n",
              total_found.load(), kNumThreads, mt_duration_ms, (expected_total / mt_duration_ms) * 1000.0);

  CHECK(total_found.load() == expected_total,
        "Lockless flow lookups mismatch: expected %" PRIu64 ", got %" PRIu64, expected_total, total_found.load());

  auto stats = core.SnapshotStats();
  CHECK(stats.connect_attempts == kNumFlows,
        "Stats connect_attempts mismatch: expected %zu, got %" PRIu64, kNumFlows, stats.connect_attempts);

  if (g_fails == 0) {
    std::printf("=== TEST PASSED: 100K Flow 64-Shard Hash Distribution & Multithreaded Concurrency Validated ===\n");
    return 0;
  } else {
    std::printf("=== TEST FAILED: %d checks failed ===\n", g_fails);
    return 1;
  }
}
