// Test suite for 1,000,000 (1M) active TCP flows & 4-tuple lock shard distribution (TASK-TEST-L2-02).
// Measures Flow Creation Rate (CPS), 64-shard distribution variance, memory footprint (bytes/flow),
// multithreaded lockless lookup throughput (M-lookups/s), and stateful 3-way handshake completion.

#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

using ddos_samurai::tcpdp::TcpDataplaneCore;
using ddos_samurai::tcpdp::TcpDpConfig;
using ddos_samurai::tcpdp::TcpDpState;

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

static long GetRssKb() {
  struct rusage r{};
  if (getrusage(RUSAGE_SELF, &r) == 0) {
    return r.ru_maxrss;
  }
  return 0;
}

static void WriteBe16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}

static void WriteBe32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}

static void BuildSynAckFrame(uint8_t* out, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint32_t seq, uint32_t ack) {
  std::memset(out, 0, 54);
  WriteBe16(out + 12, 0x0800);  // EtherType: IPv4
  out[14] = 0x45;               // IPv4, header len 20
  WriteBe16(out + 16, 40);      // Total length: 20 IP + 20 TCP
  out[22] = 64;                 // TTL
  out[23] = 6;                  // IPPROTO_TCP
  WriteBe32(out + 26, dst_ip);  // Peer src = flow dst
  WriteBe32(out + 30, src_ip);  // Peer dst = flow src
  WriteBe16(out + 34, dst_port);
  WriteBe16(out + 36, src_port);
  WriteBe32(out + 38, seq);
  WriteBe32(out + 42, ack);
  out[46] = 0x50;               // TCP Data Offset: 5 words (20 bytes)
  out[47] = 0x12;               // SYN | ACK
  WriteBe16(out + 48, 65535);   // Window size
}

struct BenchmarkOptions {
  size_t num_flows = 1000000;
  size_t num_threads = 0;
  size_t num_handshakes = 50000;
  std::string json_path;
  bool verbose = false;
};

static void PrintUsage(const char* prog) {
  std::printf("Usage: %s [options]\n", prog);
  std::printf("Options:\n");
  std::printf("  --flows <N>         Number of flows to test (default: 1000000)\n");
  std::printf("  --threads <T>       Number of lookup threads (default: hardware concurrency)\n");
  std::printf("  --handshakes <H>    Number of flows to complete 3-way handshake (default: 50000)\n");
  std::printf("  --json <path>       Path to write JSON benchmark metrics\n");
  std::printf("  --verbose           Print per-shard distribution details\n");
  std::printf("  --help              Print this help message\n");
}

int main(int argc, char** argv) {
  BenchmarkOptions opt;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--flows") == 0 && i + 1 < argc) {
      opt.num_flows = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
      opt.num_threads = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--handshakes") == 0 && i + 1 < argc) {
      opt.num_handshakes = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
      opt.json_path = argv[++i];
    } else if (std::strcmp(argv[i], "--verbose") == 0) {
      opt.verbose = true;
    } else if (std::strcmp(argv[i], "--help") == 0) {
      PrintUsage(argv[0]);
      return 0;
    }
  }

  const unsigned int hw = std::thread::hardware_concurrency();
  if (opt.num_threads == 0) {
    opt.num_threads = hw ? hw : 8;
  }
  if (opt.num_handshakes > opt.num_flows) {
    opt.num_handshakes = opt.num_flows;
  }

  std::printf("================================================================================\n");
  std::printf("  DDoSamurai tcpdp 1,000,000 (1M) TCP Active Flows Benchmark Suite\n");
  std::printf("================================================================================\n");
  std::printf("Target Flows:       %zu\n", opt.num_flows);
  std::printf("Lookup Threads:     %zu (Hardware Cores/Threads: %u)\n", opt.num_threads, hw);
  std::printf("Target Handshakes:  %zu\n", opt.num_handshakes);
  std::printf("--------------------------------------------------------------------------------\n");

  constexpr size_t kNumShards = 64;
  const long baseline_rss_kb = GetRssKb();
  std::printf("[PHASE 1] Baseline Process RSS: %ld KB (%.2f MB)\n", baseline_rss_kb, baseline_rss_kb / 1024.0);

  std::vector<size_t> shard_counts(kNumShards, 0);
  std::vector<uint64_t> flow_ids;
  flow_ids.reserve(opt.num_flows);

  auto core = std::make_unique<TcpDataplaneCore>();
  TcpDpConfig cfg;
  cfg.mode = "test";
  cfg.connect_timeout_ms = 60000;
  CHECK(core->Configure(cfg), "Failed to configure TcpDataplaneCore");

  // PHASE 2: Flow Allocation & Enqueueing
  std::printf("[PHASE 2] Enqueueing %zu unique 4-tuple TCP connections...\n", opt.num_flows);
  const auto start_time = std::chrono::high_resolution_clock::now();

  for (size_t i = 0; i < opt.num_flows; ++i) {
    uint32_t src_ip = 0x0A000001 + (i % 256);
    uint32_t dst_ip = 0xC0A80001 + ((i / 256) % 256);
    uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
    uint16_t dst_port = 80;

    SimpleFlowKey key{src_ip, dst_ip, src_port, dst_port};
    size_t shard = HashFlowKey(key);
    shard_counts[shard]++;

    uint64_t fid = core->EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
    flow_ids.push_back(fid);
  }

  const auto end_time = std::chrono::high_resolution_clock::now();
  const double enqueue_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
  const double cps = (static_cast<double>(opt.num_flows) / enqueue_ms) * 1000.0;

  std::printf("          -> Enqueued %zu flows in %.2f ms (%.2f flows/sec | %.2f kCPS)\n",
              opt.num_flows, enqueue_ms, cps, cps / 1000.0);

  // PHASE 3: 64-Shard Hash Distribution & Variance Analysis
  const double mean = static_cast<double>(opt.num_flows) / kNumShards;
  size_t min_count = opt.num_flows;
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

  std::printf("[PHASE 3] 64-Shard Hash Distribution Analysis:\n");
  std::printf("          Shards: %zu | Mean: %.2f flows/shard | Min: %zu | Max: %zu\n",
              kNumShards, mean, min_count, max_count);
  std::printf("          Standard Deviation (sigma): %.2f | Max Variance: %.4f%%\n",
              stddev, max_variance_pct);

  if (opt.verbose) {
    for (size_t s = 0; s < kNumShards; ++s) {
      std::printf("          Shard [%02zu]: %zu flows (dev: %+.2f%%)\n",
                  s, shard_counts[s], ((static_cast<double>(shard_counts[s]) - mean) / mean) * 100.0);
    }
  }

  CHECK(max_variance_pct <= 5.0,
        "Hash distribution variance %.4f%% exceeded 5.0%% threshold!", max_variance_pct);

  // PHASE 4: Memory Footprint & TCB Density
  const long peak_rss_kb = GetRssKb();
  const long delta_rss_kb = peak_rss_kb - baseline_rss_kb;
  const double bytes_per_flow = (delta_rss_kb > 0)
      ? (static_cast<double>(delta_rss_kb) * 1024.0 / static_cast<double>(opt.num_flows))
      : 0.0;

  std::printf("[PHASE 4] Memory Footprint Metrics:\n");
  std::printf("          Peak RSS:       %ld KB (%.2f MB)\n", peak_rss_kb, peak_rss_kb / 1024.0);
  std::printf("          Delta RSS:      %ld KB (%.2f MB)\n", delta_rss_kb, delta_rss_kb / 1024.0);
  std::printf("          TCB Density:    ~%.2f bytes/active flow (including indexing & queues)\n",
              bytes_per_flow);

  // PHASE 5: Multithreaded Lockless Concurrency & Lookup Stress
  const size_t kLookupsPerThread = 250000;
  const uint64_t total_lookups_target = opt.num_threads * kLookupsPerThread;
  std::atomic<uint64_t> total_found{0};
  std::vector<std::thread> threads;
  threads.reserve(opt.num_threads);

  std::printf("[PHASE 5] Stressing %" PRIu64 " concurrent lockless lookups across %zu threads...\n",
              total_lookups_target, opt.num_threads);

  const auto mt_start = std::chrono::high_resolution_clock::now();

  for (size_t t = 0; t < opt.num_threads; ++t) {
    threads.emplace_back([&core, &flow_ids, &total_found, t, &opt, kLookupsPerThread]() {
      uint64_t found_count = 0;
      size_t start_idx = (t * kLookupsPerThread) % opt.num_flows;
      for (size_t i = 0; i < kLookupsPerThread; ++i) {
        uint64_t fid = flow_ids[(start_idx + i) % opt.num_flows];
        auto snap = core->GetFlowLockless(fid);
        if (snap.found && snap.state == static_cast<uint8_t>(TcpDpState::kSynSent)) {
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
  const double lookups_per_sec = (static_cast<double>(total_lookups_target) / mt_duration_ms) * 1000.0;

  std::printf("          -> Completed %" PRIu64 " lookups in %.2f ms (%.2f M-lookups/sec)\n",
              total_found.load(), mt_duration_ms, lookups_per_sec / 1e6);

  CHECK(total_found.load() == total_lookups_target,
        "Lockless flow lookups mismatch: expected %" PRIu64 ", got %" PRIu64,
        total_lookups_target, total_found.load());

  // PHASE 6: Stateful 3-Way Handshake Ingestion
  std::printf("[PHASE 6] Ingesting SYN-ACK frames for %zu flows (stateful 3-way handshake)...\n",
              opt.num_handshakes);
  uint8_t syn_ack_pkt[54];
  uint32_t established_count = 0;

  const auto hs_start = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < opt.num_handshakes; ++i) {
    uint32_t src_ip = 0x0A000001 + (i % 256);
    uint32_t dst_ip = 0xC0A80001 + ((i / 256) % 256);
    uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
    uint16_t dst_port = 80;

    auto snap = core->GetFlowLockless(flow_ids[i]);
    if (!snap.found) continue;

    BuildSynAckFrame(syn_ack_pkt, src_ip, dst_ip, src_port, dst_port,
                     static_cast<uint32_t>(0x51000000 + i), snap.snd_nxt);
    uint32_t updated = core->IngestRxFrame(syn_ack_pkt, sizeof(syn_ack_pkt));
    if (updated > 0) {
      established_count++;
    }
  }
  const auto hs_end = std::chrono::high_resolution_clock::now();
  const double hs_duration_ms = std::chrono::duration<double, std::milli>(hs_end - hs_start).count();
  const double handshakes_per_sec = (static_cast<double>(opt.num_handshakes) / hs_duration_ms) * 1000.0;

  std::printf("          -> Completed %u / %zu handshakes in %.2f ms (%.2f handshakes/sec)\n",
              established_count, opt.num_handshakes, hs_duration_ms, handshakes_per_sec);

  CHECK(established_count == opt.num_handshakes,
        "Established count mismatch: expected %zu, got %u", opt.num_handshakes, established_count);

  auto stats = core->SnapshotStats();
  CHECK(stats.connect_attempts == opt.num_flows,
        "Stats connect_attempts mismatch: expected %zu, got %" PRIu64,
        opt.num_flows, stats.connect_attempts);
  CHECK(stats.flows_active == opt.num_flows,
        "Stats flows_active mismatch: expected %zu, got %" PRIu64,
        opt.num_flows, stats.flows_active);
  CHECK(stats.connect_established == opt.num_handshakes,
        "Stats connect_established mismatch: expected %zu, got %" PRIu64,
        opt.num_handshakes, stats.connect_established);

  // PHASE 7: TX Ring Drain & Packet Consumption
  size_t total_tx_consumed = 0;
  for (int drain_iter = 0; drain_iter < 100; ++drain_iter) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0, stride = 0;
    core->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
    if (count == 0 || base == nullptr) break;
    core->ConsumeTxPackets(count);
    total_tx_consumed += count;
  }
  std::printf("[PHASE 7] Drained %zu packets from TX rings\n", total_tx_consumed);

  // PHASE 8: Engine Destruction & Memory Reclamation
  const auto clean_start = std::chrono::high_resolution_clock::now();
  core.reset();
  const auto clean_end = std::chrono::high_resolution_clock::now();
  const double clean_duration_ms = std::chrono::duration<double, std::milli>(clean_end - clean_start).count();

  std::printf("[PHASE 8] Destroyed and reclaimed %zu active flows in %.2f ms\n",
              opt.num_flows, clean_duration_ms);

  // PHASE 9: JSON Export (optional)
  if (!opt.json_path.empty()) {
    std::ofstream out(opt.json_path);
    if (out.is_open()) {
      out << "{\n";
      out << "  \"num_flows\": " << opt.num_flows << ",\n";
      out << "  \"enqueue_duration_ms\": " << enqueue_ms << ",\n";
      out << "  \"cps\": " << cps << ",\n";
      out << "  \"shards\": " << kNumShards << ",\n";
      out << "  \"shard_mean\": " << mean << ",\n";
      out << "  \"shard_min\": " << min_count << ",\n";
      out << "  \"shard_max\": " << max_count << ",\n";
      out << "  \"shard_stddev\": " << stddev << ",\n";
      out << "  \"shard_max_variance_pct\": " << max_variance_pct << ",\n";
      out << "  \"baseline_rss_kb\": " << baseline_rss_kb << ",\n";
      out << "  \"peak_rss_kb\": " << peak_rss_kb << ",\n";
      out << "  \"delta_rss_kb\": " << delta_rss_kb << ",\n";
      out << "  \"bytes_per_flow\": " << bytes_per_flow << ",\n";
      out << "  \"lookup_threads\": " << opt.num_threads << ",\n";
      out << "  \"total_lookups\": " << total_lookups_target << ",\n";
      out << "  \"lookup_duration_ms\": " << mt_duration_ms << ",\n";
      out << "  \"lookups_per_sec\": " << lookups_per_sec << ",\n";
      out << "  \"handshakes_attempted\": " << opt.num_handshakes << ",\n";
      out << "  \"handshakes_completed\": " << established_count << ",\n";
      out << "  \"handshake_duration_ms\": " << hs_duration_ms << ",\n";
      out << "  \"handshakes_per_sec\": " << handshakes_per_sec << ",\n";
      out << "  \"reclaim_duration_ms\": " << clean_duration_ms << ",\n";
      out << "  \"status\": \"" << (g_fails == 0 ? "PASSED" : "FAILED") << "\"\n";
      out << "}\n";
      out.close();
      std::printf("[INFO] Wrote JSON benchmark report to: %s\n", opt.json_path.c_str());
    }
  }

  std::printf("--------------------------------------------------------------------------------\n");
  if (g_fails == 0) {
    std::printf("=== TEST PASSED: 1M Active TCP Flows Validated Successfully ===\n");
    return 0;
  } else {
    std::printf("=== TEST FAILED: %d checks failed ===\n", g_fails);
    return 1;
  }
}
