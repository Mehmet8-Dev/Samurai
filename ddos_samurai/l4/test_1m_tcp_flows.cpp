// Test suite for 1,000,000 (1M) active TCP flows & 4-tuple lock shard distribution (TASK-TEST-L2-02).
// Exercises full end-to-end 1M 3-way handshakes (1M SYN TX + 1M SYN-ACK RX + 1M ACK TX = 3M packets)
// across both Single-Instance (64-shard intra-core) and Shared-Nothing Multi-Core architectures,
// with live /proc/self/status kernel memory accounting (VmRSS, VmHWM, VmData) and malloc_trim reclamation.

#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>
#include <malloc.h>
#include <sched.h>
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
#include <sstream>
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

struct ProcMemInfo {
  long vm_rss_kb = 0;
  long vm_hwm_kb = 0;
  long vm_data_kb = 0;
};

static ProcMemInfo ReadProcMem() {
  ProcMemInfo info{};
  std::ifstream in("/proc/self/status");
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      std::istringstream iss(line.substr(6));
      iss >> info.vm_rss_kb;
    } else if (line.rfind("VmHWM:", 0) == 0) {
      std::istringstream iss(line.substr(6));
      iss >> info.vm_hwm_kb;
    } else if (line.rfind("VmData:", 0) == 0) {
      std::istringstream iss(line.substr(7));
      iss >> info.vm_data_kb;
    }
  }
  if (info.vm_rss_kb == 0) {
    struct rusage r{};
    if (getrusage(RUSAGE_SELF, &r) == 0) {
      info.vm_rss_kb = r.ru_maxrss;
      info.vm_hwm_kb = r.ru_maxrss;
    }
  }
  return info;
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

static uint16_t ReadBe16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

static uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

// Realistic 66-byte SYN-ACK with RFC 7323 / RFC 2018 TCP options:
// MSS(1460) + SACK-Permitted + NOP + WScale(7) + NOP + NOP (12 bytes options)
static void BuildRealisticSynAckFrame(uint8_t* out, uint32_t client_ip, uint32_t server_ip,
                                      uint16_t client_port, uint16_t server_port,
                                      uint32_t server_seq, uint32_t ack_seq) {
  std::memset(out, 0, 66);
  WriteBe16(out + 12, 0x0800);  // EtherType: IPv4
  out[14] = 0x45;               // IPv4, IHL=5 (20 bytes)
  WriteBe16(out + 16, 52);      // Total length: 20 IP + 32 TCP
  out[22] = 64;                 // TTL
  out[23] = 6;                  // IPPROTO_TCP
  WriteBe32(out + 26, server_ip);
  WriteBe32(out + 30, client_ip);
  WriteBe16(out + 34, server_port);
  WriteBe16(out + 36, client_port);
  WriteBe32(out + 38, server_seq);
  WriteBe32(out + 42, ack_seq);
  out[46] = 0x80;               // TCP Data Offset: 8 words (32 bytes = 20 hdr + 12 opts)
  out[47] = 0x12;               // Flags: SYN | ACK
  WriteBe16(out + 48, 65535);   // Window size
  // TCP Options at offset 54 (12 bytes):
  out[54] = 2; out[55] = 4; WriteBe16(out + 56, 1460);  // MSS = 1460
  out[58] = 4; out[59] = 2;                             // SACK-Permitted
  out[60] = 1;                                          // NOP
  out[61] = 3; out[62] = 3; out[63] = 7;                // WScale = 7
  out[64] = 1; out[65] = 1;                             // NOP, NOP
}

struct BenchmarkOptions {
  size_t num_flows = 1000000;
  size_t num_threads = 0;
  size_t num_handshakes = 1000000;
  std::string json_path;
  bool verbose = false;
};

static void PrintUsage(const char* prog) {
  std::printf("Usage: %s [options]\n", prog);
  std::printf("Options:\n");
  std::printf("  --flows <N>         Number of flows to test (default: 1000000)\n");
  std::printf("  --threads <T>       Number of worker threads (default: hardware concurrency)\n");
  std::printf("  --handshakes <H>    Number of flows to complete 3-way handshake (default: 1000000)\n");
  std::printf("  --json <path>       Path to write JSON benchmark metrics\n");
  std::printf("  --verbose           Print per-shard distribution details\n");
  std::printf("  --help              Print this help message\n");
}

struct SharedNothingWorkerStats {
  size_t flows_target = 0;
  size_t syn_drained = 0;
  size_t established = 0;
  size_t ack_drained = 0;
  size_t completions = 0;
  uint64_t tx_queued = 0;
  uint64_t tx_sent = 0;
  uint64_t unexpected_rx = 0;
  int observed_cpu = -1;
};

int main(int argc, char** argv) {
  BenchmarkOptions opt;
  bool handshakes_overridden = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--flows") == 0 && i + 1 < argc) {
      opt.num_flows = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
      opt.num_threads = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--handshakes") == 0 && i + 1 < argc) {
      opt.num_handshakes = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
      handshakes_overridden = true;
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
  if (!handshakes_overridden || opt.num_handshakes > opt.num_flows) {
    opt.num_handshakes = opt.num_flows;
  }

  std::printf("================================================================================\n");
  std::printf("  DDoSamurai tcpdp 1,000,000 (1M) TCP Active Flows Benchmark & Verification\n");
  std::printf("================================================================================\n");
  std::printf("Target Flows:       %zu\n", opt.num_flows);
  std::printf("Target Handshakes:  %zu (Full 3-Way Handshake: SYN -> SYN-ACK -> ACK)\n", opt.num_handshakes);
  std::printf("Worker Threads:     %zu (Hardware Cores/Threads: %u)\n", opt.num_threads, hw);
  std::printf("--------------------------------------------------------------------------------\n");

  constexpr size_t kNumShards = 64;
  constexpr size_t kBatchSize = 4096;

  const ProcMemInfo mem_base = ReadProcMem();
  std::printf("[PHASE 1] Baseline Kernel Memory (/proc/self/status):\n");
  std::printf("          VmRSS: %ld KB (%.2f MB) | VmHWM: %ld KB | VmData: %ld KB\n",
              mem_base.vm_rss_kb, mem_base.vm_rss_kb / 1024.0,
              mem_base.vm_hwm_kb, mem_base.vm_data_kb);

  std::vector<size_t> shard_counts(kNumShards, 0);
  std::vector<uint64_t> flow_ids(opt.num_flows, 0);

  auto core = std::make_unique<TcpDataplaneCore>();
  TcpDpConfig cfg;
  cfg.mode = "test";
  cfg.connect_timeout_ms = 60000;
  cfg.idle_timeout_ms = 120000;
  CHECK(core->Configure(cfg), "Failed to configure TcpDataplaneCore");

  // PHASE 2: Flow Allocation, SYN Enqueueing & Zero-Drop TX Wire Ring Drain
  std::printf("[PHASE 2] Enqueueing %zu unique 4-tuple flows & draining SYN wire frames...\n",
              opt.num_flows);
  size_t tx_syn_drained = 0;
  size_t tx_syn_bytes = 0;
  size_t valid_syn_wire_headers = 0;

  const auto syn_start = std::chrono::high_resolution_clock::now();

  for (size_t base_i = 0; base_i < opt.num_flows; base_i += kBatchSize) {
    const size_t end_i = std::min(opt.num_flows, base_i + kBatchSize);
    for (size_t i = base_i; i < end_i; ++i) {
      uint32_t src_ip = 0x0A000001u + static_cast<uint32_t>(i % 256);
      uint32_t dst_ip = 0xC0A80001u + static_cast<uint32_t>((i / 256) % 256);
      uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
      uint16_t dst_port = 80;

      SimpleFlowKey key{src_ip, dst_ip, src_port, dst_port};
      shard_counts[HashFlowKey(key)]++;

      flow_ids[i] = core->EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
    }

    // Drain emitted SYN packets from the strided TX ring before ring overflow
    for (;;) {
      const uint8_t* base = nullptr;
      uint32_t count = 0;
      size_t psize = 0, stride = 0;
      core->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
      if (count == 0 || base == nullptr) break;
      for (uint32_t k = 0; k < count; ++k) {
        const uint8_t* pkt = base + static_cast<size_t>(k) * stride;
        tx_syn_drained++;
        tx_syn_bytes += psize;
        if (psize >= 66 && ReadBe16(pkt + 12) == 0x0800 && pkt[14] == 0x45 &&
            pkt[23] == 6 && pkt[47] == 0x02 && ReadBe16(pkt + 36) == 80) {
          valid_syn_wire_headers++;
        }
      }
      core->ConsumeTxPackets(count);
    }
  }

  const auto syn_end = std::chrono::high_resolution_clock::now();
  const double enqueue_ms = std::chrono::duration<double, std::milli>(syn_end - syn_start).count();
  const double syn_cps = (static_cast<double>(opt.num_flows) / enqueue_ms) * 1000.0;

  const ProcMemInfo mem_syn = ReadProcMem();
  const long delta_syn_rss_kb = std::max<long>(0, mem_syn.vm_rss_kb - mem_base.vm_rss_kb);
  const double bytes_per_flow_syn =
      (static_cast<double>(delta_syn_rss_kb) * 1024.0) / static_cast<double>(opt.num_flows);

  std::printf("          -> Enqueued & drained %zu SYN frames (%.2f MB wire) in %.2f ms\n",
              tx_syn_drained, tx_syn_bytes / (1024.0 * 1024.0), enqueue_ms);
  std::printf("          -> Rate: %.2f flows/sec (%.2f kCPS) | Valid Wire Headers: %zu / %zu\n",
              syn_cps, syn_cps / 1000.0, valid_syn_wire_headers, opt.num_flows);
  std::printf("          -> VmRSS (SYN_SENT): %ld KB (%.2f MB) | Delta: %.2f MB (~%.2f B/flow)\n",
              mem_syn.vm_rss_kb, mem_syn.vm_rss_kb / 1024.0,
              delta_syn_rss_kb / 1024.0, bytes_per_flow_syn);

  CHECK(tx_syn_drained == opt.num_flows,
        "SYN TX drained count mismatch: expected %zu, got %zu", opt.num_flows, tx_syn_drained);
  CHECK(valid_syn_wire_headers == opt.num_flows,
        "Valid SYN wire header check failed: expected %zu, got %zu", opt.num_flows, valid_syn_wire_headers);

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

  std::printf("[PHASE 3] 64-Shard 4-Tuple Hash Distribution Analysis:\n");
  std::printf("          Shards: %zu | Mean: %.2f flows/shard | Min: %zu | Max: %zu\n",
              kNumShards, mean, min_count, max_count);
  std::printf("          Standard Deviation (sigma): %.2f | Max Variance: %.4f%%\n",
              stddev, max_variance_pct);

  if (opt.verbose) {
    for (size_t s = 0; s < kNumShards; ++s) {
      std::printf("          Shard [%02zu]: %zu flows (dev: %+.4f%%)\n",
                  s, shard_counts[s], ((static_cast<double>(shard_counts[s]) - mean) / mean) * 100.0);
    }
  }

  CHECK(max_variance_pct <= 5.0,
        "Hash distribution variance %.4f%% exceeded 5.0%% threshold!", max_variance_pct);

  // PHASE 4: Full Stateful 3-Way Handshake Completion (SYN-ACK Ingest + ACK Drain)
  std::printf("[PHASE 4] Ingesting %zu realistic 66B SYN-ACK frames & draining ACK frames...\n",
              opt.num_handshakes);
  uint8_t syn_ack_pkt[66];
  size_t established_count = 0;
  size_t tx_ack_drained = 0;
  size_t tx_ack_bytes = 0;
  size_t valid_ack_wire_headers = 0;
  size_t completions_collected = 0;

  const auto hs_start = std::chrono::high_resolution_clock::now();

  for (size_t base_i = 0; base_i < opt.num_handshakes; base_i += kBatchSize) {
    const size_t end_i = std::min(opt.num_handshakes, base_i + kBatchSize);
    for (size_t i = base_i; i < end_i; ++i) {
      uint32_t src_ip = 0x0A000001u + static_cast<uint32_t>(i % 256);
      uint32_t dst_ip = 0xC0A80001u + static_cast<uint32_t>((i / 256) % 256);
      uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
      uint16_t dst_port = 80;
      uint32_t iss = 0x10203040u + static_cast<uint32_t>(i) * 0x01010101u;
      uint32_t server_seq = 0x51000000u + static_cast<uint32_t>(i);

      BuildRealisticSynAckFrame(syn_ack_pkt, src_ip, dst_ip, src_port, dst_port,
                                server_seq, iss + 1u);
      established_count += core->IngestRxFrame(syn_ack_pkt, sizeof(syn_ack_pkt));
    }

    // Drain emitted third-leg ACK frames from TX ring
    for (;;) {
      const uint8_t* base = nullptr;
      uint32_t count = 0;
      size_t psize = 0, stride = 0;
      core->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
      if (count == 0 || base == nullptr) break;
      for (uint32_t k = 0; k < count; ++k) {
        const uint8_t* pkt = base + static_cast<size_t>(k) * stride;
        tx_ack_drained++;
        tx_ack_bytes += psize;
        if (psize == 54 && ReadBe16(pkt + 12) == 0x0800 && pkt[14] == 0x45 &&
            pkt[23] == 6 && pkt[47] == 0x10 && ReadBe16(pkt + 36) == 80) {
          valid_ack_wire_headers++;
        }
      }
      core->ConsumeTxPackets(count);
    }

    auto comps = core->CollectCompletions();
    completions_collected += comps.size();
  }

  const auto hs_end = std::chrono::high_resolution_clock::now();
  const double hs_duration_ms = std::chrono::duration<double, std::milli>(hs_end - hs_start).count();
  const double handshakes_per_sec = (static_cast<double>(opt.num_handshakes) / hs_duration_ms) * 1000.0;
  const double single_total_ms = enqueue_ms + hs_duration_ms;
  const size_t single_total_packets = tx_syn_drained + established_count + tx_ack_drained;
  const double single_total_pps = (static_cast<double>(single_total_packets) / single_total_ms) * 1000.0;

  std::printf("          -> Completed %zu / %zu handshakes in %.2f ms (%.2f M-handshakes/sec)\n",
              established_count, opt.num_handshakes, hs_duration_ms, handshakes_per_sec / 1e6);
  std::printf("          -> Emitted & drained %zu ACK frames (%.2f MB wire) | Completions: %zu\n",
              tx_ack_drained, tx_ack_bytes / (1024.0 * 1024.0), completions_collected);
  std::printf("          -> Total Single-Core Lifecycle: %zu packets in %.2f ms (%.2f M-PPS)\n",
              single_total_packets, single_total_ms, single_total_pps / 1e6);

  CHECK(established_count == opt.num_handshakes,
        "Established count mismatch: expected %zu, got %zu", opt.num_handshakes, established_count);
  CHECK(tx_ack_drained == opt.num_handshakes,
        "ACK TX drained mismatch: expected %zu, got %zu", opt.num_handshakes, tx_ack_drained);
  CHECK(valid_ack_wire_headers == opt.num_handshakes,
        "Valid ACK wire header mismatch: expected %zu, got %zu", opt.num_handshakes, valid_ack_wire_headers);
  CHECK(completions_collected == opt.num_handshakes,
        "Completion events mismatch: expected %zu, got %zu", opt.num_handshakes, completions_collected);

  // PHASE 5: Memory Footprint in ESTABLISHED State & Counter Audit
  const ProcMemInfo mem_est = ReadProcMem();
  const long delta_est_rss_kb = std::max<long>(0, mem_est.vm_rss_kb - mem_base.vm_rss_kb);
  const double bytes_per_flow_est =
      (static_cast<double>(delta_est_rss_kb) * 1024.0) / static_cast<double>(opt.num_flows);

  std::printf("[PHASE 5] Kernel Memory Footprint in ESTABLISHED State:\n");
  std::printf("          VmRSS (Current): %ld KB (%.2f MB)\n", mem_est.vm_rss_kb, mem_est.vm_rss_kb / 1024.0);
  std::printf("          VmHWM (Peak):    %ld KB (%.2f MB)\n", mem_est.vm_hwm_kb, mem_est.vm_hwm_kb / 1024.0);
  std::printf("          Delta RSS:       %ld KB (%.2f MB)\n", delta_est_rss_kb, delta_est_rss_kb / 1024.0);
  std::printf("          TCB Density:     ~%.2f bytes/active flow (TCB + 4-tuple index + timer heaps)\n",
              bytes_per_flow_est);

  const auto stats = core->SnapshotStats();
  const uint64_t expected_tx_pkts = opt.num_flows + opt.num_handshakes;
  CHECK(stats.connect_attempts == opt.num_flows,
        "Stats connect_attempts mismatch: expected %zu, got %" PRIu64, opt.num_flows, stats.connect_attempts);
  CHECK(stats.flows_active == opt.num_flows,
        "Stats flows_active mismatch: expected %zu, got %" PRIu64, opt.num_flows, stats.flows_active);
  CHECK(stats.connect_established == opt.num_handshakes,
        "Stats connect_established mismatch: expected %zu, got %" PRIu64, opt.num_handshakes, stats.connect_established);
  CHECK(stats.rx_frames == opt.num_handshakes,
        "Stats rx_frames mismatch: expected %zu, got %" PRIu64, opt.num_handshakes, stats.rx_frames);
  CHECK(stats.unexpected_rx == 0,
        "Stats unexpected_rx must be 0, got %" PRIu64, stats.unexpected_rx);
  CHECK(stats.tx_packets_queued == expected_tx_pkts,
        "Stats tx_packets_queued mismatch: expected %" PRIu64 ", got %" PRIu64, expected_tx_pkts, stats.tx_packets_queued);
  CHECK(stats.tx_packets_sent == expected_tx_pkts,
        "Stats tx_packets_sent mismatch: expected %" PRIu64 ", got %" PRIu64, expected_tx_pkts, stats.tx_packets_sent);

  // PHASE 6: Multithreaded Lockless Concurrency & Option Negotiation Stress
  const size_t kLookupsPerThread = 250000;
  const uint64_t total_lookups_target = opt.num_threads * kLookupsPerThread;
  std::atomic<uint64_t> total_found{0};
  std::vector<std::thread> lookup_threads;
  lookup_threads.reserve(opt.num_threads);

  std::printf("[PHASE 6] Stressing %" PRIu64 " concurrent lockless lookups across %zu threads...\n",
              total_lookups_target, opt.num_threads);

  const auto mt_start = std::chrono::high_resolution_clock::now();

  for (size_t t = 0; t < opt.num_threads; ++t) {
    lookup_threads.emplace_back([&core, &flow_ids, &total_found, t, &opt, kLookupsPerThread]() {
      uint64_t found_count = 0;
      size_t start_idx = (t * kLookupsPerThread) % opt.num_flows;
      for (size_t i = 0; i < kLookupsPerThread; ++i) {
        size_t idx = (start_idx + i) % opt.num_flows;
        uint64_t fid = flow_ids[idx];
        auto snap = core->GetFlowLockless(fid);
        const uint8_t expected_state = (idx < opt.num_handshakes)
            ? static_cast<uint8_t>(TcpDpState::kEstablished)
            : static_cast<uint8_t>(TcpDpState::kSynSent);
        if (snap.found && snap.state == expected_state) {
          if (idx >= opt.num_handshakes ||
              (snap.sack_permitted && snap.rcv_wscale == 7 && snap.mss == 1460)) {
            found_count++;
          }
        }
      }
      total_found.fetch_add(found_count, std::memory_order_relaxed);
    });
  }

  for (auto& th : lookup_threads) {
    th.join();
  }

  const auto mt_end = std::chrono::high_resolution_clock::now();
  const double mt_duration_ms = std::chrono::duration<double, std::milli>(mt_end - mt_start).count();
  const double lookups_per_sec = (static_cast<double>(total_lookups_target) / mt_duration_ms) * 1000.0;

  std::printf("          -> Completed %" PRIu64 " verified lookups in %.2f ms (%.2f M-lookups/sec)\n",
              total_found.load(), mt_duration_ms, lookups_per_sec / 1e6);

  CHECK(total_found.load() == total_lookups_target,
        "Lockless flow lookups mismatch: expected %" PRIu64 ", got %" PRIu64,
        total_lookups_target, total_found.load());

  // PHASE 7: Single-Instance Destruction & OS Page Reclamation
  const auto clean_start = std::chrono::high_resolution_clock::now();
  core.reset();
  flow_ids.clear();
  flow_ids.shrink_to_fit();
  (void)malloc_trim(0);
  const auto clean_end = std::chrono::high_resolution_clock::now();
  const double clean_duration_ms = std::chrono::duration<double, std::milli>(clean_end - clean_start).count();
  const ProcMemInfo mem_reclaimed = ReadProcMem();

  std::printf("[PHASE 7] Reclaimed %zu flows in %.2f ms | Post-trim VmRSS: %ld KB (%.2f MB)\n",
              opt.num_flows, clean_duration_ms,
              mem_reclaimed.vm_rss_kb, mem_reclaimed.vm_rss_kb / 1024.0);

  // PHASE 8: Shared-Nothing Multi-Core 1M Full Handshake Benchmark
  std::printf("[PHASE 8] Shared-Nothing Multi-Core Benchmark (%zu pinned workers, %zu flows)...\n",
              opt.num_threads, opt.num_flows);

  std::vector<SharedNothingWorkerStats> wstats(opt.num_threads);
  std::vector<std::unique_ptr<TcpDataplaneCore>> sn_cores(opt.num_threads);
  for (size_t i = 0; i < opt.num_flows; ++i) {
    wstats[i % opt.num_threads].flows_target++;
  }

  std::vector<std::thread> sn_threads;
  sn_threads.reserve(opt.num_threads);

  const auto sn_start = std::chrono::high_resolution_clock::now();

  for (size_t w = 0; w < opt.num_threads; ++w) {
    sn_threads.emplace_back([w, hw, &wstats, &sn_cores]() {
      if (hw > 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(static_cast<int>(w % hw), &cpuset);
        (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
      }
      wstats[w].observed_cpu = sched_getcpu();

      auto wcore = std::make_unique<TcpDataplaneCore>();
      TcpDpConfig wcfg;
      wcfg.mode = "test";
      wcfg.connect_timeout_ms = 60000;
      wcfg.idle_timeout_ms = 120000;
      wcore->Configure(wcfg);
      wcore->SetFlowIdBase((static_cast<uint64_t>(w) + 1ULL) << 32);

      const size_t my_flows = wstats[w].flows_target;
      constexpr size_t kWorkerBatch = 2048;
      uint8_t syn_ack_buf[66];

      for (size_t base_i = 0; base_i < my_flows; base_i += kWorkerBatch) {
        const size_t end_i = std::min(my_flows, base_i + kWorkerBatch);
        for (size_t i = base_i; i < end_i; ++i) {
          uint32_t src_ip = (0x0A000000u | (static_cast<uint32_t>(w + 1) << 16)) +
                            static_cast<uint32_t>(i % 256);
          uint32_t dst_ip = 0xC0A80001u + static_cast<uint32_t>((i / 256) % 256);
          uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
          uint16_t dst_port = 80;
          (void)wcore->EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
        }
        for (;;) {
          const uint8_t* base = nullptr;
          uint32_t count = 0;
          size_t psize = 0, stride = 0;
          wcore->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
          if (count == 0 || base == nullptr) break;
          wstats[w].syn_drained += count;
          wcore->ConsumeTxPackets(count);
        }
        for (size_t i = base_i; i < end_i; ++i) {
          uint32_t src_ip = (0x0A000000u | (static_cast<uint32_t>(w + 1) << 16)) +
                            static_cast<uint32_t>(i % 256);
          uint32_t dst_ip = 0xC0A80001u + static_cast<uint32_t>((i / 256) % 256);
          uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
          uint16_t dst_port = 80;
          uint32_t iss = 0x10203040u + static_cast<uint32_t>(i) * 0x01010101u;
          BuildRealisticSynAckFrame(syn_ack_buf, src_ip, dst_ip, src_port, dst_port,
                                    0x61000000u + static_cast<uint32_t>(i), iss + 1u);
          wstats[w].established += wcore->IngestRxFrame(syn_ack_buf, sizeof(syn_ack_buf));
        }
        for (;;) {
          const uint8_t* base = nullptr;
          uint32_t count = 0;
          size_t psize = 0, stride = 0;
          wcore->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
          if (count == 0 || base == nullptr) break;
          wstats[w].ack_drained += count;
          wcore->ConsumeTxPackets(count);
        }
        auto comps = wcore->CollectCompletions();
        wstats[w].completions += comps.size();
      }

      const auto wst = wcore->SnapshotStats();
      wstats[w].tx_queued = wst.tx_packets_queued;
      wstats[w].tx_sent = wst.tx_packets_sent;
      wstats[w].unexpected_rx = wst.unexpected_rx;
      sn_cores[w] = std::move(wcore);
    });
  }

  for (auto& t : sn_threads) {
    t.join();
  }

  const auto sn_end = std::chrono::high_resolution_clock::now();
  const double sn_duration_ms = std::chrono::duration<double, std::milli>(sn_end - sn_start).count();

  size_t sn_syn = 0, sn_est = 0, sn_ack = 0, sn_comp = 0;
  uint64_t sn_tx_queued = 0, sn_tx_sent = 0, sn_unexp_rx = 0;
  for (size_t w = 0; w < opt.num_threads; ++w) {
    sn_syn += wstats[w].syn_drained;
    sn_est += wstats[w].established;
    sn_ack += wstats[w].ack_drained;
    sn_comp += wstats[w].completions;
    sn_tx_queued += wstats[w].tx_queued;
    sn_tx_sent += wstats[w].tx_sent;
    sn_unexp_rx += wstats[w].unexpected_rx;
  }

  const size_t sn_total_packets = sn_syn + sn_est + sn_ack;
  const double sn_cps = (static_cast<double>(opt.num_flows) / sn_duration_ms) * 1000.0;
  const double sn_pps = (static_cast<double>(sn_total_packets) / sn_duration_ms) * 1000.0;
  const double sn_speedup = single_total_ms / sn_duration_ms;

  std::printf("          -> Shared-Nothing Completed %zu 3-Way Handshakes in %.2f ms\n",
              sn_est, sn_duration_ms);
  std::printf("          -> Rate: %.2f flows/sec (%.2f M-CPS) | %.2f packets/sec (%.2f M-PPS)\n",
              sn_cps, sn_cps / 1e6, sn_pps, sn_pps / 1e6);
  std::printf("          -> Multi-Core Speedup vs Single-Instance: %.2fx\n", sn_speedup);

  CHECK(sn_syn == opt.num_flows, "SN SYN drained mismatch: expected %zu, got %zu", opt.num_flows, sn_syn);
  CHECK(sn_est == opt.num_flows, "SN established mismatch: expected %zu, got %zu", opt.num_flows, sn_est);
  CHECK(sn_ack == opt.num_flows, "SN ACK drained mismatch: expected %zu, got %zu", opt.num_flows, sn_ack);
  CHECK(sn_comp == opt.num_flows, "SN completions mismatch: expected %zu, got %zu", opt.num_flows, sn_comp);
  CHECK(sn_tx_queued == opt.num_flows * 2, "SN tx_queued mismatch");
  CHECK(sn_tx_sent == opt.num_flows * 2, "SN tx_sent mismatch");
  CHECK(sn_unexp_rx == 0, "SN unexpected_rx must be 0, got %" PRIu64, sn_unexp_rx);

  sn_cores.clear();
  (void)malloc_trim(0);

  // PHASE 9: JSON Export (optional)
  if (!opt.json_path.empty()) {
    std::ofstream out(opt.json_path);
    if (out.is_open()) {
      out << "{\n";
      out << "  \"num_flows\": " << opt.num_flows << ",\n";
      out << "  \"enqueue_duration_ms\": " << enqueue_ms << ",\n";
      out << "  \"cps\": " << syn_cps << ",\n";
      out << "  \"tx_syn_drained\": " << tx_syn_drained << ",\n";
      out << "  \"tx_syn_bytes\": " << tx_syn_bytes << ",\n";
      out << "  \"shards\": " << kNumShards << ",\n";
      out << "  \"shard_mean\": " << mean << ",\n";
      out << "  \"shard_min\": " << min_count << ",\n";
      out << "  \"shard_max\": " << max_count << ",\n";
      out << "  \"shard_stddev\": " << stddev << ",\n";
      out << "  \"shard_max_variance_pct\": " << max_variance_pct << ",\n";
      out << "  \"baseline_rss_kb\": " << mem_base.vm_rss_kb << ",\n";
      out << "  \"syn_sent_rss_kb\": " << mem_syn.vm_rss_kb << ",\n";
      out << "  \"peak_rss_kb\": " << mem_est.vm_hwm_kb << ",\n";
      out << "  \"established_rss_kb\": " << mem_est.vm_rss_kb << ",\n";
      out << "  \"delta_rss_kb\": " << delta_est_rss_kb << ",\n";
      out << "  \"post_reclaim_rss_kb\": " << mem_reclaimed.vm_rss_kb << ",\n";
      out << "  \"bytes_per_flow_syn_sent\": " << bytes_per_flow_syn << ",\n";
      out << "  \"bytes_per_flow\": " << bytes_per_flow_est << ",\n";
      out << "  \"lookup_threads\": " << opt.num_threads << ",\n";
      out << "  \"total_lookups\": " << total_lookups_target << ",\n";
      out << "  \"lookup_duration_ms\": " << mt_duration_ms << ",\n";
      out << "  \"lookups_per_sec\": " << lookups_per_sec << ",\n";
      out << "  \"handshakes_attempted\": " << opt.num_handshakes << ",\n";
      out << "  \"handshakes_completed\": " << established_count << ",\n";
      out << "  \"tx_ack_drained\": " << tx_ack_drained << ",\n";
      out << "  \"tx_ack_bytes\": " << tx_ack_bytes << ",\n";
      out << "  \"completions_collected\": " << completions_collected << ",\n";
      out << "  \"handshake_duration_ms\": " << hs_duration_ms << ",\n";
      out << "  \"handshakes_per_sec\": " << handshakes_per_sec << ",\n";
      out << "  \"single_total_ms\": " << single_total_ms << ",\n";
      out << "  \"single_total_packets\": " << single_total_packets << ",\n";
      out << "  \"single_total_pps\": " << single_total_pps << ",\n";
      out << "  \"reclaim_duration_ms\": " << clean_duration_ms << ",\n";
      out << "  \"shared_nothing_workers\": " << opt.num_threads << ",\n";
      out << "  \"shared_nothing_duration_ms\": " << sn_duration_ms << ",\n";
      out << "  \"shared_nothing_cps\": " << sn_cps << ",\n";
      out << "  \"shared_nothing_pps\": " << sn_pps << ",\n";
      out << "  \"shared_nothing_total_packets\": " << sn_total_packets << ",\n";
      out << "  \"shared_nothing_speedup\": " << sn_speedup << ",\n";
      out << "  \"status\": \"" << (g_fails == 0 ? "PASSED" : "FAILED") << "\"\n";
      out << "}\n";
      out.close();
      std::printf("[INFO] Wrote JSON benchmark report to: %s\n", opt.json_path.c_str());
    }
  }

  std::printf("--------------------------------------------------------------------------------\n");
  if (g_fails == 0) {
    std::printf("=== TEST PASSED: 1M Active TCP Flows (Single-Core & Shared-Nothing) Validated ===\n");
    return 0;
  } else {
    std::printf("=== TEST FAILED: %d checks failed ===\n", g_fails);
    return 1;
  }
}
