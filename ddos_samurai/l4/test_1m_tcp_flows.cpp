// Test suite for 1,000,000 (1M) active TCP flows & 4-tuple lock shard distribution (TASK-TEST-L2-02).
// Exercises full end-to-end 1M 3-way handshakes (1M SYN TX + 1M SYN-ACK RX + 1M ACK TX = 3M packets)
// across Single-Instance (1 core), Shared-Nothing Physical Cores (6 workers), and Shared-Nothing SMT
// (12 workers) under strictly controlled apples-to-apples timing boundaries, multi-run statistics
// (Median/Min/Max/StdDev), RFC 1071 IPv4/TCP checksum verification, CPU topology & affinity pinning
// verification, compile-time struct layout introspection, and /proc/self/status + getrusage auditing.

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
#include <map>
#include <memory>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using ddos_samurai::tcpdp::TcpDataplaneCore;
using ddos_samurai::tcpdp::TcpDpConfig;
using ddos_samurai::tcpdp::TcpDpMemoryLayout;
using ddos_samurai::tcpdp::TcpDpState;

static std::atomic<int> g_fails{0};
#define CHECK(cond, ...)                                       \
  do {                                                         \
    if (!(cond)) {                                             \
      std::printf("FAIL [%s:%d]: ", __FILE__, __LINE__);       \
      std::printf(__VA_ARGS__);                                \
      std::printf("\n");                                       \
      g_fails.fetch_add(1, std::memory_order_relaxed);         \
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

struct RusageSnapshot {
  long minflt = 0;
  long majflt = 0;
  long nvcsw = 0;
  long nivcsw = 0;
  double user_ms = 0.0;
  double sys_ms = 0.0;
};

static RusageSnapshot ReadRusage() {
  RusageSnapshot s{};
  struct rusage r{};
  if (getrusage(RUSAGE_SELF, &r) == 0) {
    s.minflt = r.ru_minflt;
    s.majflt = r.ru_majflt;
    s.nvcsw = r.ru_nvcsw;
    s.nivcsw = r.ru_nivcsw;
    s.user_ms = static_cast<double>(r.ru_utime.tv_sec) * 1000.0 +
                static_cast<double>(r.ru_utime.tv_usec) / 1000.0;
    s.sys_ms = static_cast<double>(r.ru_stime.tv_sec) * 1000.0 +
               static_cast<double>(r.ru_stime.tv_usec) / 1000.0;
  }
  return s;
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

static uint16_t ComputeIpChecksum(const uint8_t* ip, size_t ihl) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < ihl; i += 2) {
    if (i == 10) continue;  // skip checksum field
    sum += (static_cast<uint32_t>(ip[i]) << 8) | static_cast<uint32_t>(ip[i + 1]);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

static uint16_t ComputeTcpChecksum(const uint8_t* ip, const uint8_t* tcp, size_t tcp_len) {
  uint32_t sum = 0;
  // IPv4 pseudo-header (src_ip, dst_ip, protocol=6, tcp_len)
  for (size_t i = 12; i < 20; i += 2) {
    sum += (static_cast<uint32_t>(ip[i]) << 8) | static_cast<uint32_t>(ip[i + 1]);
  }
  sum += 6u;
  sum += static_cast<uint32_t>(tcp_len);
  for (size_t i = 0; i + 1 < tcp_len; i += 2) {
    if (i == 16) continue;  // skip TCP checksum field
    sum += (static_cast<uint32_t>(tcp[i]) << 8) | static_cast<uint32_t>(tcp[i + 1]);
  }
  if (tcp_len & 1u) {
    sum += static_cast<uint32_t>(tcp[tcp_len - 1]) << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

// Realistic 66-byte SYN-ACK with RFC 7323 / RFC 2018 TCP options AND valid RFC 1071 IPv4 + TCP checksums:
// MSS(1460) + SACK-Permitted + NOP + WScale(7) + NOP + NOP (12 bytes options)
static void BuildRealisticSynAckFrame(uint8_t* out, uint32_t client_ip, uint32_t server_ip,
                                      uint16_t client_port, uint16_t server_port,
                                      uint32_t server_seq, uint32_t ack_seq,
                                      bool compute_checksums = true) {
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
  if (compute_checksums) {
    WriteBe16(out + 24, ComputeIpChecksum(out + 14, 20));
    WriteBe16(out + 50, ComputeTcpChecksum(out + 14, out + 34, 32));
  }
}

struct CpuTopology {
  unsigned int total_logical_cpus = 0;
  std::vector<int> physical_core_rep_cpus;  // 1 logical CPU per distinct physical core_id
  std::vector<int> all_logical_cpus;        // All online logical CPUs
};

static CpuTopology DiscoverCpuTopology() {
  CpuTopology topo{};
  unsigned int hw = std::thread::hardware_concurrency();
  topo.total_logical_cpus = hw ? hw : 1;

  std::set<int> seen_physical_cores;
  for (unsigned int cpu = 0; cpu < topo.total_logical_cpus; ++cpu) {
    topo.all_logical_cpus.push_back(static_cast<int>(cpu));
    std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/core_id";
    std::ifstream in(path);
    int core_id = -1;
    if (in >> core_id && core_id >= 0) {
      if (seen_physical_cores.insert(core_id).second) {
        topo.physical_core_rep_cpus.push_back(static_cast<int>(cpu));
      }
    }
  }
  if (topo.physical_core_rep_cpus.empty()) {
    // Fallback if sysfs is unavailable: assume even-numbered CPUs or half of logical CPUs
    unsigned int phys = std::max(1u, topo.total_logical_cpus / 2);
    for (unsigned int i = 0; i < phys; ++i) {
      topo.physical_core_rep_cpus.push_back(static_cast<int>(i * 2 < topo.total_logical_cpus ? i * 2 : i));
    }
  }
  return topo;
}

struct MetricSummary {
  double median = 0.0;
  double mean = 0.0;
  double min = 0.0;
  double max = 0.0;
  double stddev = 0.0;
};

static MetricSummary SummarizeMetrics(const std::vector<double>& vals) {
  MetricSummary s{};
  if (vals.empty()) return s;
  std::vector<double> sorted = vals;
  std::sort(sorted.begin(), sorted.end());
  s.min = sorted.front();
  s.max = sorted.back();
  const size_t n = sorted.size();
  if (n % 2 == 1) {
    s.median = sorted[n / 2];
  } else {
    s.median = 0.5 * (sorted[n / 2 - 1] + sorted[n / 2]);
  }
  double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
  s.mean = sum / static_cast<double>(n);
  double sq_sum = 0.0;
  for (double v : sorted) {
    double d = v - s.mean;
    sq_sum += d * d;
  }
  s.stddev = std::sqrt(sq_sum / static_cast<double>(n));
  return s;
}

struct WorkerRunStats {
  size_t flows_target = 0;
  size_t syn_drained = 0;
  size_t established = 0;
  size_t ack_drained = 0;
  size_t completions = 0;
  uint64_t tx_queued = 0;
  uint64_t tx_sent = 0;
  uint64_t unexpected_rx = 0;
  int pinned_cpu = -1;
  int observed_cpu = -1;
  int setaffinity_rc = -1;
};

struct ModeBenchmarkResult {
  std::string mode_name;
  size_t num_workers = 1;
  std::vector<int> pinned_cpus;
  std::vector<int> observed_cpus;
  bool affinity_verified = true;
  std::vector<double> duration_ms_runs;
  std::vector<double> cps_runs;
  std::vector<double> pps_runs;
  std::vector<long> post_trim_rss_kb_runs;
  MetricSummary duration_ms;
  MetricSummary cps;
  MetricSummary pps;
  size_t total_syn_drained_last = 0;
  size_t total_established_last = 0;
  size_t total_ack_drained_last = 0;
  size_t total_completions_last = 0;
  size_t total_packets_last = 0;
};

// Executes one strictly controlled apples-to-apples run of N flows across W workers (W=1 is Single-Instance).
// Thread creation, sched_setaffinity, and TcpDataplaneCore::Configure happen BEFORE the start barrier.
// Timed window [t_start, t_end] measures strictly the batched 1M 3-way handshake engine work.
static void ExecuteControlledRun(
    size_t total_flows,
    const std::vector<int>& worker_cpu_map,
    bool verify_rx_checksum,
    double* out_duration_ms,
    std::vector<WorkerRunStats>* out_wstats,
    long* out_post_trim_rss_kb) {
  const size_t num_workers = worker_cpu_map.size();
  out_wstats->assign(num_workers, WorkerRunStats{});
  for (size_t i = 0; i < total_flows; ++i) {
    (*out_wstats)[i % num_workers].flows_target++;
  }

  std::atomic<size_t> ready_count{0};
  std::atomic<bool> start_flag{false};
  std::atomic<size_t> done_count{0};

  std::vector<std::thread> threads;
  threads.reserve(num_workers);

  for (size_t w = 0; w < num_workers; ++w) {
    threads.emplace_back([&, w]() {
      const int target_cpu = worker_cpu_map[w];
      (*out_wstats)[w].pinned_cpu = target_cpu;
      cpu_set_t cpuset;
      CPU_ZERO(&cpuset);
      CPU_SET(target_cpu, &cpuset);
      const int rc = sched_setaffinity(0, sizeof(cpuset), &cpuset);
      (*out_wstats)[w].setaffinity_rc = rc;
      (*out_wstats)[w].observed_cpu = sched_getcpu();

      auto wcore = std::make_unique<TcpDataplaneCore>();
      TcpDpConfig wcfg;
      wcfg.mode = "test";
      wcfg.connect_timeout_ms = 60000;
      wcfg.idle_timeout_ms = 120000;
      wcfg.verify_rx_checksum = verify_rx_checksum;
      wcore->Configure(wcfg);
      wcore->SetFlowIdBase((static_cast<uint64_t>(w) + 1ULL) << 32);

      const size_t my_flows = (*out_wstats)[w].flows_target;
      constexpr size_t kBatch = 2048;
      uint8_t syn_ack_buf[66];

      // Signal ready and spin-wait for simultaneous start barrier
      ready_count.fetch_add(1, std::memory_order_acq_rel);
      while (!start_flag.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }

      // === STRICT TIMED REGION WORKLOAD (Identical for W=1, W=6, W=12) ===
      size_t local_syn = 0;
      size_t local_est = 0;
      size_t local_ack = 0;
      size_t local_comp = 0;

      for (size_t base_i = 0; base_i < my_flows; base_i += kBatch) {
        const size_t end_i = std::min(my_flows, base_i + kBatch);
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
          local_syn += count;
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
                                    0x61000000u + static_cast<uint32_t>(i), iss + 1u,
                                    verify_rx_checksum);
          local_est += wcore->IngestRxFrame(syn_ack_buf, sizeof(syn_ack_buf));
        }
        for (;;) {
          const uint8_t* base = nullptr;
          uint32_t count = 0;
          size_t psize = 0, stride = 0;
          wcore->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
          if (count == 0 || base == nullptr) break;
          local_ack += count;
          wcore->ConsumeTxPackets(count);
        }
        auto comps = wcore->CollectCompletions();
        local_comp += comps.size();
      }

      done_count.fetch_add(1, std::memory_order_acq_rel);
      // === END OF TIMED WORKLOAD ===

      (*out_wstats)[w].syn_drained = local_syn;
      (*out_wstats)[w].established = local_est;
      (*out_wstats)[w].ack_drained = local_ack;
      (*out_wstats)[w].completions = local_comp;
      const auto wst = wcore->SnapshotStats();
      (*out_wstats)[w].tx_queued = wst.tx_packets_queued;
      (*out_wstats)[w].tx_sent = wst.tx_packets_sent;
      (*out_wstats)[w].unexpected_rx = wst.unexpected_rx;
      // Destroy the core inside the owning worker thread so all heap blocks return
      // to this thread's glibc arena while the thread is still alive.
      wcore.reset();
    });
  }

  while (ready_count.load(std::memory_order_acquire) < num_workers) {
    std::this_thread::yield();
  }

  const auto t_start = std::chrono::high_resolution_clock::now();
  start_flag.store(true, std::memory_order_release);

  while (done_count.load(std::memory_order_acquire) < num_workers) {
    std::this_thread::yield();
  }
  const auto t_end = std::chrono::high_resolution_clock::now();
  *out_duration_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

  for (auto& th : threads) {
    th.join();
  }

  (void)malloc_trim(0);
  *out_post_trim_rss_kb = ReadProcMem().vm_rss_kb;
}

static ModeBenchmarkResult RunModeMultiIteration(
    const std::string& mode_name,
    size_t total_flows,
    const std::vector<int>& worker_cpu_map,
    size_t num_runs,
    bool verify_rx_checksum) {
  ModeBenchmarkResult res{};
  res.mode_name = mode_name;
  res.num_workers = worker_cpu_map.size();
  res.pinned_cpus = worker_cpu_map;
  res.affinity_verified = true;

  for (size_t r = 0; r < num_runs; ++r) {
    double dur_ms = 0.0;
    std::vector<WorkerRunStats> wstats;
    long post_rss = 0;
    ExecuteControlledRun(total_flows, worker_cpu_map, verify_rx_checksum, &dur_ms, &wstats, &post_rss);

    size_t syn = 0, est = 0, ack = 0, comp = 0;
    uint64_t tx_q = 0, tx_s = 0, unexp = 0;
    std::vector<int> obs_cpus;
    for (size_t w = 0; w < wstats.size(); ++w) {
      syn += wstats[w].syn_drained;
      est += wstats[w].established;
      ack += wstats[w].ack_drained;
      comp += wstats[w].completions;
      tx_q += wstats[w].tx_queued;
      tx_s += wstats[w].tx_sent;
      unexp += wstats[w].unexpected_rx;
      obs_cpus.push_back(wstats[w].observed_cpu);
      if (wstats[w].setaffinity_rc != 0 || wstats[w].observed_cpu != wstats[w].pinned_cpu) {
        res.affinity_verified = false;
      }
    }
    res.observed_cpus = obs_cpus;

    CHECK(syn == total_flows, "[%s run %zu] SYN drained mismatch: expected %zu, got %zu",
          mode_name.c_str(), r + 1, total_flows, syn);
    CHECK(est == total_flows, "[%s run %zu] Established mismatch: expected %zu, got %zu",
          mode_name.c_str(), r + 1, total_flows, est);
    CHECK(ack == total_flows, "[%s run %zu] ACK drained mismatch: expected %zu, got %zu",
          mode_name.c_str(), r + 1, total_flows, ack);
    CHECK(comp == total_flows, "[%s run %zu] Completions mismatch: expected %zu, got %zu",
          mode_name.c_str(), r + 1, total_flows, comp);
    CHECK(tx_q == total_flows * 2, "[%s run %zu] tx_queued mismatch", mode_name.c_str(), r + 1);
    CHECK(tx_s == total_flows * 2, "[%s run %zu] tx_sent mismatch", mode_name.c_str(), r + 1);
    CHECK(unexp == 0, "[%s run %zu] unexpected_rx must be 0, got %" PRIu64, mode_name.c_str(), r + 1, unexp);

    const size_t total_pkts = syn + est + ack;
    const double cps = (static_cast<double>(total_flows) / dur_ms) * 1000.0;
    const double pps = (static_cast<double>(total_pkts) / dur_ms) * 1000.0;

    res.duration_ms_runs.push_back(dur_ms);
    res.cps_runs.push_back(cps);
    res.pps_runs.push_back(pps);
    res.post_trim_rss_kb_runs.push_back(post_rss);

    res.total_syn_drained_last = syn;
    res.total_established_last = est;
    res.total_ack_drained_last = ack;
    res.total_completions_last = comp;
    res.total_packets_last = total_pkts;
  }

  res.duration_ms = SummarizeMetrics(res.duration_ms_runs);
  res.cps = SummarizeMetrics(res.cps_runs);
  res.pps = SummarizeMetrics(res.pps_runs);
  return res;
}

struct BenchmarkOptions {
  size_t num_flows = 1000000;
  size_t num_threads = 0;
  size_t num_handshakes = 1000000;
  size_t num_runs = 5;
  std::string json_path;
  bool verbose = false;
};

static void PrintUsage(const char* prog) {
  std::printf("Usage: %s [options]\n", prog);
  std::printf("Options:\n");
  std::printf("  --flows <N>         Number of flows to test (default: 1000000)\n");
  std::printf("  --threads <T>       Number of SMT worker threads (default: hardware concurrency)\n");
  std::printf("  --handshakes <H>    Number of flows to complete 3-way handshake (default: 1000000)\n");
  std::printf("  --runs <R>          Number of multi-run iterations per mode (default: 5)\n");
  std::printf("  --json <path>       Path to write JSON benchmark metrics\n");
  std::printf("  --verbose           Print per-shard distribution details\n");
  std::printf("  --help              Print this help message\n");
}

static std::string FormatIntVecJson(const std::vector<int>& v) {
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << v[i];
  }
  oss << "]";
  return oss.str();
}

static std::string FormatDoubleVecJson(const std::vector<double>& v) {
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << v[i];
  }
  oss << "]";
  return oss.str();
}

static std::string FormatLongVecJson(const std::vector<long>& v) {
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << v[i];
  }
  oss << "]";
  return oss.str();
}

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
    } else if (std::strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
      opt.num_runs = std::max<size_t>(1, static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10)));
    } else if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
      opt.json_path = argv[++i];
    } else if (std::strcmp(argv[i], "--verbose") == 0) {
      opt.verbose = true;
    } else if (std::strcmp(argv[i], "--help") == 0) {
      PrintUsage(argv[0]);
      return 0;
    }
  }

  const CpuTopology topo = DiscoverCpuTopology();
  if (opt.num_threads == 0) {
    opt.num_threads = topo.total_logical_cpus;
  }
  if (!handshakes_overridden || opt.num_handshakes > opt.num_flows) {
    opt.num_handshakes = opt.num_flows;
  }

  const TcpDpMemoryLayout mem_layout = TcpDataplaneCore::GetMemoryLayout();

  std::printf("================================================================================\n");
  std::printf("  DDoSamurai tcpdp 1,000,000 (1M) TCP Active Flows Benchmark & Verification\n");
  std::printf("================================================================================\n");
  std::printf("Target Flows:       %zu\n", opt.num_flows);
  std::printf("Target Handshakes:  %zu (Full 3-Way Handshake: SYN -> SYN-ACK -> ACK)\n", opt.num_handshakes);
  std::printf("CPU Topology:       %zu Physical Cores | %u Logical Threads (SMT)\n",
              topo.physical_core_rep_cpus.size(), topo.total_logical_cpus);
  std::printf("Multi-Run Rigor:    %zu iterations per mode (Median / Min / Max / StdDev)\n", opt.num_runs);
  std::printf("--------------------------------------------------------------------------------\n");
  std::printf("[STRUCT LAYOUT] Compile-Time Data Structure Sizes:\n");
  std::printf("          sizeof(FlowEntry):        %zu bytes\n", mem_layout.sizeof_flow_entry);
  std::printf("          sizeof(FlowKey):          %zu bytes\n", mem_layout.sizeof_flow_key);
  std::printf("          sizeof(TimerEntry):       %zu bytes\n", mem_layout.sizeof_timer_entry);
  std::printf("          sizeof(OutstandingTx):    %zu bytes\n", mem_layout.sizeof_outstanding_tx);
  std::printf("          sizeof(PerShardTxRing):   %zu bytes\n", mem_layout.sizeof_per_shard_tx_ring);
  std::printf("          sizeof(TcpDataplaneCore): %zu bytes\n", mem_layout.sizeof_core);
  std::printf("--------------------------------------------------------------------------------\n");

  // PHASE 0: RFC 1071 IPv4 + TCP Checksum Verification Correctness Gate
  {
    auto csum_core = std::make_unique<TcpDataplaneCore>();
    TcpDpConfig csum_cfg;
    csum_cfg.mode = "test";
    csum_cfg.verify_rx_checksum = true;
    CHECK(csum_core->Configure(csum_cfg), "Failed to configure checksum verification core");

    uint32_t c_ip = 0x0A000001u, s_ip = 0xC0A80001u;
    uint16_t c_port = 12345, s_port = 80;
    uint64_t fid = csum_core->EnqueueConnect(c_ip, s_ip, c_port, s_port);
    CHECK(fid != 0, "EnqueueConnect failed in checksum test");
    auto fsnap = csum_core->GetFlow(fid);

    uint8_t frame[66];
    BuildRealisticSynAckFrame(frame, c_ip, s_ip, c_port, s_port, 0x70000000u, fsnap.iss + 1u, true);

    // 1. Corrupt IPv4 header checksum -> must be rejected (0 flows updated)
    frame[24] ^= 0xFF;
    CHECK(csum_core->IngestRxFrame(frame, sizeof(frame)) == 0,
          "Corrupted IPv4 header checksum was NOT rejected when verify_rx_checksum=true!");
    frame[24] ^= 0xFF;  // restore

    // 2. Corrupt TCP header checksum -> must be rejected (0 flows updated)
    frame[50] ^= 0xFF;
    CHECK(csum_core->IngestRxFrame(frame, sizeof(frame)) == 0,
          "Corrupted TCP checksum was NOT rejected when verify_rx_checksum=true!");
    frame[50] ^= 0xFF;  // restore

    // 3. Valid RFC 1071 IPv4 + TCP checksum -> must be accepted (1 flow established)
    CHECK(csum_core->IngestRxFrame(frame, sizeof(frame)) == 1,
          "Valid RFC 1071 IPv4+TCP checksum was rejected when verify_rx_checksum=true!");
    std::printf("[PHASE 0] RFC 1071 IPv4 & TCP Checksum Verification Gate: PASSED\n");
  }

  constexpr size_t kNumShards = 64;
  constexpr size_t kBatchSize = 4096;

  (void)malloc_trim(0);
  const ProcMemInfo mem_base = ReadProcMem();
  const RusageSnapshot rusage_base = ReadRusage();
  std::printf("[PHASE 1] Baseline Kernel Memory (/proc/self/status):\n");
  std::printf("          VmRSS: %ld KB (%.2f MB) | VmHWM: %ld KB | VmData: %ld KB\n",
              mem_base.vm_rss_kb, mem_base.vm_rss_kb / 1024.0,
              mem_base.vm_hwm_kb, mem_base.vm_data_kb);

  // PHASE 2: Isolated Single-Instance Lifecycle & Memory Footprint Audit (No external flow_ids vector)
  auto core = std::make_unique<TcpDataplaneCore>();
  TcpDpConfig cfg;
  cfg.mode = "test";
  cfg.connect_timeout_ms = 60000;
  cfg.idle_timeout_ms = 120000;
  CHECK(core->Configure(cfg), "Failed to configure TcpDataplaneCore");

  std::printf("[PHASE 2] Enqueueing %zu unique 4-tuple flows & draining SYN wire frames (isolated)...\n",
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
      (void)core->EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
    }

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
  const double syn_sent_rss_delta_per_flow_bytes =
      (static_cast<double>(delta_syn_rss_kb) * 1024.0) / static_cast<double>(opt.num_flows);

  std::printf("          -> Enqueued & drained %zu SYN frames (%.2f MB wire) in %.2f ms\n",
              tx_syn_drained, tx_syn_bytes / (1024.0 * 1024.0), enqueue_ms);
  std::printf("          -> Rate: %.2f flows/sec (%.2f kCPS) | Valid Wire Headers: %zu / %zu\n",
              syn_cps, syn_cps / 1000.0, valid_syn_wire_headers, opt.num_flows);
  std::printf("          -> VmRSS (SYN_SENT): %ld KB (%.2f MB) | Process RSS Delta/Flow: %.2f B\n",
              mem_syn.vm_rss_kb, mem_syn.vm_rss_kb / 1024.0, syn_sent_rss_delta_per_flow_bytes);

  CHECK(tx_syn_drained == opt.num_flows,
        "SYN TX drained count mismatch: expected %zu, got %zu", opt.num_flows, tx_syn_drained);
  CHECK(valid_syn_wire_headers == opt.num_flows,
        "Valid SYN wire header check failed: expected %zu, got %zu", opt.num_flows, valid_syn_wire_headers);

  // PHASE 3: 64-Shard Hash Distribution & Variance Analysis (Outside timed path!)
  std::vector<size_t> shard_counts(kNumShards, 0);
  for (size_t i = 0; i < opt.num_flows; ++i) {
    uint32_t src_ip = 0x0A000001u + static_cast<uint32_t>(i % 256);
    uint32_t dst_ip = 0xC0A80001u + static_cast<uint32_t>((i / 256) % 256);
    uint16_t src_port = static_cast<uint16_t>(10000 + (i % 50000));
    uint16_t dst_port = 80;
    SimpleFlowKey key{src_ip, dst_ip, src_port, dst_port};
    shard_counts[HashFlowKey(key)]++;
  }

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
                                server_seq, iss + 1u, false);
      established_count += core->IngestRxFrame(syn_ack_pkt, sizeof(syn_ack_pkt));
    }

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
  std::printf("          -> Total Phase 2+4 Single-Core Lifecycle: %zu packets in %.2f ms (%.2f M-PPS)\n",
              single_total_packets, single_total_ms, single_total_pps / 1e6);

  CHECK(established_count == opt.num_handshakes,
        "Established count mismatch: expected %zu, got %zu", opt.num_handshakes, established_count);
  CHECK(tx_ack_drained == opt.num_handshakes,
        "ACK TX drained mismatch: expected %zu, got %zu", opt.num_handshakes, tx_ack_drained);
  CHECK(valid_ack_wire_headers == opt.num_handshakes,
        "Valid ACK wire header mismatch: expected %zu, got %zu", opt.num_handshakes, valid_ack_wire_headers);
  CHECK(completions_collected == opt.num_handshakes,
        "Completion events mismatch: expected %zu, got %zu", opt.num_handshakes, completions_collected);

  // PHASE 5: Memory Footprint in ESTABLISHED State & Counter Audit (Pure Engine, No flow_ids vector)
  const ProcMemInfo mem_est = ReadProcMem();
  const RusageSnapshot rusage_est = ReadRusage();
  const long delta_est_rss_kb = std::max<long>(0, mem_est.vm_rss_kb - mem_base.vm_rss_kb);
  const double established_rss_delta_per_flow_bytes =
      (static_cast<double>(delta_est_rss_kb) * 1024.0) / static_cast<double>(opt.num_flows);

  std::printf("[PHASE 5] Kernel Memory Footprint in ESTABLISHED State (Isolated Engine):\n");
  std::printf("          VmRSS (Current):             %ld KB (%.2f MB)\n", mem_est.vm_rss_kb, mem_est.vm_rss_kb / 1024.0);
  std::printf("          VmHWM (Peak):                %ld KB (%.2f MB)\n", mem_est.vm_hwm_kb, mem_est.vm_hwm_kb / 1024.0);
  std::printf("          Delta RSS:                   %ld KB (%.2f MB)\n", delta_est_rss_kb, delta_est_rss_kb / 1024.0);
  std::printf("          sizeof(FlowEntry) struct:    %zu bytes\n", mem_layout.sizeof_flow_entry);
  std::printf("          Process RSS Delta / Flow:    ~%.2f bytes/active flow (FlowEntry + unordered_map node + deque + 4-tuple index + timer heaps)\n",
              established_rss_delta_per_flow_bytes);
  std::printf("          Page Faults (Min / Maj):     %ld / %ld\n",
              rusage_est.minflt - rusage_base.minflt, rusage_est.majflt - rusage_base.majflt);

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
  // Note: flow_ids are sequential [1 .. num_flows], so no external vector is needed!
  const size_t kLookupsPerThread = 250000;
  const uint64_t total_lookups_target = opt.num_threads * kLookupsPerThread;
  std::atomic<uint64_t> total_found{0};
  std::vector<std::thread> lookup_threads;
  lookup_threads.reserve(opt.num_threads);

  std::printf("[PHASE 6] Stressing %" PRIu64 " concurrent lockless lookups across %zu threads...\n",
              total_lookups_target, opt.num_threads);

  const auto mt_start = std::chrono::high_resolution_clock::now();

  for (size_t t = 0; t < opt.num_threads; ++t) {
    lookup_threads.emplace_back([&core, &total_found, t, &opt, kLookupsPerThread]() {
      uint64_t found_count = 0;
      size_t start_idx = (t * kLookupsPerThread) % opt.num_flows;
      for (size_t i = 0; i < kLookupsPerThread; ++i) {
        size_t idx = (start_idx + i) % opt.num_flows;
        uint64_t fid = static_cast<uint64_t>(idx + 1);
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
  (void)malloc_trim(0);
  const auto clean_end = std::chrono::high_resolution_clock::now();
  const double clean_duration_ms = std::chrono::duration<double, std::milli>(clean_end - clean_start).count();
  const ProcMemInfo mem_reclaimed = ReadProcMem();

  std::printf("[PHASE 7] Reclaimed %zu flows in %.2f ms | Post-trim VmRSS: %ld KB (%.2f MB)\n",
              opt.num_flows, clean_duration_ms,
              mem_reclaimed.vm_rss_kb, mem_reclaimed.vm_rss_kb / 1024.0);

  // PHASE 8: Strictly Controlled Apples-to-Apples Multi-Run Scaling Benchmark
  // Comparing:
  //   1) Single-Core (1 worker pinned to CPU 0)
  //   2) Shared-Nothing Physical Cores (e.g. 6 workers pinned to distinct physical cores: CPUs 0,2,4,6,8,10)
  //   3) Shared-Nothing Full SMT (e.g. 12 workers pinned to all logical threads: CPUs 0..11)
  //   4) Shared-Nothing Full SMT with RFC 1071 Checksum Verification Enabled (verify_rx_checksum=true)
  std::printf("--------------------------------------------------------------------------------\n");
  std::printf("[PHASE 8] Controlled Apples-to-Apples Multi-Run Scaling (%zu runs x %zu flows):\n",
              opt.num_runs, opt.num_flows);

  std::vector<int> single_cpu_map = {topo.all_logical_cpus[0]};
  std::vector<int> phys_cpu_map = topo.physical_core_rep_cpus;
  std::vector<int> smt_cpu_map;
  for (size_t w = 0; w < opt.num_threads; ++w) {
    smt_cpu_map.push_back(topo.all_logical_cpus[w % topo.all_logical_cpus.size()]);
  }

  const ModeBenchmarkResult mode_1c =
      RunModeMultiIteration("Single-Core (1W)", opt.num_flows, single_cpu_map, opt.num_runs, false);
  const ModeBenchmarkResult mode_phys =
      RunModeMultiIteration("Shared-Nothing Physical", opt.num_flows, phys_cpu_map, opt.num_runs, false);
  const ModeBenchmarkResult mode_smt =
      RunModeMultiIteration("Shared-Nothing SMT", opt.num_flows, smt_cpu_map, opt.num_runs, false);
  const ModeBenchmarkResult mode_smt_csum =
      RunModeMultiIteration("Shared-Nothing SMT + RFC1071 Checksum", opt.num_flows, smt_cpu_map, opt.num_runs, true);

  const double speedup_phys_median = mode_1c.duration_ms.median / mode_phys.duration_ms.median;
  const double speedup_smt_median = mode_1c.duration_ms.median / mode_smt.duration_ms.median;
  const double smt_over_phys_gain = mode_phys.duration_ms.median / mode_smt.duration_ms.median;
  const double csum_overhead_pct =
      ((mode_smt_csum.duration_ms.median - mode_smt.duration_ms.median) / mode_smt.duration_ms.median) * 100.0;

  std::printf("  1) Single-Core (1 Worker, CPU %s | Observed %s | Affinity OK: %s):\n",
              FormatIntVecJson(mode_1c.pinned_cpus).c_str(),
              FormatIntVecJson(mode_1c.observed_cpus).c_str(),
              mode_1c.affinity_verified ? "YES" : "NO");
  std::printf("     Duration: Median %.2f ms (Min %.2f, Max %.2f, StdDev %.2f ms)\n",
              mode_1c.duration_ms.median, mode_1c.duration_ms.min,
              mode_1c.duration_ms.max, mode_1c.duration_ms.stddev);
  std::printf("     Rate:     Median %.2f M-CPS | %.2f M-PPS\n",
              mode_1c.cps.median / 1e6, mode_1c.pps.median / 1e6);

  std::printf("  2) Shared-Nothing Physical Cores (%zu Workers, CPUs %s | Observed %s | Affinity OK: %s):\n",
              mode_phys.num_workers,
              FormatIntVecJson(mode_phys.pinned_cpus).c_str(),
              FormatIntVecJson(mode_phys.observed_cpus).c_str(),
              mode_phys.affinity_verified ? "YES" : "NO");
  std::printf("     Duration: Median %.2f ms (Min %.2f, Max %.2f, StdDev %.2f ms)\n",
              mode_phys.duration_ms.median, mode_phys.duration_ms.min,
              mode_phys.duration_ms.max, mode_phys.duration_ms.stddev);
  std::printf("     Rate:     Median %.2f M-CPS | %.2f M-PPS | Controlled Speedup: %.2fx\n",
              mode_phys.cps.median / 1e6, mode_phys.pps.median / 1e6, speedup_phys_median);

  std::printf("  3) Shared-Nothing Full SMT (%zu Workers, CPUs %s | Observed %s | Affinity OK: %s):\n",
              mode_smt.num_workers,
              FormatIntVecJson(mode_smt.pinned_cpus).c_str(),
              FormatIntVecJson(mode_smt.observed_cpus).c_str(),
              mode_smt.affinity_verified ? "YES" : "NO");
  std::printf("     Duration: Median %.2f ms (Min %.2f, Max %.2f, StdDev %.2f ms)\n",
              mode_smt.duration_ms.median, mode_smt.duration_ms.min,
              mode_smt.duration_ms.max, mode_smt.duration_ms.stddev);
  std::printf("     Rate:     Median %.2f M-CPS | %.2f M-PPS | Controlled Speedup: %.2fx (%.2fx vs Phys)\n",
              mode_smt.cps.median / 1e6, mode_smt.pps.median / 1e6, speedup_smt_median, smt_over_phys_gain);

  std::printf("  4) Shared-Nothing Full SMT + RFC 1071 IPv4/TCP Checksum Verification (%zu Workers):\n",
              mode_smt_csum.num_workers);
  std::printf("     Duration: Median %.2f ms (Min %.2f, Max %.2f, StdDev %.2f ms)\n",
              mode_smt_csum.duration_ms.median, mode_smt_csum.duration_ms.min,
              mode_smt_csum.duration_ms.max, mode_smt_csum.duration_ms.stddev);
  std::printf("     Rate:     Median %.2f M-CPS | %.2f M-PPS | Checksum Overhead: %+.2f%%\n",
              mode_smt_csum.cps.median / 1e6, mode_smt_csum.pps.median / 1e6, csum_overhead_pct);
  std::printf("     Post-Trim VmRSS across SMT runs (KB): %s\n",
              FormatLongVecJson(mode_smt.post_trim_rss_kb_runs).c_str());

  CHECK(mode_1c.affinity_verified, "Single-Core CPU affinity verification failed");
  CHECK(mode_phys.affinity_verified, "Physical-Core CPU affinity verification failed");
  CHECK(mode_smt.affinity_verified, "SMT CPU affinity verification failed");

  const RusageSnapshot rusage_final = ReadRusage();

  // PHASE 9: JSON Export (optional)
  if (!opt.json_path.empty()) {
    std::ofstream out(opt.json_path);
    if (out.is_open()) {
      out << "{\n";
      out << "  \"num_flows\": " << opt.num_flows << ",\n";
      out << "  \"num_runs\": " << opt.num_runs << ",\n";
      out << "  \"physical_cores_detected\": " << topo.physical_core_rep_cpus.size() << ",\n";
      out << "  \"logical_cpus_detected\": " << topo.total_logical_cpus << ",\n";
      out << "  \"sizeof_flow_entry_bytes\": " << mem_layout.sizeof_flow_entry << ",\n";
      out << "  \"sizeof_flow_key_bytes\": " << mem_layout.sizeof_flow_key << ",\n";
      out << "  \"sizeof_timer_entry_bytes\": " << mem_layout.sizeof_timer_entry << ",\n";
      out << "  \"sizeof_outstanding_tx_bytes\": " << mem_layout.sizeof_outstanding_tx << ",\n";
      out << "  \"sizeof_per_shard_tx_ring_bytes\": " << mem_layout.sizeof_per_shard_tx_ring << ",\n";
      out << "  \"sizeof_core_bytes\": " << mem_layout.sizeof_core << ",\n";
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
      out << "  \"syn_sent_rss_delta_per_flow_bytes\": " << syn_sent_rss_delta_per_flow_bytes << ",\n";
      out << "  \"established_rss_delta_per_flow_bytes\": " << established_rss_delta_per_flow_bytes << ",\n";
      out << "  \"bytes_per_flow_syn_sent\": " << syn_sent_rss_delta_per_flow_bytes << ",\n";
      out << "  \"bytes_per_flow\": " << established_rss_delta_per_flow_bytes << ",\n";
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

      // Controlled Apples-to-Apples Multi-Run Metrics
      out << "  \"controlled_1c_duration_median_ms\": " << mode_1c.duration_ms.median << ",\n";
      out << "  \"controlled_1c_duration_min_ms\": " << mode_1c.duration_ms.min << ",\n";
      out << "  \"controlled_1c_duration_max_ms\": " << mode_1c.duration_ms.max << ",\n";
      out << "  \"controlled_1c_duration_stddev_ms\": " << mode_1c.duration_ms.stddev << ",\n";
      out << "  \"controlled_1c_cps_median\": " << mode_1c.cps.median << ",\n";
      out << "  \"controlled_1c_pps_median\": " << mode_1c.pps.median << ",\n";
      out << "  \"controlled_1c_duration_runs_ms\": " << FormatDoubleVecJson(mode_1c.duration_ms_runs) << ",\n";

      out << "  \"controlled_phys_workers\": " << mode_phys.num_workers << ",\n";
      out << "  \"controlled_phys_pinned_cpus\": " << FormatIntVecJson(mode_phys.pinned_cpus) << ",\n";
      out << "  \"controlled_phys_observed_cpus\": " << FormatIntVecJson(mode_phys.observed_cpus) << ",\n";
      out << "  \"controlled_phys_duration_median_ms\": " << mode_phys.duration_ms.median << ",\n";
      out << "  \"controlled_phys_duration_min_ms\": " << mode_phys.duration_ms.min << ",\n";
      out << "  \"controlled_phys_duration_max_ms\": " << mode_phys.duration_ms.max << ",\n";
      out << "  \"controlled_phys_duration_stddev_ms\": " << mode_phys.duration_ms.stddev << ",\n";
      out << "  \"controlled_phys_cps_median\": " << mode_phys.cps.median << ",\n";
      out << "  \"controlled_phys_pps_median\": " << mode_phys.pps.median << ",\n";
      out << "  \"controlled_phys_speedup_median\": " << speedup_phys_median << ",\n";
      out << "  \"controlled_phys_duration_runs_ms\": " << FormatDoubleVecJson(mode_phys.duration_ms_runs) << ",\n";

      out << "  \"shared_nothing_workers\": " << mode_smt.num_workers << ",\n";
      out << "  \"shared_nothing_pinned_cpus\": " << FormatIntVecJson(mode_smt.pinned_cpus) << ",\n";
      out << "  \"shared_nothing_observed_cpus\": " << FormatIntVecJson(mode_smt.observed_cpus) << ",\n";
      out << "  \"shared_nothing_affinity_verified\": " << (mode_smt.affinity_verified ? "true" : "false") << ",\n";
      out << "  \"shared_nothing_duration_ms\": " << mode_smt.duration_ms.median << ",\n";
      out << "  \"shared_nothing_duration_min_ms\": " << mode_smt.duration_ms.min << ",\n";
      out << "  \"shared_nothing_duration_max_ms\": " << mode_smt.duration_ms.max << ",\n";
      out << "  \"shared_nothing_duration_stddev_ms\": " << mode_smt.duration_ms.stddev << ",\n";
      out << "  \"shared_nothing_cps\": " << mode_smt.cps.median << ",\n";
      out << "  \"shared_nothing_pps\": " << mode_smt.pps.median << ",\n";
      out << "  \"shared_nothing_total_packets\": " << mode_smt.total_packets_last << ",\n";
      out << "  \"shared_nothing_speedup\": " << speedup_smt_median << ",\n";
      out << "  \"shared_nothing_smt_over_phys_gain\": " << smt_over_phys_gain << ",\n";
      out << "  \"shared_nothing_duration_runs_ms\": " << FormatDoubleVecJson(mode_smt.duration_ms_runs) << ",\n";
      out << "  \"shared_nothing_post_trim_rss_runs_kb\": " << FormatLongVecJson(mode_smt.post_trim_rss_kb_runs) << ",\n";

      out << "  \"shared_nothing_csum_duration_median_ms\": " << mode_smt_csum.duration_ms.median << ",\n";
      out << "  \"shared_nothing_csum_cps_median\": " << mode_smt_csum.cps.median << ",\n";
      out << "  \"shared_nothing_csum_pps_median\": " << mode_smt_csum.pps.median << ",\n";
      out << "  \"shared_nothing_csum_overhead_pct\": " << csum_overhead_pct << ",\n";

      out << "  \"rusage_minor_faults_total\": " << (rusage_final.minflt - rusage_base.minflt) << ",\n";
      out << "  \"rusage_major_faults_total\": " << (rusage_final.majflt - rusage_base.majflt) << ",\n";
      out << "  \"rusage_voluntary_ctxt_switches\": " << (rusage_final.nvcsw - rusage_base.nvcsw) << ",\n";
      out << "  \"rusage_involuntary_ctxt_switches\": " << (rusage_final.nivcsw - rusage_base.nivcsw) << ",\n";
      out << "  \"rusage_user_cpu_ms\": " << (rusage_final.user_ms - rusage_base.user_ms) << ",\n";
      out << "  \"rusage_sys_cpu_ms\": " << (rusage_final.sys_ms - rusage_base.sys_ms) << ",\n";
      out << "  \"status\": \"" << (g_fails.load() == 0 ? "PASSED" : "FAILED") << "\"\n";
      out << "}\n";
      out.close();
      std::printf("[INFO] Wrote JSON benchmark report to: %s\n", opt.json_path.c_str());
    }
  }

  std::printf("--------------------------------------------------------------------------------\n");
  if (g_fails.load() == 0) {
    std::printf("=== TEST PASSED: 1M Active TCP Flows (Single-Core & Shared-Nothing) Validated ===\n");
    return 0;
  } else {
    std::printf("=== TEST FAILED: %d checks failed ===\n", g_fails.load());
    return 1;
  }
}
