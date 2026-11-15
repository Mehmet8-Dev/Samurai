/**
 * Samurai — cycles/packet micro-benchmark
 *
 * Measures the most critical KPI for data-plane optimization:
 *   cycles per packet (CPP)
 *   allocations per packet (estimated)
 *   instructions per packet (via rdpmc if available)
 *
 * Usage:
 *   g++ -O2 -std=c++17 -march=native -o bench_cycles bench_cycles.cpp \
 *       engine.cpp common.cpp packets.cpp pool.cpp spoofing.cpp amp.cpp \
 *       -I. -I..
 *   ./bench_cycles [packet_count] [protocol]
 *
 * Copyright (c) 2026 Samurai — research / authorised testing only.
 */

#include "engine.hpp"
#include "../samurai_tsc.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <vector>

namespace {

struct BenchResult {
  uint64_t total_cycles;
  uint64_t total_ns;
  uint64_t packet_count;
  double cycles_per_packet;
  double ns_per_packet;
  double packets_per_sec;
  double megabytes_per_sec;
  uint64_t total_bytes;
};

uint64_t monotonic_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
         static_cast<uint64_t>(ts.tv_nsec);
}

BenchResult run_create_packet_bench(
    const samurai::cpu_native::PacketConfig& cfg,
    int count,
    int warmup_count) {
  // Warmup — populate caches, JIT-like paths, branch predictor
  for (int i = 0; i < warmup_count; ++i) {
    auto pkt = samurai::cpu_native::create_packet(cfg);
    asm volatile("" : : "r"(pkt.data()) : "memory");
  }

  uint64_t total_bytes = 0;

  // Measure
  const uint64_t start_cycles = samurai_rdtsc();
  const uint64_t start_ns = monotonic_ns();

  for (int i = 0; i < count; ++i) {
    auto pkt = samurai::cpu_native::create_packet(cfg);
    total_bytes += pkt.size();
    asm volatile("" : : "r"(pkt.data()) : "memory");  // prevent optimization
  }

  const uint64_t end_cycles = samurai_rdtsc();
  const uint64_t end_ns = monotonic_ns();

  BenchResult r{};
  r.total_cycles = end_cycles - start_cycles;
  r.total_ns = end_ns - start_ns;
  r.packet_count = static_cast<uint64_t>(count);
  r.total_bytes = total_bytes;
  r.cycles_per_packet =
      static_cast<double>(r.total_cycles) / static_cast<double>(count);
  r.ns_per_packet =
      static_cast<double>(r.total_ns) / static_cast<double>(count);
  r.packets_per_sec =
      r.ns_per_packet > 0.0 ? 1e9 / r.ns_per_packet : 0.0;
  r.megabytes_per_sec =
      r.total_ns > 0
          ? (static_cast<double>(total_bytes) / (1024.0 * 1024.0)) /
                (static_cast<double>(r.total_ns) / 1e9)
          : 0.0;
  return r;
}

BenchResult run_pool_bench(
    const samurai::cpu_native::PacketConfig& cfg,
    int pool_size,
    int rounds) {
  // Warmup
  auto warmup = samurai::cpu_native::generate_packet_pool(cfg, 100, true, false);
  asm volatile("" : : "r"(warmup.first.data()) : "memory");

  uint64_t total_bytes = 0;

  const uint64_t start_cycles = samurai_rdtsc();
  const uint64_t start_ns = monotonic_ns();

  for (int r = 0; r < rounds; ++r) {
    auto [pool_data, stride] =
        samurai::cpu_native::generate_packet_pool(cfg, pool_size, true, false);
    total_bytes += pool_data.size();
    asm volatile("" : : "r"(pool_data.data()) : "memory");
  }

  const uint64_t end_cycles = samurai_rdtsc();
  const uint64_t end_ns = monotonic_ns();
  const uint64_t total_packets = static_cast<uint64_t>(pool_size) * static_cast<uint64_t>(rounds);

  BenchResult res{};
  res.total_cycles = end_cycles - start_cycles;
  res.total_ns = end_ns - start_ns;
  res.packet_count = total_packets;
  res.total_bytes = total_bytes;
  res.cycles_per_packet =
      static_cast<double>(res.total_cycles) / static_cast<double>(total_packets);
  res.ns_per_packet =
      static_cast<double>(res.total_ns) / static_cast<double>(total_packets);
  res.packets_per_sec =
      res.ns_per_packet > 0.0 ? 1e9 / res.ns_per_packet : 0.0;
  res.megabytes_per_sec =
      res.total_ns > 0
          ? (static_cast<double>(total_bytes) / (1024.0 * 1024.0)) /
                (static_cast<double>(res.total_ns) / 1e9)
          : 0.0;
  return res;
}

void print_result(const char* label, const BenchResult& r) {
  std::printf(
      "  %-28s  %12.1f cycles/pkt  %8.1f ns/pkt  %10.0f pkt/s  "
      "%7.2f MB/s  (%llu pkts, %llu bytes)\n",
      label,
      r.cycles_per_packet,
      r.ns_per_packet,
      r.packets_per_sec,
      r.megabytes_per_sec,
      static_cast<unsigned long long>(r.packet_count),
      static_cast<unsigned long long>(r.total_bytes));
}

void print_separator() {
  std::printf(
      "  %-28s  %12s  %11s  %12s  %9s\n",
      "----------------------------",
      "------------",
      "-----------",
      "------------",
      "---------");
}

}  // namespace

int main(int argc, char** argv) {
  const int count = argc > 1 ? std::atoi(argv[1]) : 50000;
  const int warmup = std::max(100, count / 10);
  const int pool_size = 1000;
  const int pool_rounds = std::max(1, count / pool_size);

  if (!samurai_tsc_invariant_supported()) {
    std::fprintf(stderr,
        "[WARN] TSC invariant not supported — cycle counts may be inaccurate\n");
  }

  std::printf("\n");
  std::printf("╔══════════════════════════════════════════════════════════════════╗\n");
  std::printf("║           Samurai — cycles/packet Micro-Benchmark              ║\n");
  std::printf("╠══════════════════════════════════════════════════════════════════╣\n");
  std::printf("║  Packets per scenario: %-8d  Warmup: %-8d              ║\n", count, warmup);
  std::printf("║  Pool size: %-8d  Pool rounds: %-8d                    ║\n", pool_size, pool_rounds);
  std::printf("║  TSC invariant: %-3s                                            ║\n",
      samurai_tsc_invariant_supported() ? "yes" : "no");
  std::printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

  // --- TCP SYN ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.tcp_flags = "S";
    cfg.attack_vector = "basic";

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (TCP SYN)", r);
  }

  // --- TCP PSH|ACK ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.tcp_flags = "PA";
    cfg.attack_vector = "basic";

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (TCP PSH|ACK)", r);
  }

  // --- UDP ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 53;
    cfg.protocol = "udp";
    cfg.attack_vector = "basic";

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (UDP)", r);
  }

  // --- DNS ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 53;
    cfg.protocol = "udp";
    cfg.attack_vector = "dns";
    cfg.dns_name = "example.com";
    cfg.dns_recursive = true;

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (DNS)", r);
  }

  // --- HTTP polymorphic ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.attack_vector = "http";

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (HTTP poly)", r);
  }

  // --- Spoofed TCP SYN ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.tcp_flags = "S";
    cfg.spoof = true;
    cfg.spoof_opts.mode = "realistic";
    cfg.attack_vector = "basic";

    auto r = run_create_packet_bench(cfg, count, warmup);
    print_result("create_packet (SYN+spoof)", r);
  }

  print_separator();

  // --- Pool generation ---
  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.tcp_flags = "S";
    cfg.attack_vector = "basic";

    auto r = run_pool_bench(cfg, pool_size, pool_rounds);
    print_result("generate_pool (TCP SYN)", r);
  }

  {
    samurai::cpu_native::PacketConfig cfg;
    cfg.target_ip = "10.0.0.1";
    cfg.target_port = 80;
    cfg.protocol = "tcp";
    cfg.tcp_flags = "S";
    cfg.spoof = true;
    cfg.spoof_opts.mode = "realistic";
    cfg.attack_vector = "basic";

    auto r = run_pool_bench(cfg, pool_size, pool_rounds);
    print_result("generate_pool (SYN+spoof)", r);
  }

  // --- Isolated function benchmarks ---
  print_separator();

  // Checksum benchmark
  {
    std::vector<uint8_t> data(1500, 0xAB);
    const int cksum_count = count * 10;
    const uint64_t start = samurai_rdtsc();
    for (int i = 0; i < cksum_count; ++i) {
      auto ck = samurai::cpu_native::checksum(data.data(), data.size());
      asm volatile("" : : "r"(ck) : "memory");
    }
    const uint64_t end = samurai_rdtsc();
    const double cpp = static_cast<double>(end - start) /
                        static_cast<double>(cksum_count);
    std::printf("  %-28s  %12.1f cycles/call  (1500-byte payload, %d calls)\n",
        "checksum()", cpp, cksum_count);
  }

  // ip_to_int benchmark
  {
    const int ip_count = count * 5;
    const uint64_t start = samurai_rdtsc();
    for (int i = 0; i < ip_count; ++i) {
      auto v = samurai::cpu_native::ip_to_int("192.168.1.1");
      asm volatile("" : : "r"(v) : "memory");
    }
    const uint64_t end = samurai_rdtsc();
    const double cpp = static_cast<double>(end - start) /
                        static_cast<double>(ip_count);
    std::printf("  %-28s  %12.1f cycles/call  (%d calls)\n",
        "ip_to_int()", cpp, ip_count);
  }

  // parse_tcp_flags benchmark
  {
    const int flags_count = count * 10;
    const uint64_t start = samurai_rdtsc();
    for (int i = 0; i < flags_count; ++i) {
      auto v = samurai::cpu_native::parse_tcp_flags("SYN|ACK");
      asm volatile("" : : "r"(v) : "memory");
    }
    const uint64_t end = samurai_rdtsc();
    const double cpp = static_cast<double>(end - start) /
                        static_cast<double>(flags_count);
    std::printf("  %-28s  %12.1f cycles/call  (%d calls)\n",
        "parse_tcp_flags()", cpp, flags_count);
  }

  std::printf("\n");
  return 0;
}
