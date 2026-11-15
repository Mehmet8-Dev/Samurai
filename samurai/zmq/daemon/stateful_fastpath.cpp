#include "stateful_fastpath.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <sched.h>
#include <pthread.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "../../l4/tcp_dataplane_ffi.h"
#include "../../l4/tcp_dataplane_core.hpp"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#define SAMURAI_CPU_RELAX() _mm_pause()
#elif defined(__aarch64__)
#define SAMURAI_CPU_RELAX() __asm__ volatile("yield")
#else
#define SAMURAI_CPU_RELAX() do {} while (0)
#endif

namespace samurai::daemon {
namespace {

constexpr std::uint16_t kFrameStride = 2048;  // tek RX slot boyutu

struct PumpScratch {
  bool direct_mbuf = false;
  std::vector<std::uint8_t> rxbuf;
  std::vector<std::uint16_t> rxlens;
  std::vector<void*> rx_mbufs;

  PumpScratch(const FastpathTxRxShim& shim, std::uint16_t rx_budget)
      : direct_mbuf(shim.SupportsDirectMbufBurst()) {
    const std::size_t budget = std::max<std::size_t>(1, rx_budget);
    if (direct_mbuf) {
      rx_mbufs.resize(budget, nullptr);
    } else {
      rxbuf.resize(static_cast<std::size_t>(kFrameStride) * budget);
      rxlens.resize(budget);
    }
  }
};

struct FfiCoreAdapter {
  void IngestRxFrame(const std::uint8_t* frame, std::size_t len) const {
    std::uint32_t updated = 0;
    (void)tcpdp_ingest_rx_frame(frame, len, &updated);
  }
  void IngestDpdkRxBurst(void** mbufs, std::uint16_t count) const {
    std::uint32_t ingested = 0;
    (void)tcpdp_ingest_dpdk_rx_burst(mbufs, count, &ingested);
  }
  std::uint32_t Poll(std::uint64_t now_ns, std::uint32_t budget) const {
    std::uint32_t actions = 0;
    (void)tcpdp_poll(now_ns, budget, &actions);
    return actions;
  }
  bool PeekTxStrided(std::uint32_t max_pkts, const std::uint8_t** base,
                     std::uint32_t* count, std::size_t* psize,
                     std::size_t* stride) const {
    return tcpdp_peek_tx_packets_strided(max_pkts, base, count, psize, stride) == 0;
  }
  void ConsumeTx(std::uint32_t count) const {
    std::uint32_t consumed = 0;
    (void)tcpdp_consume_tx_packets(count, &consumed);
  }
};

struct DirectCoreAdapter {
  samurai::tcpdp::TcpDataplaneCore& core;
  void IngestRxFrame(const std::uint8_t* frame, std::size_t len) const {
    (void)core.IngestRxFrame(frame, len);
  }
  void IngestDpdkRxBurst(void** mbufs, std::uint16_t count) const {
    (void)core.IngestDpdkRxBurst(mbufs, count);
  }
  std::uint32_t Poll(std::uint64_t now_ns, std::uint32_t budget) const {
    return core.Poll(now_ns, budget);
  }
  bool PeekTxStrided(std::uint32_t max_pkts, const std::uint8_t** base,
                     std::uint32_t* count, std::size_t* psize,
                     std::size_t* stride) const {
    return core.PeekTxPacketsStrided(max_pkts, base, count, psize, stride);
  }
  void ConsumeTx(std::uint32_t count) const {
    (void)core.ConsumeTxPackets(count);
  }
};

// Tek RX->Poll->TX döngü adımı (FFI ve sharded core tarafından paylaşılır).
template <typename CoreOps>
bool PumpDataplaneStep(const CoreOps& ops, FastpathTxRxShim& shim,
                       PumpScratch& scratch, std::uint16_t rx_budget,
                       std::uint64_t now_ns, std::string& err,
                       FastpathResult& out) {
  bool did_work = false;
  if (shim.RxAvailable()) {
    if (scratch.direct_mbuf) {
      std::uint64_t rx_bytes = 0;
      const int n = shim.RecvRawMbufs(scratch.rx_mbufs.data(), rx_budget, rx_bytes, err);
      if (n > 0) {
        ops.IngestDpdkRxBurst(scratch.rx_mbufs.data(), static_cast<std::uint16_t>(n));
        out.rx_frames += static_cast<std::uint64_t>(n);
        did_work = true;
      }
    } else {
      const int n = shim.Recv(scratch.rxbuf.data(), kFrameStride,
                              scratch.rxlens.data(), rx_budget, err);
      if (n > 0) {
        for (int i = 0; i < n; ++i) {
          ops.IngestRxFrame(
              scratch.rxbuf.data() + static_cast<std::size_t>(i) * kFrameStride,
              scratch.rxlens[static_cast<std::size_t>(i)]);
        }
        out.rx_frames += static_cast<std::uint64_t>(n);
        did_work = true;
      }
    }
  }

  if (ops.Poll(now_ns, 1024) > 0) {
    did_work = true;
  }

  for (int guard = 0; guard < 16; ++guard) {
    const std::uint8_t* base = nullptr;
    std::uint32_t count = 0;
    std::size_t psize = 0;
    std::size_t stride = 0;
    if (!ops.PeekTxStrided(0, &base, &count, &psize, &stride)) break;
    if (base == nullptr || count == 0 || psize == 0) break;
    const int sent = shim.Send(base, psize, stride, count, err);
    if (sent < 0) {
      out.tx_errors += count;
      ops.ConsumeTx(count);
      break;
    }
    if (sent == 0) break;
    ops.ConsumeTx(static_cast<std::uint32_t>(sent));
    out.tx_packets += static_cast<std::uint64_t>(sent);
    out.tx_bytes += static_cast<std::uint64_t>(sent) * static_cast<std::uint64_t>(psize);
    did_work = true;
    if (static_cast<std::uint32_t>(sent) < count) break;
  }
  return did_work;
}

bool IsFastpathBusyPoll() {
  static const bool enabled = []() {
    const char* e = std::getenv("SAMURAI_FASTPATH_BUSY_POLL");
    return e != nullptr && (std::strcmp(e, "1") == 0 || std::strcmp(e, "true") == 0);
  }();
  return enabled;
}

std::uint32_t EnvU32(const char* name, std::uint32_t fallback) {
  const char* v = std::getenv(name);
  if (v == nullptr || *v == '\0') return fallback;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(v, &end, 10);
  if (end == v) return fallback;
  return static_cast<std::uint32_t>(parsed);
}

// "a.b.c.d" -> host byte order u32. Başarıda true.
bool ParseIpv4Host(const std::string& text, std::uint32_t* out) {
  if (text.empty() || out == nullptr) return false;
  in_addr addr{};
  if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return false;
  *out = ntohl(addr.s_addr);
  return true;
}

// Kaynak IP çözümü: env override, aksi halde hedefe route'lanan yerel IP
// (UDP connect + getsockname), aksi halde 10.0.0.1 fallback. engine.cpp'deki
// custom_tcp_src_ip ile aynı mantık (paylaşımsız, sürücü kendi başına yeter).
std::uint32_t ResolveSrcIp(std::uint32_t dst_ip, std::uint16_t dst_port) {
  std::uint32_t src_ip = 0;
  const char* env_src = std::getenv("SAMURAI_CUSTOM_TCP_SRC_IP");
  if (env_src != nullptr && ParseIpv4Host(env_src, &src_ip)) {
    return src_ip;
  }
  if (dst_ip != 0) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
      sockaddr_in dst{};
      dst.sin_family = AF_INET;
      dst.sin_port = htons(dst_port == 0 ? 1 : dst_port);
      dst.sin_addr.s_addr = htonl(dst_ip);
      if (::connect(fd, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == 0) {
        sockaddr_in src{};
        socklen_t len = sizeof(src);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&src), &len) == 0) {
          const std::uint32_t route_src = ntohl(src.sin_addr.s_addr);
          if (route_src != 0U) {
            ::close(fd);
            return route_src;
          }
        }
      }
      ::close(fd);
    }
  }
  return (10U << 24U) | 1U;  // 10.0.0.1
}

std::string EnvStr(const char* name, const std::string& fallback) {
  const char* v = std::getenv(name);
  return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

}  // namespace

bool IsStatefulFastpathJob(const samurai::wire::JobEnvelopeV1& base) {
  const std::string proto(base.protocol, strnlen(base.protocol, sizeof(base.protocol)));
  const std::string av(base.attack_vector, strnlen(base.attack_vector, sizeof(base.attack_vector)));
  return proto == "custom_tcp" || proto == "stateful" ||
         av == "stateful" || av == "l7_custom_tcp";
}

FastpathParams FastpathParamsFromEnvelope(const samurai::wire::JobEnvelopeV1& base) {
  FastpathParams p;
  const std::string target(base.target_ip, strnlen(base.target_ip, sizeof(base.target_ip)));
  ParseIpv4Host(target, &p.dst_ip);
  p.dst_port = base.target_port;
  p.src_ip = ResolveSrcIp(p.dst_ip, p.dst_port);
  p.target_flows = std::max<std::uint32_t>(1u, base.packet_count);
  // tcpdp knob'ları: env fallback'li (engine.cpp configure_custom_tcp_bridge ile uyumlu).
  p.mode = EnvStr("SAMURAI_CUSTOM_TCP_MODE", "required");
  p.initial_rto_ms = EnvU32("SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS", 200);
  p.max_retransmits = EnvU32("SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS", 5);
  p.connect_timeout_ms = EnvU32("SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS", 3000);
  p.idle_timeout_ms = EnvU32("SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS", 10000);
  p.max_duration_ms = EnvU32("SAMURAI_FASTPATH_MAX_DURATION_MS", 15000);
  p.drain_ms = EnvU32("SAMURAI_FASTPATH_DRAIN_MS", 500);
  return p;
}

bool StatefulFastpathDriver::Configure(const FastpathParams& p, std::string& err) {
  tcpdp_config_t config{};
  config.mode = p.mode.c_str();
  config.backend = p.backend.c_str();
  config.initial_rto_ms = p.initial_rto_ms;
  config.max_retransmits = p.max_retransmits;
  config.connect_timeout_ms = p.connect_timeout_ms;
  config.idle_timeout_ms = p.idle_timeout_ms;
  if (tcpdp_configure(&config) != 0) {
    err = "tcpdp_configure_failed";
    return false;
  }
  return true;
}

std::uint32_t StatefulFastpathDriver::SeedL4(const FastpathParams& p) {
  std::uint32_t enqueued = 0;
  for (std::uint32_t i = 0; i < p.target_flows; ++i) {
    std::uint64_t flow_id = 0;
    if (tcpdp_enqueue_connect(p.src_ip, p.dst_ip, 0, p.dst_port, &flow_id) != 0 || flow_id == 0) {
      continue;
    }
    ++enqueued;
    if (!p.payload.empty()) {
      std::uint32_t queued = 0;
      (void)tcpdp_enqueue_send(
          flow_id,
          reinterpret_cast<const std::uint8_t*>(p.payload.data()),
          p.payload.size(),
          &queued);
    }
  }
  return enqueued;
}

FastpathResult StatefulFastpathDriver::Run(
    const FastpathParams& p,
    const std::function<void(const std::atomic<bool>&)>& l7_runner,
    const std::atomic<bool>& stop,
    const FastpathHooks& hooks) {
  FastpathResult result;
  result.rx_available = shim_.RxAvailable();

  // L7 modu: profil ikinci bir thread'te koşar; sürücü thread'i (bu thread) TEK wire
  // sahibi olarak pump eder. internal_stop, hard-deadline/stop'ta l7_runner'a "bitir"
  // sinyali verir; sürücü l7_runner dönene kadar pump etmeyi sürdürür (deadlock yok).
  const bool l7_mode = static_cast<bool>(l7_runner);
  std::atomic<bool> internal_stop{false};
  std::atomic<bool> l7_done{false};
  std::thread l7_thread;
  if (l7_mode) {
    l7_thread = std::thread([&]() {
      l7_runner(internal_stop);
      l7_done.store(true, std::memory_order_release);
    });
  }

  PumpScratch scratch(shim_, p.rx_budget);
  const FfiCoreAdapter ffi_ops{};
  std::string err;

  const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
  const std::uint64_t hard_deadline_ns = start_ns + p.max_duration_ms * 1'000'000ull;
  std::uint64_t last_hb_ns = start_ns;
  std::uint64_t last_metric_ns = start_ns;
  std::uint64_t drain_started_ns = 0;

  auto emit_metric = [&](std::uint64_t now_ns) {
    tcpdp_stats_snapshot_t st{};
    (void)tcpdp_snapshot_stats(&st);
    const double dur_s = std::max(1e-9, static_cast<double>(now_ns - start_ns) / 1e9);
    samurai::wire::MetricSnapshotV2 snap{};
    snap.base.timestamp_ns = now_ns;
    snap.base.packets_sent = result.tx_packets;
    snap.base.packets_errors = result.tx_errors;
    snap.base.bytes_sent = result.tx_bytes;
    snap.base.actual_rps = static_cast<double>(result.tx_packets) / dur_s;
    snap.base.rate_accuracy_pct = 100.0;
    snap.tcp_active_tcb_count = static_cast<std::uint32_t>(st.flows_active);
    snap.hot_path_zero_copy_tx_bytes = st.tx_data_bytes;
    snap.hot_path_zero_copy_rx_bytes = st.rx_data_bytes;
    if (hooks.emit_metric) hooks.emit_metric(snap);
  };

  std::uint32_t idle_spins = 0;
  while (true) {
    const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
    const bool did_work =
        PumpDataplaneStep(ffi_ops, shim_, scratch, p.rx_budget, now_ns, err, result);

    // 4) Telemetri.
    if (now_ns - last_hb_ns >= 1'000'000'000ull) {
      if (hooks.emit_heartbeat) hooks.emit_heartbeat();
      last_hb_ns = now_ns;
    }
    if (now_ns - last_metric_ns >= 2'000'000'000ull) {
      emit_metric(now_ns);
      last_metric_ns = now_ns;
    }

    // 5) Sonlandırma.
    const bool deadline_hit = now_ns >= hard_deadline_ns;
    const bool ext_stop = stop.load(std::memory_order_relaxed);
    if (l7_mode) {
      // Deadline/stop => l7_runner'a bitir sinyali; ama l7_runner dönene kadar
      // pump etmeyi sürdür (aksi halde wire ilerlemez ve join asılır).
      if (deadline_hit || ext_stop) internal_stop.store(true, std::memory_order_relaxed);
      if (l7_done.load(std::memory_order_acquire)) {
        if (drain_started_ns == 0) drain_started_ns = now_ns;
        if (now_ns - drain_started_ns >= p.drain_ms * 1'000'000ull) break;
      }
    } else {
      // Pure-L4: tüm flow'lar terminal olunca kısa drain, sonra çık.
      tcpdp_stats_snapshot_t st{};
      (void)tcpdp_snapshot_stats(&st);
      const std::uint64_t terminal =
          st.connect_established + st.connect_timeout_count + st.retransmit_exhausted_count;
      if (terminal >= p.target_flows) {
        if (drain_started_ns == 0) drain_started_ns = now_ns;
        if (now_ns - drain_started_ns >= p.drain_ms * 1'000'000ull) break;
      }
      if (deadline_hit || ext_stop) break;
    }

    // 6) İş yoksa DPDK tarzı kesintisiz döngüde (cpu_relax) bekle, sıfır uyku.
    if (!did_work) {
      SAMURAI_CPU_RELAX();
      if (!IsFastpathBusyPoll() && ++idle_spins > 1024) {
        std::this_thread::yield();
      }
    } else {
      idle_spins = 0;
    }
  }

  // L7 thread'ini güvenle sonlandır. Loop yalnız l7_done olduğunda kırıldığı için
  // normalde thread bitmiştir; yine de internal_stop set edip join ediyoruz.
  if (l7_mode) {
    internal_stop.store(true, std::memory_order_relaxed);
    if (l7_thread.joinable()) l7_thread.join();
  }

  // Nihai snapshot'tan sonuçları topla.
  tcpdp_stats_snapshot_t st{};
  (void)tcpdp_snapshot_stats(&st);
  result.connect_attempts = st.connect_attempts;
  result.connect_established = st.connect_established;
  result.retransmit_count = st.retransmit_count;
  result.retransmit_exhausted = st.retransmit_exhausted_count;
  result.connect_timeout = st.connect_timeout_count;
  return result;
}

// ---------------------------------------------------------------------------
// ShardedFastpathDriver — shared-nothing çok-çekirdek stateful fast-path (TRex).
// ---------------------------------------------------------------------------
namespace {

void PinThisThread(int cpu) {
  if (cpu < 0) return;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(static_cast<unsigned>(cpu), &set);
  (void)sched_setaffinity(0, sizeof(set), &set);  // 0 => calling thread
}

// Worker-yerel canlı metrik kopyası (coordinator ZMQ snapshot birleştirir).
struct alignas(64) ShardLiveStats {
  std::atomic<std::uint64_t> tx_packets{0};
  std::atomic<std::uint64_t> tx_bytes{0};
  std::atomic<std::uint64_t> tx_errors{0};
  std::atomic<std::uint64_t> flows_active{0};
  std::atomic<std::uint64_t> tx_data_bytes{0};
  std::atomic<std::uint64_t> rx_data_bytes{0};
};

std::uint16_t NextPow2U16(std::uint32_t n) {
  std::uint32_t s = 1;
  while (s < n && s < 32768u) {
    s <<= 1;
  }
  return static_cast<std::uint16_t>(s);
}

// `min_base` (varsayılan 32768 = 0x8000) değerini `stride`'ın katına hizalar ve
// + (worker_idx % stride) ekler; böylece her shard tek bir residue sınıfında
// kalır: (port & (stride - 1)) == (worker_idx % stride) => rte_flow mask demux.
std::uint16_t ShardEphemeralBase(std::uint32_t worker_idx,
                                  std::uint16_t stride,
                                  std::uint16_t min_base = 32768u) {
  const std::uint32_t s = stride == 0 ? 1u : static_cast<std::uint32_t>(stride);
  const std::uint32_t rem = min_base % s;
  const std::uint32_t aligned = rem == 0 ? min_base : (min_base + s - rem);
  return static_cast<std::uint16_t>(aligned + (worker_idx % s));
}

FastpathResult MergeFastpathResults(const std::vector<FastpathResult>& results) {
  FastpathResult total;
  for (const auto& r : results) {
    total.tx_packets += r.tx_packets;
    total.tx_bytes += r.tx_bytes;
    total.tx_errors += r.tx_errors;
    total.rx_frames += r.rx_frames;
    total.connect_attempts += r.connect_attempts;
    total.connect_established += r.connect_established;
    total.retransmit_count += r.retransmit_count;
    total.retransmit_exhausted += r.retransmit_exhausted;
    total.connect_timeout += r.connect_timeout;
    total.rx_available = total.rx_available || r.rx_available;
  }
  return total;
}

// Worker-yerel çekirdeğe karşı pump loop'u (StatefulFastpathDriver::Run'ın FFI'siz,
// instance-tabanlı ikizi). Paylaşılan hiçbir duruma dokunmaz.
void RunShardWorker(samurai::tcpdp::TcpDataplaneCore& core, FastpathTxRxShim& shim,
                    const FastpathParams& p, std::uint32_t seeded_flows,
                    const std::atomic<bool>& stop, FastpathResult& out,
                    ShardLiveStats* live = nullptr) {
  out.rx_available = shim.RxAvailable();
  PumpScratch scratch(shim, p.rx_budget);
  const DirectCoreAdapter core_ops{core};
  std::string err;

  const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
  const std::uint64_t deadline_ns = start_ns + p.max_duration_ms * 1'000'000ull;
  std::uint64_t drain_started_ns = 0;
  std::uint32_t idle_spins = 0;

  while (true) {
    const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
    const bool did_work =
        PumpDataplaneStep(core_ops, shim, scratch, p.rx_budget, now_ns, err, out);

    if (live != nullptr && did_work) {
      live->tx_packets.store(out.tx_packets, std::memory_order_relaxed);
      live->tx_bytes.store(out.tx_bytes, std::memory_order_relaxed);
      live->tx_errors.store(out.tx_errors, std::memory_order_relaxed);
    }

    if (stop.load(std::memory_order_relaxed) || now_ns >= deadline_ns) break;

    const auto st = core.SnapshotStats();
    if (live != nullptr) {
      live->flows_active.store(st.flows_active, std::memory_order_relaxed);
      live->tx_data_bytes.store(st.tx_data_bytes, std::memory_order_relaxed);
      live->rx_data_bytes.store(st.rx_data_bytes, std::memory_order_relaxed);
    }
    const std::uint64_t resolved =
        st.connect_established + st.connect_timeout_count + st.retransmit_exhausted_count;
    if (seeded_flows > 0 && resolved >= seeded_flows) {
      if (drain_started_ns == 0) {
        drain_started_ns = now_ns;
      } else if (now_ns - drain_started_ns >= p.drain_ms * 1'000'000ull) {
        break;
      }
    } else {
      drain_started_ns = 0;
    }

    if (!did_work) {
      SAMURAI_CPU_RELAX();
      if (!IsFastpathBusyPoll() && ++idle_spins > 1024) {
        std::this_thread::yield();
      }
    } else {
      idle_spins = 0;
    }
  }

  const auto st = core.SnapshotStats();
  out.connect_attempts = st.connect_attempts;
  out.connect_established = st.connect_established;
  out.retransmit_count = st.retransmit_count;
  out.retransmit_exhausted = st.retransmit_exhausted_count;
  out.connect_timeout = st.connect_timeout_count;
  out.tx_errors += 0;
  if (live != nullptr) {
    live->tx_packets.store(out.tx_packets, std::memory_order_relaxed);
    live->tx_bytes.store(out.tx_bytes, std::memory_order_relaxed);
    live->tx_errors.store(out.tx_errors, std::memory_order_relaxed);
    live->flows_active.store(st.flows_active, std::memory_order_relaxed);
    live->tx_data_bytes.store(st.tx_data_bytes, std::memory_order_relaxed);
    live->rx_data_bytes.store(st.rx_data_bytes, std::memory_order_relaxed);
  }
}

}  // namespace

FastpathResult ShardedFastpathDriver::Run(const FastpathParams& p, const std::atomic<bool>& stop,
                                          std::vector<FastpathResult>* per_worker) {
  return Run(p, stop, FastpathHooks{}, per_worker);
}

FastpathResult ShardedFastpathDriver::Run(const FastpathParams& p, const std::atomic<bool>& stop,
                                          const FastpathHooks& hooks,
                                          std::vector<FastpathResult>* per_worker) {
  std::uint32_t n = cfg_.workers;
  if (n == 0) {
    n = std::thread::hardware_concurrency();
    if (n == 0) n = 1;
  }
  resolved_workers_ = n;
  const std::uint16_t ephem_stride = NextPow2U16(n);

  // Flow'ları worker'lara eşit paylaştır (kalan ilk worker'lara).
  std::vector<std::uint32_t> flows_per(n, 0);
  for (std::uint32_t i = 0; i < p.target_flows; ++i) {
    flows_per[i % n]++;
  }

  std::vector<FastpathResult> results(n);
  std::vector<ShardLiveStats> live(n);
  std::atomic<std::uint32_t> completed{0};
  std::mutex done_mu;
  std::condition_variable done_cv;
  const bool need_hooks = static_cast<bool>(hooks.emit_heartbeat) ||
                          static_cast<bool>(hooks.emit_metric);

  std::vector<std::thread> threads;
  threads.reserve(n);

  for (std::uint32_t w = 0; w < n; ++w) {
    threads.emplace_back([this, &p, &stop, &results, &live, &flows_per,
                          &completed, &done_mu, &done_cv, ephem_stride,
                          need_hooks, n, w]() {
      struct ExitNotify {
        std::atomic<std::uint32_t>& done;
        std::uint32_t total;
        std::mutex& mu;
        std::condition_variable& cv;
        ~ExitNotify() {
          if (done.fetch_add(1, std::memory_order_acq_rel) + 1 >= total) {
            std::lock_guard<std::mutex> lk(mu);
            cv.notify_all();
          }
        }
      } exit_notify{completed, n, done_mu, done_cv};

      if (cfg_.cpu_base >= 0) {
        PinThisThread(cfg_.cpu_base + static_cast<int>(w));
      }
      std::unique_ptr<FastpathTxRxShim> shim = factory_(w);
      if (!shim) return;

      samurai::tcpdp::TcpDataplaneCore core;
      samurai::tcpdp::TcpDpConfig cfg;
      cfg.mode = p.mode;
      cfg.backend = p.backend;
      cfg.initial_rto_ms = p.initial_rto_ms;
      cfg.max_retransmits = p.max_retransmits;
      cfg.connect_timeout_ms = p.connect_timeout_ms;
      cfg.idle_timeout_ms = p.idle_timeout_ms;
      (void)core.Configure(cfg);

      // Disjoint power-of-2 residue class + collision-free flow id per shard
      // so rte_flow dst-port mask rules route SYN-ACK/data to the owning queue.
      core.SetEphemeralPortBase(ShardEphemeralBase(w, ephem_stride));
      core.SetEphemeralPortStride(ephem_stride);
      core.SetFlowIdBase(static_cast<std::uint64_t>(w + 1) << 40);

      std::uint32_t seeded = 0;
      for (std::uint32_t f = 0; f < flows_per[w]; ++f) {
        const std::uint64_t fid = core.EnqueueConnect(p.src_ip, p.dst_ip, 0, p.dst_port);
        if (fid != 0) {
          ++seeded;
          if (!p.payload.empty()) {
            (void)core.EnqueueSend(fid, reinterpret_cast<const std::uint8_t*>(p.payload.data()),
                                   p.payload.size());
          }
        }
      }
      RunShardWorker(core, *shim, p, seeded, stop, results[w],
                     need_hooks ? &live[w] : nullptr);
    });
  }

  if (need_hooks) {
    const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
    std::uint64_t last_hb_ns = start_ns;
    std::uint64_t last_metric_ns = start_ns;
    std::unique_lock<std::mutex> lk(done_mu);
    while (completed.load(std::memory_order_acquire) < n) {
      done_cv.wait_for(lk, std::chrono::milliseconds(50),
                       [&]() { return completed.load(std::memory_order_acquire) >= n; });
      lk.unlock();
      const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
      if (now_ns - last_hb_ns >= 1'000'000'000ull) {
        if (hooks.emit_heartbeat) hooks.emit_heartbeat();
        last_hb_ns = now_ns;
      }
      if (now_ns - last_metric_ns >= 2'000'000'000ull) {
        if (hooks.emit_metric) {
          samurai::wire::MetricSnapshotV2 snap{};
          snap.base.timestamp_ns = now_ns;
          std::uint64_t zc_tx = 0;
          std::uint64_t zc_rx = 0;
          std::uint64_t active = 0;
          for (std::uint32_t w = 0; w < n; ++w) {
            snap.base.packets_sent += live[w].tx_packets.load(std::memory_order_relaxed);
            snap.base.bytes_sent += live[w].tx_bytes.load(std::memory_order_relaxed);
            snap.base.packets_errors += live[w].tx_errors.load(std::memory_order_relaxed);
            active += live[w].flows_active.load(std::memory_order_relaxed);
            zc_tx += live[w].tx_data_bytes.load(std::memory_order_relaxed);
            zc_rx += live[w].rx_data_bytes.load(std::memory_order_relaxed);
          }
          const double dur_s =
              std::max(1e-9, static_cast<double>(now_ns - start_ns) / 1e9);
          snap.base.actual_rps = static_cast<double>(snap.base.packets_sent) / dur_s;
          snap.base.rate_accuracy_pct = 100.0;
          snap.tcp_active_tcb_count = static_cast<std::uint32_t>(active);
          snap.hot_path_zero_copy_tx_bytes = zc_tx;
          snap.hot_path_zero_copy_rx_bytes = zc_rx;
          hooks.emit_metric(snap);
        }
        last_metric_ns = now_ns;
      }
      lk.lock();
    }
  }

  for (auto& t : threads) t.join();

  FastpathResult total = MergeFastpathResults(results);
  if (per_worker) *per_worker = std::move(results);
  return total;
}

FastpathResult ShardedFastpathDriver::RunL7(
    const FastpathParams& p,
    const ShardL7Runner& runner,
    const std::atomic<bool>& stop,
    std::vector<FastpathResult>* per_worker) {
  std::uint32_t n = cfg_.workers;
  if (n == 0) {
    n = std::thread::hardware_concurrency();
    if (n == 0) n = 1;
  }
  resolved_workers_ = n;
  const std::uint16_t ephem_stride = NextPow2U16(n);

  std::vector<FastpathResult> results(n);
  std::vector<std::thread> threads;
  threads.reserve(n);

  for (std::uint32_t w = 0; w < n; ++w) {
    threads.emplace_back([this, &p, &stop, &results, &runner, ephem_stride, w]() {
      if (cfg_.cpu_base >= 0) {
        PinThisThread(cfg_.cpu_base + static_cast<int>(w));
      }
      std::unique_ptr<FastpathTxRxShim> shim = factory_(w);
      if (!shim) return;

      samurai::tcpdp::TcpDataplaneCore core;
      samurai::tcpdp::TcpDpConfig cfg;
      cfg.mode = p.mode;
      cfg.backend = p.backend;
      cfg.initial_rto_ms = p.initial_rto_ms;
      cfg.max_retransmits = p.max_retransmits;
      cfg.connect_timeout_ms = p.connect_timeout_ms;
      cfg.idle_timeout_ms = p.idle_timeout_ms;
      (void)core.Configure(cfg);

      tcpdp_core_bind_current(&core);
      tcpdp_set_ephemeral_port_base(ShardEphemeralBase(w, ephem_stride));
      tcpdp_set_ephemeral_port_stride(ephem_stride);
      tcpdp_set_flow_id_base(static_cast<std::uint64_t>(w + 1) << 40);

      auto& out = results[w];
      out.rx_available = shim->RxAvailable();

      std::atomic<bool> l7_done{false};
      std::atomic<bool> internal_stop{false};

      std::thread l7_worker([&]() {
        tcpdp_core_bind_current(&core);
        if (runner) {
          runner(w, core, *shim, internal_stop);
        }
        l7_done.store(true, std::memory_order_release);
        tcpdp_core_bind_current(nullptr);
      });

      const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
      const std::uint64_t deadline_ns = start_ns + p.max_duration_ms * 1'000'000ull;
      std::uint64_t drain_started_ns = 0;
      PumpScratch scratch(*shim, p.rx_budget);
      const DirectCoreAdapter core_ops{core};
      std::string err;
      std::uint32_t idle_spins = 0;

      while (true) {
        const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
        const bool did_work =
            PumpDataplaneStep(core_ops, *shim, scratch, p.rx_budget, now_ns, err, out);

        const bool deadline_hit = now_ns >= deadline_ns;
        const bool ext_stop = stop.load(std::memory_order_relaxed);
        if (deadline_hit || ext_stop) {
          internal_stop.store(true, std::memory_order_relaxed);
        }

        if (l7_done.load(std::memory_order_acquire)) {
          if (drain_started_ns == 0) drain_started_ns = now_ns;
          if (now_ns - drain_started_ns >= p.drain_ms * 1'000'000ull) break;
        }
        if (deadline_hit || ext_stop) {
          if (l7_done.load(std::memory_order_acquire)) break;
        }

        if (!did_work) {
          SAMURAI_CPU_RELAX();
          if (!IsFastpathBusyPoll() && ++idle_spins > 1024) {
            std::this_thread::yield();
          }
        } else {
          idle_spins = 0;
        }
      }

      l7_worker.join();
      tcpdp_core_bind_current(nullptr);

      const auto st = core.SnapshotStats();
      out.connect_attempts = st.connect_attempts;
      out.connect_established = st.connect_established;
      out.retransmit_count = st.retransmit_count;
      out.retransmit_exhausted = st.retransmit_exhausted_count;
      out.connect_timeout = st.connect_timeout_count;
    });
  }
  for (auto& t : threads) t.join();

  FastpathResult total = MergeFastpathResults(results);
  if (per_worker) *per_worker = std::move(results);
  return total;
}

}  // namespace samurai::daemon
