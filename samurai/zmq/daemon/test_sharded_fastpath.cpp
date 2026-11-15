// ShardedFastpathDriver doğrulaması (NIC'siz, shared-nothing çok-çekirdek).
//
// N worker thread'in HER BİRİ kendi TcpDataplaneCore instance'ını + kendi
// LoopbackPeerShim'ini sahiplenir. Test: (1) tüm flow'lar worker'lara paylaştırılıp
// 3'lü el sıkışmayı tamamlar (toplam ve per-worker established), (2) worker'lar
// gerçekten paralel/bağımsız koşar, (3) cpu_base verildiğinde her worker pinlenen
// çekirdekte çalışır (sched_getcpu ile gözlenir). Tek global TX ring / poller YOK.
#include <sched.h>

#include <arpa/inet.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#include "stateful_fastpath.hpp"

namespace {

void WriteBe16(std::uint8_t* p, std::uint16_t v) { p[0] = std::uint8_t(v >> 8); p[1] = std::uint8_t(v & 0xFF); }
void WriteBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = std::uint8_t((v >> 24) & 0xFF); p[1] = std::uint8_t((v >> 16) & 0xFF);
  p[2] = std::uint8_t((v >> 8) & 0xFF);  p[3] = std::uint8_t(v & 0xFF);
}
std::uint16_t ReadBe16(const std::uint8_t* p) { return std::uint16_t((p[0] << 8) | p[1]); }
std::uint32_t ReadBe32(const std::uint8_t* p) {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kAck = 0x10;

// Per-worker observation: which CPU the worker's Send() ran on (pinning proof).
struct WorkerObs {
  std::atomic<int> cpu{-2};
  std::vector<std::uint16_t> src_ports;
};

// SYN -> SYN-ACK loopback peer. One instance per worker (shared-nothing wire).
struct LoopbackPeerShim : samurai::daemon::FastpathTxRxShim {
  std::deque<std::vector<std::uint8_t>> rx_queue;
  std::uint32_t peer_iss = 0x51000000u;
  WorkerObs* obs = nullptr;

  explicit LoopbackPeerShim(WorkerObs* o) : obs(o) {}

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    (void)err;
    if (obs && obs->cpu.load(std::memory_order_relaxed) == -2) {
      obs->cpu.store(sched_getcpu(), std::memory_order_relaxed);  // observed on first TX
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::uint8_t* pkt = base + static_cast<std::size_t>(i) * stride;
      if (psize < 54) continue;
      if (ReadBe16(pkt + 12) != 0x0800) continue;
      if (pkt[23] != 6) continue;
      const std::uint8_t flags = pkt[47];
      if ((flags & kSyn) == 0 || (flags & kAck) != 0) continue;  // only bare SYN

      const std::uint32_t src_ip = ReadBe32(pkt + 26);
      const std::uint32_t dst_ip = ReadBe32(pkt + 30);
      const std::uint16_t src_port = ReadBe16(pkt + 34);
      const std::uint16_t dst_port = ReadBe16(pkt + 36);
      const std::uint32_t syn_seq = ReadBe32(pkt + 38);
      if (obs) obs->src_ports.push_back(src_port);

      std::vector<std::uint8_t> resp(54, 0);
      WriteBe16(resp.data() + 12, 0x0800);
      resp[14] = 0x45;
      WriteBe16(resp.data() + 16, 40);
      resp[22] = 64;
      resp[23] = 6;
      WriteBe32(resp.data() + 26, dst_ip);
      WriteBe32(resp.data() + 30, src_ip);
      WriteBe16(resp.data() + 34, dst_port);
      WriteBe16(resp.data() + 36, src_port);
      WriteBe32(resp.data() + 38, ++peer_iss);
      WriteBe32(resp.data() + 42, syn_seq + 1);
      resp[46] = 0x50;
      resp[47] = static_cast<std::uint8_t>(kSyn | kAck);
      WriteBe16(resp.data() + 48, 65535);
      rx_queue.push_back(std::move(resp));
    }
    return static_cast<int>(count);
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    int n = 0;
    while (n < static_cast<int>(max) && !rx_queue.empty()) {
      const auto& f = rx_queue.front();
      std::memcpy(out + static_cast<std::size_t>(n) * stride, f.data(), f.size());
      lens[n] = static_cast<std::uint16_t>(f.size());
      rx_queue.pop_front();
      ++n;
    }
    return n;
  }

  bool RxAvailable() const override { return true; }
};

std::uint32_t Ipv4(const char* s) { in_addr a{}; inet_pton(AF_INET, s, &a); return ntohl(a.s_addr); }

int g_fails = 0;
#define CHECK(cond, ...)                                 \
  do {                                                   \
    if (!(cond)) {                                       \
      std::printf("FAIL [%s:%d]: ", __FILE__, __LINE__); \
      std::printf(__VA_ARGS__);                          \
      std::printf("\n");                                 \
      ++g_fails;                                         \
    }                                                    \
  } while (0)

}  // namespace

int main() {
  const unsigned hw = std::thread::hardware_concurrency();
  const std::uint32_t workers = std::min<std::uint32_t>(4, hw ? hw : 1);
  const bool can_pin = hw >= workers;  // only assert pinning if enough cores exist
  const std::uint32_t flows_per_worker = 8;
  const std::uint32_t target = workers * flows_per_worker;

  std::vector<WorkerObs> obs(workers);

  samurai::daemon::ShardedFastpathConfig cfg;
  cfg.workers = workers;
  cfg.cpu_base = can_pin ? 0 : -1;

  auto factory = [&obs](std::uint32_t w) -> std::unique_ptr<samurai::daemon::FastpathTxRxShim> {
    return std::make_unique<LoopbackPeerShim>(&obs[w]);
  };

  samurai::daemon::ShardedFastpathDriver driver(factory, cfg);

  samurai::daemon::FastpathParams p;
  p.dst_ip = Ipv4("10.0.0.3");
  p.dst_port = 80;
  p.src_ip = Ipv4("10.0.0.2");
  p.target_flows = target;
  p.backend = "custom_tcp";
  p.max_duration_ms = 3000;
  p.drain_ms = 100;

  std::atomic<bool> stop{false};
  std::vector<samurai::daemon::FastpathResult> per_worker;
  const samurai::daemon::FastpathResult total = driver.Run(p, stop, &per_worker);

  std::printf("workers=%u target_flows=%u total_established=%llu total_tx=%llu total_rx=%llu can_pin=%d\n",
              driver.worker_count(), target, (unsigned long long)total.connect_established,
              (unsigned long long)total.tx_packets, (unsigned long long)total.rx_frames, can_pin ? 1 : 0);

  CHECK(driver.worker_count() == workers, "worker_count=%u expected %u", driver.worker_count(), workers);
  CHECK(per_worker.size() == workers, "per_worker size=%zu expected %u", per_worker.size(), workers);
  CHECK(total.connect_established == target, "total established=%llu expected %u",
        (unsigned long long)total.connect_established, target);

  for (std::uint32_t w = 0; w < workers; ++w) {
    CHECK(per_worker[w].connect_established == flows_per_worker,
          "worker %u established=%llu expected %u (shared-nothing per-core partition)", w,
          (unsigned long long)per_worker[w].connect_established, flows_per_worker);
    if (can_pin) {
      const int cpu = obs[w].cpu.load();
      CHECK(cpu >= 0 && static_cast<std::uint32_t>(cpu) < workers,
            "worker %u ran on pinned cpu in [0,%u), observed %d", w, workers, cpu);
    }
  }

  // Ephemeral port stride / rte_flow mask separation across shards:
  // (src_port & (next_pow2(workers) - 1)) == w and globally disjoint.
  std::uint16_t stride = 1;
  while (stride < workers) stride <<= 1;
  const std::uint16_t mask = static_cast<std::uint16_t>(stride - 1u);
  std::unordered_set<std::uint16_t> global_ports;
  for (std::uint32_t w = 0; w < workers; ++w) {
    CHECK(obs[w].src_ports.size() >= flows_per_worker,
          "worker %u observed %zu SYN src ports, expected >= %u",
          w, obs[w].src_ports.size(), flows_per_worker);
    for (std::uint16_t sp : obs[w].src_ports) {
      CHECK((sp & mask) == w,
            "worker %u src_port=%u mask=0x%x residue=%u != %u (rte_flow steering mismatch)",
            w, sp, mask, static_cast<unsigned>(sp & mask), w);
      CHECK(global_ports.insert(sp).second,
            "duplicate ephemeral src_port=%u across shards (worker %u)", sp, w);
    }
  }

  // Verify FastpathTxRxShim::SupportsDirectMbufBurst() routes through RecvRawMbufs
  // instead of Recv() on both ShardedFastpathDriver::Run(hooks) and StatefulFastpathDriver::Run().
  {
    struct SpyObs {
      std::atomic<int> raw_calls{0};
      std::atomic<int> legacy_calls{0};
    };
    struct DirectBurstSpyShim : samurai::daemon::FastpathTxRxShim {
      SpyObs& obs;
      int bursts_left = 1;
      explicit DirectBurstSpyShim(SpyObs& o) : obs(o) {}
      int Send(const std::uint8_t*, std::size_t, std::size_t,
               std::uint32_t count, std::string&) override {
        return static_cast<int>(count);
      }
      int Recv(std::uint8_t*, std::uint16_t, std::uint16_t*, std::uint16_t,
               std::string&) override {
        obs.legacy_calls.fetch_add(1, std::memory_order_relaxed);
        return 0;
      }
      bool SupportsDirectMbufBurst() const override { return true; }
      int RecvRawMbufs(void** out_mbufs, std::uint16_t max_burst,
                       std::uint64_t& out_bytes, std::string&) override {
        obs.raw_calls.fetch_add(1, std::memory_order_relaxed);
        if (bursts_left <= 0 || max_burst < 2) return 0;
        --bursts_left;
        out_mbufs[0] = nullptr;
        out_mbufs[1] = nullptr;
        out_bytes += 128;
        return 2;
      }
      bool RxAvailable() const override { return true; }
    };

    SpyObs sharded_spy;
    auto spy_factory = [&](std::uint32_t) -> std::unique_ptr<samurai::daemon::FastpathTxRxShim> {
      return std::make_unique<DirectBurstSpyShim>(sharded_spy);
    };
    samurai::daemon::ShardedFastpathConfig scfg;
    scfg.workers = 2;
    scfg.cpu_base = -1;
    samurai::daemon::FastpathParams sp = p;
    sp.target_flows = 2;
    sp.max_duration_ms = 50;
    sp.drain_ms = 10;
    std::atomic<bool> stop2{false};
    samurai::daemon::FastpathHooks hooks;
    hooks.emit_heartbeat = []() {};
    samurai::daemon::ShardedFastpathDriver sdriver(spy_factory, scfg);
    const auto sres = sdriver.Run(sp, stop2, hooks);
    CHECK(sharded_spy.raw_calls.load() > 0, "ShardedFastpathDriver did not call RecvRawMbufs");
    CHECK(sharded_spy.legacy_calls.load() == 0,
          "ShardedFastpathDriver fell back to Recv() (%d calls)", sharded_spy.legacy_calls.load());
    CHECK(sres.rx_frames >= 4, "ShardedFastpathDriver raw rx_frames=%llu expected >= 4",
          (unsigned long long)sres.rx_frames);

    SpyObs single_spy;
    DirectBurstSpyShim single_shim(single_spy);
    samurai::daemon::StatefulFastpathDriver single_driver(single_shim);
    std::string cfg_err;
    CHECK(single_driver.Configure(sp, cfg_err), "single_driver Configure failed: %s", cfg_err.c_str());
    const auto fpres = single_driver.Run(sp, {}, stop2, hooks);
    CHECK(single_spy.raw_calls.load() > 0, "StatefulFastpathDriver did not call RecvRawMbufs");
    CHECK(single_spy.legacy_calls.load() == 0,
          "StatefulFastpathDriver fell back to Recv() (%d calls)", single_spy.legacy_calls.load());
    CHECK(fpres.rx_frames >= 2, "StatefulFastpathDriver raw rx_frames=%llu expected >= 2",
          (unsigned long long)fpres.rx_frames);
  }

  if (g_fails == 0) {
    std::printf("ALL SHARDED FASTPATH TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("SHARDED FASTPATH TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
