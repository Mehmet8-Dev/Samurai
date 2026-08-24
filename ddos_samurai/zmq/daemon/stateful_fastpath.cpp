#include "stateful_fastpath.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "../../l4/tcp_dataplane_ffi.h"

namespace samurai::daemon {
namespace {

constexpr std::uint16_t kFrameStride = 2048;  // tek RX slot boyutu

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

  std::vector<std::uint8_t> rxbuf(static_cast<std::size_t>(kFrameStride) * p.rx_budget);
  std::vector<std::uint16_t> rxlens(p.rx_budget);
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

  while (true) {
    const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
    bool did_work = false;

    // 1) RX -> tcpdp ingest (handshake'in ilerlemesi için SYN-ACK'ler buradan girer).
    if (shim_.RxAvailable()) {
      const int n = shim_.Recv(rxbuf.data(), kFrameStride, rxlens.data(), p.rx_budget, err);
      if (n > 0) {
        for (int i = 0; i < n; ++i) {
          std::uint32_t updated = 0;
          (void)tcpdp_ingest_rx_frame(
              rxbuf.data() + static_cast<std::size_t>(i) * kFrameStride,
              rxlens[static_cast<std::size_t>(i)], &updated);
        }
        result.rx_frames += static_cast<std::uint64_t>(n);
        did_work = true;
      }
    }

    // 2) Zamanlayıcılar + durum makinesi ilerlet.
    std::uint32_t actions = 0;
    (void)tcpdp_poll(now_ns, 1024, &actions);
    if (actions > 0) did_work = true;

    // 3) TX drain: tcpdp'nin ürettiği frame'leri wire'a bas (tek owner biz'iz).
    for (int guard = 0; guard < 16; ++guard) {
      const std::uint8_t* base = nullptr;
      std::uint32_t count = 0;
      std::size_t psize = 0;
      std::size_t stride = 0;
      if (tcpdp_peek_tx_packets_strided(0, &base, &count, &psize, &stride) != 0) break;
      if (base == nullptr || count == 0 || psize == 0) break;
      const int sent = shim_.Send(base, psize, stride, count, err);
      if (sent < 0) {
        result.tx_errors += count;
        std::uint32_t consumed = 0;
        (void)tcpdp_consume_tx_packets(count, &consumed);  // hatalıları düş, asma
        break;
      }
      if (sent == 0) break;  // wire dolu; sonraki iterasyonda tekrar dene
      std::uint32_t consumed = 0;
      (void)tcpdp_consume_tx_packets(static_cast<std::uint32_t>(sent), &consumed);
      result.tx_packets += static_cast<std::uint64_t>(sent);
      result.tx_bytes += static_cast<std::uint64_t>(sent) * static_cast<std::uint64_t>(psize);
      did_work = true;
      if (static_cast<std::uint32_t>(sent) < count) break;
    }

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

    // 6) İş yoksa CPU'yu yakma.
    if (!did_work) {
      struct timespec ts { 0, 200'000L };  // 200 us
      nanosleep(&ts, nullptr);
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

}  // namespace samurai::daemon
