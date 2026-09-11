// Kernel_socket H2 threaded driver end-to-end doğrulaması (gerçek h2c sunucu).
//
// Bir dış HTTP/2 cleartext (h2c prior-knowledge) sunucusuna bağlanır -- sunucu
// gerçek Hyper `h2` protokol yığınıdır (test_h2c_server.py). Engine, protocol=
// http2 + transport_backend=kernel_socket + concurrency>1 (shards>1) ile koşar,
// böylece run_http2_profile'ın yeni "kernel_threaded" dalı (wire thread YOK; her
// shard kendi epoll_fd'siyle nghttp2 oturumlarını süren bir worker) gerçek kernel
// soketleri üzerinden, çok-shard'lı, çok-thread'li çalışır.
//
// Sunucu portu `H2_TEST_PORT` ortam değişkeninden okunur (harness sunucuyu açar).
#include <cstdio>
#include <cstdlib>
#include <string>

#include "engine.hpp"

namespace {

using namespace ddos_samurai::l7_emu_native;

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

FlowOp MakeGet(const char* path) {
  FlowOp op;
  op.opcode = "SEND_HEADERS";
  op.method = "GET";
  op.path = path;
  op.headers["accept"] = "*/*";
  return op;
}

}  // namespace

int main() {
  const char* port_env = std::getenv("H2_TEST_PORT");
  if (port_env == nullptr || *port_env == '\0') {
    std::printf("FAIL: H2_TEST_PORT not set (harness must start test_h2c_server.py)\n");
    std::fflush(stdout);
    return 2;
  }
  const int port = std::atoi(port_env);

  constexpr int kRequests = 40;
  constexpr int kConcurrency = 4;  // shards = min(concurrency, max_connections)

  Profile profile;
  profile.protocol = "http2";
  profile.transport_backend = "kernel_socket";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = "127.0.0.1";
  profile.target_port = port;
  profile.scheme = "http";  // h2c (use_tls=false) -> cleartext HTTP/2 prior-knowledge
  profile.host_header = "127.0.0.1";
  profile.keepalive = 1;  // H2 multiplexer; connections reused across streams
  profile.verify = 0;
  profile.timeout_ms = 5000;
  profile.max_connections = kConcurrency;
  profile.max_streams_per_connection = 4;
  for (int i = 0; i < kRequests; ++i) {
    profile.ops.push_back(MakeGet("/"));
  }

  // Drive the sessions through the io_uring reactor where the host supports it,
  // so this exercises the ring-backed H2 readiness path (multishot POLL feeding
  // SSL_read/nghttp2), not just epoll. Falls back to epoll otherwise.
  const RuntimeCapabilities caps = detect_capabilities();
  const bool want_io_uring = caps.io_uring;
  profile.reactor_backend = want_io_uring ? "socket_io_uring" : "auto";

  RuntimeConfig cfg;
  cfg.concurrency = kConcurrency;
  cfg.profile_l7 = 1;

  const std::map<std::string, double> out = run_profile(profile, cfg);

  auto get = [&](const char* k) -> double {
    const auto it = out.find(k);
    return it == out.end() ? -1.0 : it->second;
  };

  const double shards = get("runtime_shards");
  const double attempted = get("attempted");
  const double sent = get("sent");
  const double status_2xx = get("status_2xx");
  const double conn_established = get("l7_conn_established");
  const double h2_cap = get("h2_native_capability_available");
  const double epoll_wakeups = get("l7_epoll_wakeups");
  const double cqe_reaped = get("l7_io_uring_cqe_reaped");
  const double uring_active = get("runtime_reactor_io_uring_active");

  std::printf(
      "runtime_shards=%.0f attempted=%.0f sent=%.0f status_2xx=%.0f "
      "conn_established=%.0f h2_native_capability=%.0f uring_active=%.0f "
      "epoll_wakeups=%.0f cqe_reaped=%.0f\n",
      shards, attempted, sent, status_2xx, conn_established, h2_cap,
      uring_active, epoll_wakeups, cqe_reaped);

  CHECK(h2_cap == 1.0, "nghttp2 native H2 not available in this build");
  CHECK(shards > 1.0, "expected runtime_shards>1 (threaded kernel path), got %.0f", shards);
  CHECK(attempted == static_cast<double>(kRequests), "attempted=%.0f expected %d", attempted, kRequests);
  CHECK(sent == static_cast<double>(kRequests), "sent=%.0f expected %d (all streams completed)", sent, kRequests);
  CHECK(status_2xx == static_cast<double>(kRequests), "status_2xx=%.0f expected %d", status_2xx, kRequests);

  if (want_io_uring) {
    // The io_uring reactor drives the H2 shard loop (service_ready_lanes routes
    // to the ring path). Note: H2 byte I/O itself is still synchronous
    // (SSL_read/SSL_write + nghttp2 + wait_for_fd) - the ring supplies readiness
    // via a multishot POLL, so on fast localhost the exchange can complete inside
    // the synchronous service call before a POLL CQE is needed (cqe_reaped may be
    // 0, and wait_for_fd may register a few epoll wakeups). Moving the H2 byte
    // transfer onto ring send/recv requires the nghttp2 mem-API rewrite and is
    // tracked separately; this test asserts functional correctness under the
    // io_uring reactor.
    CHECK(uring_active == 1.0, "expected io_uring reactor active, got %.0f", uring_active);
  }

  if (g_fails == 0) {
    std::printf("ALL KERNEL THREADED H2 TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("KERNEL THREADED H2 TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
