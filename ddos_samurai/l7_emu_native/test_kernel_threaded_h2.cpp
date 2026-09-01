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

  std::printf(
      "runtime_shards=%.0f attempted=%.0f sent=%.0f status_2xx=%.0f "
      "conn_established=%.0f h2_native_capability=%.0f\n",
      shards, attempted, sent, status_2xx, conn_established, h2_cap);

  CHECK(h2_cap == 1.0, "nghttp2 native H2 not available in this build");
  CHECK(shards > 1.0, "expected runtime_shards>1 (threaded kernel path), got %.0f", shards);
  CHECK(attempted == static_cast<double>(kRequests), "attempted=%.0f expected %d", attempted, kRequests);
  CHECK(sent == static_cast<double>(kRequests), "sent=%.0f expected %d (all streams completed)", sent, kRequests);
  CHECK(status_2xx == static_cast<double>(kRequests), "status_2xx=%.0f expected %d", status_2xx, kRequests);

  if (g_fails == 0) {
    std::printf("ALL KERNEL THREADED H2 TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("KERNEL THREADED H2 TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
