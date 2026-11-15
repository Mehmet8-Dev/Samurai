// Kernel_socket H1 threaded driver end-to-end doğrulaması.
//
// Gerçek bir localhost HTTP/1.1 sunucusu açar ve engine'i transport_backend=
// kernel_socket + concurrency>1 (shards>1) ile koşturur. Böylece run_profile'ın
// yeni "kernel_threaded" dalı (wire thread YOK; her shard kendi epoll_fd'sini
// süren bir worker) gerçek kernel soketleriyle, çok-shard'lı, çok-thread'li
// çalışır ve tüm istekler tamamlanır. Tek-thread seri yola düşmediğini
// runtime_shards>1 ile doğrular.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "engine.hpp"

namespace {

using namespace samurai::l7_emu_native;

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

// Minimal, connection-per-request HTTP/1.1 sunucu. `expected` bağlantı işleyene
// veya stop işaretlenene kadar accept eder; her bağlantıya detached bir handler
// thread'i verir (çok-shard client eşzamanlı bağlanır, seri accept yeterli).
struct TinyHttpServer {
  int listen_fd = -1;
  uint16_t port = 0;
  std::atomic<bool> stop{false};
  std::atomic<int> served{0};
  std::thread accept_thread;

  bool Start() {
    listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return false;
    int one = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // ephemeral
    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
    socklen_t alen = sizeof(addr);
    if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) return false;
    port = ntohs(addr.sin_port);
    if (::listen(listen_fd, 128) != 0) return false;
    accept_thread = std::thread([this]() { AcceptLoop(); });
    return true;
  }

  void AcceptLoop() {
    while (!stop.load(std::memory_order_relaxed)) {
      sockaddr_in peer{};
      socklen_t plen = sizeof(peer);
      const int fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
      if (fd < 0) {
        if (stop.load(std::memory_order_relaxed)) break;
        continue;
      }
      std::thread([this, fd]() { HandleConn(fd); }).detach();
    }
  }

  void HandleConn(int fd) {
    // İstek başlıklarının sonunu (\r\n\r\n) görene kadar oku, sonra tek yanıt yaz.
    std::string buf;
    char tmp[2048];
    while (buf.find("\r\n\r\n") == std::string::npos) {
      const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
      if (n <= 0) {
        ::close(fd);
        return;
      }
      buf.append(tmp, static_cast<std::size_t>(n));
      if (buf.size() > (1 << 16)) break;
    }
    static const char kResp[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
    const char* p = kResp;
    std::size_t left = sizeof(kResp) - 1;
    while (left > 0) {
      const ssize_t w = ::send(fd, p, left, 0);
      if (w <= 0) break;
      p += w;
      left -= static_cast<std::size_t>(w);
    }
    served.fetch_add(1, std::memory_order_relaxed);
    ::close(fd);
  }

  void Stop() {
    stop.store(true, std::memory_order_relaxed);
    if (listen_fd >= 0) {
      ::shutdown(listen_fd, SHUT_RDWR);
      ::close(listen_fd);
      listen_fd = -1;
    }
    if (accept_thread.joinable()) accept_thread.join();
  }
};

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
  TinyHttpServer server;
  if (!server.Start()) {
    std::printf("FAIL: could not start localhost HTTP server\n");
    std::fflush(stdout);
    return 1;
  }

  constexpr int kRequests = 40;
  constexpr int kConcurrency = 4;  // shards = min(concurrency, max_connections)

  Profile profile;
  profile.protocol = "http";
  profile.transport_backend = "kernel_socket";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = "127.0.0.1";
  profile.target_port = server.port;
  profile.scheme = "http";
  profile.host_header = "127.0.0.1";
  profile.keepalive = 0;  // her istek yeni bağlantı => connect yolu da threaded çalışır
  profile.verify = 0;
  profile.timeout_ms = 5000;
  profile.max_connections = kConcurrency;
  profile.max_streams_per_connection = 1;
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

  std::printf(
      "runtime_shards=%.0f attempted=%.0f sent=%.0f status_2xx=%.0f "
      "conn_established=%.0f server_served=%d\n",
      shards, attempted, sent, status_2xx, conn_established,
      server.served.load());

  // Çok-shard threaded yola girildi mi?
  CHECK(shards > 1.0, "expected runtime_shards>1 (threaded kernel path), got %.0f", shards);
  // Tüm istekler tamamlandı mı ve 2xx aldı mı?
  CHECK(attempted == static_cast<double>(kRequests), "attempted=%.0f expected %d", attempted, kRequests);
  CHECK(sent == static_cast<double>(kRequests), "sent=%.0f expected %d (all requests completed)", sent, kRequests);
  CHECK(status_2xx == static_cast<double>(kRequests), "status_2xx=%.0f expected %d", status_2xx, kRequests);

  server.Stop();

  if (g_fails == 0) {
    std::printf("ALL KERNEL THREADED L7 TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("KERNEL THREADED L7 TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
