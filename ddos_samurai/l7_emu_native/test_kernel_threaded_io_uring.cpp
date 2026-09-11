// Kernel Socket H1 threaded io_uring reactor end-to-end integration test.
//
// Spawns a real localhost HTTP/1.1 server and runs the native engine configured
// with transport_backend=kernel_socket, reactor_backend=SocketIoUring, and concurrency > 1 (multi-core shards).
// Verifies:
// 1. runtime_shards > 1 (multi-threaded per-core ring sharding)
// 2. 100% request completion with HTTP 200 (status_2xx == requests)
// 3. l7_epoll_wakeups == 0 (epoll is completely bypassed)
// 4. l7_io_uring_cqe_reaped > 0 (completions processed via kernel io_uring rings)
// 5. bridge.cpp run_profile_json reports runtime_reactor_backend == "socket_io_uring"

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
#include "bridge.hpp"

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
    addr.sin_port = 0;
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
  const RuntimeCapabilities caps = detect_capabilities();
  if (!caps.io_uring) {
    std::printf("SKIP: kernel io_uring capability not supported on this host\n");
    return 0;
  }

  TinyHttpServer server;
  if (!server.Start()) {
    std::printf("FAIL: could not start localhost HTTP server\n");
    std::fflush(stdout);
    return 1;
  }

  constexpr int kRequests = 40;
  constexpr int kConcurrency = 4;

  Profile profile;
  profile.protocol = "http";
  profile.transport_backend = "kernel_socket";
  profile.reactor_backend = "socket_io_uring";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = "127.0.0.1";
  profile.target_port = server.port;
  profile.scheme = "http";
  profile.host_header = "127.0.0.1";
  profile.keepalive = 0;
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

  std::printf("Running native run_profile with SocketIoUring reactor...\n");
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
  const double epoll_wakeups = get("l7_epoll_wakeups");
  const double sqe_submitted = get("l7_io_uring_sqe_submitted");
  const double cqe_reaped = get("l7_io_uring_cqe_reaped");

  std::printf(
      "shards=%.0f attempted=%.0f sent=%.0f status_2xx=%.0f conn_established=%.0f "
      "epoll_wakeups=%.0f sqe_sub=%.0f cqe_reaped=%.0f server_served=%d\n",
      shards, attempted, sent, status_2xx, conn_established,
      epoll_wakeups, sqe_submitted, cqe_reaped, server.served.load());

  CHECK(shards > 1.0, "expected runtime_shards>1, got %.0f", shards);
  CHECK(attempted == static_cast<double>(kRequests), "attempted=%.0f expected %d", attempted, kRequests);
  CHECK(sent == static_cast<double>(kRequests), "sent=%.0f expected %d", sent, kRequests);
  CHECK(status_2xx == static_cast<double>(kRequests), "status_2xx=%.0f expected %d", status_2xx, kRequests);
  CHECK(epoll_wakeups == 0.0, "expected l7_epoll_wakeups == 0 (epoll bypassed), got %.0f", epoll_wakeups);
  CHECK(cqe_reaped > 0.0, "expected l7_io_uring_cqe_reaped > 0, got %.0f", cqe_reaped);
  CHECK(sqe_submitted > 0.0, "expected l7_io_uring_sqe_submitted > 0, got %.0f", sqe_submitted);

  // Test JSON bridge integration as well
  std::printf("Testing JSON bridge run_profile_json with reactor_backend=io_uring...\n");
  samurai::core::json::Value prof_dict = samurai::core::json::Value::Object();
  prof_dict.set("protocol", samurai::core::json::Value::Str("http"));
  prof_dict.set("flow_attempted", samurai::core::json::Value::Int(kRequests));
  prof_dict.set("reactor_backend", samurai::core::json::Value::Str("io_uring"));

  samurai::core::json::Value conn_tmpl = samurai::core::json::Value::Object();
  conn_tmpl.set("transport_backend", samurai::core::json::Value::Str("kernel_socket"));
  conn_tmpl.set("reactor_backend", samurai::core::json::Value::Str("socket_io_uring"));
  conn_tmpl.set("target_ip", samurai::core::json::Value::Str("127.0.0.1"));
  conn_tmpl.set("target_port", samurai::core::json::Value::Int(server.port));
  conn_tmpl.set("max_connections", samurai::core::json::Value::Int(kConcurrency));
  conn_tmpl.set("timeout_ms", samurai::core::json::Value::Int(5000));
  prof_dict.set("connection_template", std::move(conn_tmpl));

  samurai::core::json::Value cfg_dict = samurai::core::json::Value::Object();
  cfg_dict.set("concurrency", samurai::core::json::Value::Int(kConcurrency));
  cfg_dict.set("profile_l7", samurai::core::json::Value::Int(1));

  samurai::core::json::Value bridge_res = run_profile_json(prof_dict, cfg_dict);
  const auto* reactor_val = bridge_res.find("runtime_reactor_backend");
  const std::string runtime_reactor = reactor_val != nullptr ? reactor_val->as_string() : "";
  std::printf("Bridge runtime_reactor_backend=%s\n", runtime_reactor.c_str());
  CHECK(runtime_reactor == "socket_io_uring", "expected socket_io_uring, got %s", runtime_reactor.c_str());

  const auto caps_json = runtime_capabilities_json();
  const auto* io_uring_val = caps_json.find("io_uring");
  CHECK(io_uring_val != nullptr && io_uring_val->as_bool() == true, "expected caps io_uring == true");

  server.Stop();

  if (g_fails == 0) {
    std::printf("ALL KERNEL THREADED IO_URING TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("KERNEL THREADED IO_URING TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
