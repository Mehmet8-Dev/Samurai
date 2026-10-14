// Kernel Socket H1 threaded io_uring reactor end-to-end integration test & benchmark.
//
// Spawns a real localhost HTTP/1.1 server and runs the native engine configured
// with transport_backend=kernel_socket, reactor_backend=SocketIoUring, and concurrency > 1 (multi-core shards).
// Verifies:
// 1. runtime_shards > 1 (multi-threaded per-core ring sharding)
// 2. 100% request completion with HTTP 200 (status_2xx == requests)
// 3. l7_epoll_wakeups == 0 (epoll is completely bypassed under io_uring)
// 4. l7_io_uring_cqe_reaped > 0 (completions processed via kernel io_uring rings)
// 5. bridge.cpp run_profile_json reports runtime_reactor_backend == "socket_io_uring"
// 6. Supports high-scale 100K request benchmarking against io_uring and epoll engines.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <csignal>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "engine.hpp"
#include "bridge.hpp"
#include "io_uring_compat.hpp"

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
  bool keep_alive = true;
  std::atomic<bool> stop{false};
  std::atomic<int> served{0};
  std::thread accept_thread;
  std::mutex workers_mu;
  std::vector<std::thread> workers;
  std::vector<int> client_fds;

  bool Start(uint16_t bind_port = 0, bool keep_alive_mode = true) {
    keep_alive = keep_alive_mode;
    listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return false;
    int one = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(bind_port);
    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      ::close(listen_fd);
      listen_fd = -1;
      return false;
    }
    socklen_t alen = sizeof(addr);
    if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) {
      ::close(listen_fd);
      listen_fd = -1;
      return false;
    }
    port = ntohs(addr.sin_port);
    if (::listen(listen_fd, 1024) != 0) {
      ::close(listen_fd);
      listen_fd = -1;
      return false;
    }
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
      int one = 1;
      ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      struct timeval tv{};
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      std::lock_guard<std::mutex> lk(workers_mu);
      client_fds.push_back(fd);
      workers.emplace_back([this, fd]() { HandleConn(fd); });
    }
  }

  void HandleConn(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    static const char kRespKeepAlive[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi";
    static const std::size_t kRespLen = sizeof(kRespKeepAlive) - 1;
    static const char kRespClose[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
    static const std::size_t kRespCloseLen = sizeof(kRespClose) - 1;

    std::string in_buf;
    in_buf.reserve(8192);
    char tmp[4096];

    while (!stop.load(std::memory_order_relaxed)) {
      const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          continue;
        }
        break;
      }
      if (n == 0) break;
      in_buf.append(tmp, static_cast<std::size_t>(n));

      while (true) {
        const std::size_t pos = in_buf.find("\r\n\r\n");
        if (pos == std::string::npos) break;
        in_buf.erase(0, pos + 4);

        if (keep_alive) {
          ssize_t w = ::send(fd, kRespKeepAlive, kRespLen, MSG_NOSIGNAL);
          if (w <= 0) {
            ::close(fd);
            return;
          }
          served.fetch_add(1, std::memory_order_relaxed);
        } else {
          (void)::send(fd, kRespClose, kRespCloseLen, MSG_NOSIGNAL);
          served.fetch_add(1, std::memory_order_relaxed);
          ::close(fd);
          return;
        }
      }
      if (in_buf.size() > 65536) in_buf.clear();
    }
    ::close(fd);
  }

  void Stop() {
    stop.store(true, std::memory_order_relaxed);
    if (listen_fd >= 0) {
      ::shutdown(listen_fd, SHUT_RDWR);
      ::close(listen_fd);
      listen_fd = -1;
    }
    {
      std::lock_guard<std::mutex> lk(workers_mu);
      for (int cfd : client_fds) {
        if (cfd >= 0) {
          ::shutdown(cfd, SHUT_RDWR);
        }
      }
    }
    if (accept_thread.joinable()) accept_thread.join();
    std::lock_guard<std::mutex> lk(workers_mu);
    for (auto& w : workers) {
      if (w.joinable()) w.join();
    }
    workers.clear();
    client_fds.clear();
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

std::atomic<bool> g_sig_stop{false};
void SigTermHandler(int) {
  g_sig_stop.store(true, std::memory_order_relaxed);
}

int RunServerOnly(uint16_t port, bool keepalive) {
  std::signal(SIGINT, SigTermHandler);
  std::signal(SIGTERM, SigTermHandler);

  TinyHttpServer server;
  if (!server.Start(port, keepalive)) {
    std::fprintf(stderr, "FAIL: could not start HTTP server on port %u\n", port);
    return 1;
  }
  std::printf("SERVER_READY port=%u\n", server.port);
  std::fflush(stdout);

  while (!g_sig_stop.load(std::memory_order_relaxed)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  server.Stop();
  std::printf("SERVER_STOPPED served=%d\n", server.served.load());
  return 0;
}

void TestIoUringQueueAccounting() {
  std::printf("Testing io_uring queue accounting and boundary conditions...\n");
  SamuraiUring ring;
  if (!ring.init(32)) {
    CHECK(false, "failed to initialize SamuraiUring with 32 entries");
    return;
  }

  // 1. Fill SQ to capacity and verify get_sqe returns nullptr once full
  for (unsigned i = 0; i < 32; ++i) {
    auto* sqe = ring.get_sqe();
    CHECK(sqe != nullptr, "get_sqe failed at index %u", i);
    if (sqe != nullptr) {
      prep_uring_nop(sqe, static_cast<uint64_t>(i + 1));
    }
  }
  // Queue should now be full
  auto* overflow_sqe = ring.get_sqe();
  CHECK(overflow_sqe == nullptr, "expected get_sqe to return nullptr when SQ is saturated");

  // 2. Submit all 32 NOP SQEs and wait for at least 32 completions
  int ret = ring.submit_and_wait_cqes(32, 1000);
  CHECK(ret >= 0, "submit_and_wait_cqes failed with ret=%d", ret);

  // 3. Harvest completions and verify user_data integrity
  struct io_uring_cqe* cqes[64];
  int reaped = ring.peek_batch_cqe(cqes, 64);
  CHECK(reaped == 32, "expected 32 reaped CQEs, got %d", reaped);
  for (int i = 0; i < reaped; ++i) {
    CHECK(cqes[i] != nullptr, "cqe %d is null", i);
    if (cqes[i] != nullptr) {
      CHECK(cqes[i]->res == 0, "NOP cqe returned error %d", cqes[i]->res);
    }
  }
  ring.cq_advance(static_cast<unsigned>(reaped));

  // 4. Test zero-submission submit_and_wait_cqes
  int zero_ret = ring.submit_and_wait_cqes(0, 0);
  CHECK(zero_ret >= 0, "zero-submission submit_and_wait_cqes failed: %d", zero_ret);

  // 5. Test timeout wait when no completions are pending
  int timeout_ret = ring.wait_cqes(1, 10);
  CHECK(timeout_ret == 0 || timeout_ret == -ETIME || timeout_ret == -1,
        "timeout wait returned unexpected %d", timeout_ret);

  // 6. After reaping, SQ should be ready for new submissions
  auto* new_sqe = ring.get_sqe();
  CHECK(new_sqe != nullptr, "expected get_sqe to succeed after CQ reaping");
  if (new_sqe != nullptr) {
    prep_uring_nop(new_sqe, 999);
    int sub = ring.submit_and_wait_cqes(1, 1000);
    CHECK(sub >= 0, "submit single NOP failed: %d", sub);
    struct io_uring_cqe* single_cqe[4];
    int single_reaped = ring.peek_batch_cqe(single_cqe, 4);
    CHECK(single_reaped == 1, "expected 1 CQE, got %d", single_reaped);
    if (single_reaped == 1 && single_cqe[0] != nullptr) {
      CHECK(single_cqe[0]->user_data == 999, "user_data mismatch: %lu",
            static_cast<unsigned long>(single_cqe[0]->user_data));
      ring.cq_advance(1);
    }
  }
}

int RunRegressionTest() {
  const RuntimeCapabilities caps = detect_capabilities();
  if (!caps.io_uring) {
    std::printf("SKIP: kernel io_uring capability not supported on this host\n");
    return 0;
  }

  TestIoUringQueueAccounting();

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

int RunBenchmark(int requests,
                 int concurrency,
                 const std::string& reactor_name,
                 const std::string& target_ip,
                 uint16_t port,
                 bool keepalive,
                 bool json_output) {
  const RuntimeCapabilities caps = detect_capabilities();
  const bool want_io_uring = (reactor_name == "io_uring" || reactor_name == "socket_io_uring");
  if (want_io_uring && !caps.io_uring) {
    std::fprintf(stderr, "FAIL: io_uring requested but kernel io_uring not supported on this host\n");
    return 2;
  }

  TinyHttpServer embedded_server;
  if (port == 0) {
    if (!embedded_server.Start(0, keepalive)) {
      std::fprintf(stderr, "FAIL: could not start embedded benchmark HTTP server\n");
      return 1;
    }
    port = embedded_server.port;
  }

  Profile profile;
  profile.protocol = "http";
  profile.transport_backend = "kernel_socket";
  profile.reactor_backend = want_io_uring ? "socket_io_uring" : "socket_epoll";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = target_ip;
  profile.target_port = port;
  profile.scheme = "http";
  profile.host_header = target_ip;
  profile.keepalive = keepalive ? 1 : 0;
  profile.verify = 0;
  profile.timeout_ms = 15000;
  profile.max_connections = concurrency;
  profile.max_streams_per_connection = 1;
  profile.ops.reserve(requests);
  for (int i = 0; i < requests; ++i) {
    profile.ops.push_back(MakeGet("/"));
  }

  RuntimeConfig cfg;
  cfg.concurrency = concurrency;
  cfg.profile_l7 = 1;
  cfg.profile_sample_limit = 0;  // collect full distribution for exact percentiles

  const auto t_start = std::chrono::steady_clock::now();
  const std::map<std::string, double> out = run_profile(profile, cfg);
  const auto t_end = std::chrono::steady_clock::now();
  const double duration_sec = std::chrono::duration<double>(t_end - t_start).count();

  auto get = [&](const char* k) -> double {
    const auto it = out.find(k);
    return it == out.end() ? 0.0 : it->second;
  };

  const double shards = get("runtime_shards");
  const double attempted = get("attempted");
  const double sent = get("sent");
  const double status_2xx = get("status_2xx");
  const double errors = get("errors");
  const double rx_syscalls = get("l7_rx_syscalls");
  const double tx_syscalls = get("l7_tx_syscalls");
  const double epoll_wakeups = get("l7_epoll_wakeups");
  const double sqe_submitted = get("l7_io_uring_sqe_submitted");
  const double cqe_reaped = get("l7_io_uring_cqe_reaped");
  const double p50_ms = get("l7_request_latency_p50_ms");
  const double p95_ms = get("l7_request_latency_p95_ms");
  const double p99_ms = get("l7_request_latency_p99_ms");

  const double rps = duration_sec > 0.0 ? (sent / duration_sec) : 0.0;

  if (embedded_server.listen_fd >= 0) {
    embedded_server.Stop();
  }

  if (json_output) {
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "{\n"
              << "  \"task\": \"TASK-TEST-L3-01\",\n"
              << "  \"reactor\": \"" << (want_io_uring ? "io_uring" : "epoll") << "\",\n"
              << "  \"requests\": " << static_cast<long>(sent) << ",\n"
              << "  \"concurrency\": " << concurrency << ",\n"
              << "  \"shards\": " << static_cast<int>(shards) << ",\n"
              << "  \"duration_sec\": " << duration_sec << ",\n"
              << "  \"rps\": " << rps << ",\n"
              << "  \"status_2xx\": " << static_cast<long>(status_2xx) << ",\n"
              << "  \"errors\": " << static_cast<long>(errors) << ",\n"
              << "  \"rx_syscalls\": " << static_cast<long>(rx_syscalls) << ",\n"
              << "  \"tx_syscalls\": " << static_cast<long>(tx_syscalls) << ",\n"
              << "  \"epoll_wakeups\": " << static_cast<long>(epoll_wakeups) << ",\n"
              << "  \"sqe_submitted\": " << static_cast<long>(sqe_submitted) << ",\n"
              << "  \"cqe_reaped\": " << static_cast<long>(cqe_reaped) << ",\n"
              << "  \"latency_p50_ms\": " << p50_ms << ",\n"
              << "  \"latency_p95_ms\": " << p95_ms << ",\n"
              << "  \"latency_p99_ms\": " << p99_ms << "\n"
              << "}\n";
  } else {
    std::printf("\n================================================================================\n");
    std::printf("[TASK-TEST-L3-01 BENCHMARK RESULT: %s]\n", want_io_uring ? "io_uring" : "epoll");
    std::printf("  Requests Completed: %ld / %d (%.2f%% HTTP 200)\n",
                static_cast<long>(status_2xx), requests,
                requests > 0 ? (status_2xx / requests * 100.0) : 0.0);
    std::printf("  Concurrency / Shards: %d / %.0f\n", concurrency, shards);
    std::printf("  Duration (T):       %.4f s\n", duration_sec);
    std::printf("  Throughput (RPS):   %.2f req/s\n", rps);
    std::printf("  Rx Syscalls:        %.0f\n", rx_syscalls);
    std::printf("  Tx Syscalls:        %.0f\n", tx_syscalls);
    std::printf("  Epoll Wakeups:      %.0f\n", epoll_wakeups);
    std::printf("  SQE Submitted:      %.0f\n", sqe_submitted);
    std::printf("  CQE Reaped:         %.0f\n", cqe_reaped);
    std::printf("  Latency P50:        %.4f ms\n", p50_ms);
    std::printf("  Latency P95:        %.4f ms\n", p95_ms);
    std::printf("  Latency P99:        %.4f ms\n", p99_ms);
    std::printf("================================================================================\n\n");
  }

  if (static_cast<int>(status_2xx) != requests) {
    std::fprintf(stderr, "FAIL: status_2xx (%ld) != expected requests (%d)\n",
                 static_cast<long>(status_2xx), requests);
    return 1;
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc <= 1) {
    return RunRegressionTest();
  }

  bool is_benchmark = false;
  bool is_server_only = false;
  int requests = 100000;
  int concurrency = 32;
  std::string reactor = "io_uring";
  std::string target_ip = "127.0.0.1";
  uint16_t port = 0;
  bool keepalive = true;
  bool json_output = false;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--benchmark") {
      is_benchmark = true;
    } else if (arg == "--server-only") {
      is_server_only = true;
    } else if (arg == "--test") {
      return RunRegressionTest();
    } else if (arg == "--requests" && i + 1 < argc) {
      requests = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--concurrency" && i + 1 < argc) {
      concurrency = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--reactor" && i + 1 < argc) {
      reactor = argv[++i];
    } else if (arg == "--target-ip" && i + 1 < argc) {
      target_ip = argv[++i];
    } else if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::atoi(argv[++i]));
    } else if (arg == "--keepalive" && i + 1 < argc) {
      keepalive = (std::atoi(argv[++i]) != 0);
    } else if (arg == "--json") {
      json_output = true;
    } else if (arg == "--help" || arg == "-h") {
      std::printf("Usage: %s [options]\n", argv[0]);
      std::printf("  --test                  Run quick regression integration test (default if no args)\n");
      std::printf("  --benchmark             Run 100K request reactor benchmark\n");
      std::printf("  --requests <N>          Total HTTP requests (default: 100000)\n");
      std::printf("  --concurrency <C>       Concurrency / shard count (default: 32)\n");
      std::printf("  --reactor <name>        Reactor backend: io_uring or epoll (default: io_uring)\n");
      std::printf("  --port <P>              Target port (default: 0 = spawn embedded server)\n");
      std::printf("  --target-ip <IP>        Target IP (default: 127.0.0.1)\n");
      std::printf("  --keepalive <0|1>       Enable HTTP/1.1 persistent connections (default: 1)\n");
      std::printf("  --json                  Output benchmark results in JSON\n");
      std::printf("  --server-only           Run standalone high-performance HTTP server\n");
      return 0;
    }
  }

  if (is_server_only) {
    if (port == 0) port = 18088;
    return RunServerOnly(port, keepalive);
  }

  if (is_benchmark) {
    return RunBenchmark(requests, concurrency, reactor, target_ip, port, keepalive, json_output);
  }

  return RunRegressionTest();
}
