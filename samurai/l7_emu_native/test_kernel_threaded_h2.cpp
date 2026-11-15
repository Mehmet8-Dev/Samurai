// Kernel_socket H2 threaded driver end-to-end and benchmark runner.
//
// Supports:
// 1. Correctness / regression verification: validates h2c cleartext, TLS memory-BIO,
//    and kTLS socket-BIO paths across io_uring and epoll reactors.
// 2. TASK-TEST-L3-02 Benchmark: stress tests 100 concurrent streams over a single
//    TLS connection, measuring CPU overhead and comparing kTLS socket-BIO vs
//    OpenSSL memory-BIO.
//
// Server port is read from H2_TEST_PORT or --port.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

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

FlowOp MakeGet(const char* path) {
  FlowOp op;
  op.opcode = "SEND_HEADERS";
  op.method = "GET";
  op.path = path;
  op.headers["accept"] = "*/*";
  return op;
}

int RunRegressionTest() {
  const char* port_env = std::getenv("H2_TEST_PORT");
  if (port_env == nullptr || *port_env == '\0') {
    std::printf("FAIL: H2_TEST_PORT not set (harness must start test_h2c_server.py)\n");
    std::fflush(stdout);
    return 2;
  }
  const int port = std::atoi(port_env);
  const char* tls_env = std::getenv("H2_TEST_TLS");
  const bool use_tls = tls_env != nullptr && *tls_env != '\0' && *tls_env != '0';
  const char* ktls_env = std::getenv("H2_TEST_KTLS");
  const bool want_ktls = ktls_env != nullptr && *ktls_env != '\0' && *ktls_env != '0';

  auto env_int = [](const char* name, int fallback) -> int {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return fallback;
    const int n = std::atoi(v);
    return n > 0 ? n : fallback;
  };
  // Load knobs (default to correctness-test values). Raise via env for
  // perf runs, e.g. H2_TEST_REQS=4000 H2_TEST_CONNS=8 H2_TEST_STREAMS=32.
  const int kRequests = env_int("H2_TEST_REQS", 40);
  const int kConcurrency = env_int("H2_TEST_CONNS", 4);  // shards = min(concurrency, max_connections)
  const int kStreams = env_int("H2_TEST_STREAMS", 4);

  Profile profile;
  profile.protocol = "http2";
  profile.transport_backend = "kernel_socket";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = "127.0.0.1";
  profile.target_port = port;
  profile.scheme = use_tls ? "https" : "http";
  profile.tls_ktls = want_ktls ? 1 : 0;
  profile.host_header = "127.0.0.1";
  profile.keepalive = 1;  // H2 multiplexer; connections reused across streams
  profile.verify = 0;
  profile.timeout_ms = 5000;
  profile.max_connections = kConcurrency;
  profile.max_streams_per_connection = kStreams;
  profile.ops.reserve(kRequests);
  for (int i = 0; i < kRequests; ++i) {
    profile.ops.push_back(MakeGet("/"));
  }

  const char* epoll_env = std::getenv("H2_TEST_EPOLL");
  const bool force_epoll = epoll_env != nullptr && *epoll_env != '\0' && *epoll_env != '0';
  const RuntimeCapabilities caps = detect_capabilities();
  const bool want_io_uring = caps.io_uring && !force_epoll;
  profile.reactor_backend = force_epoll ? "socket_epoll"
                            : (want_io_uring ? "socket_io_uring" : "auto");

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
  const double rx_syscalls = get("l7_rx_syscalls");
  const double tx_syscalls = get("l7_tx_syscalls");
  const double sqe = get("l7_io_uring_sqe_submitted");

  std::printf(
      "runtime_shards=%.0f attempted=%.0f sent=%.0f status_2xx=%.0f "
      "conn_established=%.0f h2_native_capability=%.0f uring_active=%.0f "
      "epoll_wakeups=%.0f cqe_reaped=%.0f sqe=%.0f rx_syscalls=%.0f tx_syscalls=%.0f\n",
      shards, attempted, sent, status_2xx, conn_established, h2_cap,
      uring_active, epoll_wakeups, cqe_reaped, sqe, rx_syscalls, tx_syscalls);

  CHECK(h2_cap == 1.0, "nghttp2 native H2 not available in this build");
  if (kConcurrency > 1) {
    CHECK(shards > 1.0, "expected runtime_shards>1 (threaded kernel path), got %.0f", shards);
  } else {
    CHECK(shards == 1.0, "expected runtime_shards=1 (single connection path), got %.0f", shards);
  }
  CHECK(attempted == static_cast<double>(kRequests), "attempted=%.0f expected %d", attempted, kRequests);
  CHECK(sent == static_cast<double>(kRequests), "sent=%.0f expected %d (all streams completed)", sent, kRequests);
  CHECK(status_2xx == static_cast<double>(kRequests), "status_2xx=%.0f expected %d", status_2xx, kRequests);
  CHECK(conn_established == static_cast<double>(kConcurrency), "conn_established=%.0f expected %d", conn_established, kConcurrency);

  if (want_io_uring) {
    CHECK(uring_active == 1.0, "expected io_uring reactor active, got %.0f", uring_active);
    CHECK(cqe_reaped > 0.0,
          "expected H2 ring byte-path completions (l7_io_uring_cqe_reaped>0), got %.0f",
          cqe_reaped);
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

int RunBenchmark(int requests,
                 int concurrency,
                 int streams,
                 bool use_tls,
                 bool want_ktls,
                 bool force_epoll,
                 const std::string& target_ip,
                 int port,
                 bool json_output) {
  if (port <= 0) {
    std::fprintf(stderr, "FAIL: port must be specified via --port or H2_TEST_PORT\n");
    return 2;
  }

  const RuntimeCapabilities caps = detect_capabilities();
  if (!(caps.openssl && caps.nghttp2)) {
    std::fprintf(stderr, "FAIL: openssl and nghttp2 capabilities required for H2 benchmark\n");
    return 2;
  }

  const bool want_io_uring = caps.io_uring && !force_epoll;

  Profile profile;
  profile.protocol = "http2";
  profile.transport_backend = "kernel_socket";
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = target_ip;
  profile.target_port = port;
  profile.scheme = use_tls ? "https" : "http";
  profile.tls_ktls = want_ktls ? 1 : 0;
  profile.host_header = target_ip;
  profile.keepalive = 1;
  profile.verify = 0;
  profile.timeout_ms = 15000;
  profile.max_connections = concurrency;
  profile.max_streams_per_connection = streams;
  profile.ops.reserve(requests);
  for (int i = 0; i < requests; ++i) {
    profile.ops.push_back(MakeGet("/"));
  }

  profile.reactor_backend = force_epoll ? "socket_epoll"
                            : (want_io_uring ? "socket_io_uring" : "auto");

  RuntimeConfig cfg;
  cfg.concurrency = concurrency;
  cfg.profile_l7 = 1;
  cfg.profile_sample_limit = 0;  // collect full distribution for exact latency percentiles

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
  const double conn_established = get("l7_conn_established");
  const double goaway_count = get("h2_goaway_count");
  const double active_streams_peak = get("l7_h2_active_streams_peak");
  const double rx_bytes = get("l7_rx_bytes");
  const double tx_bytes = get("l7_tx_bytes");
  const double rx_syscalls = get("l7_rx_syscalls");
  const double tx_syscalls = get("l7_tx_syscalls");
  const double epoll_wakeups = get("l7_epoll_wakeups");
  const double sqe = get("l7_io_uring_sqe_submitted");
  const double cqe = get("l7_io_uring_cqe_reaped");
  const double p50_ms = get("l7_request_latency_p50_ms");
  const double p90_ms = get("l7_request_latency_p90_ms");
  const double p95_ms = get("l7_request_latency_p95_ms");
  const double p99_ms = get("l7_request_latency_p99_ms");
  const double avg_ms = get("l7_request_latency_avg_ms");
  const double max_ms = get("l7_request_latency_max_ms");
  const double rst_ratio = get("h2_stream_reset_ratio");

  const double rps = duration_sec > 0.0 ? (sent / duration_sec) : 0.0;
  const double bytes_total = rx_bytes + tx_bytes;
  const double bytes_per_sec = duration_sec > 0.0 ? (bytes_total / duration_sec) : 0.0;
  const std::string mode_str = want_ktls ? "ktls" : (use_tls ? "memory_bio" : "plaintext");
  const std::string reactor_str = force_epoll ? "socket_epoll" : (want_io_uring ? "socket_io_uring" : "auto");

  if (json_output) {
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "{\n"
              << "  \"task\": \"TASK-TEST-L3-02\",\n"
              << "  \"mode\": \"" << mode_str << "\",\n"
              << "  \"reactor\": \"" << reactor_str << "\",\n"
              << "  \"requests\": " << static_cast<long>(sent) << ",\n"
              << "  \"concurrency\": " << concurrency << ",\n"
              << "  \"streams\": " << streams << ",\n"
              << "  \"shards\": " << static_cast<int>(shards) << ",\n"
              << "  \"duration_sec\": " << duration_sec << ",\n"
              << "  \"rps\": " << rps << ",\n"
              << "  \"bytes_per_sec\": " << bytes_per_sec << ",\n"
              << "  \"status_2xx\": " << static_cast<long>(status_2xx) << ",\n"
              << "  \"errors\": " << static_cast<long>(errors) << ",\n"
              << "  \"goaway_count\": " << static_cast<long>(goaway_count) << ",\n"
              << "  \"stream_reset_ratio\": " << rst_ratio << ",\n"
              << "  \"active_streams_peak\": " << static_cast<long>(active_streams_peak) << ",\n"
              << "  \"conn_established\": " << static_cast<long>(conn_established) << ",\n"
              << "  \"rx_bytes\": " << static_cast<long>(rx_bytes) << ",\n"
              << "  \"tx_bytes\": " << static_cast<long>(tx_bytes) << ",\n"
              << "  \"rx_syscalls\": " << static_cast<long>(rx_syscalls) << ",\n"
              << "  \"tx_syscalls\": " << static_cast<long>(tx_syscalls) << ",\n"
              << "  \"epoll_wakeups\": " << static_cast<long>(epoll_wakeups) << ",\n"
              << "  \"sqe_submitted\": " << static_cast<long>(sqe) << ",\n"
              << "  \"cqe_reaped\": " << static_cast<long>(cqe) << ",\n"
              << "  \"latency_avg_ms\": " << avg_ms << ",\n"
              << "  \"latency_p50_ms\": " << p50_ms << ",\n"
              << "  \"latency_p90_ms\": " << p90_ms << ",\n"
              << "  \"latency_p95_ms\": " << p95_ms << ",\n"
              << "  \"latency_p99_ms\": " << p99_ms << ",\n"
              << "  \"latency_max_ms\": " << max_ms << "\n"
              << "}\n";
  } else {
    std::printf("\n================================================================================\n");
    std::printf("[TASK-TEST-L3-02 BENCHMARK: %s | Reactor: %s]\n", mode_str.c_str(), reactor_str.c_str());
    std::printf("  Requests Completed: %ld / %d (%.2f%% HTTP 200)\n",
                static_cast<long>(status_2xx), requests,
                requests > 0 ? (status_2xx / requests * 100.0) : 0.0);
    std::printf("  Connections:        %ld (Target: %d)\n", static_cast<long>(conn_established), concurrency);
    std::printf("  Streams / Conn:     Target=%d, Peak=%ld\n", streams, static_cast<long>(active_streams_peak));
    std::printf("  GOAWAY Frames:      %ld (DoD requirement: 0)\n", static_cast<long>(goaway_count));
    std::printf("  Errors:             %ld\n", static_cast<long>(errors));
    std::printf("  Duration (T):       %.4f s\n", duration_sec);
    std::printf("  Throughput (RPS):   %.2f req/s\n", rps);
    std::printf("  Data Transferred:   Tx=%.2f KB, Rx=%.2f KB\n", tx_bytes / 1024.0, rx_bytes / 1024.0);
    std::printf("  Latency P50:        %.4f ms\n", p50_ms);
    std::printf("  Latency P95:        %.4f ms\n", p95_ms);
    std::printf("  Latency P99:        %.4f ms\n", p99_ms);
    std::printf("================================================================================\n\n");
  }

  if (static_cast<long>(status_2xx) != requests || errors > 0.0 || goaway_count > 0.0) {
    std::fprintf(stderr, "FAIL: benchmark expectations failed (status_2xx=%ld, errors=%ld, goaway=%ld)\n",
                 static_cast<long>(status_2xx), static_cast<long>(errors), static_cast<long>(goaway_count));
    return 1;
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  bool is_benchmark = false;
  bool is_test = false;
  int requests = 10000;
  int concurrency = 1;
  int streams = 100;
  bool use_tls = true;
  bool want_ktls = false;
  bool force_epoll = false;
  bool json_output = false;
  std::string target_ip = "127.0.0.1";
  int port = 0;

  const char* port_env = std::getenv("H2_TEST_PORT");
  if (port_env != nullptr && *port_env != '\0') {
    port = std::atoi(port_env);
  }
  const char* bench_env = std::getenv("H2_BENCHMARK");
  if (bench_env != nullptr && *bench_env != '\0' && *bench_env != '0') {
    is_benchmark = true;
  }
  const char* tls_env = std::getenv("H2_TEST_TLS");
  if (tls_env != nullptr && *tls_env != '\0') {
    use_tls = (*tls_env != '0');
  }
  const char* ktls_env = std::getenv("H2_TEST_KTLS");
  if (ktls_env != nullptr && *ktls_env != '\0') {
    want_ktls = (*ktls_env != '0');
  }
  const char* epoll_env = std::getenv("H2_TEST_EPOLL");
  if (epoll_env != nullptr && *epoll_env != '\0') {
    force_epoll = (*epoll_env != '0');
  }
  const char* json_env = std::getenv("H2_TEST_JSON");
  if (json_env != nullptr && *json_env != '\0' && *json_env != '0') {
    json_output = true;
  }
  const char* reqs_env = std::getenv("H2_TEST_REQS");
  if (reqs_env != nullptr && *reqs_env != '\0') {
    requests = std::max(1, std::atoi(reqs_env));
  }
  const char* conns_env = std::getenv("H2_TEST_CONNS");
  if (conns_env != nullptr && *conns_env != '\0') {
    concurrency = std::max(1, std::atoi(conns_env));
  }
  const char* streams_env = std::getenv("H2_TEST_STREAMS");
  if (streams_env != nullptr && *streams_env != '\0') {
    streams = std::max(1, std::atoi(streams_env));
  }

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--benchmark") {
      is_benchmark = true;
    } else if (arg == "--test") {
      is_test = true;
    } else if (arg == "--requests" && i + 1 < argc) {
      requests = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--concurrency" && i + 1 < argc) {
      concurrency = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--streams" && i + 1 < argc) {
      streams = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--host" && i + 1 < argc) {
      target_ip = argv[++i];
    } else if (arg == "--tls") {
      use_tls = true;
    } else if (arg == "--no-tls") {
      use_tls = false;
    } else if (arg == "--ktls") {
      use_tls = true;
      want_ktls = true;
    } else if (arg == "--memory-bio") {
      use_tls = true;
      want_ktls = false;
    } else if (arg == "--epoll") {
      force_epoll = true;
    } else if (arg == "--json") {
      json_output = true;
    }
  }

  if (is_benchmark) {
    return RunBenchmark(requests, concurrency, streams, use_tls, want_ktls, force_epoll, target_ip, port, json_output);
  }

  return RunRegressionTest();
}
