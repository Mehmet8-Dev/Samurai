// QUIC/H3 threaded driver end-to-end doğrulaması (gerçek aioquic H3 sunucusu).
//
// run_h3_ngtcp2_client'ın çok-worker fan-out'u (Faz C, KernelSocket) gerçek bir
// HTTP/3 sunucusuna (test_h3_server.py, aioquic) karşı sürülür. Engine gerçek
// ngtcp2+nghttp3 client'ıyla QUIC/TLS1.3 el sıkışır (ALPN h3), N connect'i
// worker'lara paylaştırır (her worker connect()'li kendi UDP soketi → ayrı
// ephemeral src-port, 4-tuple çakışması yok) ve H3 isteklerini koşar.
//
// İki mod koşulur ve KARŞILAŞTIRILIR:
//   (1) threaded  (varsayılan) — çok-worker fan-out
//   (2) serial    (SAMURAI_QUIC_THREADS_DISABLE=1) — tek-thread referans
// İkisi de aynı fonksiyonel sonucu (tüm handshake + istek/yanıt) vermeli;
// bu, threaded yolun doğruluğu bozmadan gerçek H3 sunucusuyla çalıştığını kanıtlar.
//
// Sunucu portu `H3_TEST_PORT` ortam değişkeninden okunur (harness sunucuyu açar).
#include <cstdio>
#include <cstdlib>
#include <map>
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
  return op;
}

Profile MakeProfile(int port, int requests, int conc) {
  Profile profile;
  profile.protocol = "quic";
  profile.transport_backend = "kernel_socket";
  profile.stateful_runtime_backend = "kernel";  // -> QuicUdpIoBackend::KernelSocket
  profile.target_ip = "127.0.0.1";
  profile.target_port = port;
  profile.scheme = "https";
  profile.host_header = "localhost";  // SNI + :authority
  profile.verify = 0;                 // self-signed server cert; skip verification
  profile.keepalive = 1;
  profile.timeout_ms = 5000;
  profile.max_connections = conc;
  // Faz C, BAĞLANTI döngüsünü thread'ledi (stream'i değil). streams=1 → her istek
  // kendi QUIC bağlantısıdır, dolayısıyla `requests` bağlantı `conc` worker'a
  // paylaştırılır ve fan-out doğrudan sürülür. (max_streams_per_connection>1
  // çok-stream drain'i ayrı, thread'lemeden bağımsız bir konudur; seri yolda da
  // aynı timeout'u verir — bu test onu kapsamaz.)
  profile.max_streams_per_connection = 1;
  profile.flow_attempted = requests;        // QUIC istek/bağlantı sayısını bu belirler
  profile.ops.push_back(MakeGet("/"));
  return profile;
}

double Get(const std::map<std::string, double>& out, const char* k) {
  const auto it = out.find(k);
  return it == out.end() ? -1.0 : it->second;
}

void Report(const char* label, const std::map<std::string, double>& out) {
  std::printf(
      "[%s] cap=%.0f conn_success=%.0f req_sent=%.0f resp_recv=%.0f alpn_h3=%.2f "
      "conn_pool=%.0f handshake_ratio=%.2f\n",
      label, Get(out, "quic_capability_available"), Get(out, "quic_connection_success"),
      Get(out, "quic_requests_sent"), Get(out, "quic_responses_received"),
      Get(out, "quic_alpn_h3_ratio"), Get(out, "quic_conn_pool_size"),
      Get(out, "quic_handshake_success_ratio"));
}

void AssertHealthy(const char* label, const std::map<std::string, double>& out, int requests) {
  CHECK(Get(out, "quic_capability_available") == 1.0, "[%s] quic_capability_available != 1", label);
  CHECK(Get(out, "quic_alpn_h3_ratio") == 1.0, "[%s] ALPN h3 not negotiated (ratio=%.2f)", label,
        Get(out, "quic_alpn_h3_ratio"));
  CHECK(Get(out, "quic_requests_sent") == static_cast<double>(requests),
        "[%s] requests_sent=%.0f expected %d", label, Get(out, "quic_requests_sent"), requests);
  CHECK(Get(out, "quic_responses_received") == static_cast<double>(requests),
        "[%s] responses_received=%.0f expected %d", label, Get(out, "quic_responses_received"), requests);
}

}  // namespace

int main() {
  const char* port_env = std::getenv("H3_TEST_PORT");
  if (port_env == nullptr || *port_env == '\0') {
    std::printf("FAIL: H3_TEST_PORT not set (harness must start test_h3_server.py)\n");
    std::fflush(stdout);
    return 2;
  }
  const int port = std::atoi(port_env);
  constexpr int kRequests = 40;
  constexpr int kConcurrency = 4;  // conn_pool = min(max_connections, concurrency)

  RuntimeConfig cfg;
  cfg.concurrency = kConcurrency;
  cfg.profile_l7 = 1;

  // (1) Threaded fan-out (default). conn_pool=4 + 4 planned conns => multi-worker.
  ::unsetenv("SAMURAI_QUIC_THREADS_DISABLE");
  const Profile p_threaded = MakeProfile(port, kRequests, kConcurrency);
  const std::map<std::string, double> threaded = run_profile(p_threaded, cfg);
  Report("threaded", threaded);
  AssertHealthy("threaded", threaded, kRequests);
  // streams=1 => one connection per request; kRequests connections fanned out over
  // 4 workers (conn_plans.size()=kRequests>1 && conn_pool=4>1 => threaded branch).
  CHECK(Get(threaded, "quic_connection_success") == static_cast<double>(kRequests),
        "expected %d established connections (one per request), got %.0f", kRequests,
        Get(threaded, "quic_connection_success"));

  // (2) Serial reference (threads disabled): must match the threaded result.
  ::setenv("SAMURAI_QUIC_THREADS_DISABLE", "1", 1);
  const Profile p_serial = MakeProfile(port, kRequests, kConcurrency);
  const std::map<std::string, double> serial = run_profile(p_serial, cfg);
  Report("serial", serial);
  AssertHealthy("serial", serial, kRequests);
  ::unsetenv("SAMURAI_QUIC_THREADS_DISABLE");

  // Parity: threaded and serial deliver the same request/response outcome.
  CHECK(Get(threaded, "quic_requests_sent") == Get(serial, "quic_requests_sent"),
        "threaded/serial requests_sent mismatch: %.0f vs %.0f",
        Get(threaded, "quic_requests_sent"), Get(serial, "quic_requests_sent"));
  CHECK(Get(threaded, "quic_responses_received") == Get(serial, "quic_responses_received"),
        "threaded/serial responses_received mismatch: %.0f vs %.0f",
        Get(threaded, "quic_responses_received"), Get(serial, "quic_responses_received"));

  if (g_fails == 0) {
    std::printf("ALL KERNEL THREADED H3 TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("KERNEL THREADED H3 TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
