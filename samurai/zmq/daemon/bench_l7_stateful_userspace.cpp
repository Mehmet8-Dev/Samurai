#include <arpa/inet.h>
#include <sched.h>
#include <sys/resource.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "bridge.hpp"
#include "engine.hpp"
#include "json.hpp"
#include "stateful_fastpath.hpp"
#include "custom_quic_stack/quic_cuda_crypto.hpp"

#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

namespace {

void WriteBe16(std::uint8_t* p, std::uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
void WriteBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF;
}
std::uint16_t ReadBe16(const std::uint8_t* p) { return (p[0] << 8) | p[1]; }
std::uint32_t ReadBe32(const std::uint8_t* p) {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
         (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

constexpr std::uint8_t kFin = 0x01, kSyn = 0x02, kRst = 0x04, kPsh = 0x08, kAck = 0x10;

std::uint32_t Ipv4(const char* s) {
  in_addr a{};
  inet_pton(AF_INET, s, &a);
  return ntohl(a.s_addr);
}

struct MemoryStats {
  long vmrss_kb{0};
  long vmpeak_kb{0};
  long vmdata_kb{0};
};

MemoryStats ReadProcMemory() {
  MemoryStats stats;
  std::ifstream f("/proc/self/status");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      std::sscanf(line.c_str(), "VmRSS: %ld", &stats.vmrss_kb);
    } else if (line.rfind("VmPeak:", 0) == 0) {
      std::sscanf(line.c_str(), "VmPeak: %ld", &stats.vmpeak_kb);
    } else if (line.rfind("VmData:", 0) == 0) {
      std::sscanf(line.c_str(), "VmData: %ld", &stats.vmdata_kb);
    }
  }
  return stats;
}

struct LatencyStats {
  double min_ms{0.0};
  double p50_ms{0.0};
  double p90_ms{0.0};
  double p95_ms{0.0};
  double p99_ms{0.0};
  double max_ms{0.0};
  double avg_ms{0.0};
};

LatencyStats ComputeLatencyStats(std::vector<double> lats) {
  LatencyStats s{};
  if (lats.empty()) return s;
  std::sort(lats.begin(), lats.end());
  s.min_ms = lats.front();
  s.max_ms = lats.back();
  double sum = 0.0;
  for (double v : lats) sum += v;
  s.avg_ms = sum / static_cast<double>(lats.size());
  auto pct = [&](double p) {
    std::size_t idx = static_cast<std::size_t>(p * static_cast<double>(lats.size() - 1));
    return lats[idx];
  };
  s.p50_ms = pct(0.50);
  s.p90_ms = pct(0.90);
  s.p95_ms = pct(0.95);
  s.p99_ms = pct(0.99);
  return s;
}

struct StatefulHttpPeerShim : samurai::daemon::FastpathTxRxShim {
  std::deque<std::vector<std::uint8_t>> rx;
  std::unordered_map<std::uint64_t, std::uint32_t> peer_next;
  std::uint32_t iss_gen = 0x51000000u;
  int responses_sent = 0;
  int syns_seen = 0, synacks_sent = 0, data_seen = 0, frames_seen = 0, frames_delivered = 0;

  static std::uint64_t Key(std::uint32_t ip, std::uint16_t port) {
    return (std::uint64_t(ip) << 16) | port;
  }

  std::vector<std::uint8_t> BuildFrame(
      std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port,
      std::uint16_t dst_port, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
      const std::string& payload) {
    std::vector<std::uint8_t> f(54 + payload.size(), 0);
    WriteBe16(f.data() + 12, 0x0800);
    f[14] = 0x45;
    WriteBe16(f.data() + 16, static_cast<std::uint16_t>(40 + payload.size()));
    f[22] = 64; f[23] = 6;
    WriteBe32(f.data() + 26, src_ip);
    WriteBe32(f.data() + 30, dst_ip);
    WriteBe16(f.data() + 34, src_port);
    WriteBe16(f.data() + 36, dst_port);
    WriteBe32(f.data() + 38, seq);
    WriteBe32(f.data() + 42, ack);
    f[46] = 0x50; f[47] = flags;
    WriteBe16(f.data() + 48, 65535);
    if (!payload.empty()) std::memcpy(f.data() + 54, payload.data(), payload.size());
    return f;
  }

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    (void)err;
    frames_seen += static_cast<int>(count);
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::uint8_t* pkt = base + std::size_t(i) * stride;
      if (psize < 54 || ReadBe16(pkt + 12) != 0x0800 || pkt[23] != 6) continue;
      const std::uint16_t ip_total = ReadBe16(pkt + 16);
      const std::uint8_t flags = pkt[47];
      const std::uint32_t cli_ip = ReadBe32(pkt + 26);
      const std::uint32_t srv_ip = ReadBe32(pkt + 30);
      const std::uint16_t cli_port = ReadBe16(pkt + 34);
      const std::uint16_t srv_port = ReadBe16(pkt + 36);
      const std::uint32_t cli_seq = ReadBe32(pkt + 38);
      const std::size_t payload_len = ip_total >= 40 ? ip_total - 40 : 0;
      const std::uint64_t key = Key(cli_ip, cli_port);

      if ((flags & kSyn) && !(flags & kAck)) {
        ++syns_seen;
        const std::uint32_t my_iss = ++iss_gen;
        peer_next[key] = my_iss + 1;
        rx.push_back(BuildFrame(srv_ip, cli_ip, srv_port, cli_port,
                                my_iss, cli_seq + 1, kSyn | kAck, ""));
        ++synacks_sent;
      } else if (payload_len > 0) {
        ++data_seen;
        std::uint32_t& pseq = peer_next[key];
        const std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
        const std::uint32_t cli_next = cli_seq + static_cast<std::uint32_t>(payload_len);
        rx.push_back(BuildFrame(srv_ip, cli_ip, srv_port, cli_port,
                                pseq, cli_next, kPsh | kAck, resp));
        pseq += static_cast<std::uint32_t>(resp.size());
        ++responses_sent;
      } else if (flags & kFin) {
        auto it = peer_next.find(key);
        if (it != peer_next.end()) {
          rx.push_back(BuildFrame(srv_ip, cli_ip, srv_port, cli_port,
                                  it->second, cli_seq + 1, kAck, ""));
          peer_next.erase(it);
        }
      }
    }
    return static_cast<int>(count);
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    int n = 0;
    while (n < int(max) && !rx.empty()) {
      const auto& f = rx.front();
      std::memcpy(out + std::size_t(n) * stride, f.data(), f.size());
      lens[n] = static_cast<std::uint16_t>(f.size());
      rx.pop_front();
      ++n;
    }
    frames_delivered += n;
    return n;
  }
  bool RxAvailable() const override { return true; }
};

#ifdef SAMURAI_WITH_NGHTTP2
struct H2PeerShim : samurai::daemon::FastpathTxRxShim {
  struct Flow {
    nghttp2_session* session{nullptr};
    std::uint32_t peer_seq{0};
    std::uint32_t cli_ack{0};
    std::uint32_t srv_ip{0}, cli_ip{0};
    std::uint16_t srv_port{0}, cli_port{0};
  };
  std::deque<std::vector<std::uint8_t>> rx;
  std::unordered_map<std::uint64_t, Flow> flows;
  std::uint32_t iss_gen = 0x71000000u;
  int responses_sent = 0;
  int syns_seen = 0, synacks_sent = 0, data_seen = 0, frames_seen = 0, frames_delivered = 0;

  ~H2PeerShim() override {
    for (auto& kv : flows) {
      if (kv.second.session) nghttp2_session_del(kv.second.session);
    }
  }

  static std::uint64_t Key(std::uint32_t ip, std::uint16_t port) {
    return (std::uint64_t(ip) << 16) | port;
  }

  std::vector<std::uint8_t> BuildFrame(
      std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port,
      std::uint16_t dst_port, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
      const std::string& payload) {
    std::vector<std::uint8_t> f(54 + payload.size(), 0);
    WriteBe16(f.data() + 12, 0x0800);
    f[14] = 0x45;
    WriteBe16(f.data() + 16, static_cast<std::uint16_t>(40 + payload.size()));
    f[22] = 64; f[23] = 6;
    WriteBe32(f.data() + 26, src_ip);
    WriteBe32(f.data() + 30, dst_ip);
    WriteBe16(f.data() + 34, src_port);
    WriteBe16(f.data() + 36, dst_port);
    WriteBe32(f.data() + 38, seq);
    WriteBe32(f.data() + 42, ack);
    f[46] = 0x50; f[47] = flags;
    WriteBe16(f.data() + 48, 65535);
    if (!payload.empty()) std::memcpy(f.data() + 54, payload.data(), payload.size());
    return f;
  }

  static ssize_t DataRead(nghttp2_session*, std::int32_t, std::uint8_t* buf, std::size_t length,
                          std::uint32_t* data_flags, nghttp2_data_source*, void*) {
    static const char kBody[] = "hi";
    std::size_t n = sizeof(kBody) - 1;
    if (n > length) n = length;
    std::memcpy(buf, kBody, n);
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(n);
  }

  static int OnFrameRecv(nghttp2_session* s, const nghttp2_frame* f, void* user) {
    auto* self = static_cast<H2PeerShim*>(user);
    if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      nghttp2_nv nv[] = {
          {(std::uint8_t*)":status", (std::uint8_t*)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
          {(std::uint8_t*)"content-length", (std::uint8_t*)"2", 14, 1, NGHTTP2_NV_FLAG_NONE},
      };
      nghttp2_data_provider prd{};
      prd.read_callback = &H2PeerShim::DataRead;
      nghttp2_submit_response(s, f->hd.stream_id, nv, 2, &prd);
      self->responses_sent += 1;
    }
    return 0;
  }

  Flow& EnsureFlow(std::uint64_t key, std::uint32_t srv_ip, std::uint32_t cli_ip,
                   std::uint16_t srv_port, std::uint16_t cli_port) {
    Flow& fl = flows[key];
    if (fl.session == nullptr) {
      nghttp2_session_callbacks* cbs = nullptr;
      nghttp2_session_callbacks_new(&cbs);
      nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, &H2PeerShim::OnFrameRecv);
      nghttp2_session_server_new(&fl.session, cbs, this);
      nghttp2_session_callbacks_del(cbs);
      nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
      nghttp2_submit_settings(fl.session, NGHTTP2_FLAG_NONE, iv, 1);
      fl.srv_ip = srv_ip; fl.cli_ip = cli_ip; fl.srv_port = srv_port; fl.cli_port = cli_port;
    }
    return fl;
  }

  void PumpOut(Flow& fl) {
    std::string outbuf;
    const std::uint8_t* data = nullptr;
    for (;;) {
      const ssize_t n = nghttp2_session_mem_send(fl.session, &data);
      if (n <= 0) break;
      outbuf.append(reinterpret_cast<const char*>(data), static_cast<std::size_t>(n));
    }
    if (!outbuf.empty()) {
      rx.push_back(BuildFrame(fl.srv_ip, fl.cli_ip, fl.srv_port, fl.cli_port,
                              fl.peer_seq, fl.cli_ack, kPsh | kAck, outbuf));
      fl.peer_seq += static_cast<std::uint32_t>(outbuf.size());
    }
  }

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    (void)err;
    frames_seen += static_cast<int>(count);
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::uint8_t* pkt = base + std::size_t(i) * stride;
      if (psize < 54 || ReadBe16(pkt + 12) != 0x0800 || pkt[23] != 6) continue;
      const std::uint16_t ip_total = ReadBe16(pkt + 16);
      const std::uint8_t flags = pkt[47];
      const std::uint32_t cli_ip = ReadBe32(pkt + 26);
      const std::uint32_t srv_ip = ReadBe32(pkt + 30);
      const std::uint16_t cli_port = ReadBe16(pkt + 34);
      const std::uint16_t srv_port = ReadBe16(pkt + 36);
      const std::uint32_t cli_seq = ReadBe32(pkt + 38);
      const std::size_t payload_len = ip_total >= 40 ? ip_total - 40 : 0;
      const std::uint64_t key = Key(cli_ip, cli_port);

      if ((flags & kSyn) && !(flags & kAck)) {
        ++syns_seen;
        const std::uint32_t my_iss = ++iss_gen;
        Flow& fl = EnsureFlow(key, srv_ip, cli_ip, srv_port, cli_port);
        fl.peer_seq = my_iss + 1;
        fl.cli_ack = cli_seq + 1;
        rx.push_back(BuildFrame(srv_ip, cli_ip, srv_port, cli_port,
                                my_iss, cli_seq + 1, kSyn | kAck, ""));
        ++synacks_sent;
      } else if (payload_len > 0) {
        ++data_seen;
        Flow& fl = EnsureFlow(key, srv_ip, cli_ip, srv_port, cli_port);
        fl.cli_ack = cli_seq + static_cast<std::uint32_t>(payload_len);
        nghttp2_session_mem_recv(fl.session, pkt + 54, payload_len);
        PumpOut(fl);
      } else if (flags & kFin) {
        auto it = flows.find(key);
        if (it != flows.end()) {
          Flow& fl = it->second;
          rx.push_back(BuildFrame(fl.srv_ip, fl.cli_ip, fl.srv_port, fl.cli_port,
                                  fl.peer_seq, cli_seq + 1, kAck, ""));
          if (fl.session != nullptr) {
            nghttp2_session_del(fl.session);
            fl.session = nullptr;
          }
          flows.erase(it);
        }
      }
    }
    return static_cast<int>(count);
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    int n = 0;
    while (n < int(max) && !rx.empty()) {
      const auto& f = rx.front();
      std::memcpy(out + std::size_t(n) * stride, f.data(), f.size());
      lens[n] = static_cast<std::uint16_t>(f.size());
      rx.pop_front();
      ++n;
    }
    frames_delivered += n;
    return n;
  }
  bool RxAvailable() const override { return true; }
};
#endif  // SAMURAI_WITH_NGHTTP2

}  // namespace

struct BenchMetricResult {
  std::string protocol;
  int concurrency{1};
  int total_flows{0};
  double duration_sec{0.0};
  std::uint64_t attempted{0};
  std::uint64_t sent{0};
  std::uint64_t errors{0};
  std::uint64_t status_2xx{0};
  double cps{0.0};
  double rps{0.0};
  double tx_mbytes{0.0};
  double rx_mbytes{0.0};
  std::uint64_t tx_packets{0};
  std::uint64_t rx_frames{0};
  LatencyStats latency;
  long rss_before_kb{0};
  long rss_after_kb{0};
  long rss_peak_kb{0};
  long rss_delta_kb{0};
  double bytes_per_flow{0.0};
};

BenchMetricResult BenchmarkH1(int concurrency, int flows, int keepalive) {
  BenchMetricResult res;
  res.protocol = "HTTP/1.1 (Userspace TCP)";
  res.concurrency = concurrency;
  res.total_flows = flows;

  const auto mem_before = ReadProcMemory();
  res.rss_before_kb = mem_before.vmrss_kb;

  using samurai::core::json::Value;
  Value profile = Value::Object();
  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str("dpdk_direct"));
  conn.set("target_ip", Value::Str("10.0.0.3"));
  conn.set("target_port", Value::Int(80));
  conn.set("scheme", Value::Str("http"));
  conn.set("host_header", Value::Str("10.0.0.3"));
  conn.set("keepalive", Value::Int(keepalive));
  // Eşzamanlı bağlantı havuzu (Concurrency Pool Window):
  // 100k akış test edilirken tüm akışlar için aynı anda 100k lane tahsis edilmez.
  // Gerçekçi bir eşzamanlı bağlantı penceresi (shard başına 200 lane)
  // kullanılarak 100k istek havuza beslenir ve bellek kullanımı O(1) sabit tutulur.
  const int pool_size = std::min(flows, std::max(100, concurrency * 200));
  conn.set("max_connections", Value::Int(pool_size));
  conn.set("max_streams_per_connection", Value::Int(1));
  conn.set("session_repeats", Value::Int(flows));
  conn.set("timeout_ms", Value::Int(30000));
  profile.set("connection_template", conn);
  profile.set("flow_attempted", Value::Int(flows));
  profile.set("protocol", Value::Str("http1"));

  Value op = Value::Object();
  op.set("opcode", Value::Str("SEND_HEADERS"));
  op.set("method", Value::Str("GET"));
  op.set("path", Value::Str("/"));
  Value ops = Value::Array();
  for (int i = 0; i < flows; ++i) ops.push_back(op);
  Value fp = Value::Object();
  fp.set("ops", ops);
  profile.set("flow_program", fp);

  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(concurrency));
  cfg.set("profile_l7", Value::Int(1));

  const auto t0 = std::chrono::steady_clock::now();
  Value json_result = samurai::l7_emu_native::run_profile_json(profile, cfg);
  const auto t1 = std::chrono::steady_clock::now();

  const double dur = std::chrono::duration<double>(t1 - t0).count();
  res.duration_sec = dur > 1e-6 ? dur : 1e-6;

  const auto mem_after = ReadProcMemory();
  res.rss_after_kb = mem_after.vmrss_kb;
  res.rss_peak_kb = mem_after.vmpeak_kb;
  res.rss_delta_kb = std::max(0L, res.rss_after_kb - res.rss_before_kb);
  res.bytes_per_flow = flows > 0 ? (res.rss_delta_kb * 1024.0) / flows : 0.0;

  auto ru64 = [&](const char* k) -> std::uint64_t {
    const Value* v = json_result.find(k);
    return (v && v->is_number()) ? static_cast<std::uint64_t>(std::max(0.0, v->as_double())) : 0u;
  };

  res.attempted = ru64("attempted");
  res.sent = ru64("sent");
  res.errors = ru64("errors");
  res.status_2xx = ru64("status_2xx");
  const std::uint64_t conn_est = ru64("tcp_connect_established");
  res.tx_packets = ru64("tcp_connect_attempts") + res.sent + ru64("tcp_rx_ack_count");
  res.rx_frames = conn_est + ru64("responses_total") + ru64("tcp_rx_ack_count");
  res.tx_mbytes = static_cast<double>(ru64("l7_tx_bytes")) / (1024.0 * 1024.0);
  res.rx_mbytes = static_cast<double>(ru64("l7_rx_bytes")) / (1024.0 * 1024.0);

  res.cps = static_cast<double>(conn_est > 0 ? conn_est : res.status_2xx) / res.duration_sec;
  res.rps = static_cast<double>(res.status_2xx) / res.duration_sec;

  // Extract latencies
  std::vector<double> latencies;
  auto step_results = samurai::l7_emu_native::consume_last_scenario_step_results();
  for (const auto& step : step_results) {
    latencies.push_back(step.latency_ms);
  }
  if (latencies.empty()) {
    const Value* steps = json_result.find("scenario_step_results");
    if (steps && steps->is_array()) {
      for (const auto& item : steps->elements()) {
        const Value* lat = item.find("latency_ms");
        if (lat && lat->is_number()) {
          latencies.push_back(lat->as_double());
        }
      }
    }
  }
  res.latency = ComputeLatencyStats(latencies);

  return res;
}

#ifdef SAMURAI_WITH_NGHTTP2
BenchMetricResult BenchmarkH2(int concurrency, int flows, int keepalive) {
  BenchMetricResult res;
  res.protocol = "HTTP/2 h2c (Userspace TCP)";
  res.concurrency = concurrency;
  res.total_flows = flows;

  const auto mem_before = ReadProcMemory();
  res.rss_before_kb = mem_before.vmrss_kb;

  using samurai::core::json::Value;
  Value profile = Value::Object();
  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str("dpdk_direct"));
  conn.set("target_ip", Value::Str("10.0.0.3"));
  conn.set("target_port", Value::Int(80));
  conn.set("scheme", Value::Str("http"));
  conn.set("host_header", Value::Str("10.0.0.3"));
  conn.set("keepalive", Value::Int(keepalive));
  const int pool_size = std::min(flows, std::max(100, concurrency * 200));
  conn.set("max_connections", Value::Int(pool_size));
  conn.set("max_streams_per_connection", Value::Int(1));
  conn.set("session_repeats", Value::Int(flows));
  conn.set("timeout_ms", Value::Int(30000));
  profile.set("connection_template", conn);
  profile.set("flow_attempted", Value::Int(flows));
  profile.set("protocol", Value::Str("http2"));

  Value op = Value::Object();
  op.set("opcode", Value::Str("SEND_HEADERS"));
  op.set("method", Value::Str("GET"));
  op.set("path", Value::Str("/"));
  Value ops = Value::Array();
  for (int i = 0; i < flows; ++i) ops.push_back(op);
  Value fp = Value::Object();
  fp.set("ops", ops);
  profile.set("flow_program", fp);

  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(concurrency));
  cfg.set("profile_l7", Value::Int(1));

  const auto t0 = std::chrono::steady_clock::now();
  Value json_result = samurai::l7_emu_native::run_profile_json(profile, cfg);
  const auto t1 = std::chrono::steady_clock::now();

  const double dur = std::chrono::duration<double>(t1 - t0).count();
  res.duration_sec = dur > 1e-6 ? dur : 1e-6;

  const auto mem_after = ReadProcMemory();
  res.rss_after_kb = mem_after.vmrss_kb;
  res.rss_peak_kb = mem_after.vmpeak_kb;
  res.rss_delta_kb = std::max(0L, res.rss_after_kb - res.rss_before_kb);
  res.bytes_per_flow = flows > 0 ? (res.rss_delta_kb * 1024.0) / flows : 0.0;

  auto ru64 = [&](const char* k) -> std::uint64_t {
    const Value* v = json_result.find(k);
    return (v && v->is_number()) ? static_cast<std::uint64_t>(std::max(0.0, v->as_double())) : 0u;
  };

  res.attempted = ru64("attempted");
  res.sent = ru64("sent");
  res.errors = ru64("errors");
  res.status_2xx = ru64("status_2xx");
  const std::uint64_t conn_est = ru64("tcp_connect_established");
  res.tx_packets = ru64("tcp_connect_attempts") + res.sent + ru64("tcp_rx_ack_count");
  res.rx_frames = conn_est + ru64("responses_total") + ru64("tcp_rx_ack_count");
  res.tx_mbytes = static_cast<double>(ru64("l7_tx_bytes")) / (1024.0 * 1024.0);
  res.rx_mbytes = static_cast<double>(ru64("l7_rx_bytes")) / (1024.0 * 1024.0);

  res.cps = static_cast<double>(conn_est > 0 ? conn_est : res.status_2xx) / res.duration_sec;
  res.rps = static_cast<double>(res.status_2xx) / res.duration_sec;

  // Extract latencies
  std::vector<double> latencies;
  auto step_results = samurai::l7_emu_native::consume_last_scenario_step_results();
  for (const auto& step : step_results) {
    latencies.push_back(step.latency_ms);
  }
  if (latencies.empty()) {
    const Value* steps = json_result.find("scenario_step_results");
    if (steps && steps->is_array()) {
      for (const auto& item : steps->elements()) {
        const Value* lat = item.find("latency_ms");
        if (lat && lat->is_number()) {
          latencies.push_back(lat->as_double());
        }
      }
    }
  }
  res.latency = ComputeLatencyStats(latencies);

  return res;
}
#endif

BenchMetricResult BenchmarkH3(int concurrency, int requests, int h3_port) {
  BenchMetricResult res;
  res.protocol = "HTTP/3 QUIC (ngtcp2+nghttp3)";
  res.concurrency = concurrency;
  res.total_flows = requests;

  const auto mem_before = ReadProcMemory();
  res.rss_before_kb = mem_before.vmrss_kb;

  samurai::l7_emu_native::Profile profile;
  profile.protocol = "quic";
  if (h3_port <= 0) {
    std::fprintf(stderr, "[ERROR] BenchmarkH3 requires an active HTTP/3 server port (h3_port > 0). Mock peer removed.\n");
    res.duration_sec = 0.001;
    res.errors = requests;
    return res;
  }
  profile.transport_backend = "kernel_socket";
  profile.target_port = h3_port;
  profile.stateful_runtime_backend = "kernel";
  profile.target_ip = "127.0.0.1";
  profile.scheme = "https";
  profile.host_header = "localhost";
  profile.verify = 0;
  profile.keepalive = 1;
  profile.timeout_ms = 8000;
  profile.max_connections = concurrency;
  if (const char* mc = std::getenv("SAMURAI_QUIC_MAX_CONNS"); mc != nullptr && mc[0] != '\0') {
    profile.max_connections = std::max(1, std::atoi(mc));
  }
  profile.max_streams_per_connection = 10;
  if (const char* sm = std::getenv("SAMURAI_QUIC_STREAMS_PER_CONN"); sm != nullptr && sm[0] != '\0') {
    profile.max_streams_per_connection = std::max(1, std::atoi(sm));
  }
  profile.flow_attempted = requests;

  samurai::l7_emu_native::FlowOp op;
  op.opcode = "SEND_HEADERS";
  op.method = "GET";
  op.path = "/";
  profile.ops.push_back(op);

  samurai::l7_emu_native::RuntimeConfig cfg;
  cfg.concurrency = concurrency;
  cfg.profile_l7 = 1;

  const auto t0 = std::chrono::steady_clock::now();
  const std::map<std::string, double> result =
      samurai::l7_emu_native::run_profile(profile, cfg);
  const auto t1 = std::chrono::steady_clock::now();

  const double dur = std::chrono::duration<double>(t1 - t0).count();
  res.duration_sec = dur > 1e-6 ? dur : 1e-6;

  const auto mem_after = ReadProcMemory();
  res.rss_after_kb = mem_after.vmrss_kb;
  res.rss_peak_kb = mem_after.vmpeak_kb;
  res.rss_delta_kb = std::max(0L, res.rss_after_kb - res.rss_before_kb);
  res.bytes_per_flow = requests > 0 ? (res.rss_delta_kb * 1024.0) / requests : 0.0;

  auto get_val = [&](const char* k) -> double {
    auto it = result.find(k);
    return it != result.end() ? it->second : 0.0;
  };

  res.attempted = static_cast<std::uint64_t>(get_val("quic_requests_sent"));
  res.sent = static_cast<std::uint64_t>(get_val("quic_requests_sent"));
  res.status_2xx = static_cast<std::uint64_t>(get_val("quic_responses_received"));
  res.errors = static_cast<std::uint64_t>(get_val("quic_errors"));
  res.tx_packets = static_cast<std::uint64_t>(get_val("quic_tx_datagrams"));
  res.rx_frames = static_cast<std::uint64_t>(get_val("quic_rx_datagrams"));
  res.tx_mbytes = get_val("l7_tx_bytes") / (1024.0 * 1024.0);
  res.rx_mbytes = get_val("l7_rx_bytes") / (1024.0 * 1024.0);

  res.cps = get_val("quic_connection_success") / res.duration_sec;
  res.rps = static_cast<double>(res.status_2xx) / res.duration_sec;

  // Latencies from scenario step results or QUIC stream latency percentiles
  auto step_results = samurai::l7_emu_native::consume_last_scenario_step_results();
  std::vector<double> latencies;
  for (const auto& step : step_results) {
    latencies.push_back(step.latency_ms);
  }
  if (!latencies.empty()) {
    res.latency = ComputeLatencyStats(latencies);
  } else {
    res.latency.p50_ms = get_val("latency_p50_ms");
    res.latency.p95_ms = get_val("latency_p95_ms");
    res.latency.p99_ms = get_val("latency_p99_ms");
    res.latency.max_ms = get_val("quic_scenario_step_latency_ms_max");
    res.latency.avg_ms = get_val("quic_scenario_step_latency_ms_avg");
  }

  return res;
}

void RunCudaCryptoBenchmark(int n_keys = 100000) {
  std::printf("\n========================================================================================================================\n");
  std::printf("                         NVIDIA GPU (CUDA) QUIC CRYPTO COPROCESSOR ENGINE BENCHMARK                              \n");
  std::printf("========================================================================================================================\n");

  if (!samurai::l7_emu_native::custom_quic_stack::quic_cuda_crypto_available()) {
    std::printf("[CUDA CRYPTO] No CUDA-capable NVIDIA GPU detected. Skipping GPU microbenchmarks.\n");
    return;
  }

  // 1. Warm-up and Selftest against official RFC 9001 Appendix A.1
  const bool selftest_ok = samurai::l7_emu_native::custom_quic_stack::quic_cuda_crypto_selftest();
  std::printf("[CUDA CRYPTO] Self-test against IETF RFC 9001 Appendix A.1: %s\n",
              selftest_ok ? "PASS (Byte-Exact Match)" : "FAIL");

  // 2. Initial Key Derivation Batch Benchmark:
  // HKDF-Extract + HKDF-Expand-Label (client in, quic key, quic iv, quic hp) over SHA-256
  std::vector<int> test_scales = {10000, 50000, n_keys};
  for (int scale : test_scales) {
    std::vector<uint8_t> dcids(scale * 8u);
    std::vector<uint8_t> scids(scale * 8u);
    std::vector<samurai::l7_emu_native::custom_quic_stack::QuicInitialKeyMaterial> out_materials(scale);

    for (std::size_t i = 0; i < dcids.size(); ++i) dcids[i] = static_cast<uint8_t>(i ^ 0x5a);
    for (std::size_t i = 0; i < scids.size(); ++i) scids[i] = static_cast<uint8_t>(i ^ 0xa5);

    uint64_t elapsed_ns = 0;
    const auto t0 = std::chrono::steady_clock::now();
    samurai::l7_emu_native::custom_quic_stack::quic_cuda_derive_initial_keys_batch(
        dcids.data(), scids.data(), scale, out_materials.data(), &elapsed_ns);
    const auto t1 = std::chrono::steady_clock::now();
    const double wall_sec = std::chrono::duration<double>(t1 - t0).count();
    const double gpu_sec = static_cast<double>(elapsed_ns) / 1e9;
    const double keys_per_sec = static_cast<double>(scale) / (gpu_sec > 1e-9 ? gpu_sec : wall_sec);

    std::printf("  [GPU Initial Key Deriv] Scale: %-7d conns | GPU Kernel: %6.2f ms | Wall: %6.2f ms | Throughput: %10.1f keys/sec (%.2f Mkeys/s)\n",
                scale, gpu_sec * 1000.0, wall_sec * 1000.0, keys_per_sec, keys_per_sec / 1e6);
  }

  // 3. RFC 9001 Section 5.4.3 AES-128-ECB Header Protection Mask Generation Benchmark
  for (int scale : test_scales) {
    std::vector<uint8_t> hp_keys(scale * 16u, 0x3d);
    std::vector<uint8_t> samples(scale * 16u, 0x8a);
    std::vector<uint8_t> masks(scale * 5u, 0);

    uint64_t elapsed_ns = 0;
    const auto t0 = std::chrono::steady_clock::now();
    samurai::l7_emu_native::custom_quic_stack::quic_cuda_aes128_hp_mask_batch(
        hp_keys.data(), samples.data(), scale, masks.data(), &elapsed_ns);
    const auto t1 = std::chrono::steady_clock::now();
    const double wall_sec = std::chrono::duration<double>(t1 - t0).count();
    const double gpu_sec = static_cast<double>(elapsed_ns) / 1e9;
    const double masks_per_sec = static_cast<double>(scale) / (gpu_sec > 1e-9 ? gpu_sec : wall_sec);

    std::printf("  [GPU AES-128 HP Mask  ] Scale: %-7d pkts  | GPU Kernel: %6.2f ms | Wall: %6.2f ms | Throughput: %10.1f masks/sec (%.2f Mmasks/s)\n",
                scale, gpu_sec * 1000.0, wall_sec * 1000.0, masks_per_sec, masks_per_sec / 1e6);
  }

  // 4. Batch AEAD Encryption (AES-128-GCM & ChaCha20-Poly1305)
  for (int scale : {10000, std::min(n_keys, 65536)}) {
    constexpr std::size_t kPacketStride = 1452u;
    std::vector<samurai::l7_emu_native::custom_quic_stack::QuicAeadBatchItem> items(scale);
    std::vector<uint8_t> packet_buf(scale * kPacketStride, 0x42);

    for (int i = 0; i < scale; ++i) {
      items[i].aad_len = 25;
      items[i].plaintext_len = 1200;
      items[i].pn_offset = 20;
      items[i].pn_length = 4;
      items[i].pkt_num = static_cast<uint64_t>(i);
    }

    uint64_t gcm_ns = 0;
    samurai::l7_emu_native::custom_quic_stack::quic_cuda_aes128_gcm_encrypt_batch(
        items.data(), packet_buf.data(), kPacketStride, scale, &gcm_ns);
    const double gcm_sec = static_cast<double>(gcm_ns) / 1e9;
    const double gcm_mbytes = (static_cast<double>(scale) * 1200.0) / (1024.0 * 1024.0);
    const double gcm_mbps = gcm_mbytes / (gcm_sec > 1e-9 ? gcm_sec : 1e-6);

    uint64_t chacha_ns = 0;
    samurai::l7_emu_native::custom_quic_stack::quic_cuda_chacha20_poly1305_encrypt_batch(
        items.data(), packet_buf.data(), kPacketStride, scale, &chacha_ns);
    const double chacha_sec = static_cast<double>(chacha_ns) / 1e9;
    const double chacha_mbytes = (static_cast<double>(scale) * 1200.0) / (1024.0 * 1024.0);
    const double chacha_mbps = chacha_mbytes / (chacha_sec > 1e-9 ? chacha_sec : 1e-6);

    std::printf("  [GPU AES-128-GCM AEAD ] Scale: %-7d pkts  | GPU Kernel: %6.2f ms | Data: %6.1f MB  | Throughput: %8.1f MB/s (%8.0f PPS)\n",
                scale, gcm_sec * 1000.0, gcm_mbytes, gcm_mbps, static_cast<double>(scale) / (gcm_sec > 1e-9 ? gcm_sec : 1e-6));
    std::printf("  [GPU ChaCha20-Poly1305] Scale: %-7d pkts  | GPU Kernel: %6.2f ms | Data: %6.1f MB  | Throughput: %8.1f MB/s (%8.0f PPS)\n",
                scale, chacha_sec * 1000.0, chacha_mbytes, chacha_mbps, static_cast<double>(scale) / (chacha_sec > 1e-9 ? chacha_sec : 1e-6));
  }
  std::printf("========================================================================================================================\n\n");
}

void PrintTable(const std::vector<BenchMetricResult>& results) {
  std::printf("\n========================================================================================================================\n");
  std::printf("                                    L7 STATEFUL USERSPACE ENGINE BENCHMARK REPORT                                       \n");
  std::printf("========================================================================================================================\n");
  std::printf("| %-26s | %-6s | %-6s | %-8s | %-7s | %-10s | %-10s | %-7s | %-7s | %-7s | %-9s |\n",
              "Protocol", "Shards", "Flows", "Time(s)", "Succ%", "CPS", "RPS", "P50(ms)", "P95(ms)", "P99(ms)", "RSS(MB)");
  std::printf("|----------------------------|--------|--------|----------|---------|------------|------------|---------|---------|---------|-----------|\n");

  for (const auto& r : results) {
    const double succ_pct = r.attempted > 0 ? (100.0 * static_cast<double>(r.status_2xx)) / static_cast<double>(r.attempted) : 0.0;
    std::printf("| %-26s | %-6d | %-6d | %8.3f | %6.1f%% | %10.1f | %10.1f | %7.2f | %7.2f | %7.2f | %9.1f |\n",
                r.protocol.c_str(),
                r.concurrency,
                r.total_flows,
                r.duration_sec,
                succ_pct,
                r.cps,
                r.rps,
                r.latency.p50_ms,
                r.latency.p95_ms,
                r.latency.p99_ms,
                static_cast<double>(r.rss_after_kb) / 1024.0);
  }
  std::printf("========================================================================================================================\n\n");
}

void ExportJson(const std::vector<BenchMetricResult>& results, const std::string& path) {
  if (path.empty()) return;
  std::ofstream out(path);
  if (!out.is_open()) return;

  out << "[\n";
  for (std::size_t i = 0; i < results.size(); ++i) {
    const auto& r = results[i];
    out << "  {\n";
    out << "    \"protocol\": \"" << r.protocol << "\",\n";
    out << "    \"concurrency\": " << r.concurrency << ",\n";
    out << "    \"total_flows\": " << r.total_flows << ",\n";
    out << "    \"duration_sec\": " << r.duration_sec << ",\n";
    out << "    \"attempted\": " << r.attempted << ",\n";
    out << "    \"sent\": " << r.sent << ",\n";
    out << "    \"errors\": " << r.errors << ",\n";
    out << "    \"status_2xx\": " << r.status_2xx << ",\n";
    out << "    \"cps\": " << r.cps << ",\n";
    out << "    \"rps\": " << r.rps << ",\n";
    out << "    \"tx_mbytes\": " << r.tx_mbytes << ",\n";
    out << "    \"rx_mbytes\": " << r.rx_mbytes << ",\n";
    out << "    \"tx_packets\": " << r.tx_packets << ",\n";
    out << "    \"rx_frames\": " << r.rx_frames << ",\n";
    out << "    \"latency_min_ms\": " << r.latency.min_ms << ",\n";
    out << "    \"latency_p50_ms\": " << r.latency.p50_ms << ",\n";
    out << "    \"latency_p90_ms\": " << r.latency.p90_ms << ",\n";
    out << "    \"latency_p95_ms\": " << r.latency.p95_ms << ",\n";
    out << "    \"latency_p99_ms\": " << r.latency.p99_ms << ",\n";
    out << "    \"latency_max_ms\": " << r.latency.max_ms << ",\n";
    out << "    \"latency_avg_ms\": " << r.latency.avg_ms << ",\n";
    out << "    \"rss_before_kb\": " << r.rss_before_kb << ",\n";
    out << "    \"rss_after_kb\": " << r.rss_after_kb << ",\n";
    out << "    \"rss_peak_kb\": " << r.rss_peak_kb << ",\n";
    out << "    \"rss_delta_kb\": " << r.rss_delta_kb << ",\n";
    out << "    \"bytes_per_flow\": " << r.bytes_per_flow << "\n";
    out << "  }" << (i + 1 < results.size() ? ",\n" : "\n");
  }
  out << "]\n";
}

int main(int argc, char** argv) {
  setenv("SAMURAI_CUSTOM_TCP_SRC_IP", "10.0.0.2", 1);
  setenv("SAMURAI_CUSTOM_TCP_WIRE", "in_memory", 1);
  setenv("SAMURAI_FASTPATH_BUSY_POLL", "1", 1);

  std::string proto = "all";
  std::string json_path = "";
  int h3_port = 0;
  bool run_gpu_bench = false;
  int gpu_bench_keys = 100000;
  if (const char* p = std::getenv("H3_TEST_PORT"); p != nullptr && *p != '\0') {
    h3_port = std::atoi(p);
  }

  std::vector<int> concurrency_levels = {1, 4, 8, 12};
  int base_flows = 500;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--proto" && i + 1 < argc) {
      proto = argv[++i];
    } else if (arg == "--flows" && i + 1 < argc) {
      base_flows = std::atoi(argv[++i]);
    } else if (arg == "--concurrency" && i + 1 < argc) {
      concurrency_levels = {std::atoi(argv[++i])};
    } else if (arg == "--h3-port" && i + 1 < argc) {
      h3_port = std::atoi(argv[++i]);
    } else if ((arg == "--json" || arg == "--json-out") && i + 1 < argc) {
      json_path = argv[++i];
    } else if (arg == "--gpu-crypto-bench") {
      run_gpu_bench = true;
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        gpu_bench_keys = std::atoi(argv[++i]);
      }
    }
  }

  if (run_gpu_bench) {
    RunCudaCryptoBenchmark(gpu_bench_keys);
  }

  std::printf("[BENCHMARK] Starting L7 Stateful Userspace Suite (proto=%s, base_flows=%d, h3_port=%d)\n",
              proto.c_str(), base_flows, h3_port);

  std::vector<BenchMetricResult> all_results;

  // 1) HTTP/1.1 Benchmarks
  if (proto == "all" || proto == "h1" || proto == "http1") {
    std::printf("\n--- Running L7 H1 Stateful Userspace Benchmarks ---\n");
    for (int conc : concurrency_levels) {
      std::printf("[H1] Testing shards=%d flows=%d...\n", conc, base_flows);
      BenchMetricResult r = BenchmarkH1(conc, base_flows, 0);
      all_results.push_back(r);
      std::printf("     -> Done: %lu/%lu 2xx, RPS=%.1f, P50=%.2fms, P99=%.2fms\n",
                  (unsigned long)r.status_2xx, (unsigned long)r.attempted, r.rps, r.latency.p50_ms, r.latency.p99_ms);
    }
  }

  // 2) HTTP/2 Benchmarks
#ifdef SAMURAI_WITH_NGHTTP2
  if (proto == "all" || proto == "h2" || proto == "http2") {
    std::printf("\n--- Running L7 H2 Stateful Userspace Benchmarks ---\n");
    std::vector<int> h2_concurrency;
    for (int c : concurrency_levels) {
      int ec = (c < 2) ? 2 : c;
      if (std::find(h2_concurrency.begin(), h2_concurrency.end(), ec) == h2_concurrency.end()) {
        h2_concurrency.push_back(ec);
      }
    }
    for (int conc : h2_concurrency) {
      std::printf("[H2] Testing shards=%d flows=%d...\n", conc, base_flows);
      BenchMetricResult r = BenchmarkH2(conc, base_flows, 0);
      all_results.push_back(r);
      std::printf("     -> Done: %lu/%lu 2xx, RPS=%.1f, P50=%.2fms, P99=%.2fms\n",
                  (unsigned long)r.status_2xx, (unsigned long)r.attempted, r.rps, r.latency.p50_ms, r.latency.p99_ms);
    }
  }
#endif

  // 3) HTTP/3 Benchmarks
  if (proto == "all" || proto == "h3" || proto == "http3" || proto == "quic") {
    std::printf("\n--- Running L7 H3 Stateful Userspace Benchmarks (real network port %d) ---\n", h3_port);
    std::vector<int> h3_concurrency = concurrency_levels;
    int h3_requests = base_flows;
    for (int conc : h3_concurrency) {
      std::printf("[H3] Testing workers=%d requests=%d...\n", conc, h3_requests);
      BenchMetricResult r = BenchmarkH3(conc, h3_requests, h3_port);
      all_results.push_back(r);
      std::printf("     -> Done: %lu/%lu 2xx, RPS=%.1f, P50=%.2fms, P99=%.2fms\n",
                  (unsigned long)r.status_2xx, (unsigned long)r.attempted, r.rps, r.latency.p50_ms, r.latency.p99_ms);
    }
  }

  // Final Output
  PrintTable(all_results);
  if (!json_path.empty()) {
    ExportJson(all_results, json_path);
    std::printf("[BENCHMARK] Exported raw metrics to %s\n", json_path.c_str());
  }

  return 0;
}
