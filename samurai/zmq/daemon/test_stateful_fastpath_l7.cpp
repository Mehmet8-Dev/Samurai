// Faz 2 doğrulaması: gerçek run_profile_json (transport=dpdk_direct) HTTP/1.1
// akışını, StatefulFastpathDriver'ın sahip olduğu wire üzerinden koşar. NIC yok;
// StatefulHttpPeerShim tam bir TCP+HTTP akranı gibi davranır (SYN->SYN-ACK, veri
// istegine 200 OK yanıtı). Böylece Faz-0/2 engine gate'leri + sürücünün L7 thread
// modeli uçtan uca kanıtlanır.

#include <arpa/inet.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "bridge.hpp"
#include "json.hpp"
#include "stateful_fastpath.hpp"
#include <thread>
#include "../../l4/tcp_dataplane_ffi.h"
#include "../../l4/tcp_dataplane_core.hpp"

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

constexpr std::uint8_t kFin = 0x01, kSyn = 0x02, kPsh = 0x08, kAck = 0x10;

struct StatefulHttpPeerShim : samurai::daemon::FastpathTxRxShim {
  std::deque<std::vector<std::uint8_t>> rx;
  std::unordered_map<std::uint64_t, std::uint32_t> peer_next;  // key -> peer sonraki seq
  std::uint32_t iss_gen = 0x51000000u;
  int responses_sent = 0;
  int syns_seen = 0, synacks_sent = 0, data_seen = 0, frames_seen = 0, frames_delivered = 0;

  static std::uint64_t Key(std::uint32_t ip, std::uint16_t port) {
    return (std::uint64_t(ip) << 16) | port;
  }

  // 54(+payload) baytlık IPv4/TCP frame üret (tcpdp BuildPacket düzeni, MAC=0).
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
        // İstek verisi geldi: 200 OK yanıtını PSH|ACK ile geri gönder.
        const std::uint32_t cli_next = cli_seq + static_cast<std::uint32_t>(payload_len);
        std::uint32_t& pseq = peer_next[key];
        const std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
        // Content-Length: 2 yanıt gövdesini tek DATA segmentinde gönder. FIN
        // göndermeyiz: client Content-Length ile tamamlar; FIN'i aynı cycle'da
        // işlemek rx_payload'dan önce peer_fin ile flow'u kapatırdı.
        rx.push_back(BuildFrame(srv_ip, cli_ip, srv_port, cli_port,
                                pseq, cli_next, kPsh | kAck, resp));
        pseq += static_cast<std::uint32_t>(resp.size());
        ++responses_sent;
      }
      // saf ACK / FIN: yok say.
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

std::uint32_t Ipv4(const char* s) { in_addr a{}; inet_pton(AF_INET, s, &a); return ntohl(a.s_addr); }

#ifdef SAMURAI_WITH_NGHTTP2
// h2c (cleartext HTTP/2 over "prior knowledge") loopback peer: her TCP flow'u ayrı
// bir nghttp2 SERVER oturumuna besler. Client preface+SETTINGS+HEADERS gönderir; peer
// mem_recv ile işler, HEADERS(END_STREAM)'te 200+"hi" yanıtını submit eder, mem_send
// çıktısını (server SETTINGS/ACK + response HEADERS/DATA) tek PSH|ACK segmentiyle geri
// çerçeveler. Böylece gerçek nghttp2 reactor'ının custom_tcp/dpdk_direct yolu uçtan uca
// kanıtlanır (H1 peer'ının H2 karşılığı).
struct H2PeerShim : samurai::daemon::FastpathTxRxShim {
  struct Flow {
    nghttp2_session* session{nullptr};
    std::uint32_t peer_seq{0};   // server'ın göndereceği sonraki seq
    std::uint32_t cli_ack{0};    // client baytlarının kümülatif ack'i
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

// flows: eşzamanlı H1 lane sayısı. Her lane ayrı connect + GET/200 döngüsü koşar.
// flows>1 çok-shard (concurrency>1) completion finalizasyonunu zorlar; run_profile
// ana döngüsü tüm shard kuyruklarını boşaltmalıdır (aksi halde sent<flows olur).
bool run_scenario(int flows) {
  using samurai::core::json::Value;
  Value profile = Value::Object();
  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str("dpdk_direct"));
  conn.set("target_ip", Value::Str("10.0.0.3"));
  conn.set("target_port", Value::Int(80));
  conn.set("scheme", Value::Str("http"));
  conn.set("host_header", Value::Str("10.0.0.3"));
  conn.set("keepalive", Value::Int(0));
  conn.set("max_connections", Value::Int(flows));
  conn.set("max_streams_per_connection", Value::Int(1));
  conn.set("session_repeats", Value::Int(flows));
  conn.set("timeout_ms", Value::Int(5000));
  profile.set("connection_template", conn);
  profile.set("flow_attempted", Value::Int(flows));
  profile.set("protocol", Value::Str("http1"));
  {
    const std::string req = "GET / HTTP/1.1\r\nHost: 10.0.0.3\r\nConnection: close\r\n\r\n";
    Value op = Value::Object();
    op.set("opcode", Value::Str("SEND_HEADERS"));
    op.set("method", Value::Str("GET"));
    op.set("path", Value::Str("/"));
    Value body = Value::Object();
    body.set("kind", Value::Str("raw"));
    Value bytes = Value::Array();
    for (char c : req) bytes.push_back(Value::Int(static_cast<std::uint8_t>(c)));
    body.set("bytes", bytes);
    op.set("body", body);
    Value ops = Value::Array();
    for (int i = 0; i < flows; ++i) ops.push_back(op);
    Value fp = Value::Object();
    fp.set("ops", ops);
    profile.set("flow_program", fp);
  }
  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(flows));
  cfg.set("profile_l7", Value::Int(1));

  StatefulHttpPeerShim peer;
  samurai::daemon::StatefulFastpathDriver driver(peer);

  samurai::daemon::FastpathParams params;
  params.dst_ip = Ipv4("10.0.0.3");
  params.dst_port = 80;
  params.max_duration_ms = 12000;
  params.drain_ms = 200;

  // tcpdp'yi (TX ring dahil) önceden yapılandır: L7 yolu (H1 custom_tcp) kendisi
  // configure etmez; sürücü tek wire sahibi olarak ring'i hazır etmelidir.
  std::string cfg_err;
  if (!driver.Configure(params, cfg_err)) {
    std::fprintf(stderr, "FAIL: Configure: %s\n", cfg_err.c_str());
    return 1;
  }

  Value result = Value::Object();
  auto runner = [&](const std::atomic<bool>&) {
    result = samurai::l7_emu_native::run_profile_json(profile, cfg);
  };

  std::atomic<bool> stop{false};
  samurai::daemon::FastpathHooks hooks;
  hooks.emit_metric = [&](const samurai::wire::MetricSnapshotV2& s) {
    std::fprintf(stderr,
                 "[progress] active_tcb=%u frames_seen=%d syns=%d synacks=%d data=%d "
                 "delivered=%d peer_resp=%d\n",
                 s.tcp_active_tcb_count, peer.frames_seen, peer.syns_seen,
                 peer.synacks_sent, peer.data_seen, peer.frames_delivered, peer.responses_sent);
  };
  const samurai::daemon::FastpathResult res = driver.Run(params, runner, stop, hooks);

  auto ru64 = [&](const char* k) -> std::uint64_t {
    const Value* v = result.find(k);
    return (v && v->is_number()) ? static_cast<std::uint64_t>(std::max(0.0, v->as_double())) : 0u;
  };
  const std::uint64_t attempted = ru64("attempted");
  const std::uint64_t sent = ru64("sent");
  const std::uint64_t errors = ru64("errors");

  std::printf("[flows=%d] driver: connect_established=%llu tx_packets=%llu rx_frames=%llu\n",
              flows,
              (unsigned long long)res.connect_established,
              (unsigned long long)res.tx_packets,
              (unsigned long long)res.rx_frames);
  std::printf("[flows=%d] l7: attempted=%llu sent=%llu errors=%llu peer_responses=%d\n",
              flows, (unsigned long long)attempted, (unsigned long long)sent,
              (unsigned long long)errors, peer.responses_sent);
  std::printf("[flows=%d] l7_result=%s\n", flows, result.dump().c_str());

  if (res.connect_established < static_cast<std::uint64_t>(flows)) {
    std::fprintf(stderr, "FAIL[flows=%d]: yalnız %llu handshake tamamlandı (beklenen %d)\n",
                 flows, (unsigned long long)res.connect_established, flows);
    return false;
  }
  if (peer.responses_sent < flows) {
    std::fprintf(stderr, "FAIL[flows=%d]: peer yalnız %d isteğe yanıt verdi (beklenen %d)\n",
                 flows, peer.responses_sent, flows);
    return false;
  }
  if (sent < static_cast<std::uint64_t>(flows) || errors != 0) {
    std::fprintf(stderr, "FAIL[flows=%d]: sent=%llu errors=%llu (beklenen sent>=%d, errors=0)\n",
                 flows, (unsigned long long)sent, (unsigned long long)errors, flows);
    return false;
  }
  return true;
}

#ifdef SAMURAI_WITH_NGHTTP2
// H2 karşılığı: aynı sürücü/wire üzerinden protocol=http2 (h2c) akışını gerçek nghttp2
// reactor'ıyla (custom_tcp/dpdk_direct) koşar. flows>1 çok-shard finalize'ı zorlar.
bool run_h2_scenario(int flows) {
  using samurai::core::json::Value;
  Value profile = Value::Object();
  Value conn = Value::Object();
  conn.set("transport_backend", Value::Str("dpdk_direct"));
  conn.set("target_ip", Value::Str("10.0.0.3"));
  conn.set("target_port", Value::Int(80));
  conn.set("scheme", Value::Str("http"));
  conn.set("host_header", Value::Str("10.0.0.3"));
  conn.set("keepalive", Value::Int(0));
  conn.set("max_connections", Value::Int(flows));
  conn.set("max_streams_per_connection", Value::Int(1));
  conn.set("session_repeats", Value::Int(flows));
  conn.set("timeout_ms", Value::Int(5000));
  profile.set("connection_template", conn);
  profile.set("flow_attempted", Value::Int(flows));
  profile.set("protocol", Value::Str("http2"));
  {
    // H2: yalnız SEND_HEADERS (GET /). Gövde yok => HEADERS END_STREAM taşır, peer
    // OnFrameRecv'de yanıtı hemen submit eder.
    Value op = Value::Object();
    op.set("opcode", Value::Str("SEND_HEADERS"));
    op.set("method", Value::Str("GET"));
    op.set("path", Value::Str("/"));
    Value ops = Value::Array();
    for (int i = 0; i < flows; ++i) ops.push_back(op);
    Value fp = Value::Object();
    fp.set("ops", ops);
    profile.set("flow_program", fp);
  }
  Value cfg = Value::Object();
  cfg.set("concurrency", Value::Int(flows));
  cfg.set("profile_l7", Value::Int(1));

  H2PeerShim peer;
  samurai::daemon::StatefulFastpathDriver driver(peer);

  samurai::daemon::FastpathParams params;
  params.dst_ip = Ipv4("10.0.0.3");
  params.dst_port = 80;
  params.max_duration_ms = 12000;
  params.drain_ms = 200;

  std::string cfg_err;
  if (!driver.Configure(params, cfg_err)) {
    std::fprintf(stderr, "FAIL(h2): Configure: %s\n", cfg_err.c_str());
    return false;
  }

  Value result = Value::Object();
  auto runner = [&](const std::atomic<bool>&) {
    result = samurai::l7_emu_native::run_profile_json(profile, cfg);
  };

  std::atomic<bool> stop{false};
  samurai::daemon::FastpathHooks hooks;
  hooks.emit_metric = [&](const samurai::wire::MetricSnapshotV2& s) {
    std::fprintf(stderr,
                 "[h2 progress] active_tcb=%u frames_seen=%d syns=%d synacks=%d data=%d "
                 "delivered=%d peer_resp=%d\n",
                 s.tcp_active_tcb_count, peer.frames_seen, peer.syns_seen,
                 peer.synacks_sent, peer.data_seen, peer.frames_delivered, peer.responses_sent);
  };
  const samurai::daemon::FastpathResult res = driver.Run(params, runner, stop, hooks);

  auto ru64 = [&](const char* k) -> std::uint64_t {
    const Value* v = result.find(k);
    return (v && v->is_number()) ? static_cast<std::uint64_t>(std::max(0.0, v->as_double())) : 0u;
  };
  const std::uint64_t attempted = ru64("attempted");
  const std::uint64_t sent = ru64("sent");
  const std::uint64_t errors = ru64("errors");

  std::printf("[h2 flows=%d] driver: connect_established=%llu tx_packets=%llu rx_frames=%llu\n",
              flows, (unsigned long long)res.connect_established,
              (unsigned long long)res.tx_packets, (unsigned long long)res.rx_frames);
  std::printf("[h2 flows=%d] l7: attempted=%llu sent=%llu errors=%llu peer_responses=%d\n",
              flows, (unsigned long long)attempted, (unsigned long long)sent,
              (unsigned long long)errors, peer.responses_sent);
  std::printf("[h2 flows=%d] l7_result=%s\n", flows, result.dump().c_str());

  if (res.connect_established < static_cast<std::uint64_t>(flows)) {
    std::fprintf(stderr, "FAIL(h2)[flows=%d]: yalnız %llu handshake (beklenen %d)\n",
                 flows, (unsigned long long)res.connect_established, flows);
    return false;
  }
  if (peer.responses_sent < flows) {
    std::fprintf(stderr, "FAIL(h2)[flows=%d]: peer yalnız %d yanıt (beklenen %d)\n",
                 flows, peer.responses_sent, flows);
    return false;
  }
  if (sent < static_cast<std::uint64_t>(flows) || errors != 0) {
    std::fprintf(stderr, "FAIL(h2)[flows=%d]: sent=%llu errors=%llu (beklenen sent>=%d, errors=0)\n",
                 flows, (unsigned long long)sent, (unsigned long long)errors, flows);
    return false;
  }
  return true;
}
#endif  // SAMURAI_WITH_NGHTTP2

bool run_sharded_l7_scenario(int workers) {
  samurai::daemon::ShardedFastpathConfig cfg;
  cfg.workers = static_cast<std::uint32_t>(workers);
  cfg.cpu_base = -1;

  auto factory = [](std::uint32_t) -> std::unique_ptr<samurai::daemon::FastpathTxRxShim> {
    return std::make_unique<StatefulHttpPeerShim>();
  };

  samurai::daemon::ShardedFastpathDriver driver(factory, cfg);

  samurai::daemon::FastpathParams params;
  params.dst_ip = Ipv4("10.0.0.3");
  params.dst_port = 80;
  params.max_duration_ms = 4000;
  params.drain_ms = 100;

  std::atomic<bool> stop{false};
  std::atomic<int> completed_workers{0};

  auto runner = [&](std::uint32_t w,
                    samurai::tcpdp::TcpDataplaneCore& core,
                    samurai::daemon::FastpathTxRxShim& shim,
                    const std::atomic<bool>& internal_stop) {
    (void)shim;
    (void)w;
    uint64_t flow_id = 0;
    const int rc = tcpdp_enqueue_connect(Ipv4("10.0.0.2"), Ipv4("10.0.0.3"), 0, 80, &flow_id);
    if (rc != 0 || flow_id == 0) return;

    const uint64_t t0 = samurai_pacing_monotonic_now_ns();
    while (samurai_pacing_monotonic_now_ns() - t0 < 2000'000'000ull && !internal_stop.load()) {
      if (core.SnapshotStats().connect_established > 0) break;
      std::this_thread::yield();
    }
    if (core.SnapshotStats().connect_established == 0) return;

    const char req[] = "GET / HTTP/1.1\r\nHost: 10.0.0.3\r\nConnection: close\r\n\r\n";
    uint32_t queued = 0;
    (void)tcpdp_enqueue_send(flow_id, reinterpret_cast<const uint8_t*>(req), sizeof(req) - 1, &queued);

    const uint64_t t1 = samurai_pacing_monotonic_now_ns();
    while (samurai_pacing_monotonic_now_ns() - t1 < 2000'000'000ull && !internal_stop.load()) {
      if (core.SnapshotStats().rx_data_bytes > 0) break;
      std::this_thread::yield();
    }

    if (core.SnapshotStats().rx_data_bytes > 0) {
      completed_workers.fetch_add(1);
    }
  };

  std::vector<samurai::daemon::FastpathResult> per_worker;
  const samurai::daemon::FastpathResult res = driver.RunL7(params, runner, stop, &per_worker);

  std::printf("[sharded_l7 workers=%d] total: est=%llu tx=%llu rx=%llu completed_workers=%d\n",
              workers, (unsigned long long)res.connect_established,
              (unsigned long long)res.tx_packets, (unsigned long long)res.rx_frames,
              completed_workers.load());

  if (completed_workers.load() != workers || res.connect_established != static_cast<uint64_t>(workers)) {
    std::fprintf(stderr, "FAIL: sharded_l7 completed_workers=%d est=%llu expected %d\n",
                 completed_workers.load(), (unsigned long long)res.connect_established, workers);
    return false;
  }
  return true;
}

int main(int argc, char** argv) {
  setenv("SAMURAI_CUSTOM_TCP_SRC_IP", "10.0.0.2", 1);
  // argv[1] verilirse yalnız o flow sayısı; aksi halde tek-lane + çok-lane (regresyon
  // koruması: çok-shard completion finalizasyonu). Hepsi geçmeli.
  std::vector<int> flow_counts;
  if (argc > 1) {
    flow_counts.push_back(std::max(1, std::atoi(argv[1])));
  } else {
    flow_counts = {1, 4};
  }
  for (const int flows : flow_counts) {
    if (!run_scenario(flows)) {
      return 1;
    }
  }
#ifdef SAMURAI_WITH_NGHTTP2
  for (const int flows : flow_counts) {
    if (!run_h2_scenario(flows)) {
      return 1;
    }
  }
#else
  std::printf("[skip] nghttp2 yok: H2 custom_tcp senaryosu atlandı\n");
#endif
  if (!run_sharded_l7_scenario(4)) {
    return 1;
  }
  std::printf("ALL STATEFUL FASTPATH L7 TESTS PASSED\n");
  return 0;
}
