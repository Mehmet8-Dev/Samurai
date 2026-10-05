// Focused verification of the tcpdp sliding-window sender (replaces the legacy
// single-outstanding / stop-and-wait model). Drives the real TcpDataplaneCore
// in-process (no NIC): EnqueueConnect -> synthetic SYN-ACK -> Established, then
// exercises multi-outstanding sends, MSS segmentation, effective-window limiting,
// cumulative-ACK retirement, slow-start cwnd growth, and no-deadlock draining.
#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using ddos_samurai::tcpdp::TcpDataplaneCore;
using ddos_samurai::tcpdp::TcpDpConfig;
using ddos_samurai::tcpdp::TcpDpFlowSnapshot;

static int g_fails = 0;
#define CHECK(cond, ...)                                       \
  do {                                                         \
    if (!(cond)) {                                             \
      std::printf("FAIL [%s:%d]: ", __FILE__, __LINE__);       \
      std::printf(__VA_ARGS__);                                \
      std::printf("\n");                                       \
      g_fails++;                                               \
    }                                                          \
  } while (0)

static void WriteBe16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v & 0xFF); }
static void WriteBe32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v & 0xFF);
}
static uint32_t ReadBe32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
static uint32_t Ipv4(const char* s) { in_addr a{}; inet_pton(AF_INET, s, &a); return ntohl(a.s_addr); }

struct Seg {
  uint8_t flags;
  uint32_t seq;
  uint32_t ack;
  uint32_t payload_len;
  uint8_t doff_words;
  std::vector<uint8_t> raw;
};

// Drain every packet currently on the TX ring into a flat segment list. doff_words is
// the TCP data-offset (header words); >5 means TCP options are present.
static std::vector<Seg> Drain(TcpDataplaneCore& core) {
  std::vector<Seg> out;
  for (;;) {
    const uint8_t* base = nullptr; uint32_t count = 0; size_t psize = 0, stride = 0;
    core.PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
    if (count == 0 || base == nullptr) break;
    for (uint32_t i = 0; i < count; ++i) {
      const uint8_t* p = base + i * stride;
      Seg s;
      s.flags = p[47];
      s.seq = ReadBe32(p + 38);
      s.ack = ReadBe32(p + 42);
      s.doff_words = uint8_t(p[46] >> 4);  // TCP data offset at frame byte 14+20+12=46
      const size_t tcp_hdr = size_t(s.doff_words) * 4;
      const size_t hdr = 34 + tcp_hdr;     // 14 L2 + 20 IP + TCP header (incl options)
      s.payload_len = psize > hdr ? uint32_t(psize - hdr) : 0;
      s.raw.assign(p, p + psize);
      out.push_back(s);
    }
    core.ConsumeTxPackets(count);
  }
  return out;
}

// Peer -> us frame. Our flow key is {our_ip, tgt_ip, ephem, 80}; IngestRxFrame keys
// on {frame.dst, frame.src, frame.dport, frame.sport}, so the peer stamps
// src=tgt/sport=80, dst=our/dport=ephem.
static std::vector<uint8_t> PeerFrame(uint32_t our_ip, uint32_t tgt_ip, uint16_t ephem, uint32_t seq,
                                      uint32_t ack, uint8_t flags, uint16_t win,
                                      const uint8_t* payload = nullptr, uint16_t plen = 0) {
  std::vector<uint8_t> f(54 + plen, 0);
  WriteBe16(f.data() + 12, 0x0800);
  f[14] = 0x45;
  WriteBe16(f.data() + 16, uint16_t(40 + plen));
  f[22] = 64;
  f[23] = 6;
  WriteBe32(f.data() + 26, tgt_ip);   // src = target
  WriteBe32(f.data() + 30, our_ip);   // dst = us
  WriteBe16(f.data() + 34, 80);       // src_port = target
  WriteBe16(f.data() + 36, ephem);    // dst_port = ephemeral
  WriteBe32(f.data() + 38, seq);
  WriteBe32(f.data() + 42, ack);
  f[46] = 0x50;
  f[47] = flags;
  WriteBe16(f.data() + 48, win);
  if (payload && plen) std::memcpy(f.data() + 54, payload, plen);
  return f;
}

// Peer -> us frame carrying TCP options (opts_len must be a multiple of 4).
static std::vector<uint8_t> PeerFrameOpt(uint32_t our_ip, uint32_t tgt_ip, uint16_t ephem, uint32_t seq,
                                         uint32_t ack, uint8_t flags, uint16_t win,
                                         const uint8_t* opts, uint8_t opts_len) {
  const uint8_t tcp_hdr = uint8_t(20 + opts_len);
  std::vector<uint8_t> f(14 + 20 + tcp_hdr, 0);
  WriteBe16(f.data() + 12, 0x0800);
  f[14] = 0x45;
  WriteBe16(f.data() + 16, uint16_t(20 + tcp_hdr));
  f[22] = 64;
  f[23] = 6;
  WriteBe32(f.data() + 26, tgt_ip);
  WriteBe32(f.data() + 30, our_ip);
  WriteBe16(f.data() + 34, 80);
  WriteBe16(f.data() + 36, ephem);
  WriteBe32(f.data() + 38, seq);
  WriteBe32(f.data() + 42, ack);
  f[46] = uint8_t((tcp_hdr / 4) << 4);
  f[47] = flags;
  WriteBe16(f.data() + 48, win);
  if (opts && opts_len) std::memcpy(f.data() + 54, opts, opts_len);
  return f;
}

int main() {
  TcpDataplaneCore core;
  TcpDpConfig cfg;
  cfg.mode = "on";
  cfg.default_mss = 1460;
  cfg.local_window = 65535;
  cfg.initial_rto_ms = 250;
  core.Configure(cfg);

  const uint32_t our_ip = Ipv4("10.0.0.2");
  const uint32_t tgt = Ipv4("10.0.0.3");
  const uint16_t IW10 = 0;  // placeholder (unused)
  (void)IW10;

  const uint64_t fid = core.EnqueueConnect(our_ip, tgt, 0, 80);
  CHECK(fid != 0, "EnqueueConnect returned a flow id");
  TcpDpFlowSnapshot s = core.GetFlow(fid);
  const uint16_t ephem = s.src_port;
  const uint32_t iss = s.iss;

  auto syn = Drain(core);
  CHECK(syn.size() == 1 && (syn[0].flags & 0x02), "exactly one SYN emitted (got %zu)", syn.size());

  const uint32_t peer_iss = 0x51000000u;
  auto sa = PeerFrame(our_ip, tgt, ephem, peer_iss, iss + 1, 0x12 /*SYN|ACK*/, 65535);
  core.IngestRxFrame(sa.data(), sa.size());
  s = core.GetFlow(fid);
  CHECK(s.state == 3, "flow Established after SYN-ACK (state=%u)", s.state);
  CHECK(s.snd_una == iss + 1, "snd_una=%u expected %u", s.snd_una, iss + 1);
  Drain(core);  // discard the handshake ACK

  // ---- TEST A: stop-and-wait removed. Three back-to-back sends, no ACK between.
  // Legacy behaviour: the 1st send is accepted, the 2nd/3rd return 0 (one segment
  // outstanding). New behaviour: all three are accepted and hit the wire.
  std::vector<uint8_t> b1(1000, 'A'), b2(1000, 'B'), b3(1000, 'C');
  const uint32_t q1 = core.EnqueueSend(fid, b1.data(), b1.size());
  const uint32_t q2 = core.EnqueueSend(fid, b2.data(), b2.size());
  const uint32_t q3 = core.EnqueueSend(fid, b3.data(), b3.size());
  CHECK(q1 == 1000 && q2 == 1000 && q3 == 1000,
        "3 back-to-back sends all accepted (q=%u,%u,%u; legacy stop-and-wait: 2nd/3rd==0)", q1, q2, q3);
  auto segsA = Drain(core);
  uint32_t bytesA = 0;
  for (auto& seg : segsA) bytesA += seg.payload_len;
  CHECK(bytesA == 3000, "3000 data bytes on the wire before any ACK (got %u across %zu segs)", bytesA, segsA.size());
  s = core.GetFlow(fid);
  CHECK(s.snd_nxt - s.snd_una == 3000, "3000 bytes in flight (snd_nxt-snd_una=%u)", s.snd_nxt - s.snd_una);

  const uint32_t ack_to = s.snd_una + 3000;
  auto ack1 = PeerFrame(our_ip, tgt, ephem, peer_iss + 1, ack_to, 0x10 /*ACK*/, 65535);
  core.IngestRxFrame(ack1.data(), ack1.size());
  s = core.GetFlow(fid);
  CHECK(s.snd_una == ack_to, "snd_una advanced to %u after cumulative ACK (got %u)", ack_to, s.snd_una);
  CHECK(s.snd_nxt == s.snd_una, "nothing in flight after full ACK (inflight=%u)", s.snd_nxt - s.snd_una);
  const uint32_t cwnd_after = s.cwnd;
  CHECK(cwnd_after > 10u * 1460u, "cwnd grew past IW10 via slow start (cwnd=%u)", cwnd_after);

  // ---- TEST B: MSS segmentation + effective-window limiting + no deadlock.
  std::vector<uint8_t> big(40000, 'Z');
  const uint32_t qb = core.EnqueueSend(fid, big.data(), big.size());
  CHECK(qb == 40000, "40000 bytes buffered (socket send() semantics; got %u)", qb);
  auto segsB = Drain(core);
  uint32_t bytesB = 0;
  bool non_final_all_mss = true;
  for (size_t i = 0; i < segsB.size(); ++i) {
    bytesB += segsB[i].payload_len;
    if (i + 1 < segsB.size() && segsB[i].payload_len != 1460) non_final_all_mss = false;
  }
  const uint32_t awnd = std::min<uint32_t>(cwnd_after, 65535);
  CHECK(bytesB > 0 && bytesB <= awnd + 1460, "first burst bounded by effective window (%u, awnd~%u)", bytesB, awnd);
  CHECK(bytesB < 40000, "burst is window-limited, not the whole payload (%u)", bytesB);
  CHECK(non_final_all_mss, "non-final segments are full MSS (1460)");

  uint32_t total = bytesB;
  for (int round = 0; round < 64 && total < 40000; ++round) {
    s = core.GetFlow(fid);
    const uint32_t inflight = s.snd_nxt - s.snd_una;
    auto ackN = PeerFrame(our_ip, tgt, ephem, peer_iss + 1, s.snd_una + inflight, 0x10, 65535);
    core.IngestRxFrame(ackN.data(), ackN.size());
    auto more = Drain(core);
    for (auto& seg : more) total += seg.payload_len;
  }
  CHECK(total == 40000, "all 40000 bytes drained across ACK-clocked rounds, no deadlock (got %u)", total);

  // ---- TEST C: window scaling. Fresh flow whose SYN-ACK advertises WScale=7; a later
  // segment advertising a small raw window scales up past the 16-bit ceiling.
  {
    const uint64_t fid2 = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fid2);
    const uint16_t eph2 = t.src_port;
    const uint32_t iss2 = t.iss;
    Drain(core);
    // SACK-permitted(04 02) + WScale(03 03 07) + NOP pad -> 8-byte option block.
    const uint8_t opts[8] = {0x04, 0x02, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01};
    auto sa2 = PeerFrameOpt(our_ip, tgt, eph2, 0x60000000u, iss2 + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(sa2.data(), sa2.size());
    Drain(core);
    t = core.GetFlow(fid2);
    CHECK(t.state == 3, "wscale flow Established");
    // A pure ACK advertising raw window 1000 must scale to 1000<<7 = 128000.
    auto win_upd = PeerFrame(our_ip, tgt, eph2, 0x60000001u, t.snd_una, 0x10, 1000);
    core.IngestRxFrame(win_upd.data(), win_upd.size());
    t = core.GetFlow(fid2);
    CHECK(t.peer_window == 128000u, "window scale applied: peer_window=%u expected 128000", t.peer_window);
  }

  // ---- TEST D: RTT-estimated RTO. Handshake seeds srtt away from the 100ms default;
  // a delayed data ACK moves it toward the measured RTT (Jacobson/Karels).
  {
    const uint64_t fid3 = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fid3);
    const uint16_t eph3 = t.src_port;
    const uint32_t iss3 = t.iss;
    Drain(core);
    auto sa3 = PeerFrame(our_ip, tgt, eph3, 0x70000000u, iss3 + 1, 0x12, 65535);
    core.IngestRxFrame(sa3.data(), sa3.size());
    Drain(core);
    t = core.GetFlow(fid3);
    const uint32_t srtt_hs = t.srtt_ms;
    CHECK(srtt_hs < 100u, "srtt seeded from handshake RTT, not the 100ms default (srtt=%u)", srtt_hs);

    std::vector<uint8_t> d(500, 'D');
    core.EnqueueSend(fid3, d.data(), d.size());
    Drain(core);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    t = core.GetFlow(fid3);
    auto ackd = PeerFrame(our_ip, tgt, eph3, 0x70000001u, t.snd_una + 500, 0x10, 65535);
    core.IngestRxFrame(ackd.data(), ackd.size());
    t = core.GetFlow(fid3);
    CHECK(t.srtt_ms >= srtt_hs && t.srtt_ms <= 40u,
          "srtt tracks the ~20ms delayed ACK (srtt=%u, was %u)", t.srtt_ms, srtt_hs);
  }

  // ---- TEST E: SACK-aware selective retransmit. Peer SACKs segments 2 and 3 while the
  // cumulative ACK stalls at segment 1; fast retransmit must resend only the hole (seg 1).
  {
    const uint64_t fid4 = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fid4);
    const uint16_t eph4 = t.src_port;
    const uint32_t iss4 = t.iss;
    Drain(core);
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};  // SACK-permitted + NOP pad
    auto sa4 = PeerFrameOpt(our_ip, tgt, eph4, 0x80000000u, iss4 + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(sa4.data(), sa4.size());
    Drain(core);
    t = core.GetFlow(fid4);
    CHECK(t.sack_permitted, "SACK negotiated on this flow");
    const uint32_t base = t.snd_una;

    std::vector<uint8_t> s1(1000, '1'), s2(1000, '2'), s3(1000, '3');
    core.EnqueueSend(fid4, s1.data(), s1.size());
    core.EnqueueSend(fid4, s2.data(), s2.size());
    core.EnqueueSend(fid4, s3.data(), s3.size());
    Drain(core);  // three segments now in flight at base, base+1000, base+2000

    // Three dup-ACKs (cumulative stuck at base) each SACK-ing [base+1000, base+3000].
    uint8_t sack_opt[12] = {0x05, 0x0A};  // kind 5, len 10
    WriteBe32(sack_opt + 2, base + 1000);
    WriteBe32(sack_opt + 6, base + 3000);
    sack_opt[10] = 0x01; sack_opt[11] = 0x01;  // NOP pad to 12
    std::vector<Seg> rtx;
    for (int i = 0; i < 3; ++i) {
      auto dup = PeerFrameOpt(our_ip, tgt, eph4, 0x80000001u, base, 0x10, 65535, sack_opt, 12);
      core.IngestRxFrame(dup.data(), dup.size());
      auto out = Drain(core);
      for (auto& seg : out) rtx.push_back(seg);
    }
    CHECK(rtx.size() == 1, "exactly one segment fast-retransmitted (the hole), got %zu", rtx.size());
    CHECK(!rtx.empty() && rtx[0].seq == base, "retransmit targets the hole seg1 (seq=%u expected %u)",
          rtx.empty() ? 0u : rtx[0].seq, base);
    CHECK(!rtx.empty() && rtx[0].payload_len == 1000, "retransmit is the full seg1 (len=%u)",
          rtx.empty() ? 0u : rtx[0].payload_len);
  }

  // ---- TEST F: RFC 6675 multi-hole recovery. Six segments in flight; the peer SACKs
  // the top three so segs 1-3 are all "lost" (>= 3 SACKed above). A single recovery
  // episode must retransmit ALL THREE holes at once (NewReno would resend only seg1).
  {
    const uint64_t fidF = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidF);
    const uint16_t ephF = t.src_port;
    const uint32_t issF = t.iss;
    Drain(core);
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};  // SACK-perm
    auto saF = PeerFrameOpt(our_ip, tgt, ephF, 0x82000000u, issF + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saF.data(), saF.size());
    Drain(core);
    t = core.GetFlow(fidF);
    const uint32_t base = t.snd_una;
    std::vector<uint8_t> chunk(1000, 'x');
    for (int i = 0; i < 6; ++i) core.EnqueueSend(fidF, chunk.data(), chunk.size());
    auto sent = Drain(core);
    CHECK(sent.size() == 6, "six segments in flight (got %zu)", sent.size());

    // SACK the top three segments [base+3000, base+6000] on three dup-ACKs.
    uint8_t sack_opt[12] = {0x05, 0x0A};
    WriteBe32(sack_opt + 2, base + 3000);
    WriteBe32(sack_opt + 6, base + 6000);
    sack_opt[10] = 0x01; sack_opt[11] = 0x01;
    std::vector<Seg> rtx;
    for (int i = 0; i < 3; ++i) {
      auto dup = PeerFrameOpt(our_ip, tgt, ephF, 0x82000001u, base, 0x10, 65535, sack_opt, 12);
      core.IngestRxFrame(dup.data(), dup.size());
      auto out = Drain(core);
      for (auto& s : out) rtx.push_back(s);
    }
    CHECK(rtx.size() == 3, "RFC6675 resent all three holes in one episode (got %zu)", rtx.size());
    bool seq1 = false, seq2 = false, seq3 = false;
    for (auto& s : rtx) {
      if (s.seq == base) seq1 = true;
      if (s.seq == base + 1000) seq2 = true;
      if (s.seq == base + 2000) seq3 = true;
    }
    CHECK(seq1 && seq2 && seq3, "holes seg1+seg2+seg3 all retransmitted");
  }

  // ---- TEST G: a retransmitted SYN carries its options (MSS/SACK-perm/WScale) instead
  // of degrading to a bare header. Force the SYN RTO with no SYN-ACK.
  {
    const uint64_t fidG = core.EnqueueConnect(our_ip, tgt, 0, 80);
    auto syn0 = Drain(core);
    CHECK(syn0.size() == 1 && syn0[0].doff_words > 5, "initial SYN carries options (doff=%u)",
          syn0.empty() ? 0 : syn0[0].doff_words);
    TcpDpFlowSnapshot t = core.GetFlow(fidG);
    // Fire exactly the SYN's RTO (earlier than the connect timeout).
    core.Poll(t.rto_deadline_ns + 1000, 1000);
    auto synR = Drain(core);
    CHECK(!synR.empty() && (synR[0].flags & 0x02), "SYN was retransmitted (got %zu pkts)", synR.size());
    CHECK(!synR.empty() && synR[0].doff_words > 5, "retransmitted SYN still carries options (doff=%u)",
          synR.empty() ? 0 : synR[0].doff_words);
  }

  // ---- TEST H: timestamps (RFC 7323) negotiation + echo + PAWS, on an opt-in core.
  {
    TcpDataplaneCore tcore;
    TcpDpConfig tcfg;
    tcfg.mode = "on"; tcfg.default_mss = 1460; tcfg.local_window = 65535; tcfg.initial_rto_ms = 250;
    tcfg.enable_timestamps = true;
    tcore.Configure(tcfg);
    const uint64_t fidH = tcore.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = tcore.GetFlow(fidH);
    const uint16_t ephH = t.src_port;
    const uint32_t issH = t.iss;
    auto syn = Drain(tcore);
    CHECK(!syn.empty() && syn[0].doff_words == 10, "SYN advertises TS (doff=%u, expect 10)",
          syn.empty() ? 0 : syn[0].doff_words);
    // SYN-ACK echoing SACK-perm + TS.
    uint8_t sa_opt[12] = {0x04, 0x02, 0x08, 0x0A};
    WriteBe32(sa_opt + 4, 1000u);        // peer TSval (ts_recent starts here)
    WriteBe32(sa_opt + 8, 0x0);          // peer TSecr
    auto sa = PeerFrameOpt(our_ip, tgt, ephH, 0x83000000u, issH + 1, 0x12, 65535, sa_opt, 12);
    tcore.IngestRxFrame(sa.data(), sa.size());
    Drain(tcore);
    // A data send now carries the TS option (2 NOP + TS = 12 bytes -> doff 8).
    std::vector<uint8_t> body(200, 'z');
    tcore.EnqueueSend(fidH, body.data(), body.size());
    auto dseg = Drain(tcore);
    CHECK(!dseg.empty() && dseg[0].doff_words == 8, "data segment carries TS (doff=%u, expect 8)",
          dseg.empty() ? 0 : dseg[0].doff_words);

    // PAWS: deliver in-order data with TSval=100 (accepted -> ts_recent=100), then a
    // fresh in-order segment with TSval=50 must be dropped (rcv_nxt frozen).
    t = tcore.GetFlow(fidH);
    const uint32_t rcv0 = t.rcv_nxt;
    auto mk_data = [&](uint32_t seq, uint32_t tsval, uint8_t plen) {
      uint8_t o[12] = {0x01, 0x01, 0x08, 0x0A};
      WriteBe32(o + 4, tsval); WriteBe32(o + 8, 0x0);
      const uint8_t tcp_hdr = uint8_t(20 + 12);
      std::vector<uint8_t> f(14 + 20 + tcp_hdr + plen, 0);
      WriteBe16(f.data() + 12, 0x0800); f[14] = 0x45;
      WriteBe16(f.data() + 16, uint16_t(20 + tcp_hdr + plen));
      f[22] = 64; f[23] = 6;
      WriteBe32(f.data() + 26, tgt); WriteBe32(f.data() + 30, our_ip);
      WriteBe16(f.data() + 34, 80); WriteBe16(f.data() + 36, ephH);
      WriteBe32(f.data() + 38, seq); WriteBe32(f.data() + 42, issH + 1);
      f[46] = uint8_t((tcp_hdr / 4) << 4); f[47] = 0x10;
      WriteBe16(f.data() + 48, 65535);
      std::memcpy(f.data() + 54, o, 12);
      return f;
    };
    auto d1 = mk_data(rcv0, 2000, 50);  // TSval > ts_recent(1000) -> accepted
    tcore.IngestRxFrame(d1.data(), d1.size());
    t = tcore.GetFlow(fidH);
    const uint32_t rcv1 = t.rcv_nxt;
    CHECK(rcv1 == rcv0 + 50, "in-order TS data accepted (rcv_nxt advanced)");
    auto d2 = mk_data(rcv1, 1500, 50);  // TSval < ts_recent(2000) -> PAWS drop
    tcore.IngestRxFrame(d2.data(), d2.size());
    t = tcore.GetFlow(fidH);
    CHECK(t.rcv_nxt == rcv1, "PAWS dropped the stale-TSval segment (rcv_nxt frozen)");
  }

  // ---- TEST I: delayed-ACK + Nagle on an opt-in core.
  {
    TcpDataplaneCore dcore;
    TcpDpConfig dcfg;
    dcfg.mode = "on"; dcfg.default_mss = 1460; dcfg.local_window = 65535; dcfg.initial_rto_ms = 250;
    dcfg.enable_delayed_ack = true; dcfg.enable_nagle = true;
    dcore.Configure(dcfg);
    const uint64_t fidI = dcore.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = dcore.GetFlow(fidI);
    const uint16_t ephI = t.src_port;
    const uint32_t issI = t.iss;
    Drain(dcore);
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    auto sa = PeerFrameOpt(our_ip, tgt, ephI, 0x84000000u, issI + 1, 0x12, 65535, opts, 8);
    dcore.IngestRxFrame(sa.data(), sa.size());
    Drain(dcore);  // clear the handshake ACK

    // Delayed-ACK: first data segment is NOT acked immediately; the second forces it.
    const uint32_t pseq = 0x84000001u;
    std::vector<uint8_t> pay(100, 'a');
    auto p1 = PeerFrame(our_ip, tgt, ephI, pseq, issI + 1, 0x10, 65535, pay.data(), 100);
    dcore.IngestRxFrame(p1.data(), p1.size());
    auto a1 = Drain(dcore);
    int acks1 = 0; for (auto& s : a1) if (s.flags == 0x10) acks1++;
    CHECK(acks1 == 0, "delayed-ACK withheld the ACK for the first segment (got %d)", acks1);
    auto p2 = PeerFrame(our_ip, tgt, ephI, pseq + 100, issI + 1, 0x10, 65535, pay.data(), 100);
    dcore.IngestRxFrame(p2.data(), p2.size());
    auto a2 = Drain(dcore);
    int acks2 = 0; for (auto& s : a2) if (s.flags == 0x10) acks2++;
    CHECK(acks2 == 1, "second segment forced a single delayed ACK (got %d)", acks2);

    // Nagle: a small write while data is unacked is withheld until the in-flight
    // data is acknowledged. First 100B write goes (nothing outstanding); second is held.
    std::vector<uint8_t> w(100, 'w');
    dcore.EnqueueSend(fidI, w.data(), w.size());
    auto n1 = Drain(dcore);
    int data1 = 0; for (auto& s : n1) if (s.payload_len > 0) data1++;
    CHECK(data1 == 1, "first small write is sent (no data outstanding), got %d", data1);
    dcore.EnqueueSend(fidI, w.data(), w.size());  // held by Nagle (prev still unacked)
    auto n2 = Drain(dcore);
    int data2 = 0; for (auto& s : n2) if (s.payload_len > 0) data2++;
    CHECK(data2 == 0, "second small write held by Nagle while unacked, got %d", data2);
    // ACK the first write -> the withheld byte flushes.
    t = dcore.GetFlow(fidI);
    auto ackw = PeerFrame(our_ip, tgt, ephI, issI + 1, t.snd_una + 100, 0x10, 65535);
    dcore.IngestRxFrame(ackw.data(), ackw.size());
    auto n3 = Drain(dcore);
    int data3 = 0; for (auto& s : n3) if (s.payload_len > 0) data3++;
    CHECK(data3 == 1, "Nagle-held write flushes after the ACK, got %d", data3);
  }

  // ---- TEST J: L4 Custom User-Space TCP RX Out-of-Order Segment Reassembly Queue.
  // Segment 2 arrives before Segment 1. Segment 2 must be buffered in rx_oo_queue
  // and trigger a dup-ACK carrying SACK block [seq2, seq2+len2]. Segment 3 arrives
  // next, expanding the SACK block. Segment 1 arrives last, filling the hole;
  // all 3 segments must be drained into rx_payloads_ in strict sequential order.
  {
    const uint64_t fidJ = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidJ);
    const uint16_t ephJ = t.src_port;
    const uint32_t issJ = t.iss;
    Drain(core);

    // SYN-ACK with SACK-permitted
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    const uint32_t peer_issJ = 0x90000000u;
    auto saJ = PeerFrameOpt(our_ip, tgt, ephJ, peer_issJ, issJ + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saJ.data(), saJ.size());
    Drain(core);  // clear handshake ACK
    t = core.GetFlow(fidJ);
    CHECK(t.state == 3, "Flow established for OO reassembly test");
    CHECK(t.sack_permitted, "SACK negotiated for OO reassembly test");

    const uint32_t base_rx = t.rcv_nxt;  // peer_issJ + 1
    const uint32_t len = 100;
    std::vector<uint8_t> p1(len, '1');
    std::vector<uint8_t> p2(len, '2');
    std::vector<uint8_t> p3(len, '3');

    // 1. Send segment 2 FIRST (seq = base_rx + 100).
    auto f2 = PeerFrame(our_ip, tgt, ephJ, base_rx + 100, issJ + 1, 0x10, 65535, p2.data(), len);
    core.IngestRxFrame(f2.data(), f2.size());

    // Payload 2 must NOT be delivered yet because hole exists at base_rx.
    auto rx1 = core.CollectRxPayloads();
    CHECK(rx1.empty(), "Segment 2 held in reassembly queue; no L7 payload delivered yet");

    // Must emit exactly one dup-ACK with SACK block [base_rx+100, base_rx+200].
    auto acks1 = Drain(core);
    CHECK(acks1.size() == 1, "Emitted 1 dup-ACK for out-of-order segment 2 (got %zu)", acks1.size());
    if (!acks1.empty()) {
      CHECK(acks1[0].ack == base_rx, "dup-ACK ack=%u expected base_rx=%u", acks1[0].ack, base_rx);
      CHECK(acks1[0].doff_words > 5, "dup-ACK carries TCP options");
      if (acks1[0].raw.size() >= 66) {
        // Frame byte 54: options start. 54, 55: NOPs. 56: Kind 5, 57: Len 10.
        CHECK(acks1[0].raw[56] == 0x05, "SACK option kind is 5 (got %u)", acks1[0].raw[56]);
        const uint32_t sack_left = ReadBe32(acks1[0].raw.data() + 58);
        const uint32_t sack_right = ReadBe32(acks1[0].raw.data() + 62);
        CHECK(sack_left == base_rx + 100, "SACK left=%u expected %u", sack_left, base_rx + 100);
        CHECK(sack_right == base_rx + 200, "SACK right=%u expected %u", sack_right, base_rx + 200);
      }
    }

    // 2. Send segment 3 NEXT (seq = base_rx + 200).
    auto f3 = PeerFrame(our_ip, tgt, ephJ, base_rx + 200, issJ + 1, 0x10, 65535, p3.data(), len);
    core.IngestRxFrame(f3.data(), f3.size());

    auto rx2 = core.CollectRxPayloads();
    CHECK(rx2.empty(), "Segment 3 held; hole still exists at base_rx");

    auto acks2 = Drain(core);
    CHECK(acks2.size() == 1, "Emitted 1 dup-ACK for out-of-order segment 3 (got %zu)", acks2.size());
    if (!acks2.empty() && acks2[0].raw.size() >= 66) {
      CHECK(acks2[0].ack == base_rx, "dup-ACK ack=%u expected base_rx=%u", acks2[0].ack, base_rx);
      const uint32_t sack_left = ReadBe32(acks2[0].raw.data() + 58);
      const uint32_t sack_right = ReadBe32(acks2[0].raw.data() + 62);
      CHECK(sack_left == base_rx + 100, "Merged SACK left=%u expected %u", sack_left, base_rx + 100);
      CHECK(sack_right == base_rx + 300, "Merged SACK right=%u expected %u", sack_right, base_rx + 300);
    }

    // 3. Send segment 1 LAST (seq = base_rx, fills hole!).
    auto f1 = PeerFrame(our_ip, tgt, ephJ, base_rx, issJ + 1, 0x10, 65535, p1.data(), len);
    core.IngestRxFrame(f1.data(), f1.size());

    // All 3 segments must now be delivered in exact sequence: p1 then p2 then p3.
    auto rx3 = core.CollectRxPayloads();
    std::vector<uint8_t> all_bytes;
    for (const auto& item : rx3) {
      all_bytes.insert(all_bytes.end(), item.payload.begin(), item.payload.end());
    }
    CHECK(all_bytes.size() == 300, "Reassembled all 300 bytes (got %zu)", all_bytes.size());
    bool order_ok = (all_bytes.size() == 300);
    if (order_ok) {
      for (size_t i = 0; i < 100; ++i) if (all_bytes[i] != '1') order_ok = false;
      for (size_t i = 100; i < 200; ++i) if (all_bytes[i] != '2') order_ok = false;
      for (size_t i = 200; i < 300; ++i) if (all_bytes[i] != '3') order_ok = false;
    }
    CHECK(order_ok, "Payload reassembled in exact sequential order: 100 '1's, 100 '2's, 100 '3's");

    t = core.GetFlow(fidJ);
    CHECK(t.rcv_nxt == base_rx + 300, "rcv_nxt advanced to %u (got %u)", base_rx + 300, t.rcv_nxt);

    // TX ring must have cumulative ACK covering base_rx + 300 without SACK blocks.
    auto acks3 = Drain(core);
    CHECK(acks3.size() == 1, "Emitted 1 cumulative ACK after hole fill (got %zu)", acks3.size());
    if (!acks3.empty()) {
      CHECK(acks3[0].ack == base_rx + 300, "Cumulative ACK ack=%u expected %u", acks3[0].ack, base_rx + 300);
    }

    // 4. Test duplicate segment rejection: send segment 2 again.
    core.IngestRxFrame(f2.data(), f2.size());
    auto rx_dup = core.CollectRxPayloads();
    CHECK(rx_dup.empty(), "Old duplicate segment rejected; no payload delivered");
    auto acks_dup = Drain(core);
    CHECK(acks_dup.size() == 1, "Duplicate segment re-ACKed current rcv_nxt");
    if (!acks_dup.empty()) {
      CHECK(acks_dup[0].ack == base_rx + 300, "Duplicate segment ACKed current rcv_nxt=%u", base_rx + 300);
    }

    // 5. Test queue capacity bound (max 32 out-of-order segments to prevent bloat):
    // Send 40 disjoint segments with gaps between them.
    for (uint32_t i = 0; i < 40; ++i) {
      const uint32_t seg_seq = base_rx + 1000 + i * 200;  // 100-byte segment, 100-byte gap
      std::vector<uint8_t> p_extra(100, static_cast<uint8_t>('A' + (i % 26)));
      auto f_extra = PeerFrame(our_ip, tgt, ephJ, seg_seq, issJ + 1, 0x10, 65535, p_extra.data(), 100);
      core.IngestRxFrame(f_extra.data(), f_extra.size());
    }
    Drain(core);
    auto rx_extra = core.CollectRxPayloads();
    CHECK(rx_extra.empty(), "Segments past hole kept bounded in queue; none delivered");
  }

  // ---- TEST K: Sequence Number Wrap-around across 2^32-1 -> 0 boundary.
  // Tests out-of-order queueing, SACK block ordering, and seamless reassembly across wrap boundary.
  {
    const uint64_t fidK = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidK);
    const uint16_t ephK = t.src_port;
    const uint32_t issK = t.iss;
    Drain(core);

    // Peer ISS close to wrap-around: 0xFFFFFFF0
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    const uint32_t peer_issK = 0xFFFFFFF0u;
    auto saK = PeerFrameOpt(our_ip, tgt, ephK, peer_issK, issK + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saK.data(), saK.size());
    Drain(core);
    t = core.GetFlow(fidK);
    const uint32_t base_rx = t.rcv_nxt; // 0xFFFFFFF1u
    CHECK(base_rx == 0xFFFFFFF1u, "Flow rcv_nxt initialized to pre-wrap sequence number");

    // Segment 2: seq = 0x00000010u (post-wrap!), len = 50, content 'B'
    // Hole is [0xFFFFFFF1, 0x00000010) = 31 bytes
    std::vector<uint8_t> p2(50, 'B');
    auto f2 = PeerFrame(our_ip, tgt, ephK, 0x00000010u, issK + 1, 0x10, 65535, p2.data(), 50);
    core.IngestRxFrame(f2.data(), f2.size());
    auto rx_k1 = core.CollectRxPayloads();
    CHECK(rx_k1.empty(), "TEST K: Post-wrap Segment 2 held in queue; no L7 delivery yet");
    auto acks_k1 = Drain(core);
    CHECK(acks_k1.size() == 1, "TEST K: Emitted dup-ACK for post-wrap segment");
    if (!acks_k1.empty() && acks_k1[0].raw.size() >= 66) {
      const uint32_t sack_left = ReadBe32(acks_k1[0].raw.data() + 58);
      const uint32_t sack_right = ReadBe32(acks_k1[0].raw.data() + 62);
      CHECK(sack_left == 0x00000010u, "TEST K: SACK left=%u expected 0x00000010", sack_left);
      CHECK(sack_right == 0x00000010u + 50, "TEST K: SACK right=%u expected %u", sack_right, 0x00000010u + 50);
    }

    // Segment 3: seq = 0x00000050u (post-wrap!), len = 40, content 'C'
    std::vector<uint8_t> p3(40, 'C');
    auto f3 = PeerFrame(our_ip, tgt, ephK, 0x00000050u, issK + 1, 0x10, 65535, p3.data(), 40);
    core.IngestRxFrame(f3.data(), f3.size());
    auto acks_k2 = Drain(core);
    CHECK(acks_k2.size() == 1, "TEST K: Emitted dup-ACK for segment 3");
    if (!acks_k2.empty() && acks_k2[0].raw.size() >= 74) {
      // Must have triggering block 3 at head, then block 2
      const uint32_t sack1_left = ReadBe32(acks_k2[0].raw.data() + 58);
      const uint32_t sack1_right = ReadBe32(acks_k2[0].raw.data() + 62);
      const uint32_t sack2_left = ReadBe32(acks_k2[0].raw.data() + 66);
      const uint32_t sack2_right = ReadBe32(acks_k2[0].raw.data() + 70);
      CHECK(sack1_left == 0x00000050u && sack1_right == 0x00000050u + 40, "TEST K: Triggering SACK block is segment 3");
      CHECK(sack2_left == 0x00000010u && sack2_right == 0x00000010u + 50, "TEST K: Second SACK block is segment 2");
    }

    // Segment 1: seq = 0xFFFFFFF1u, len = 31 (0xFFFFFFF1 + 31 = 0x00000010u!), content 'A'
    // Fills the hole across the wrap-around boundary!
    std::vector<uint8_t> p1(31, 'A');
    auto f1 = PeerFrame(our_ip, tgt, ephK, 0xFFFFFFF1u, issK + 1, 0x10, 65535, p1.data(), 31);
    core.IngestRxFrame(f1.data(), f1.size());

    // Segments 1 and 2 must drain! (Segment 3 still has gap between 0x42 and 0x50)
    auto rx_k2 = core.CollectRxPayloads();
    std::vector<uint8_t> k_bytes;
    for (const auto& item : rx_k2) {
      k_bytes.insert(k_bytes.end(), item.payload.begin(), item.payload.end());
    }
    CHECK(k_bytes.size() == 31 + 50, "TEST K: Drained segment 1 + 2 across wrap boundary (got %zu bytes)", k_bytes.size());
    t = core.GetFlow(fidK);
    CHECK(t.rcv_nxt == 0x00000010u + 50, "TEST K: rcv_nxt advanced across 0 boundary to %u (got %u)", 0x00000010u + 50, t.rcv_nxt);
    Drain(core);

    // Segment 4: seq = 0x00000042u, len = 14 (fills remaining gap 0x42..0x50)
    std::vector<uint8_t> p4(14, 'D');
    auto f4 = PeerFrame(our_ip, tgt, ephK, 0x00000042u, issK + 1, 0x10, 65535, p4.data(), 14);
    core.IngestRxFrame(f4.data(), f4.size());
    auto rx_k3 = core.CollectRxPayloads();
    size_t rx_k3_len = 0;
    for (const auto& item : rx_k3) rx_k3_len += item.payload.size();
    CHECK(rx_k3_len == 14 + 40, "TEST K: Drained segment 4 + segment 3 (got %zu bytes)", rx_k3_len);
    t = core.GetFlow(fidK);
    CHECK(t.rcv_nxt == 0x00000050u + 40, "TEST K: Final rcv_nxt=%u expected %u", t.rcv_nxt, 0x00000050u + 40);
    Drain(core);
  }

  // ---- TEST L: Overlapping, duplicate, and subsumed out-of-order segments.
  {
    const uint64_t fidL = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidL);
    const uint16_t ephL = t.src_port;
    const uint32_t issL = t.iss;
    Drain(core);
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    auto saL = PeerFrameOpt(our_ip, tgt, ephL, 0x50000000u, issL + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saL.data(), saL.size());
    Drain(core);
    t = core.GetFlow(fidL);
    const uint32_t base = t.rcv_nxt; // 0x50000001u

    // 1. Arrive at base + 100, len 100 ('B')
    std::vector<uint8_t> pB(100, 'B');
    auto fB = PeerFrame(our_ip, tgt, ephL, base + 100, issL + 1, 0x10, 65535, pB.data(), 100);
    core.IngestRxFrame(fB.data(), fB.size());

    // 2. Arrive at base + 120, len 50 ('C') - completely subsumed inside previous!
    std::vector<uint8_t> pC(50, 'C');
    auto fC = PeerFrame(our_ip, tgt, ephL, base + 120, issL + 1, 0x10, 65535, pC.data(), 50);
    core.IngestRxFrame(fC.data(), fC.size());

    // 3. Arrive at base + 150, len 100 ('D') - partial right overlap with B, extends to base + 250!
    std::vector<uint8_t> pD(100, 'D');
    auto fD = PeerFrame(our_ip, tgt, ephL, base + 150, issL + 1, 0x10, 65535, pD.data(), 100);
    core.IngestRxFrame(fD.data(), fD.size());

    Drain(core);
    auto rx_l0 = core.CollectRxPayloads();
    CHECK(rx_l0.empty(), "TEST L: No payload delivered before hole fill");

    // 4. In-order segment arrives: base, len 100 ('A')
    std::vector<uint8_t> pA(100, 'A');
    auto fA = PeerFrame(our_ip, tgt, ephL, base, issL + 1, 0x10, 65535, pA.data(), 100);
    core.IngestRxFrame(fA.data(), fA.size());

    // All data from base to base + 250 must be delivered!
    auto rx_l1 = core.CollectRxPayloads();
    std::vector<uint8_t> l_bytes;
    for (const auto& item : rx_l1) {
      l_bytes.insert(l_bytes.end(), item.payload.begin(), item.payload.end());
    }
    CHECK(l_bytes.size() == 250, "TEST L: Reassembled 250 bytes without duplicate overlap corruption (got %zu)", l_bytes.size());
    t = core.GetFlow(fidL);
    CHECK(t.rcv_nxt == base + 250, "TEST L: rcv_nxt advanced to base+250 (got %u)", t.rcv_nxt);
    Drain(core);
  }

  // ---- TEST M: Out-of-Order FIN handling.
  // Segment 2 arrives with FIN; segment 1 arrives second. Connection must deliver all
  // data and transition cleanly to kTimeWait.
  {
    const uint64_t fidM = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidM);
    const uint16_t ephM = t.src_port;
    const uint32_t issM = t.iss;
    Drain(core);
    const uint8_t opts[8] = {0x04, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    auto saM = PeerFrameOpt(our_ip, tgt, ephM, 0x60000000u, issM + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saM.data(), saM.size());
    Drain(core);
    t = core.GetFlow(fidM);
    const uint32_t base = t.rcv_nxt;

    // Segment 2: base + 100, len 100, flags = FIN | ACK
    std::vector<uint8_t> p2(100, 'Z');
    auto f2 = PeerFrame(our_ip, tgt, ephM, base + 100, issM + 1, 0x11, 65535, p2.data(), 100);
    core.IngestRxFrame(f2.data(), f2.size());
    t = core.GetFlow(fidM);
    CHECK(t.state == 3, "TEST M: Flow remains established while FIN is pending (state=%u)", t.state);
    auto acks_m1 = Drain(core);
    CHECK(acks_m1.size() == 1, "TEST M: Emitted dup-ACK for out-of-order FIN");

    // Segment 1: base, len 100, flags = ACK
    std::vector<uint8_t> p1(100, 'Y');
    auto f1 = PeerFrame(our_ip, tgt, ephM, base, issM + 1, 0x10, 65535, p1.data(), 100);
    core.IngestRxFrame(f1.data(), f1.size());

    // Both segments delivered
    auto rx_m = core.CollectRxPayloads();
    size_t total_m = 0;
    for (const auto& item : rx_m) total_m += item.payload.size();
    CHECK(total_m == 200, "TEST M: Delivered all 200 bytes before FIN processing (got %zu)", total_m);

    t = core.GetFlow(fidM);
    CHECK(t.state == 5, "TEST M: Flow transitioned to kTimeWait (state=5, got %u)", t.state);
    CHECK(t.rcv_nxt == base + 201, "TEST M: rcv_nxt advanced over FIN byte to base+201 (got %u)", t.rcv_nxt);
    auto acks_m2 = Drain(core);
    CHECK(!acks_m2.empty(), "TEST M: Sent final ACK for FIN");
    if (!acks_m2.empty()) {
      CHECK(acks_m2.back().ack == base + 201, "TEST M: Final ACK ack=%u expected %u", acks_m2.back().ack, base + 201);
    }
  }

  // ---- TEST N: Out-of-Order Reassembly without SACK option.
  // Segment 2 arrives before Segment 1 on a connection without SACK.
  // Segment 2 must be buffered, dup-ACK sent without SACK options, and
  // ordered reassembly delivered when segment 1 arrives.
  {
    const uint64_t fidN = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidN);
    const uint16_t ephN = t.src_port;
    const uint32_t issN = t.iss;
    Drain(core);
    // Plain SYN-ACK (no options at all, bare 20-byte header)
    auto saN = PeerFrame(our_ip, tgt, ephN, 0x70000000u, issN + 1, 0x12, 65535);
    core.IngestRxFrame(saN.data(), saN.size());
    Drain(core);
    t = core.GetFlow(fidN);
    CHECK(t.state == 3, "TEST N: Flow established");
    CHECK(!t.sack_permitted, "TEST N: SACK is NOT negotiated");
    const uint32_t base = t.rcv_nxt;

    // Segment 2 arrives first
    std::vector<uint8_t> p2(100, '2');
    auto f2 = PeerFrame(our_ip, tgt, ephN, base + 100, issN + 1, 0x10, 65535, p2.data(), 100);
    core.IngestRxFrame(f2.data(), f2.size());
    auto acks_n1 = Drain(core);
    CHECK(acks_n1.size() == 1, "TEST N: Emitted dup-ACK");
    if (!acks_n1.empty()) {
      CHECK(acks_n1[0].ack == base, "TEST N: dup-ACK acknowledges base");
      CHECK(acks_n1[0].doff_words == 5, "TEST N: dup-ACK carries bare TCP header without SACK (doff=%u)", acks_n1[0].doff_words);
    }

    // Segment 1 arrives second
    std::vector<uint8_t> p1(100, '1');
    auto f1 = PeerFrame(our_ip, tgt, ephN, base, issN + 1, 0x10, 65535, p1.data(), 100);
    core.IngestRxFrame(f1.data(), f1.size());

    auto rx_n = core.CollectRxPayloads();
    std::vector<uint8_t> n_bytes;
    for (const auto& item : rx_n) n_bytes.insert(n_bytes.end(), item.payload.begin(), item.payload.end());
    CHECK(n_bytes.size() == 200, "TEST N: Delivered all 200 bytes in order without SACK (got %zu)", n_bytes.size());
    bool n_order = true;
    for (size_t i = 0; i < 100; ++i) if (n_bytes[i] != '1') n_order = false;
    for (size_t i = 100; i < 200; ++i) if (n_bytes[i] != '2') n_order = false;
    CHECK(n_order, "TEST N: Sequential delivery: 100 '1's followed by 100 '2's");
    Drain(core);
  }

  // ---- TEST O: Continuous Sliding Window Throughput Benchmark (1 MB transfer).
  {
    const uint64_t fidO = core.EnqueueConnect(our_ip, tgt, 0, 80);
    TcpDpFlowSnapshot t = core.GetFlow(fidO);
    const uint16_t ephO = t.src_port;
    const uint32_t issO = t.iss;
    Drain(core);
    // SYN-ACK with WScale=7, SACK-permitted
    const uint8_t opts[8] = {0x04, 0x02, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01};
    auto saO = PeerFrameOpt(our_ip, tgt, ephO, 0x88000000u, issO + 1, 0x12, 65535, opts, 8);
    core.IngestRxFrame(saO.data(), saO.size());
    Drain(core);

    const size_t target_bytes = 1024 * 1024; // 1 MB
    std::vector<uint8_t> chunk(32768, 'U');
    size_t enqueued = 0;
    size_t total_acked = 0;
    size_t total_segs_sent = 0;

    auto t_start = std::chrono::steady_clock::now();
    while (total_acked < target_bytes) {
      while (enqueued < target_bytes) {
        size_t to_send = std::min<size_t>(chunk.size(), target_bytes - enqueued);
        uint32_t accepted = core.EnqueueSend(fidO, chunk.data(), to_send);
        if (accepted == 0) break;
        enqueued += accepted;
      }
      auto out = Drain(core);
      total_segs_sent += out.size();
      t = core.GetFlow(fidO);
      const uint32_t inflight = t.snd_nxt - t.snd_una;
      if (inflight > 0) {
        auto ack = PeerFrame(our_ip, tgt, ephO, 0x88000001u, t.snd_una + inflight, 0x10, 65535);
        core.IngestRxFrame(ack.data(), ack.size());
        total_acked += inflight;
      }
    }
    auto t_end = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
    double mb_sec = (total_acked / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0);
    double kpps = (total_segs_sent / 1000.0) / (elapsed_ms / 1000.0);
    std::printf("[BENCHMARK] Sliding Window Throughput: %zu bytes in %.2f ms (%.2f MB/s, %.1f kpps)\n",
                total_acked, elapsed_ms, mb_sec, kpps);
    CHECK(total_acked == target_bytes, "Transferred 1 MB via sliding window");
    Drain(core);
  }

  if (g_fails == 0) {
    std::printf("ALL TCP SLIDING-WINDOW TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("TCP SLIDING-WINDOW TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
