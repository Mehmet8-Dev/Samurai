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

struct Seg { uint8_t flags; uint32_t seq; uint32_t payload_len; uint8_t doff_words; };

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
      s.doff_words = uint8_t(p[46] >> 4);  // TCP data offset at frame byte 14+20+12=46
      const size_t tcp_hdr = size_t(s.doff_words) * 4;
      const size_t hdr = 34 + tcp_hdr;     // 14 L2 + 20 IP + TCP header (incl options)
      s.payload_len = psize > hdr ? uint32_t(psize - hdr) : 0;
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

  if (g_fails == 0) {
    std::printf("ALL TCP SLIDING-WINDOW TESTS PASSED\n");
    std::fflush(stdout);
    return 0;
  }
  std::printf("TCP SLIDING-WINDOW TESTS FAILED (%d)\n", g_fails);
  std::fflush(stdout);
  return 1;
}
