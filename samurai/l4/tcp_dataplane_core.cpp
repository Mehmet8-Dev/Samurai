#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <new>

#ifdef SAMURAI_WITH_DPDK
extern "C" {
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
}
#endif

namespace samurai::tcpdp {

namespace {
constexpr uint8_t kTcpFlagFin = 0x01;
constexpr uint8_t kTcpFlagSyn = 0x02;
constexpr uint8_t kTcpFlagRst = 0x04;
constexpr uint8_t kTcpFlagPsh = 0x08;
constexpr uint8_t kTcpFlagAck = 0x10;

// Send-side sliding-window limits.
constexpr size_t kSndBufCap = 1u << 20;           // 1 MiB per-flow app send buffer
constexpr size_t kSndBufCompactThreshold = 64u * 1024u;  // compact once head passes this
constexpr size_t kSegBufPoolCap = 64;             // max recycled segment buffers held per flow
constexpr uint32_t kMaxCwnd = 16u * 1024u * 1024u;       // cwnd ceiling (bytes)
constexpr uint32_t kMinRtoMs = 50u;                      // RTO floor (LAN-oriented load generator)
constexpr uint8_t kOptEnd = 0, kOptNop = 1, kOptMss = 2, kOptWScale = 3, kOptSackPerm = 4, kOptSack = 5;
constexpr uint8_t kOptTimestamp = 8;                    // RFC 7323 timestamp option kind
constexpr uint8_t kSynWScale = 7;                        // window scale shift we advertise
constexpr uint32_t kDupThresh = 3;                       // RFC 6675 duplicate ACK / SACK threshold
constexpr size_t kTsOptLen = 12;                         // 2 NOP + kind(1)+len(1)+TSval(4)+TSecr(4)

// RFC 1982 serial-number comparison for 32-bit TCP sequence space.
inline bool SeqLt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
inline bool SeqLeq(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
inline bool SeqGt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }

// Sequence footprint a segment consumes (payload + 1 for each of SYN/FIN).
inline uint32_t SegSeqLen(const uint8_t flags, const uint32_t payload_len) {
  return payload_len + ((flags & kTcpFlagSyn) ? 1u : 0u) + ((flags & kTcpFlagFin) ? 1u : 0u);
}

inline uint16_t ReadBe16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

inline uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define SAMURAI_HOST_BIG_ENDIAN 1
#else
#define SAMURAI_HOST_BIG_ENDIAN 0
#endif

// One's-complement 16-bit sum of the buffer, interpreting each 16-bit word in
// host byte order, folded to 16 bits. Processed 8 bytes per iteration off a
// 64-bit accumulator so the compiler auto-vectorizes the reduction; a scalar
// tail handles the last <8 bytes. ~2.4x faster at -O2 and ~10x with AVX2 vs the
// byte-at-a-time scalar loop, byte-identical for every input (fuzz-verified).
inline uint32_t OnesSumHost16(const uint8_t* p, size_t n) {
  uint64_t sum = 0;
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t w;
    std::memcpy(&w, p + i, 8);
    sum += (w & 0xFFFFu) + ((w >> 16) & 0xFFFFu) + ((w >> 32) & 0xFFFFu) + ((w >> 48) & 0xFFFFu);
  }
  for (; i + 2 <= n; i += 2) {
    uint16_t w;
    std::memcpy(&w, p + i, 2);
    sum += w;
  }
  if (i < n) {
    // Trailing odd byte. The wire checksum pads the tail as the HIGH byte of a
    // big-endian 16-bit word (b<<8): that is the high byte on BE hosts and the
    // low byte on LE hosts (the final bswap in ToBe16Space restores it).
#if SAMURAI_HOST_BIG_ENDIAN
    sum += static_cast<uint64_t>(p[i]) << 8;
#else
    sum += static_cast<uint64_t>(p[i]);
#endif
  }
  while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
  return static_cast<uint32_t>(sum);
}

// Convert a host-word-space folded sum into big-endian-word space (the space the
// pseudo-header terms below are accumulated in).
inline uint32_t ToBe16Space(uint32_t host_folded) {
#if SAMURAI_HOST_BIG_ENDIAN
  return host_folded;
#else
  return __builtin_bswap16(static_cast<uint16_t>(host_folded));
#endif
}

uint16_t InternetChecksum(const uint8_t* ptr, size_t nbytes) {
  return static_cast<uint16_t>(~ToBe16Space(OnesSumHost16(ptr, nbytes)));
}

uint16_t TcpChecksum(const uint8_t* ip_header, const uint8_t* tcp_header, size_t tcp_len) {
  const uint8_t* src_ip = ip_header + 12;
  const uint8_t* dst_ip = ip_header + 16;

  uint32_t sum = ToBe16Space(OnesSumHost16(tcp_header, tcp_len));  // payload, BE-word space
  sum += (static_cast<uint32_t>(src_ip[0]) << 8) | static_cast<uint32_t>(src_ip[1]);
  sum += (static_cast<uint32_t>(src_ip[2]) << 8) | static_cast<uint32_t>(src_ip[3]);
  sum += (static_cast<uint32_t>(dst_ip[0]) << 8) | static_cast<uint32_t>(dst_ip[1]);
  sum += (static_cast<uint32_t>(dst_ip[2]) << 8) | static_cast<uint32_t>(dst_ip[3]);
  sum += 6;
  sum += static_cast<uint32_t>(tcp_len);

  while (sum >> 16) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

inline void SaturatingDecrement(std::atomic<uint64_t>& counter) {
  uint64_t cur = counter.load(std::memory_order_relaxed);
  while (cur > 0) {
    if (counter.compare_exchange_weak(cur, cur - 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
      return;
    }
  }
}

uint32_t env_u32_bounded(const char* name, uint32_t fallback, uint32_t min_value, uint32_t max_value) {
  if (!name || min_value > max_value) {
    return fallback;
  }
  const char* raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0') {
    return fallback;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(raw, &end, 10);
  if (end == raw || (end != nullptr && *end != '\0')) {
    return fallback;
  }
  if (parsed < static_cast<unsigned long>(min_value) || parsed > static_cast<unsigned long>(max_value)) {
    return fallback;
  }
  return static_cast<uint32_t>(parsed);
}

// Env override for a bool toggle: "1"/"true"/"on"/"yes" -> true, "0"/"false"/
// "off"/"no" -> false, unset/unrecognised -> fallback.
bool env_bool(const char* name, bool fallback) {
  const char* raw = name ? std::getenv(name) : nullptr;
  if (raw == nullptr || raw[0] == '\0') {
    return fallback;
  }
  if (raw[0] == '1' || raw[0] == 't' || raw[0] == 'T' || raw[0] == 'y' || raw[0] == 'Y' ||
      raw[0] == 'o' || raw[0] == 'O') {
    // "on"/"off" both start with 'o' -> disambiguate.
    if ((raw[0] == 'o' || raw[0] == 'O') && (raw[1] == 'f' || raw[1] == 'F')) return false;
    return true;
  }
  return false;
}
}  // namespace

TcpDataplaneCore::TcpDataplaneCore() {
  for (auto& hint : timer_shard_min_due_ns_) {
    hint.store(UINT64_MAX, std::memory_order_relaxed);
  }
  const size_t per_shard_cap = 128;
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    tx_shard_[i].storage.assign(per_shard_cap * tx_ring_slot_size_, 0U);
    tx_shard_[i].lengths.assign(per_shard_cap, 0U);
    tx_shard_[i].seqs.assign(per_shard_cap, 0U);
  }
}

void TcpDataplaneCore::RefreshTimerHint(size_t shard) {
  timer_shard_min_due_ns_[shard].store(
      timer_heap_shard_[shard].empty() ? UINT64_MAX : timer_heap_shard_[shard].top().due_ns,
      std::memory_order_relaxed);
}

bool TcpDataplaneCore::FlowKey::operator==(const FlowKey& other) const {
  return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port && dst_port == other.dst_port;
}

size_t TcpDataplaneCore::FlowKeyHash::operator()(const FlowKey& key) const {
  uint64_t h = static_cast<uint64_t>(key.src_ip);
  h ^= (static_cast<uint64_t>(key.dst_ip) << 1);
  h ^= (static_cast<uint64_t>(key.src_port) << 33);
  h ^= (static_cast<uint64_t>(key.dst_port) << 49);
  return static_cast<size_t>(h ^ (h >> 32));
}

bool TcpDataplaneCore::Configure(const TcpDpConfig& config) {
  if (config.initial_rto_ms == 0 || config.max_retransmits == 0 || config.connect_timeout_ms == 0 ||
      config.idle_timeout_ms == 0) {
    return false;
  }
  std::lock_guard<SpinLock> sguard(state_mu_);
  config_ = config;
  // TCP maturity toggles: env overrides the config default (RFC6675 on, the three
  // behaviour-changing ones off) so operators can flip them without a rebuild.
  config_.enable_rfc6675_recovery = env_bool("SAMURAI_TCPDP_RFC6675", config_.enable_rfc6675_recovery);
  config_.enable_delayed_ack = env_bool("SAMURAI_TCPDP_DELAYED_ACK", config_.enable_delayed_ack);
  config_.enable_nagle = env_bool("SAMURAI_TCPDP_NAGLE", config_.enable_nagle);
  config_.enable_timestamps = env_bool("SAMURAI_TCPDP_TIMESTAMPS", config_.enable_timestamps);
  config_.verify_rx_checksum = env_bool("SAMURAI_TCPDP_VERIFY_RX_CHECKSUM", config_.verify_rx_checksum);
  tx_ring_capacity_ = static_cast<size_t>(env_u32_bounded(
      "SAMURAI_TCPDP_TX_RING_CAPACITY",
      static_cast<uint32_t>(tx_ring_capacity_),
      1U,
      1U << 20));
  tx_overflow_capacity_ = static_cast<size_t>(env_u32_bounded(
      "SAMURAI_TCPDP_TX_OVERFLOW_CAPACITY",
      static_cast<uint32_t>(tx_overflow_capacity_),
      1U,
      1U << 20));
  next_flow_id_ = 1;
  next_ephemeral_port_ = 40000;
  seq_seed_ = 0x10203040U;
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<SpinLock> fguard(flow_shard_mu_[i]);
    flows_by_id_shard_[i].clear();
  }
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<SpinLock> iguard(flow_index_shard_mu_[i]);
    flow_index_shard_[i].clear();
  }
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<SpinLock> tguard(timer_shard_mu_[i]);
    timer_heap_shard_[i] = std::priority_queue<TimerEntry, std::vector<TimerEntry>, TimerEntryMin>();
    timer_shard_min_due_ns_[i].store(UINT64_MAX, std::memory_order_relaxed);
  }
  const size_t per_shard_cap = std::max<size_t>(64, tx_ring_capacity_ / kFlowLockShards);
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<SpinLock> guard(tx_shard_[i].mu);
    tx_shard_[i].storage.assign(per_shard_cap * tx_ring_slot_size_, 0U);
    tx_shard_[i].lengths.assign(per_shard_cap, 0U);
    tx_shard_[i].seqs.assign(per_shard_cap, 0U);
    tx_shard_[i].head = 0;
    tx_shard_[i].tail = 0;
    tx_shard_[i].count = 0;
    tx_shard_[i].pin_active = false;
    tx_shard_[i].pin_head = 0;
    tx_shard_[i].pin_count = 0;
    tx_shard_[i].pin_packet_size = 0;
    tx_shard_[i].pin_stride = 0;
    tx_shard_[i].overflow.clear();
  }
  {
    std::lock_guard<SpinLock> cguard(tx_consumer_mu_);
    current_peek_shard_ = 0;
  }
  {
    std::lock_guard<SpinLock> cguard(completion_mu_);
    completions_.clear();
  }
  {
    std::lock_guard<SpinLock> rguard(rx_payload_mu_);
    rx_payloads_.clear();
  }
  for (auto& s : stats_shard_) { s.Reset(); }
  tx_packets_queued_.store(0, std::memory_order_relaxed);
  tx_packets_drained_.store(0, std::memory_order_relaxed);
  tx_packets_sent_.store(0, std::memory_order_relaxed);
  tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
  poll_rr_shard_ = 0;
  return true;
}

uint32_t TcpDataplaneCore::IngestTxPackets(const uint8_t* packets, size_t packet_size, size_t count) {
  if (!packets || packet_size == 0 || count == 0) {
    return 0;
  }
  uint32_t updated = 0;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* pkt = packets + (i * packet_size);
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    uint16_t window = 0;
    uint16_t payload_len = 0;
    uint8_t ttl = 0;
    if (!ParseIpv4TcpFrame(
            pkt, packet_size, &src_ip, &dst_ip, &src_port, &dst_port, &seq, &ack, &flags, &window, &payload_len, &ttl)) {
      continue;
    }

    const FlowKey key{src_ip, dst_ip, src_port, dst_port};
    const size_t index_shard = FlowIndexShardForKey(key);
    uint64_t flow_id = 0;
    {
      std::lock_guard<SpinLock> iguard(flow_index_shard_mu_[index_shard]);
      auto idx = flow_index_shard_[index_shard].find(key);
      if (idx == flow_index_shard_[index_shard].end()) {
        FlowEntry created;
        {
          std::lock_guard<SpinLock> sguard(state_mu_);
          created.flow_id = next_flow_id_++;
        }
        created.key = key;
        created.iss = seq;
        created.snd_una = seq;
        created.snd_nxt = seq;
        created.rcv_nxt = ack;
        created.peer_window = 0;
        created.local_window = window > 0 ? window : config_.local_window;
        created.mss = config_.default_mss;
        created.cwnd = 10u * static_cast<uint32_t>(config_.default_mss);  // IW10
        created.ttl = ttl > 0 ? ttl : config_.default_ttl;
        created.last_activity_ns = DefaultNowNs();
        flow_id = created.flow_id;
        const size_t flow_shard = FlowLockShardForFlowId(flow_id);
        {
          std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
          flows_by_id_shard_[flow_shard].emplace(flow_id, std::move(created));
        }
        flow_index_shard_[index_shard][key] = flow_id;
      } else {
        flow_id = idx->second;
      }
    }

    const size_t flow_shard = FlowLockShardForFlowId(flow_id);
    std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
    auto it = flows_by_id_shard_[flow_shard].find(flow_id);
    if (it == flows_by_id_shard_[flow_shard].end()) {
      continue;
    }
    FlowEntry* flow = &it->second;
    flow->last_activity_ns = DefaultNowNs();

    if ((flags & kTcpFlagSyn) != 0 && (flags & kTcpFlagAck) == 0) {
      SetFlowState(*flow, TcpDpState::kSynSent);
      flow->iss = seq;
      flow->snd_una = seq;
      flow->snd_nxt = AdvanceSeq(seq, 1U);
      flow->rcv_nxt = 0;
      flow->retransmit_count = 0;
      flow->cwnd = 10u * static_cast<uint32_t>(config_.default_mss);  // IW10
      flow->sndbuf.clear();
      flow->sndbuf_head = 0;
      flow->unacked.clear();
      OutstandingTx out;
      out.seq = seq;
      out.ack = 0;
      out.payload_len = 0;
      out.flags = kTcpFlagSyn;
      out.xmit_count = 1;
      flow->unacked.push_back(std::move(out));
      flow->cur_rto_ms = config_.initial_rto_ms;
      flow->rto_deadline_ns = DefaultNowNs() + NsFromMs(flow->cur_rto_ms);
      stats_shard_[flow_shard].connect_attempts.fetch_add(1, std::memory_order_relaxed);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
      updated++;
      continue;
    }

    if ((flags & kTcpFlagAck) != 0 && payload_len == 0 && flow->state == TcpDpState::kSynAckRcvd) {
      SetFlowState(*flow, TcpDpState::kEstablished);
      flow->snd_una = ack;
      flow->snd_nxt = seq;
      flow->unacked.clear();
      flow->rto_deadline_ns = 0;
      flow->cur_rto_ms = 0;
      stats_shard_[flow_shard].connect_established.fetch_add(1, std::memory_order_relaxed);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
      updated++;
      continue;
    }

    if ((flags & kTcpFlagAck) != 0 && payload_len > 0) {
      SetFlowState(*flow, TcpDpState::kEstablished);
      // snd_una advances only from received ACKs (HandleAck); the ack field on our
      // own outbound packet is our rcv_nxt, not an acknowledgement of our data.
      flow->snd_nxt = AdvanceSeq(seq, payload_len);
      flow->rcv_nxt = ack;
      flow->local_window = window > 0 ? window : flow->local_window;
      flow->retransmit_count = 0;
      OutstandingTx out;
      out.seq = seq;
      out.ack = ack;
      out.payload_len = payload_len;
      out.flags = static_cast<uint8_t>(flags & static_cast<uint8_t>(kTcpFlagFin | kTcpFlagPsh | kTcpFlagAck));
      out.xmit_count = 1;
      const uint8_t* ip = pkt + 14;
      const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
      const uint8_t* tcp = ip + ihl;
      const size_t data_off = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4U;
      const uint8_t* payload = tcp + data_off;
      out.data.assign(payload, payload + payload_len);
      flow->unacked.push_back(std::move(out));
      if (flow->rto_deadline_ns == 0) {
        flow->cur_rto_ms = flow->cur_rto_ms ? flow->cur_rto_ms : config_.initial_rto_ms;
        flow->rto_deadline_ns = DefaultNowNs() + NsFromMs(flow->cur_rto_ms);
      }
      stats_shard_[flow_shard].tx_data_bytes.fetch_add(static_cast<uint64_t>(payload_len), std::memory_order_relaxed);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
      updated++;
      continue;
    }

    if ((flags & kTcpFlagFin) != 0) {
      SetFlowState(*flow, TcpDpState::kFinWait);
      flow->snd_nxt = AdvanceSeq(seq, 1U);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
      updated++;
      continue;
    }
  }
  return updated;
}

void TcpDataplaneCore::SetEphemeralPortBase(uint16_t base) {
  std::lock_guard<SpinLock> sguard(state_mu_);
  next_ephemeral_port_ = base;
  ephemeral_port_base_ = base;
}

void TcpDataplaneCore::SetEphemeralPortStride(uint16_t stride) {
  std::lock_guard<SpinLock> sguard(state_mu_);
  ephemeral_port_stride_ = stride == 0 ? 1 : stride;
}

void TcpDataplaneCore::SetFlowIdBase(uint64_t base) {
  std::lock_guard<SpinLock> sguard(state_mu_);
  next_flow_id_ = base == 0 ? 1 : base;
}

uint64_t TcpDataplaneCore::EnqueueConnect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
  if (src_ip == 0 || dst_ip == 0 || dst_port == 0) {
    return 0;
  }
  uint64_t flow_id = 0;
  uint32_t flow_iss = 0;
  if (src_port == 0) {
    std::lock_guard<SpinLock> sguard(state_mu_);
    src_port = static_cast<uint16_t>(next_ephemeral_port_);
    next_ephemeral_port_ += ephemeral_port_stride_;
    // Wrap back to the base so a shard's ports stay in one residue class (mask
    // steering). With stride 1 and base 40000 this preserves the legacy behaviour
    // (natural uint16 wrap well above the base).
    if (next_ephemeral_port_ > 65535u) {
      next_ephemeral_port_ = ephemeral_port_base_;
    }
  }
  {
    std::lock_guard<SpinLock> sguard(state_mu_);
    flow_id = next_flow_id_++;
    flow_iss = seq_seed_;
    seq_seed_ += 0x01010101U;
  }
  const uint64_t now_ns = DefaultNowNs();
  FlowEntry flow;
  flow.flow_id = flow_id;
  flow.key = FlowKey{src_ip, dst_ip, src_port, dst_port};
  flow.iss = flow_iss;
  flow.snd_una = flow_iss;
  flow.snd_nxt = flow_iss;
  flow.rcv_nxt = 0;
  flow.peer_window = 0;
  flow.local_window = config_.local_window;
  flow.mss = config_.default_mss;
  flow.cwnd = 10u * static_cast<uint32_t>(config_.default_mss);  // IW10 (RFC 6928)
  flow.snd_wscale = kSynWScale;
  flow.ttl = config_.default_ttl;
  flow.state = TcpDpState::kSynSent;
  flow.last_activity_ns = now_ns;

  thread_local uint8_t tls_scratch_buf[2048];
  uint8_t syn_opts[40];
  // MSS + SACK-perm + WScale (+ TS when enabled). We only advertise TS in our SYN;
  // ts_ok is confirmed on the SYN-ACK if the peer echoes a TS option.
  const bool ts_offer = config_.enable_timestamps;
  const size_t syn_opts_len = BuildSynOptions(syn_opts, kSynWScale, ts_offer, TimestampMs());
  size_t syn_len = BuildPacketOpt(flow, flow.snd_nxt, 0, kTcpFlagSyn, nullptr, 0, syn_opts, syn_opts_len, tls_scratch_buf);
  flow.snd_nxt = AdvanceSeq(flow.snd_nxt, 1);
  QueuePacket(flow, tls_scratch_buf, syn_len, flow.iss, 0, kTcpFlagSyn, nullptr, 0, true);
  // Store the SYN options inline so a retransmitted SYN replays them (BuildOutstandingPacket) without heap alloc.
  if (!flow.unacked.empty() && syn_opts_len <= flow.unacked.back().opts.size()) {
    std::memcpy(flow.unacked.back().opts.data(), syn_opts, syn_opts_len);
    flow.unacked.back().opts_len = static_cast<uint8_t>(syn_opts_len);
  }
  ScheduleFlowTimers(flow, now_ns);

  const size_t index_shard = FlowIndexShardForKey(flow.key);
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  const FlowKey fkey = flow.key;
  std::lock_guard<SpinLock> iguard(flow_index_shard_mu_[index_shard]);
  std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
  flows_by_id_shard_[flow_shard].insert_or_assign(flow_id, std::move(flow));
  flow_index_shard_[index_shard][fkey] = flow_id;
  stats_shard_[flow_shard].flows_active.fetch_add(1, std::memory_order_relaxed);
  stats_shard_[flow_shard].connect_attempts.fetch_add(1, std::memory_order_relaxed);
  return flow_id;
}

uint32_t TcpDataplaneCore::EnqueueSend(uint64_t flow_id, const uint8_t* payload, size_t payload_len) {
  if (!payload || payload_len == 0) {
    return 0;
  }
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    return 0;
  }
  FlowEntry* flow = &it->second;
  if (flow->state != TcpDpState::kEstablished) {
    return 0;
  }
  // socket send() semantics: accepted bytes are copied into the per-flow send
  // buffer (== owned by us), so a short write is safe — the caller re-offers only
  // its unaccepted tail. PumpSend then clocks the buffer onto the wire in
  // MSS-sized segments as the effective window min(cwnd, rwnd) allows. This
  // replaces the legacy one-outstanding-segment gate (stop-and-wait).
  const size_t buffered = flow->sndbuf.size() - flow->sndbuf_head;
  const size_t room = kSndBufCap > buffered ? kSndBufCap - buffered : 0;
  const size_t accept = std::min(payload_len, room);
  if (accept == 0) {
    return 0;  // send buffer full -> backpressure, caller retries later
  }
  flow->sndbuf.insert(flow->sndbuf.end(), payload, payload + accept);
  const uint64_t now_ns = DefaultNowNs();
  flow->last_activity_ns = now_ns;
  PumpSend(*flow, now_ns);
  ScheduleFlowTimers(*flow, now_ns);
  return static_cast<uint32_t>(accept);
}

uint32_t TcpDataplaneCore::IngestRxFrame(const uint8_t* frame, size_t frame_len) {
  if (!frame || frame_len == 0) {
    return 0;
  }
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t flags = 0;
  uint16_t window = 0;
  uint16_t payload_len = 0;
  uint8_t ttl = 0;
  if (!ParseIpv4TcpFrame(
          frame, frame_len, &src_ip, &dst_ip, &src_port, &dst_port, &seq, &ack, &flags, &window, &payload_len, &ttl, config_.verify_rx_checksum)) {
    return 0;
  }

  TcpOptionInfo opt;
  ParseTcpOptions(frame, frame_len, &opt);

  uint64_t flow_id = 0;
  const FlowKey key{dst_ip, src_ip, dst_port, src_port};
  const size_t index_shard = FlowIndexShardForKey(key);
  stats_shard_[index_shard].rx_frames.fetch_add(1, std::memory_order_relaxed);
  {
    std::lock_guard<SpinLock> iguard(flow_index_shard_mu_[index_shard]);
    auto idx = flow_index_shard_[index_shard].find(key);
    if (idx == flow_index_shard_[index_shard].end()) {
      stats_shard_[index_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return 0;
    }
    flow_id = idx->second;
  }

  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  FlowEntry* flow = &it->second;

  flow->last_activity_ns = DefaultNowNs();
  const auto finish = [&](uint32_t rc) -> uint32_t {
    ScheduleFlowTimers(*flow, flow->last_activity_ns);
    return rc;
  };
  if (window > 0) {
    // Window scaling (RFC 7323): the SYN-ACK window itself is never scaled; every
    // later segment's window is left-shifted by the peer's advertised shift.
    const bool is_synack = (flags & kTcpFlagSyn) != 0;
    uint32_t pw = is_synack ? static_cast<uint32_t>(window)
                            : (static_cast<uint32_t>(window) << flow->rcv_wscale);
    if (pw > (1u << 30)) pw = 1u << 30;
    flow->peer_window = pw;
  }

  if ((flags & kTcpFlagRst) != 0) {
    SetFlowState(*flow, TcpDpState::kRstSeen);
    flow->unacked.clear();
    flow->sndbuf.clear();
    flow->sndbuf_head = 0;
    flow->rto_deadline_ns = 0;
    flow->cur_rto_ms = 0;
    flow->rx_oo_queue.clear();
    flow->rx_oo_bytes = 0;
    flow->pending_fin_seq.reset();
    flow->sack_blocks.clear();
    stats_shard_[flow_shard].peer_rst_count.fetch_add(1, std::memory_order_relaxed);
    PushCompletion(flow->flow_id, flow->state, false, "peer_rst");
    return finish(1);
  }

  if ((flags & (kTcpFlagSyn | kTcpFlagAck)) == (kTcpFlagSyn | kTcpFlagAck) && flow->state == TcpDpState::kSynSent) {
    if (ack != flow->snd_nxt) {
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return finish(0);
    }
    flow->snd_una = ack;
    flow->rcv_nxt = seq + 1U;
    SetFlowState(*flow, TcpDpState::kSynAckRcvd);
    // Negotiated options — we always offer SACK-permitted + WScale + MSS in our SYN,
    // so honour whatever the peer echoed.
    flow->sack_permitted = opt.sack_permitted;
    flow->rcv_wscale = opt.has_wscale ? opt.wscale : 0;
    if (opt.has_mss && opt.mss > 0 && opt.mss < flow->mss) {
      flow->mss = opt.mss;  // effective MSS is the smaller of the two advertisements
    }
    // Timestamps (RFC 7323): active only if we offered AND the peer echoed a TS on the
    // SYN-ACK. Seed ts_recent from its TSval so our first data segment echoes it.
    if (config_.enable_timestamps && opt.has_ts) {
      flow->ts_ok = true;
      flow->ts_recent = opt.ts_val;
    }
    // Seed the RTO estimate from the handshake RTT (SYN -> SYN-ACK); the SYN was sent
    // exactly once, so this is Karn-safe. UpdateRtt sets cur_rto_ms.
    if (!flow->unacked.empty() && flow->unacked.front().xmit_count == 1) {
      UpdateRtt(*flow, flow->unacked.front().sent_ns);
    }
    std::vector<OutstandingTx>().swap(flow->unacked);  // our SYN is acknowledged; release initial vector buffer
    flow->rto_deadline_ns = 0;
    thread_local uint8_t tls_scratch_buf[2048];
    size_t ack_len = BuildSeg(*flow, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, tls_scratch_buf);
    QueuePacket(*flow, tls_scratch_buf, ack_len, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, false);
    SetFlowState(*flow, TcpDpState::kEstablished);
    stats_shard_[flow_shard].connect_established.fetch_add(1, std::memory_order_relaxed);
    PushCompletion(flow->flow_id, flow->state, true, "connect_established");
    return finish(1);
  }

  if ((flags & kTcpFlagAck) != 0) {
    HandleAck(*flow, ack, &opt);
    stats_shard_[FlowLockShardForFlowId(flow_id)].rx_ack_count.fetch_add(1, std::memory_order_relaxed);
    // A pure window update (no new data acked) can also reopen the send window.
    PumpSend(*flow, flow->last_activity_ns);
  }

  if (payload_len > 0) {
    // PAWS (RFC 7323, opt-in TS): drop an old duplicate whose TSval regressed and
    // re-acknowledge the current receive point.
    if (PawsReject(*flow, &opt)) {
      stats_shard_[flow_shard].out_of_order_rx_count.fetch_add(1, std::memory_order_relaxed);
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      SendAckNow(*flow);
      return finish(1);
    }

    const bool state_ok_for_rx = (flow->state == TcpDpState::kEstablished ||
                                  flow->state == TcpDpState::kSynAckRcvd ||
                                  flow->state == TcpDpState::kFinWait);
    if (!state_ok_for_rx) {
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return finish(1);
    }

    // 1. Old duplicate segment: payload completely before or up to rcv_nxt.
    if (SeqLeq(AdvanceSeq(seq, payload_len), flow->rcv_nxt)) {
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      SendAckNow(*flow);
      return finish(1);
    }

    // 2. Out-of-order future segment: seq > rcv_nxt (a hole precedes it).
    if (SeqGt(seq, flow->rcv_nxt)) {
      stats_shard_[flow_shard].out_of_order_rx_count.fetch_add(1, std::memory_order_relaxed);
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      std::vector<uint8_t> p = ExtractIpv4TcpPayload(frame, frame_len);
      if (p.size() > payload_len) {
        p.resize(payload_len);
      }
      const size_t p_size = p.size();
      bool queued = false;

      // Check if this segment is completely covered by an existing segment in queue
      bool covered = false;
      for (const auto& seg : flow->rx_oo_queue) {
        const uint32_t s_end = AdvanceSeq(seg.seq, static_cast<uint32_t>(seg.payload.size()));
        if (SeqLeq(seg.seq, seq) && SeqLeq(AdvanceSeq(seq, static_cast<uint32_t>(p_size)), s_end)) {
          covered = true;
          break;
        }
      }

      if (!covered && p_size > 0 &&
          flow->rx_oo_queue.size() < kMaxRxOoSegments &&
          (flow->rx_oo_bytes + p_size <= kMaxRxOoBytes)) {
        // If this new segment completely covers existing smaller segments, purge them
        for (auto q_it = flow->rx_oo_queue.begin(); q_it != flow->rx_oo_queue.end(); ) {
          const uint32_t s_end = AdvanceSeq(q_it->seq, static_cast<uint32_t>(q_it->payload.size()));
          if (SeqLeq(seq, q_it->seq) && SeqLeq(s_end, AdvanceSeq(seq, static_cast<uint32_t>(p_size)))) {
            flow->rx_oo_bytes = (flow->rx_oo_bytes >= q_it->payload.size()) ?
                                (flow->rx_oo_bytes - q_it->payload.size()) : 0;
            q_it = flow->rx_oo_queue.erase(q_it);
          } else {
            ++q_it;
          }
        }

        auto it_oo = std::find_if(flow->rx_oo_queue.begin(), flow->rx_oo_queue.end(),
                                  [seq](const FlowEntry::RxOoSegment& s) { return s.seq == seq; });
        if (it_oo == flow->rx_oo_queue.end()) {
          flow->rx_oo_bytes += p_size;
          flow->rx_oo_queue.push_back(FlowEntry::RxOoSegment{seq, std::move(p)});
          queued = true;
        } else if (p_size > it_oo->payload.size()) {
          flow->rx_oo_bytes = flow->rx_oo_bytes + p_size - it_oo->payload.size();
          it_oo->payload = std::move(p);
          queued = true;
        }
      }

      if ((flags & kTcpFlagFin) != 0 && (queued || covered)) {
        flow->pending_fin_seq = AdvanceSeq(seq, static_cast<uint32_t>(p_size));
      }

      UpdateFlowSackBlocks(*flow, seq, static_cast<uint32_t>(p_size));
      SendAckNow(*flow);
      return finish(1);
    }

    // 3. Partial overlap: starts before rcv_nxt, ends after rcv_nxt.
    // Trim the already acknowledged prefix so seq == flow->rcv_nxt.
    uint32_t trim_offset = 0;
    if (SeqLt(seq, flow->rcv_nxt)) {
      trim_offset = flow->rcv_nxt - seq;
      seq = flow->rcv_nxt;
      payload_len -= static_cast<uint16_t>(trim_offset);
    }

    // 4. In-order segment: seq == flow->rcv_nxt.
    std::vector<uint8_t> in_order_payload = ExtractIpv4TcpPayload(frame, frame_len);
    if (trim_offset > 0) {
      if (trim_offset < in_order_payload.size()) {
        in_order_payload.erase(in_order_payload.begin(), in_order_payload.begin() + trim_offset);
      } else {
        in_order_payload.clear();
      }
    }
    if (in_order_payload.size() > payload_len) {
      in_order_payload.resize(payload_len);
    }
    flow->rcv_nxt = AdvanceSeq(seq, payload_len);
    if (flow->ts_ok && opt.has_ts) flow->ts_recent = opt.ts_val;
    stats_shard_[flow_shard].rx_data_bytes.fetch_add(static_cast<uint64_t>(payload_len), std::memory_order_relaxed);
    {
      std::lock_guard<SpinLock> qguard(rx_payload_mu_);
      rx_payloads_.push_back(TcpDpRxPayload{flow->flow_id, std::move(in_order_payload)});
    }

    // 5. Drain consecutive / overlapping segments from rx_oo_queue.
    bool drained_any = false;
    while (!flow->rx_oo_queue.empty()) {
      auto it_oo = std::find_if(flow->rx_oo_queue.begin(), flow->rx_oo_queue.end(),
                                [rcv = flow->rcv_nxt](const FlowEntry::RxOoSegment& s) { return s.seq == rcv; });
      if (it_oo == flow->rx_oo_queue.end()) {
        bool found_overlap = false;
        for (auto o_it = flow->rx_oo_queue.begin(); o_it != flow->rx_oo_queue.end(); ) {
          const uint32_t s_seq = o_it->seq;
          const size_t s_len = o_it->payload.size();
          const uint32_t s_end = AdvanceSeq(s_seq, static_cast<uint32_t>(s_len));
          if (SeqLeq(s_end, flow->rcv_nxt)) {
            flow->rx_oo_bytes = (flow->rx_oo_bytes >= s_len) ? (flow->rx_oo_bytes - s_len) : 0;
            o_it = flow->rx_oo_queue.erase(o_it);
            found_overlap = true; // keeps outer drain loop active to check next segments
          } else if (SeqLt(s_seq, flow->rcv_nxt) && SeqGt(s_end, flow->rcv_nxt)) {
            const size_t offset = static_cast<size_t>(flow->rcv_nxt - s_seq);
            const size_t usable_len = s_len - offset;
            flow->rcv_nxt = AdvanceSeq(flow->rcv_nxt, static_cast<uint32_t>(usable_len));
            stats_shard_[flow_shard].rx_data_bytes.fetch_add(static_cast<uint64_t>(usable_len), std::memory_order_relaxed);
            {
              std::lock_guard<SpinLock> qguard(rx_payload_mu_);
              rx_payloads_.push_back(TcpDpRxPayload{
                  flow->flow_id,
                  std::vector<uint8_t>(o_it->payload.begin() + offset, o_it->payload.end())});
            }
            flow->rx_oo_bytes = (flow->rx_oo_bytes >= s_len) ? (flow->rx_oo_bytes - s_len) : 0;
            flow->rx_oo_queue.erase(o_it);
            found_overlap = true;
            drained_any = true;
            break;
          } else {
            ++o_it;
          }
        }
        if (!found_overlap) {
          break;
        }
        continue;
      }

      const size_t seg_len = it_oo->payload.size();
      flow->rcv_nxt = AdvanceSeq(flow->rcv_nxt, static_cast<uint32_t>(seg_len));
      stats_shard_[flow_shard].rx_data_bytes.fetch_add(static_cast<uint64_t>(seg_len), std::memory_order_relaxed);
      {
        std::lock_guard<SpinLock> qguard(rx_payload_mu_);
        rx_payloads_.push_back(TcpDpRxPayload{flow->flow_id, std::move(it_oo->payload)});
      }
      flow->rx_oo_bytes = (flow->rx_oo_bytes >= seg_len) ? (flow->rx_oo_bytes - seg_len) : 0;
      flow->rx_oo_queue.erase(it_oo);
      drained_any = true;
    }

    UpdateFlowSackBlocks(*flow, 0, 0);

    if (flow->pending_fin_seq.has_value() && flow->rcv_nxt == *flow->pending_fin_seq) {
      flow->pending_fin_seq.reset();
      flow->rcv_nxt = AdvanceSeq(flow->rcv_nxt, 1U);
      SendAckNow(*flow);
      SetFlowState(*flow, TcpDpState::kTimeWait);
      stats_shard_[flow_shard].peer_fin_count.fetch_add(1, std::memory_order_relaxed);
      PushCompletion(flow->flow_id, flow->state, true, "peer_fin");
      return finish(1);
    }

    if ((flags & kTcpFlagFin) == 0) {
      // RFC 5681: An acknowledgment SHOULD be generated immediately when an incoming segment fills a gap.
      OnDataReceivedAck(*flow, DefaultNowNs(), /*force_now=*/drained_any);
    }
  }

  if ((flags & kTcpFlagFin) != 0 && flow->state != TcpDpState::kTimeWait && flow->state != TcpDpState::kClosed) {
    const uint32_t fin_seq = AdvanceSeq(seq, payload_len);
    if (SeqGt(fin_seq, flow->rcv_nxt)) {
      flow->pending_fin_seq = fin_seq;
      stats_shard_[flow_shard].out_of_order_rx_count.fetch_add(1, std::memory_order_relaxed);
      stats_shard_[flow_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      SendAckNow(*flow);
      return finish(1);
    }
    if (fin_seq == flow->rcv_nxt) {
      flow->rcv_nxt = AdvanceSeq(flow->rcv_nxt, 1U);
      if (flow->ts_ok && opt.has_ts) flow->ts_recent = opt.ts_val;
      SendAckNow(*flow);
      SetFlowState(*flow, TcpDpState::kTimeWait);
      stats_shard_[flow_shard].peer_fin_count.fetch_add(1, std::memory_order_relaxed);
      PushCompletion(flow->flow_id, flow->state, true, "peer_fin");
    }
  }
  (void)ttl;
  return finish(1);
}

uint32_t TcpDataplaneCore::Poll(uint64_t now_ns, uint32_t budget) {
  if (budget == 0) {
    budget = 1024;
  }
  if (now_ns == 0) {
    now_ns = DefaultNowNs();
  }
  stats_shard_[poll_rr_shard_.load(std::memory_order_relaxed) % kFlowLockShards].poll_calls.fetch_add(1, std::memory_order_relaxed);
  uint32_t actions = 0;
  while (actions < budget) {
    TimerEntry entry{};
    size_t selected_shard = kFlowLockShards;
    bool have_entry = false;
    {
      const uint32_t rr_base = poll_rr_shard_.load(std::memory_order_relaxed);
      for (size_t probe = 0; probe < kFlowLockShards; ++probe) {
        const size_t shard = static_cast<size_t>((rr_base + probe) % static_cast<uint32_t>(kFlowLockShards));
        // Lock-free skip: nothing in this shard is due yet.
        if (timer_shard_min_due_ns_[shard].load(std::memory_order_relaxed) > now_ns) {
          continue;
        }
        std::lock_guard<SpinLock> tguard(timer_shard_mu_[shard]);
        if (timer_heap_shard_[shard].empty()) {
          RefreshTimerHint(shard);
          continue;
        }
        const TimerEntry top = timer_heap_shard_[shard].top();
        if (top.due_ns == 0 || top.due_ns > now_ns) {
          RefreshTimerHint(shard);
          continue;
        }
        timer_heap_shard_[shard].pop();
        RefreshTimerHint(shard);
        entry = top;
        selected_shard = shard;
        have_entry = true;
        poll_rr_shard_.store(static_cast<uint32_t>((shard + 1) % kFlowLockShards), std::memory_order_relaxed);
        break;
      }
      if (!have_entry) {
        break;
      }
    }
    if (selected_shard >= kFlowLockShards) {
      break;
    }

    std::lock_guard<SpinLock> fguard(flow_shard_mu_[selected_shard]);
    auto it = flows_by_id_shard_[selected_shard].find(entry.flow_id);
    if (it == flows_by_id_shard_[selected_shard].end() || !IsCountedActive(it->second.state)) {
      continue;
    }
    FlowEntry* flow = &it->second;
    switch (entry.kind) {
      case TimerKind::kRto: {
        if (entry.generation != flow->rto_timer_gen || flow->unacked.empty() || flow->rto_deadline_ns == 0 ||
            flow->rto_deadline_ns != entry.due_ns) {
          break;
        }
        if (flow->retransmit_count >= config_.max_retransmits) {
          CloseTimedOutFlow(*flow, TcpDpState::kClosed, "retransmit_exhausted");
          ScheduleFlowTimers(*flow, now_ns);
          actions++;
          break;
        }
        flow->retransmit_count++;
        stats_shard_[selected_shard].retransmit_count.fetch_add(1, std::memory_order_relaxed);
        // RTO recovery (Reno): remember half the flight as ssthresh, collapse cwnd
        // to one segment, and slow-start again.
        {
          const uint32_t rmss = EffectiveMss(*flow);
          const uint32_t flight = flow->snd_nxt - flow->snd_una;
          flow->ssthresh = std::max(flight / 2u, 2u * rmss);
          flow->cwnd = rmss;
          flow->in_fast_recovery = false;
          flow->dup_ack_streak = 0;
          // Abort any RFC 6675 episode: the RTO governs recovery now (go-back-N from
          // snd_una). Keep SACK marks so we still skip SACKed holes, but reset the
          // retransmitted flags + high_rxt so a fresh episode can re-arm later.
          flow->sack_recovery = false;
          flow->high_rxt = flow->snd_una;
          flow->high_sack = 0;
          flow->rescue_rxt = 0;
          for (auto& s : flow->unacked) s.retransmitted = false;
          stats_shard_[selected_shard].congestion_window_reductions.fetch_add(1, std::memory_order_relaxed);
        }
        // Exponential backoff of the retransmit timer, then resend the oldest segment.
        flow->cur_rto_ms =
            std::min((flow->cur_rto_ms ? flow->cur_rto_ms : config_.initial_rto_ms) * 2U, config_.connect_timeout_ms);
        flow->rto_deadline_ns = now_ns + NsFromMs(flow->cur_rto_ms);
        RetransmitOldest(*flow);
        ScheduleFlowTimers(*flow, now_ns);
        actions++;
        break;
      }
      case TimerKind::kConnectTimeout: {
        if (entry.generation != flow->connect_timer_gen || flow->connect_deadline_ns == 0 ||
            flow->connect_deadline_ns != entry.due_ns) {
          break;
        }
        // Preserve legacy precedence: when both RTO and connect-timeout are due,
        // retransmit/retransmit-exhausted path must run first.
        if (flow->rto_deadline_ns > 0 && now_ns >= flow->rto_deadline_ns) {
          break;
        }
        if (flow->state == TcpDpState::kSynSent && !flow->unacked.empty() && now_ns >= flow->connect_deadline_ns) {
          CloseTimedOutFlow(*flow, TcpDpState::kClosed, "connect_timeout");
          ScheduleFlowTimers(*flow, now_ns);
          actions++;
        }
        break;
      }
      case TimerKind::kIdleTimeout: {
        if (entry.generation != flow->idle_timer_gen || flow->idle_deadline_ns == 0 ||
            flow->idle_deadline_ns != entry.due_ns) {
          break;
        }
        if (flow->state == TcpDpState::kEstablished && flow->unacked.empty() && now_ns >= flow->idle_deadline_ns) {
          CloseTimedOutFlow(*flow, TcpDpState::kTimeWait, "idle_timeout");
          ScheduleFlowTimers(*flow, now_ns);
          actions++;
        }
        break;
      }
      case TimerKind::kDelayedAck: {
        // Delayed-ACK expiry: flush the withheld acknowledgement (opt-in path).
        if (entry.generation != flow->delack_timer_gen || flow->delack_deadline_ns == 0 ||
            flow->delack_deadline_ns != entry.due_ns) {
          break;
        }
        if (flow->pending_ack_segs > 0) {
          SendAckNow(*flow);
          actions++;
        }
        break;
      }
      case TimerKind::kZeroWindowProbe:
        break;
    }
  }
  return actions;
}

bool TcpDataplaneCore::PeekTxPacketsStrided(
    uint32_t max_packets,
    const uint8_t** out_base,
    uint32_t* out_count,
    size_t* out_packet_size,
    size_t* out_stride) {
  if (!out_base || !out_count || !out_packet_size || !out_stride) {
    return false;
  }
  *out_base = nullptr;
  *out_count = 0;
  *out_packet_size = 0;
  *out_stride = 0;

  std::lock_guard<SpinLock> cguard(tx_consumer_mu_);
  const size_t per_shard_cap = std::max<size_t>(64, tx_ring_capacity_ / kFlowLockShards);

  if (current_peek_shard_ < kFlowLockShards) {
    auto& ring = tx_shard_[current_peek_shard_];
    std::lock_guard<SpinLock> guard(ring.mu);
    if (ring.pin_active) {
      if (ring.pin_count == 0) {
        ring.pin_active = false;
        ring.pin_head = 0;
        ring.pin_packet_size = 0;
        ring.pin_stride = 0;
      } else {
        const size_t base = static_cast<size_t>(ring.pin_head) * tx_ring_slot_size_;
        *out_base = ring.storage.data() + base;
        *out_count = ring.pin_count;
        *out_packet_size = ring.pin_packet_size;
        *out_stride = ring.pin_stride;
        return true;
      }
    }
  }

  size_t best_shard = kFlowLockShards;
  uint64_t best_seq = UINT64_MAX;

  for (size_t s = 0; s < kFlowLockShards; ++s) {
    auto& ring = tx_shard_[s];
    std::lock_guard<SpinLock> guard(ring.mu);

    while (ring.count < static_cast<uint32_t>(per_shard_cap) && !ring.overflow.empty()) {
      const auto& of = ring.overflow.front();
      if (of.second.size() > tx_ring_slot_size_) {
        break;
      }
      const uint32_t idx = ring.tail;
      const size_t base = static_cast<size_t>(idx) * tx_ring_slot_size_;
      std::memcpy(ring.storage.data() + base, of.second.data(), of.second.size());
      ring.lengths[idx] = static_cast<uint16_t>(of.second.size());
      ring.seqs[idx] = of.first;
      ring.tail = (ring.tail + 1U) % static_cast<uint32_t>(per_shard_cap);
      ring.count++;
      ring.overflow.pop_front();
    }

    if (ring.count > 0) {
      const uint64_t cur_seq = ring.seqs[ring.head];
      if (cur_seq < best_seq) {
        best_seq = cur_seq;
        best_shard = s;
      }
    }
  }

  if (best_shard >= kFlowLockShards) {
    return true;
  }

  auto& ring = tx_shard_[best_shard];
  std::lock_guard<SpinLock> guard(ring.mu);
  if (ring.count == 0) {
    return true;
  }

  const uint32_t linear_available =
      std::min<uint32_t>(ring.count, static_cast<uint32_t>(per_shard_cap) - ring.head);
  if (linear_available == 0) {
    return true;
  }

  uint32_t take = linear_available;
  if (max_packets > 0 && take > max_packets) {
    take = max_packets;
  }
  if (take == 0) {
    return true;
  }

  const size_t first_len = static_cast<size_t>(ring.lengths[ring.head]);
  if (first_len == 0) {
    return true;
  }

  uint32_t uniform_count = 1;
  for (; uniform_count < take; ++uniform_count) {
    const uint32_t idx = ring.head + uniform_count;
    if (static_cast<size_t>(ring.lengths[idx]) != first_len) {
      break;
    }
  }
  if (uniform_count == 0) {
    return true;
  }

  const size_t base = static_cast<size_t>(ring.head) * tx_ring_slot_size_;
  *out_base = ring.storage.data() + base;
  *out_count = uniform_count;
  *out_packet_size = first_len;
  *out_stride = tx_ring_slot_size_;
  ring.pin_active = true;
  ring.pin_head = ring.head;
  ring.pin_count = uniform_count;
  ring.pin_packet_size = first_len;
  ring.pin_stride = tx_ring_slot_size_;
  current_peek_shard_ = static_cast<uint32_t>(best_shard);
  return true;
}

uint32_t TcpDataplaneCore::ConsumeTxPackets(uint32_t max_packets) {
  if (max_packets == 0) {
    return 0;
  }
  std::lock_guard<SpinLock> cguard(tx_consumer_mu_);
  const size_t per_shard_cap = std::max<size_t>(64, tx_ring_capacity_ / kFlowLockShards);

  if (current_peek_shard_ < kFlowLockShards) {
    auto& ring = tx_shard_[current_peek_shard_];
    std::lock_guard<SpinLock> guard(ring.mu);
    if (ring.pin_active) {
      if (ring.pin_count == 0) {
        ring.pin_active = false;
        ring.pin_head = 0;
        ring.pin_packet_size = 0;
        ring.pin_stride = 0;
      } else {
        uint32_t to_drain = std::min(max_packets, ring.pin_count);
        for (uint32_t i = 0; i < to_drain; ++i) {
          ring.lengths[ring.head] = 0;
          ring.seqs[ring.head] = 0;
          ring.head = (ring.head + 1U) % static_cast<uint32_t>(per_shard_cap);
        }
        ring.count -= to_drain;
        ring.pin_count -= to_drain;
        if (ring.pin_count == 0) {
          ring.pin_active = false;
          ring.pin_head = 0;
          ring.pin_packet_size = 0;
          ring.pin_stride = 0;
        } else {
          ring.pin_head = ring.head;
        }
        tx_packets_drained_.fetch_add(to_drain, std::memory_order_relaxed);
        tx_packets_sent_.fetch_add(to_drain, std::memory_order_relaxed);
        tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
        return to_drain;
      }
    }
  }

  uint32_t total_drained = 0;
  while (total_drained < max_packets) {
    size_t best_shard = kFlowLockShards;
    uint64_t best_seq = UINT64_MAX;
    uint64_t next_best_seq = UINT64_MAX;
    for (size_t s = 0; s < kFlowLockShards; ++s) {
      auto& ring = tx_shard_[s];
      std::lock_guard<SpinLock> guard(ring.mu);
      uint64_t s_seq = UINT64_MAX;
      if (ring.count > 0) {
        s_seq = ring.seqs[ring.head];
      } else if (!ring.overflow.empty()) {
        s_seq = ring.overflow.front().first;
      }
      if (s_seq < best_seq) {
        next_best_seq = best_seq;
        best_seq = s_seq;
        best_shard = s;
      } else if (s_seq < next_best_seq) {
        next_best_seq = s_seq;
      }
    }
    if (best_shard >= kFlowLockShards) {
      break;
    }
    auto& ring = tx_shard_[best_shard];
    std::lock_guard<SpinLock> guard(ring.mu);
    while (total_drained < max_packets) {
      if (ring.count > 0 && ring.seqs[ring.head] < next_best_seq) {
        ring.lengths[ring.head] = 0;
        ring.seqs[ring.head] = 0;
        ring.head = (ring.head + 1U) % static_cast<uint32_t>(per_shard_cap);
        ring.count--;
        total_drained++;
      } else if (ring.count == 0 && !ring.overflow.empty() && ring.overflow.front().first < next_best_seq) {
        ring.overflow.pop_front();
        total_drained++;
      } else {
        break;
      }
    }
    if (ring.pin_active) {
      ring.pin_active = false;
      ring.pin_head = 0;
      ring.pin_count = 0;
      ring.pin_packet_size = 0;
      ring.pin_stride = 0;
    }
  }

  if (total_drained > 0) {
    tx_packets_drained_.fetch_add(total_drained, std::memory_order_relaxed);
    tx_packets_sent_.fetch_add(total_drained, std::memory_order_relaxed);
    tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
  }
  return total_drained;
}

std::vector<TcpDpCompletion> TcpDataplaneCore::CollectCompletions() {
  std::deque<TcpDpCompletion> local;
  {
    std::lock_guard<SpinLock> guard(completion_mu_);
    local.swap(completions_);
  }
  std::vector<TcpDpCompletion> out;
  out.reserve(local.size());
  for (const auto& item : local) {
    out.push_back(item);
  }
  return out;
}

std::vector<TcpDpRxPayload> TcpDataplaneCore::CollectRxPayloads() {
  std::deque<TcpDpRxPayload> local;
  {
    std::lock_guard<SpinLock> guard(rx_payload_mu_);
    local.swap(rx_payloads_);
  }
  std::vector<TcpDpRxPayload> out;
  out.reserve(local.size());
  for (auto& item : local) {
    out.push_back(std::move(item));
  }
  return out;
}

TcpDpStatsSnapshot TcpDataplaneCore::SnapshotStats() const {
  TcpDpStatsSnapshot out{};
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    out.flows_active += stats_shard_[i].flows_active.load(std::memory_order_relaxed);
    out.connect_attempts += stats_shard_[i].connect_attempts.load(std::memory_order_relaxed);
    out.connect_established += stats_shard_[i].connect_established.load(std::memory_order_relaxed);
    out.retransmit_count += stats_shard_[i].retransmit_count.load(std::memory_order_relaxed);
    out.timeout_close_count += stats_shard_[i].timeout_close_count.load(std::memory_order_relaxed);
    out.connect_timeout_count += stats_shard_[i].connect_timeout_count.load(std::memory_order_relaxed);
    out.idle_timeout_count += stats_shard_[i].idle_timeout_count.load(std::memory_order_relaxed);
    out.retransmit_exhausted_count += stats_shard_[i].retransmit_exhausted_count.load(std::memory_order_relaxed);
    out.rx_ack_count += stats_shard_[i].rx_ack_count.load(std::memory_order_relaxed);
    out.dup_ack_count += stats_shard_[i].dup_ack_count.load(std::memory_order_relaxed);
    out.partial_ack_count += stats_shard_[i].partial_ack_count.load(std::memory_order_relaxed);
    out.fast_retransmit_count += stats_shard_[i].fast_retransmit_count.load(std::memory_order_relaxed);
    out.unexpected_ack_count += stats_shard_[i].unexpected_ack_count.load(std::memory_order_relaxed);
    out.tx_data_bytes += stats_shard_[i].tx_data_bytes.load(std::memory_order_relaxed);
    out.rx_data_bytes += stats_shard_[i].rx_data_bytes.load(std::memory_order_relaxed);
    out.poll_calls += stats_shard_[i].poll_calls.load(std::memory_order_relaxed);
    out.rx_frames += stats_shard_[i].rx_frames.load(std::memory_order_relaxed);
    out.unexpected_rx += stats_shard_[i].unexpected_rx.load(std::memory_order_relaxed);
    out.out_of_order_rx_count += stats_shard_[i].out_of_order_rx_count.load(std::memory_order_relaxed);
    out.peer_rst_count += stats_shard_[i].peer_rst_count.load(std::memory_order_relaxed);
    out.peer_fin_count += stats_shard_[i].peer_fin_count.load(std::memory_order_relaxed);
    out.sack_blocks_rx_count += stats_shard_[i].sack_blocks_rx_count.load(std::memory_order_relaxed);
    out.zero_window_probes_sent += stats_shard_[i].zero_window_probes_sent.load(std::memory_order_relaxed);
    out.congestion_window_reductions += stats_shard_[i].congestion_window_reductions.load(std::memory_order_relaxed);
    out.native_tls_handshakes_completed += stats_shard_[i].native_tls_handshakes_completed.load(std::memory_order_relaxed);
  }
  out.tx_packets_queued = tx_packets_queued_.load(std::memory_order_relaxed);
  out.tx_packets_drained = tx_packets_drained_.load(std::memory_order_relaxed);
  out.tx_packets_sent = tx_packets_sent_.load(std::memory_order_relaxed);
  return out;
}

TcpDpFlowSnapshot TcpDataplaneCore::GetFlow(uint64_t flow_id) const {
  TcpDpFlowSnapshot out;
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> fguard(flow_shard_mu_[flow_shard]);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    return out;
  }
  const FlowEntry& flow = it->second;
  out.flow_id = flow.flow_id;
  out.src_ip = flow.key.src_ip;
  out.dst_ip = flow.key.dst_ip;
  out.src_port = flow.key.src_port;
  out.dst_port = flow.key.dst_port;
  out.iss = flow.iss;
  out.snd_una = flow.snd_una;
  out.snd_nxt = flow.snd_nxt;
  out.rcv_nxt = flow.rcv_nxt;
  out.peer_window = flow.peer_window;
  out.local_window = flow.local_window;
  out.snd_wscale = flow.snd_wscale;
  out.rcv_wscale = flow.rcv_wscale;
  out.sack_permitted = flow.sack_permitted;
  out.sack_recovery = flow.sack_recovery;
  out.cwnd = flow.cwnd;
  out.ssthresh = flow.ssthresh;
  out.high_rxt = flow.high_rxt;
  out.srtt_ms = flow.srtt_ms;
  out.zero_window_probing = flow.zero_window_probing;
  out.mss = flow.mss;
  out.ttl = flow.ttl;
  out.state = static_cast<uint8_t>(flow.state);
  out.retransmit_count = flow.retransmit_count;
  out.rto_deadline_ns = flow.rto_deadline_ns;
  out.last_activity_ns = flow.last_activity_ns;
  out.found = true;
  return out;
}

TcpDpFlowSnapshot TcpDataplaneCore::GetFlowLockless(uint64_t flow_id) const {
  TcpDpFlowSnapshot out;
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    return out;
  }
  const FlowEntry& flow = it->second;
  out.flow_id = flow.flow_id;
  out.src_ip = flow.key.src_ip;
  out.dst_ip = flow.key.dst_ip;
  out.src_port = flow.key.src_port;
  out.dst_port = flow.key.dst_port;
  out.iss = flow.iss;
  out.snd_una = flow.snd_una;
  out.snd_nxt = flow.snd_nxt;
  out.rcv_nxt = flow.rcv_nxt;
  out.peer_window = flow.peer_window;
  out.local_window = flow.local_window;
  out.snd_wscale = flow.snd_wscale;
  out.rcv_wscale = flow.rcv_wscale;
  out.sack_permitted = flow.sack_permitted;
  out.sack_recovery = flow.sack_recovery;
  out.cwnd = flow.cwnd;
  out.ssthresh = flow.ssthresh;
  out.high_rxt = flow.high_rxt;
  out.srtt_ms = flow.srtt_ms;
  out.zero_window_probing = flow.zero_window_probing;
  out.mss = flow.mss;
  out.ttl = flow.ttl;
  out.state = static_cast<uint8_t>(flow.state);
  out.retransmit_count = flow.retransmit_count;
  out.rto_deadline_ns = flow.rto_deadline_ns;
  out.last_activity_ns = flow.last_activity_ns;
  out.found = true;
  return out;
}

bool TcpDataplaneCore::TestInspectIsLost(uint64_t flow_id, uint32_t seg_seq) const {
  const size_t shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> guard(flow_shard_mu_[shard]);
  auto it = flows_by_id_shard_[shard].find(flow_id);
  if (it == flows_by_id_shard_[shard].end()) {
    return false;
  }
  return IsLostSeg(it->second, seg_seq);
}

uint32_t TcpDataplaneCore::TestInspectComputePipe(uint64_t flow_id) const {
  const size_t shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> guard(flow_shard_mu_[shard]);
  auto it = flows_by_id_shard_[shard].find(flow_id);
  if (it == flows_by_id_shard_[shard].end()) {
    return 0;
  }
  return ComputePipe(it->second);
}

TcpDpMemoryLayout TcpDataplaneCore::GetMemoryLayout() {
  TcpDpMemoryLayout layout{};
  layout.sizeof_flow_entry = sizeof(FlowEntry);
  layout.sizeof_flow_key = sizeof(FlowKey);
  layout.sizeof_timer_entry = sizeof(TimerEntry);
  layout.sizeof_outstanding_tx = sizeof(OutstandingTx);
  layout.sizeof_per_shard_tx_ring = sizeof(PerShardTxRing);
  layout.sizeof_core = sizeof(TcpDataplaneCore);
  return layout;
}

bool TcpDataplaneCore::ParseIpv4TcpFrame(
    const uint8_t* pkt,
    size_t pkt_len,
    uint32_t* out_src_ip,
    uint32_t* out_dst_ip,
    uint16_t* out_src_port,
    uint16_t* out_dst_port,
    uint32_t* out_seq,
    uint32_t* out_ack,
    uint8_t* out_flags,
    uint16_t* out_window,
    uint16_t* out_payload_len,
    uint8_t* out_ttl,
    bool verify_checksum) {
  if (!pkt || pkt_len < 20) {
    return false;
  }
  int ip_offset = -1;
  if (pkt_len >= 18) {
    const uint16_t eth_type = ReadBe16(pkt + 12);
    if (eth_type == 0x8100 && pkt_len >= 22) {
      const uint16_t inner_type = ReadBe16(pkt + 16);
      if (inner_type == 0x0800) {
        ip_offset = 18;
      }
    } else if (eth_type == 0x0800) {
      ip_offset = 14;
    }
  }
  if (ip_offset < 0 && ((pkt[0] >> 4) & 0x0F) == 4) {
    ip_offset = 0;
  }
  if (ip_offset < 0 || pkt_len < static_cast<size_t>(ip_offset + 20)) {
    return false;
  }
  const uint8_t ver = (pkt[ip_offset] >> 4) & 0x0F;
  if (ver != 4) {
    return false;
  }
  const uint8_t ihl = static_cast<uint8_t>((pkt[ip_offset] & 0x0F) * 4);
  if (ihl < 20 || pkt_len < static_cast<size_t>(ip_offset + ihl + 20)) {
    return false;
  }
  if (pkt[ip_offset + 9] != 6) {
    return false;
  }
  const int tcp_offset = ip_offset + ihl;
  const uint8_t data_off = static_cast<uint8_t>((pkt[tcp_offset + 12] >> 4) * 4);
  if (data_off < 20 || pkt_len < static_cast<size_t>(tcp_offset + data_off)) {
    return false;
  }
  const uint16_t total_len = ReadBe16(pkt + ip_offset + 2);
  if (total_len < static_cast<uint16_t>(ihl + data_off) ||
      pkt_len < static_cast<size_t>(ip_offset + total_len)) {
    return false;
  }
  const size_t payload_len = total_len - ihl - data_off;

  if (verify_checksum) {
    if (InternetChecksum(pkt + ip_offset, ihl) != 0) {
      return false;
    }
    const size_t tcp_total_len = static_cast<size_t>(data_off) + payload_len;
    if (TcpChecksum(pkt + ip_offset, pkt + tcp_offset, tcp_total_len) != 0) {
      return false;
    }
  }

  if (out_src_ip) *out_src_ip = ReadBe32(pkt + ip_offset + 12);
  if (out_dst_ip) *out_dst_ip = ReadBe32(pkt + ip_offset + 16);
  if (out_src_port) *out_src_port = ReadBe16(pkt + tcp_offset);
  if (out_dst_port) *out_dst_port = ReadBe16(pkt + tcp_offset + 2);
  if (out_seq) *out_seq = ReadBe32(pkt + tcp_offset + 4);
  if (out_ack) *out_ack = ReadBe32(pkt + tcp_offset + 8);
  if (out_flags) *out_flags = pkt[tcp_offset + 13];
  if (out_window) *out_window = ReadBe16(pkt + tcp_offset + 14);
  if (out_payload_len) *out_payload_len = static_cast<uint16_t>(payload_len);
  if (out_ttl) *out_ttl = pkt[ip_offset + 8];
  return true;
}

uint64_t TcpDataplaneCore::DefaultNowNs() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

uint64_t TcpDataplaneCore::NsFromMs(uint32_t ms) { return static_cast<uint64_t>(ms) * 1000000ULL; }

uint32_t TcpDataplaneCore::AdvanceSeq(uint32_t seq, uint32_t amount) { return seq + amount; }

size_t TcpDataplaneCore::FlowLockShardForFlowId(uint64_t flow_id) const {
  return static_cast<size_t>(flow_id % static_cast<uint64_t>(kFlowLockShards));
}

size_t TcpDataplaneCore::FlowIndexShardForKey(const FlowKey& key) const {
  return FlowKeyHash{}(key) % kFlowLockShards;
}

std::vector<uint8_t> TcpDataplaneCore::ExtractIpv4TcpPayload(const uint8_t* pkt, size_t pkt_len) {
  if (!pkt || pkt_len < 20) {
    return {};
  }
  int ip_offset = -1;
  if (pkt_len >= 18) {
    const uint16_t eth_type = ReadBe16(pkt + 12);
    if (eth_type == 0x8100 && pkt_len >= 22) {
      const uint16_t inner_type = ReadBe16(pkt + 16);
      if (inner_type == 0x0800) {
        ip_offset = 18;
      }
    } else if (eth_type == 0x0800) {
      ip_offset = 14;
    }
  }
  if (ip_offset < 0 && ((pkt[0] >> 4) & 0x0F) == 4) {
    ip_offset = 0;
  }
  if (ip_offset < 0 || pkt_len < static_cast<size_t>(ip_offset + 20)) {
    return {};
  }
  const uint8_t ihl = static_cast<uint8_t>((pkt[ip_offset] & 0x0F) * 4);
  const int tcp_offset = ip_offset + ihl;
  if (pkt_len < static_cast<size_t>(tcp_offset + 20)) {
    return {};
  }
  const uint8_t data_off = static_cast<uint8_t>((pkt[tcp_offset + 12] >> 4) * 4);
  if (data_off < 20 || pkt_len < static_cast<size_t>(tcp_offset + data_off)) {
    return {};
  }
  const uint16_t total_len = ReadBe16(pkt + ip_offset + 2);
  const size_t payload_len = total_len >= static_cast<uint16_t>(ihl + data_off) ? total_len - ihl - data_off : 0U;
  if (payload_len == 0) {
    return {};
  }
  const uint8_t* payload = pkt + tcp_offset + data_off;
  return std::vector<uint8_t>(payload, payload + payload_len);
}

size_t TcpDataplaneCore::BuildPacket(
    const FlowEntry& flow,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_buffer) const {
  return BuildPacketOpt(flow, seq, ack, flags, payload, payload_len, nullptr, 0, out_buffer);
}

size_t TcpDataplaneCore::BuildPacketOpt(
    const FlowEntry& flow,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* opts,
    size_t opts_len,
    uint8_t* out_buffer) const {
  if (!out_buffer) return 0;
  if (!opts) opts_len = 0;

  const size_t l2_len = 14;
  const size_t ip_len = 20;
  const size_t tcp_len = 20 + opts_len;  // opts_len is a multiple of 4
  const size_t total_pkt_len = l2_len + ip_len + tcp_len + payload_len;

  std::memset(out_buffer, 0, total_pkt_len);

  out_buffer[12] = 0x08;
  out_buffer[13] = 0x00;
  uint8_t* ip = out_buffer + l2_len;
  uint8_t* tcp = ip + ip_len;
  ip[0] = 0x45;
  const uint16_t total_len = htons(static_cast<uint16_t>(ip_len + tcp_len + payload_len));
  std::memcpy(ip + 2, &total_len, sizeof(total_len));
  ip[8] = flow.ttl > 0 ? flow.ttl : config_.default_ttl;
  ip[9] = 6;
  const uint32_t src_ip_be = htonl(flow.key.src_ip);
  const uint32_t dst_ip_be = htonl(flow.key.dst_ip);
  std::memcpy(ip + 12, &src_ip_be, sizeof(src_ip_be));
  std::memcpy(ip + 16, &dst_ip_be, sizeof(dst_ip_be));

  const uint16_t src_port_be = htons(flow.key.src_port);
  const uint16_t dst_port_be = htons(flow.key.dst_port);
  const uint32_t seq_be = htonl(seq);
  const uint32_t ack_be = htonl(ack);
  std::memcpy(tcp + 0, &src_port_be, sizeof(src_port_be));
  std::memcpy(tcp + 2, &dst_port_be, sizeof(dst_port_be));
  std::memcpy(tcp + 4, &seq_be, sizeof(seq_be));
  std::memcpy(tcp + 8, &ack_be, sizeof(ack_be));
  tcp[12] = static_cast<uint8_t>((tcp_len / 4) << 4);  // data offset in 32-bit words
  tcp[13] = flags;
  const uint16_t base_win = flow.local_window > 0 ? flow.local_window : config_.local_window;
  const uint16_t eff_win = (base_win > flow.rx_oo_bytes) ? static_cast<uint16_t>(base_win - flow.rx_oo_bytes) : 0;
  const uint16_t win_be = htons(eff_win);
  std::memcpy(tcp + 14, &win_be, sizeof(win_be));
  if (opts_len > 0) {
    std::memcpy(tcp + 20, opts, opts_len);
  }
  if (payload_len > 0 && payload) {
    std::memcpy(tcp + tcp_len, payload, payload_len);
  }

  const uint16_t ip_cksum = htons(InternetChecksum(ip, ip_len));
  std::memcpy(ip + 10, &ip_cksum, sizeof(ip_cksum));
  const uint16_t tcp_cksum = htons(TcpChecksum(ip, tcp, tcp_len + payload_len));
  std::memcpy(tcp + 16, &tcp_cksum, sizeof(tcp_cksum));

  return total_pkt_len;
}

size_t TcpDataplaneCore::BuildSynOptions(uint8_t* out, uint8_t wscale, bool ts_enabled,
                                         uint32_t ts_val) const {
  size_t n = 0;
  const uint16_t mss = config_.default_mss ? config_.default_mss : 1460;
  out[n++] = kOptMss;      out[n++] = 4; out[n++] = static_cast<uint8_t>(mss >> 8); out[n++] = static_cast<uint8_t>(mss & 0xFF);
  out[n++] = kOptSackPerm; out[n++] = 2;
  if (ts_enabled) {
    // Timestamp(10): kind+len+TSval(4)+TSecr(4). TSecr is 0 on the initial SYN.
    out[n++] = kOptTimestamp; out[n++] = 10;
    out[n++] = static_cast<uint8_t>(ts_val >> 24); out[n++] = static_cast<uint8_t>(ts_val >> 16);
    out[n++] = static_cast<uint8_t>(ts_val >> 8);  out[n++] = static_cast<uint8_t>(ts_val & 0xFF);
    out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 0;  // TSecr = 0
    out[n++] = kOptNop;
    out[n++] = kOptWScale;   out[n++] = 3; out[n++] = wscale;
    // MSS(4)+SACKperm(2)+TS(10)+NOP(1)+WScale(3) = 20 -> already 4-aligned.
    return n;  // 20
  }
  // MSS(4) + SACK-permitted(2) + NOP(1) + WScale(3) + NOP + NOP = 12 bytes (4-aligned).
  out[n++] = kOptNop;
  out[n++] = kOptWScale;   out[n++] = 3; out[n++] = wscale;
  out[n++] = kOptNop;      out[n++] = kOptNop;
  return n;  // 12
}

uint32_t TcpDataplaneCore::TimestampMs() {
  return static_cast<uint32_t>(DefaultNowNs() / 1000000ull);
}

size_t TcpDataplaneCore::BuildSegmentOptions(const FlowEntry& flow, uint8_t* out) const {
  if (!flow.ts_ok) return 0;
  // 2 NOP pad + Timestamp(10) = 12 bytes (4-aligned). TSval=now, TSecr=ts_recent.
  const uint32_t ts_val = TimestampMs();
  size_t n = 0;
  out[n++] = kOptNop; out[n++] = kOptNop;
  out[n++] = kOptTimestamp; out[n++] = 10;
  out[n++] = static_cast<uint8_t>(ts_val >> 24); out[n++] = static_cast<uint8_t>(ts_val >> 16);
  out[n++] = static_cast<uint8_t>(ts_val >> 8);  out[n++] = static_cast<uint8_t>(ts_val & 0xFF);
  out[n++] = static_cast<uint8_t>(flow.ts_recent >> 24); out[n++] = static_cast<uint8_t>(flow.ts_recent >> 16);
  out[n++] = static_cast<uint8_t>(flow.ts_recent >> 8);  out[n++] = static_cast<uint8_t>(flow.ts_recent & 0xFF);
  return n;  // 12
}

size_t TcpDataplaneCore::BuildSeg(const FlowEntry& flow, uint32_t seq, uint32_t ack, uint8_t flags,
                                  const uint8_t* payload, size_t payload_len, uint8_t* out_buffer) const {
  if (flow.ts_ok) {
    uint8_t opts[kTsOptLen];
    const size_t opts_len = BuildSegmentOptions(flow, opts);
    return BuildPacketOpt(flow, seq, ack, flags, payload, payload_len, opts, opts_len, out_buffer);
  }
  return BuildPacket(flow, seq, ack, flags, payload, payload_len, out_buffer);
}

bool TcpDataplaneCore::PawsReject(const FlowEntry& flow, const TcpOptionInfo* opt) const {
  // RFC 7323 PAWS: drop an otherwise-acceptable segment whose TSval regressed.
  if (!flow.ts_ok || opt == nullptr || !opt->has_ts) return false;
  return SeqLt(opt->ts_val, flow.ts_recent);  // wrap-safe TSval < ts_recent
}

bool TcpDataplaneCore::ParseTcpOptions(const uint8_t* frame, size_t frame_len, TcpOptionInfo* out) {
  if (!frame || !out) return false;
  int ip_offset = -1;
  if (frame_len >= 18) {
    const uint16_t eth = ReadBe16(frame + 12);
    if (eth == 0x8100 && frame_len >= 22) {
      if (ReadBe16(frame + 16) == 0x0800) ip_offset = 18;
    } else if (eth == 0x0800) {
      ip_offset = 14;
    }
  }
  if (ip_offset < 0 && ((frame[0] >> 4) & 0x0F) == 4) ip_offset = 0;
  if (ip_offset < 0 || frame_len < static_cast<size_t>(ip_offset + 20)) return false;
  const uint8_t ihl = static_cast<uint8_t>((frame[ip_offset] & 0x0F) * 4);
  if (ihl < 20 || frame_len < static_cast<size_t>(ip_offset + ihl + 20)) return false;
  const size_t tcp_off = static_cast<size_t>(ip_offset) + ihl;
  const uint8_t data_off = static_cast<uint8_t>((frame[tcp_off + 12] >> 4) * 4);
  if (data_off < 20 || frame_len < tcp_off + data_off) return false;
  size_t i = tcp_off + 20;
  const size_t end = tcp_off + data_off;
  while (i < end) {
    const uint8_t kind = frame[i];
    if (kind == kOptEnd) break;
    if (kind == kOptNop) { i++; continue; }
    if (i + 1 >= end) break;
    const uint8_t len = frame[i + 1];
    if (len < 2 || i + len > end) break;
    if (kind == kOptMss && len == 4) {
      out->has_mss = true;
      out->mss = ReadBe16(frame + i + 2);
    } else if (kind == kOptWScale && len == 3) {
      out->has_wscale = true;
      out->wscale = frame[i + 2];
    } else if (kind == kOptSackPerm && len == 2) {
      out->sack_permitted = true;
    } else if (kind == kOptSack && len >= 10 && ((len - 2) % 8) == 0) {
      const int blocks = (len - 2) / 8;
      for (int b = 0; b < blocks && out->sack_block_count < 4; ++b) {
        const size_t off = i + 2 + static_cast<size_t>(b) * 8;
        out->sack_left[out->sack_block_count] = ReadBe32(frame + off);
        out->sack_right[out->sack_block_count] = ReadBe32(frame + off + 4);
        out->sack_block_count++;
      }
    } else if (kind == kOptTimestamp && len == 10) {
      out->has_ts = true;
      out->ts_val = ReadBe32(frame + i + 2);
      out->ts_ecr = ReadBe32(frame + i + 6);
    }
    i += len;
  }
  return true;
}

void TcpDataplaneCore::UpdateRtt(FlowEntry& flow, uint64_t sample_ns) {
  if (sample_ns == 0) return;
  const uint64_t now = DefaultNowNs();
  if (now <= sample_ns) return;
  uint32_t r_ms = static_cast<uint32_t>((now - sample_ns) / 1000000ULL);
  if (r_ms == 0) r_ms = 1;  // floor sub-millisecond RTT
  if (!flow.rtt_sampled) {
    flow.srtt_ms = r_ms;
    flow.rttvar_ms = r_ms / 2;
    flow.rtt_sampled = true;
  } else {
    const int32_t err = static_cast<int32_t>(r_ms) - static_cast<int32_t>(flow.srtt_ms);
    const uint32_t abs_err = err < 0 ? static_cast<uint32_t>(-err) : static_cast<uint32_t>(err);
    flow.rttvar_ms = (flow.rttvar_ms * 3u + abs_err) / 4u;  // (1-1/4)·rttvar + 1/4·|err|
    flow.srtt_ms = (flow.srtt_ms * 7u + r_ms) / 8u;         // (1-1/8)·srtt + 1/8·R
  }
  uint32_t rto = flow.srtt_ms + std::max(1u, 4u * flow.rttvar_ms);  // RFC 6298
  if (rto < kMinRtoMs) rto = kMinRtoMs;
  if (rto > config_.connect_timeout_ms) rto = config_.connect_timeout_ms;
  flow.cur_rto_ms = rto;
}

bool TcpDataplaneCore::EnqueueTxPacketBytes(const uint8_t* data, size_t len, size_t shard) {
  if (!data || len == 0) {
    return false;
  }
  if (shard >= kFlowLockShards) {
    static std::atomic<uint32_t> any_shard_rr{0};
    shard = any_shard_rr.fetch_add(1, std::memory_order_relaxed) % kFlowLockShards;
  }
  const size_t per_shard_cap = std::max<size_t>(64, tx_ring_capacity_ / kFlowLockShards);
  const size_t per_shard_overflow_cap = std::max<size_t>(64, tx_overflow_capacity_ / kFlowLockShards);

  std::vector<uint8_t> pkt_prebuilt;
  if (len > tx_ring_slot_size_) {
    pkt_prebuilt.assign(data, data + len);
  }
  const uint64_t seq = tx_packets_queued_.fetch_add(1, std::memory_order_relaxed);
  tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);

  auto& ring = tx_shard_[shard];
  std::lock_guard<SpinLock> guard(ring.mu);
  if (len <= tx_ring_slot_size_ && ring.count < static_cast<uint32_t>(per_shard_cap)) {
    const uint32_t idx = ring.tail;
    const size_t base = static_cast<size_t>(idx) * tx_ring_slot_size_;
    std::memcpy(ring.storage.data() + base, data, len);
    ring.lengths[idx] = static_cast<uint16_t>(len);
    ring.seqs[idx] = seq;
    ring.tail = (ring.tail + 1U) % static_cast<uint32_t>(per_shard_cap);
    ring.count++;
    return true;
  }
  std::vector<uint8_t> pkt = std::move(pkt_prebuilt);
  if (pkt.empty()) {
    pkt.assign(data, data + len);
  }
  if (ring.overflow.size() >= per_shard_overflow_cap) {
    ring.overflow.pop_front();
  }
  ring.overflow.push_back({seq, std::move(pkt)});
  return true;
}

void TcpDataplaneCore::PushTimer(uint64_t flow_id, TimerKind kind, uint64_t due_ns, uint32_t generation) {
  if (flow_id == 0 || due_ns == 0 || generation == 0) {
    return;
  }
  const size_t shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<SpinLock> tguard(timer_shard_mu_[shard]);
  timer_heap_shard_[shard].push(TimerEntry{due_ns, flow_id, kind, generation});
  RefreshTimerHint(shard);
}

void TcpDataplaneCore::ScheduleFlowTimers(FlowEntry& flow, uint64_t now_ns) {
  if (now_ns == 0) {
    now_ns = DefaultNowNs();
  }
  const bool active = IsCountedActive(flow.state);
  if (!active) {
    flow.rto_deadline_ns = 0;
    flow.connect_deadline_ns = 0;
    flow.idle_deadline_ns = 0;
    flow.rto_timer_gen++;
    flow.connect_timer_gen++;
    flow.idle_timer_gen++;
    return;
  }

  // The RTO deadline itself is owned by the send path (PumpSend / HandleAck / Poll /
  // QueuePacket); here we only (re)publish a timer entry for the current deadline.
  if (!flow.unacked.empty() && flow.rto_deadline_ns > 0) {
    flow.rto_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kRto, flow.rto_deadline_ns, flow.rto_timer_gen);
  } else {
    flow.rto_deadline_ns = 0;
    flow.rto_timer_gen++;
  }

  if (flow.state == TcpDpState::kSynSent && !flow.unacked.empty()) {
    flow.connect_deadline_ns = flow.last_activity_ns + NsFromMs(config_.connect_timeout_ms);
    flow.connect_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kConnectTimeout, flow.connect_deadline_ns, flow.connect_timer_gen);
  } else {
    flow.connect_deadline_ns = 0;
    flow.connect_timer_gen++;
  }

  if (flow.state == TcpDpState::kEstablished && flow.unacked.empty()) {
    flow.idle_deadline_ns = flow.last_activity_ns + NsFromMs(config_.idle_timeout_ms);
    flow.idle_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kIdleTimeout, flow.idle_deadline_ns, flow.idle_timer_gen);
  } else {
    flow.idle_deadline_ns = 0;
    flow.idle_timer_gen++;
  }
}

uint32_t TcpDataplaneCore::EffectiveMss(const FlowEntry& flow) const {
  uint32_t mss = flow.mss ? flow.mss : config_.default_mss;
  if (mss == 0) mss = 1460u;
  // Timestamps consume 12 bytes of every segment's TCP header; shrink the payload
  // MSS so a full segment still fits the path MTU.
  if (flow.ts_ok && mss > static_cast<uint32_t>(kTsOptLen)) {
    mss -= static_cast<uint32_t>(kTsOptLen);
  }
  return mss;
}

uint64_t TcpDataplaneCore::CurrentRtoNs(const FlowEntry& flow) const {
  const uint32_t rto_ms = flow.cur_rto_ms ? flow.cur_rto_ms : config_.initial_rto_ms;
  return NsFromMs(rto_ms ? rto_ms : 250u);
}

std::vector<uint8_t> TcpDataplaneCore::AcquireSegBuf(FlowEntry& flow) {
  if (!flow.seg_buf_pool.empty()) {
    std::vector<uint8_t> buf = std::move(flow.seg_buf_pool.back());
    flow.seg_buf_pool.pop_back();
    buf.clear();  // keep capacity, drop stale contents (assign overwrites anyway)
    return buf;
  }
  return {};
}

void TcpDataplaneCore::RecycleSegBuf(FlowEntry& flow, std::vector<uint8_t>&& buf) {
  // Only pool buffers that actually own storage, and cap the hoard so a flow that
  // briefly bursts does not pin memory forever.
  if (buf.capacity() == 0 || flow.seg_buf_pool.size() >= kSegBufPoolCap) {
    return;
  }
  flow.seg_buf_pool.push_back(std::move(buf));
}

uint32_t TcpDataplaneCore::EmitOneDataSegment(FlowEntry& flow, uint64_t now_ns, uint32_t window_room) {
  const size_t buffered = flow.sndbuf.size() - flow.sndbuf_head;
  if (buffered == 0 || window_room == 0) {
    return 0;
  }
  const uint32_t mss = EffectiveMss(flow);
  uint32_t seg_len = static_cast<uint32_t>(std::min<size_t>(buffered, mss));
  if (seg_len > window_room) {
    seg_len = window_room;
  }
  if (seg_len == 0) {
    return 0;
  }
  // Nagle (opt-in): withhold a sub-MSS segment while any data is still unacknowledged,
  // coalescing small writes. The first small write (no data in flight) always goes.
  if (config_.enable_nagle && seg_len < mss && flow.snd_nxt != flow.snd_una) {
    return 0;
  }
  const uint8_t* src = flow.sndbuf.data() + flow.sndbuf_head;
  const bool is_tail = (flow.sndbuf_head + seg_len == flow.sndbuf.size());
  const uint8_t flags = static_cast<uint8_t>(kTcpFlagAck | (is_tail ? kTcpFlagPsh : 0));
  const uint32_t seq = flow.snd_nxt;
  thread_local uint8_t scratch[65536];
  const size_t pkt_len = BuildSeg(flow, seq, flow.rcv_nxt, flags, src, seg_len, scratch);
  (void)EnqueueTxPacketBytes(scratch, pkt_len, FlowLockShardForFlowId(flow.flow_id));
  OutstandingTx seg;
  seg.seq = seq;
  seg.ack = flow.rcv_nxt;
  seg.payload_len = seg_len;
  seg.flags = flags;
  seg.xmit_count = 1;
  seg.sent_ns = now_ns;
  seg.data = AcquireSegBuf(flow);
  seg.data.assign(src, src + seg_len);
  flow.unacked.push_back(std::move(seg));
  flow.snd_nxt = AdvanceSeq(flow.snd_nxt, seg_len);
  flow.sndbuf_head += seg_len;
  stats_shard_[FlowLockShardForFlowId(flow.flow_id)].tx_data_bytes.fetch_add(
      static_cast<uint64_t>(seg_len), std::memory_order_relaxed);
  // Reclaim the consumed prefix of the send buffer.
  if (flow.sndbuf_head >= flow.sndbuf.size()) {
    flow.sndbuf.clear();
    flow.sndbuf_head = 0;
  } else if (flow.sndbuf_head >= kSndBufCompactThreshold) {
    flow.sndbuf.erase(flow.sndbuf.begin(), flow.sndbuf.begin() + static_cast<std::ptrdiff_t>(flow.sndbuf_head));
    flow.sndbuf_head = 0;
  }
  if (flow.rto_deadline_ns == 0) {
    flow.rto_deadline_ns = now_ns + CurrentRtoNs(flow);
  }
  return seg_len;
}

void TcpDataplaneCore::PumpSend(FlowEntry& flow, uint64_t now_ns) {
  if (flow.state != TcpDpState::kEstablished) {
    return;
  }
  // In an RFC6675 SACK-recovery episode transmission is governed by pipe, not the
  // plain window; defer to the recovery clock.
  if (flow.sack_recovery) {
    SackRecoveryTransmit(flow, now_ns);
    return;
  }
  while (true) {
    // Effective window is the tighter of the congestion window and the peer's
    // advertised receive window; we may inject up to (awnd - in-flight) bytes.
    const uint32_t flight = flow.snd_nxt - flow.snd_una;  // seq-space outstanding
    const uint32_t rwnd = flow.peer_window ? flow.peer_window : config_.local_window;
    const uint32_t awnd = std::min(flow.cwnd, rwnd);
    if (flight >= awnd) {
      break;  // window full: nothing more may be sent until an ACK opens it
    }
    if (EmitOneDataSegment(flow, now_ns, awnd - flight) == 0) {
      break;  // buffer empty / window closed / Nagle-held
    }
  }
}

void TcpDataplaneCore::RetransmitOldest(FlowEntry& flow) {
  if (flow.unacked.empty()) {
    return;
  }
  thread_local uint8_t scratch[65536];
  // SACK-aware: retransmit the lowest hole — the first segment the peer has NOT
  // selectively acknowledged. Falls back to the head if every segment is SACKed.
  OutstandingTx* seg = &flow.unacked.front();
  for (auto& s : flow.unacked) {
    if (!s.sacked) { seg = &s; break; }
  }
  seg->ack = flow.rcv_nxt;  // carry the freshest cumulative ACK on the resend
  const size_t pkt_len = BuildOutstandingPacket(flow, *seg, scratch);
  (void)EnqueueTxPacketBytes(scratch, pkt_len, FlowLockShardForFlowId(flow.flow_id));
  seg->xmit_count++;
  seg->retransmitted = true;
}

// RFC 6675 IsLost(seg): the segment is deemed lost when at least DupThresh SACKed
// segments (or more than (DupThresh-1)*SMSS SACKed bytes) lie above it in the scoreboard.
bool TcpDataplaneCore::IsLostSeg(const FlowEntry& flow, uint32_t seg_seq) const {
  const uint32_t mss = EffectiveMss(flow);
  uint32_t sacked_segs_above = 0;
  uint32_t sacked_bytes_above = 0;
  for (const auto& s : flow.unacked) {
    if (!s.sacked) continue;
    if (SeqGt(s.seq, seg_seq)) {
      sacked_segs_above++;
      sacked_bytes_above += SegSeqLen(s.flags, s.payload_len);
    }
  }
  return sacked_segs_above >= kDupThresh || sacked_bytes_above > (kDupThresh - 1) * mss;
}

// RFC 6675 SetPipe: estimate of bytes in flight over the scoreboard.
uint32_t TcpDataplaneCore::ComputePipe(const FlowEntry& flow) const {
  uint32_t pipe = 0;
  for (const auto& s : flow.unacked) {
    if (s.sacked) continue;
    const uint32_t len = SegSeqLen(s.flags, s.payload_len);
    if (!IsLostSeg(flow, s.seq)) pipe += len;  // original assumed in flight
    if (s.retransmitted) pipe += len;          // retransmission also in flight
  }
  return pipe;
}

void TcpDataplaneCore::EnterSackRecovery(FlowEntry& flow, uint64_t now_ns) {
  if (flow.sack_recovery) {
    return;
  }
  const size_t stat_shard = FlowLockShardForFlowId(flow.flow_id);
  const uint32_t mss = EffectiveMss(flow);
  const uint32_t flight = flow.snd_nxt - flow.snd_una;
  flow.ssthresh = std::max(flight / 2u, 2u * mss);
  flow.cwnd = flow.ssthresh;               // RFC6675: cwnd = ssthresh, pipe governs
  flow.recovery_point = flow.snd_nxt;      // exit once this is cumulatively acked
  flow.high_rxt = flow.snd_una;
  flow.rescue_rxt = flow.snd_una;          // RFC 6675 5.4.3: prevent premature rescue retransmission
  flow.sack_recovery = true;
  flow.in_fast_recovery = false;           // SACK path supersedes the NewReno fallback
  stats_shard_[stat_shard].congestion_window_reductions.fetch_add(1, std::memory_order_relaxed);

  // RFC 6675 Section 5 (4.3): Retransmit the first data segment presumed dropped (HighACK + 1).
  // Set both HighRxt and RescueRxt to the highest sequence number in the retransmitted segment.
  if (!flow.unacked.empty()) {
    OutstandingTx* first_seg = &flow.unacked.front();
    for (auto& s : flow.unacked) {
      if (!s.sacked) { first_seg = &s; break; }
    }
    const uint32_t seg_end = first_seg->seq + SegSeqLen(first_seg->flags, first_seg->payload_len);
    if (!first_seg->retransmitted && SeqGt(seg_end, flow.high_rxt)) {
      thread_local uint8_t scratch[65536];
      first_seg->ack = flow.rcv_nxt;
      const size_t pkt_len = BuildOutstandingPacket(flow, *first_seg, scratch);
      (void)EnqueueTxPacketBytes(scratch, pkt_len, FlowLockShardForFlowId(flow.flow_id));
      first_seg->xmit_count++;
      first_seg->retransmitted = true;
      flow.high_rxt = seg_end;
      flow.rescue_rxt = seg_end;
      stats_shard_[stat_shard].fast_retransmit_count.fetch_add(1, std::memory_order_relaxed);
      stats_shard_[stat_shard].retransmit_count.fetch_add(1, std::memory_order_relaxed);
    } else {
      if (SeqGt(seg_end, flow.rescue_rxt)) flow.rescue_rxt = seg_end;
    }
  }

  // RFC 6675 Section 5 (4.5): proceed to transmit additional segments if cwnd - pipe allows
  SackRecoveryTransmit(flow, now_ns);
}

void TcpDataplaneCore::SackRecoveryTransmit(FlowEntry& flow, uint64_t now_ns) {
  const size_t stat_shard = FlowLockShardForFlowId(flow.flow_id);
  thread_local uint8_t scratch[65536];
  const uint32_t rwnd = flow.peer_window ? flow.peer_window : config_.local_window;
  for (int guard = 0; guard < 4096; ++guard) {
    const uint32_t pipe = ComputePipe(flow);
    if (pipe >= flow.cwnd) {
      break;  // pipe full
    }
    // NextSeg rule 1: lowest-seq lost hole not yet retransmitted (RFC 6675 1.a: S2 > HighRxt).
    OutstandingTx* hole = nullptr;
    for (auto& s : flow.unacked) {
      if (s.sacked || s.retransmitted) continue;
      const uint32_t send_end = s.seq + SegSeqLen(s.flags, s.payload_len);
      if (SeqLeq(send_end, flow.high_rxt)) continue;
      if (IsLostSeg(flow, s.seq)) { hole = &s; break; }
    }
    if (hole != nullptr) {
      hole->ack = flow.rcv_nxt;
      const size_t pkt_len = BuildOutstandingPacket(flow, *hole, scratch);
      (void)EnqueueTxPacketBytes(scratch, pkt_len, FlowLockShardForFlowId(flow.flow_id));
      hole->xmit_count++;
      hole->retransmitted = true;
      const uint32_t hole_end = hole->seq + SegSeqLen(hole->flags, hole->payload_len);
      if (SeqGt(hole_end, flow.high_rxt)) flow.high_rxt = hole_end;
      if (SeqGt(hole_end, flow.rescue_rxt)) flow.rescue_rxt = hole_end;
      stats_shard_[stat_shard].fast_retransmit_count.fetch_add(1, std::memory_order_relaxed);
      stats_shard_[stat_shard].retransmit_count.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    // NextSeg rule 2: new data, if the window allows.
    const uint32_t flight = flow.snd_nxt - flow.snd_una;
    const uint32_t rwnd_room = rwnd > flight ? rwnd - flight : 0;
    const uint32_t cwnd_room = flow.cwnd > pipe ? flow.cwnd - pipe : 0;
    const uint32_t room = std::min(cwnd_room, rwnd_room);
    if (room > 0 && (flow.sndbuf.size() - flow.sndbuf_head) > 0) {
      if (EmitOneDataSegment(flow, now_ns, room) > 0) {
        continue;
      }
    }
    // NextSeg rule 3 (RFC 6675 Rule 4): rescue retransmit — the highest-seq unSACKed, unretransmitted
    // segment, to avoid an RTO when only tail segments remain outstanding.
    const bool can_rescue = (flow.rescue_rxt != 0 && SeqGt(flow.snd_una, flow.rescue_rxt));
    if (can_rescue) {
      OutstandingTx* rescue = nullptr;
      for (auto& s : flow.unacked) {
        if (s.sacked || s.retransmitted) continue;
        rescue = &s;  // keep walking -> ends on the highest such segment
      }
      if (rescue != nullptr) {
        rescue->ack = flow.rcv_nxt;
        const size_t pkt_len = BuildOutstandingPacket(flow, *rescue, scratch);
        (void)EnqueueTxPacketBytes(scratch, pkt_len, FlowLockShardForFlowId(flow.flow_id));
        rescue->xmit_count++;
        rescue->retransmitted = true;
        flow.rescue_rxt = flow.recovery_point;
        // RFC 6675: HighRxt MUST NOT be updated on rescue retransmission.
        stats_shard_[stat_shard].retransmit_count.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
    }
    break;  // nothing left to (re)transmit
  }
  if (!flow.unacked.empty() && flow.rto_deadline_ns == 0) {
    flow.rto_deadline_ns = now_ns + CurrentRtoNs(flow);
  }
}

void TcpDataplaneCore::UpdateFlowSackBlocks(FlowEntry& flow, uint32_t newly_arrived_seq, uint32_t newly_arrived_len) {
  if (!flow.sack_permitted || flow.rx_oo_queue.empty()) {
    flow.sack_blocks.clear();
    return;
  }

  struct Block {
    uint32_t left;
    uint32_t right;
  };

  std::vector<Block> raw;
  raw.reserve(flow.rx_oo_queue.size());
  for (const auto& seg : flow.rx_oo_queue) {
    if (seg.payload.empty()) continue;
    raw.push_back(Block{seg.seq, AdvanceSeq(seg.seq, static_cast<uint32_t>(seg.payload.size()))});
  }

  if (raw.empty()) {
    flow.sack_blocks.clear();
    return;
  }

  // Sort blocks in TCP sequence space order starting from flow.rcv_nxt.
  // Using uint32_t distance from rcv_nxt handles 32-bit wrap-around correctly.
  const uint32_t rcv = flow.rcv_nxt;
  std::sort(raw.begin(), raw.end(), [rcv](const Block& a, const Block& b) {
    return static_cast<uint32_t>(a.left - rcv) < static_cast<uint32_t>(b.left - rcv);
  });

  std::vector<TcpDpSackBlock> merged;
  for (const auto& b : raw) {
    if (merged.empty()) {
      merged.push_back(TcpDpSackBlock{b.left, b.right});
    } else {
      auto& prev = merged.back();
      const uint32_t prev_r_offset = static_cast<uint32_t>(prev.right - rcv);
      const uint32_t b_l_offset = static_cast<uint32_t>(b.left - rcv);
      const uint32_t b_r_offset = static_cast<uint32_t>(b.right - rcv);
      if (b_l_offset <= prev_r_offset) {
        if (b_r_offset > prev_r_offset) {
          prev.right = b.right;
        }
      } else {
        merged.push_back(TcpDpSackBlock{b.left, b.right});
      }
    }
  }

  int target_idx = -1;
  if (newly_arrived_len > 0) {
    const uint32_t arr_end = AdvanceSeq(newly_arrived_seq, newly_arrived_len);
    const uint32_t arr_l_off = static_cast<uint32_t>(newly_arrived_seq - rcv);
    const uint32_t arr_r_off = static_cast<uint32_t>(arr_end - rcv);
    for (size_t i = 0; i < merged.size(); ++i) {
      const uint32_t m_l_off = static_cast<uint32_t>(merged[i].left - rcv);
      const uint32_t m_r_off = static_cast<uint32_t>(merged[i].right - rcv);
      if (m_l_off <= arr_l_off && arr_r_off <= m_r_off) {
        target_idx = static_cast<int>(i);
        break;
      }
    }
  }

  const size_t max_blocks = flow.ts_ok ? 3 : 4;
  flow.sack_blocks.clear();
  if (target_idx >= 0) {
    flow.sack_blocks.push_back(merged[static_cast<size_t>(target_idx)]);
  }
  for (size_t i = 0; i < merged.size(); ++i) {
    if (static_cast<int>(i) == target_idx) continue;
    if (flow.sack_blocks.size() >= max_blocks) break;
    flow.sack_blocks.push_back(merged[i]);
  }
}

size_t TcpDataplaneCore::BuildAckOptions(const FlowEntry& flow, uint8_t* out) const {
  if (!out) return 0;
  size_t n = 0;
  if (flow.ts_ok) {
    n += BuildSegmentOptions(flow, out);
  }
  if (flow.sack_permitted && !flow.sack_blocks.empty()) {
    const size_t max_blocks = flow.ts_ok ? 3 : 4;
    const size_t num_blocks = std::min(flow.sack_blocks.size(), max_blocks);
    const size_t needed = 2 + 2 + num_blocks * 8;
    if (num_blocks > 0 && n + needed <= 40) {
      out[n++] = kOptNop;
      out[n++] = kOptNop;
      out[n++] = kOptSack;
      out[n++] = static_cast<uint8_t>(2 + num_blocks * 8);
      for (size_t b = 0; b < num_blocks; ++b) {
        const uint32_t left = flow.sack_blocks[b].left;
        const uint32_t right = flow.sack_blocks[b].right;
        out[n++] = static_cast<uint8_t>(left >> 24);
        out[n++] = static_cast<uint8_t>(left >> 16);
        out[n++] = static_cast<uint8_t>(left >> 8);
        out[n++] = static_cast<uint8_t>(left & 0xFF);
        out[n++] = static_cast<uint8_t>(right >> 24);
        out[n++] = static_cast<uint8_t>(right >> 16);
        out[n++] = static_cast<uint8_t>(right >> 8);
        out[n++] = static_cast<uint8_t>(right & 0xFF);
      }
    }
  }
  return n;
}

void TcpDataplaneCore::SendAckNow(FlowEntry& flow) {
  uint8_t opts[40];
  const size_t opts_len = BuildAckOptions(flow, opts);
  thread_local uint8_t scratch[65536];
  size_t len = 0;
  if (opts_len > 0) {
    len = BuildPacketOpt(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0, opts, opts_len, scratch);
  } else {
    len = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0, scratch);
  }
  (void)EnqueueTxPacketBytes(scratch, len, FlowLockShardForFlowId(flow.flow_id));
  flow.pending_ack_segs = 0;
  flow.delack_deadline_ns = 0;  // disarm (stale generation ignored on fire)
}

// Delayed-ACK (opt-in): with delayed ACKs disabled we ACK every segment immediately
// (aggressive load-gen default). Enabled, we ACK every 2nd full segment or arm a
// short timer so a lone segment is still acknowledged promptly.
void TcpDataplaneCore::OnDataReceivedAck(FlowEntry& flow, uint64_t now_ns, bool force_now) {
  if (!config_.enable_delayed_ack || force_now) {
    SendAckNow(flow);
    return;
  }
  flow.pending_ack_segs++;
  if (flow.pending_ack_segs >= 2) {
    SendAckNow(flow);
    return;
  }
  // Arm the delACK timer (40ms, RFC 5681 upper bound is 500ms; LAN-oriented here).
  flow.delack_timer_gen++;
  flow.delack_deadline_ns = now_ns + NsFromMs(40u);
  PushTimer(flow.flow_id, TimerKind::kDelayedAck, flow.delack_deadline_ns, flow.delack_timer_gen);
}

void TcpDataplaneCore::QueuePacket(
    FlowEntry& flow,
    const uint8_t* packet_data,
    size_t packet_len,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t* payload,
    uint32_t payload_len,
    bool arm_rto) {
  if (packet_data != nullptr && packet_len > 0) {
    (void)EnqueueTxPacketBytes(packet_data, packet_len, FlowLockShardForFlowId(flow.flow_id));
  }
  if (!arm_rto) {
    return;
  }
  OutstandingTx out;
  out.seq = seq;
  out.ack = ack;
  out.flags = flags;
  out.payload_len = payload_len;
  out.xmit_count = 1;
  out.sent_ns = DefaultNowNs();
  if (payload != nullptr && payload_len > 0) {
    out.data.assign(payload, payload + payload_len);
  }
  flow.unacked.push_back(std::move(out));
  if (flow.rto_deadline_ns == 0) {
    if (flow.cur_rto_ms == 0) {
      flow.cur_rto_ms = config_.initial_rto_ms;
    }
    flow.rto_deadline_ns = DefaultNowNs() + CurrentRtoNs(flow);
  }
}

size_t TcpDataplaneCore::BuildOutstandingPacket(const FlowEntry& flow, const OutstandingTx& out, uint8_t* out_buffer) const {
  const uint8_t* payload_ptr = nullptr;
  size_t payload_size = 0;
  if (out.payload_len > 0 && out.data.size() >= static_cast<size_t>(out.payload_len)) {
    payload_ptr = out.data.data();
    payload_size = static_cast<size_t>(out.payload_len);
  }
  // Replay the segment's stored options (e.g. the SYN's MSS/SACK-perm/WScale/TS) so a
  // retransmitted SYN re-negotiates identically instead of dropping to a bare header.
  if (out.opts_len > 0) {
    return BuildPacketOpt(flow, out.seq, out.ack, out.flags, payload_ptr, payload_size,
                          out.opts.data(), out.opts_len, out_buffer);
  }
  // Ordinary data/ACK segments carry a freshly regenerated timestamp (TSval=now).
  if (flow.ts_ok) {
    uint8_t opts[kTsOptLen];
    const size_t opts_len = BuildSegmentOptions(flow, opts);
    return BuildPacketOpt(flow, out.seq, out.ack, out.flags, payload_ptr, payload_size,
                          opts, opts_len, out_buffer);
  }
  return BuildPacket(flow, out.seq, out.ack, out.flags, payload_ptr, payload_size, out_buffer);
}

void TcpDataplaneCore::PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event) {
  std::lock_guard<SpinLock> guard(completion_mu_);
  completions_.push_back(TcpDpCompletion{flow_id, static_cast<uint8_t>(state), static_cast<uint8_t>(success ? 1 : 0), event});
}

bool TcpDataplaneCore::IsCountedActive(TcpDpState state) const {
  switch (state) {
    case TcpDpState::kSynSent:
    case TcpDpState::kSynAckRcvd:
    case TcpDpState::kEstablished:
    case TcpDpState::kFinWait:
      return true;
    case TcpDpState::kClosed:
    case TcpDpState::kTimeWait:
    case TcpDpState::kRstSeen:
      return false;
  }
  return false;
}

void TcpDataplaneCore::SetFlowState(FlowEntry& flow, TcpDpState next_state) {
  const bool was_active = IsCountedActive(flow.state);
  const bool now_active = IsCountedActive(next_state);
  flow.state = next_state;
  // flow.state yukarıda zaten next_state'e atandığından eski/yeni durum
  // karşılaştırması, atamadan önce hesaplanan was_active/now_active ile yapılmalı.
  if (now_active && !was_active) {
    stats_shard_[FlowLockShardForFlowId(flow.flow_id)].flows_active.fetch_add(1, std::memory_order_relaxed);
  } else if (was_active && !now_active) {
    SaturatingDecrement(stats_shard_[FlowLockShardForFlowId(flow.flow_id)].flows_active);
  }
}

void TcpDataplaneCore::HandleAck(FlowEntry& flow, uint32_t ack_value, const TcpOptionInfo* opt) {
  const size_t stat_shard = FlowLockShardForFlowId(flow.flow_id);
  if (flow.unacked.empty()) {
    return;  // nothing outstanding to acknowledge
  }
  const uint32_t mss = EffectiveMss(flow);
  const uint64_t now_ns = DefaultNowNs();

  // Selective ACK: mark any outstanding segment fully covered by a SACK block so the
  // retransmit path skips it (holes only). SACK rides on dup-ACKs too, so apply it
  // before the cumulative-ACK branching.
  if (flow.sack_permitted && opt && opt->sack_block_count > 0) {
    for (int b = 0; b < opt->sack_block_count; ++b) {
      if (flow.high_sack == 0 || SeqGt(opt->sack_right[b], flow.high_sack)) {
        flow.high_sack = opt->sack_right[b];
      }
    }
    for (auto& s : flow.unacked) {
      if (s.sacked) continue;
      const uint32_t s_end = s.seq + SegSeqLen(s.flags, s.payload_len);
      for (int b = 0; b < opt->sack_block_count; ++b) {
        if (!SeqLt(s.seq, opt->sack_left[b]) && !SeqGt(s_end, opt->sack_right[b])) {
          s.sacked = true;
          stats_shard_[stat_shard].sack_blocks_rx_count.fetch_add(1, std::memory_order_relaxed);
          break;
        }
      }
    }
  }

  if (SeqLeq(ack_value, flow.snd_una)) {
    // Old or duplicate ACK. A pure dup-ACK (== snd_una) with data outstanding is a
    // loss signal: on the third, fast-retransmit the oldest segment and halve the
    // window (NewReno-style fast recovery).
    if (ack_value == flow.snd_una) {
      stats_shard_[stat_shard].dup_ack_count.fetch_add(1, std::memory_order_relaxed);
      flow.dup_ack_streak++;
      const bool use_sack = config_.enable_rfc6675_recovery && flow.sack_permitted;
      if (use_sack) {
        if (!flow.sack_recovery) {
          // Enter recovery on the classic 3 dup-ACKs OR early when the scoreboard
          // already marks the oldest outstanding segment as lost (RFC 6675).
          const bool oldest_lost =
              !flow.unacked.empty() && IsLostSeg(flow, flow.unacked.front().seq);
          if (oldest_lost || flow.dup_ack_streak >= kDupThresh) {
            EnterSackRecovery(flow, now_ns);
            flow.cur_rto_ms = 0;
            flow.rto_deadline_ns = now_ns + CurrentRtoNs(flow);
          } else {
            // Limited Transmit (RFC 5681 / RFC 6675 Section 5 step 3):
            // Transmit up to 1 SMSS of unsent data if (cwnd - pipe) >= 1 SMSS.
            const uint32_t pipe = ComputePipe(flow);
            if (flow.cwnd > pipe && (flow.cwnd - pipe) >= mss && (flow.sndbuf.size() - flow.sndbuf_head) > 0) {
              const uint32_t rwnd = flow.peer_window ? flow.peer_window : config_.local_window;
              const uint32_t flight = flow.snd_nxt - flow.snd_una;
              const uint32_t rwnd_room = rwnd > flight ? rwnd - flight : 0;
              const uint32_t cwnd_room = flow.cwnd - pipe;
              const uint32_t room = std::min(cwnd_room, rwnd_room);
              if (room >= mss) {
                EmitOneDataSegment(flow, now_ns, mss);
              }
            }
          }
        } else {
          // Already recovering: fresh SACK info may have opened the pipe.
          SackRecoveryTransmit(flow, now_ns);
        }
      } else if (!flow.in_fast_recovery && flow.dup_ack_streak == 3) {
        // NewReno fallback (no SACK negotiated).
        const uint32_t flight = flow.snd_nxt - flow.snd_una;
        flow.ssthresh = std::max(flight / 2u, 2u * mss);
        flow.cwnd = flow.ssthresh + 3u * mss;  // inflate for the 3 dup-ACKs
        flow.in_fast_recovery = true;
        RetransmitOldest(flow);
        stats_shard_[stat_shard].fast_retransmit_count.fetch_add(1, std::memory_order_relaxed);
        stats_shard_[stat_shard].retransmit_count.fetch_add(1, std::memory_order_relaxed);
        stats_shard_[stat_shard].congestion_window_reductions.fetch_add(1, std::memory_order_relaxed);
        flow.cur_rto_ms = 0;
        flow.rto_deadline_ns = now_ns + CurrentRtoNs(flow);
      } else if (flow.in_fast_recovery) {
        flow.cwnd = std::min(flow.cwnd + mss, kMaxCwnd);  // window inflation per extra dup-ACK
        PumpSend(flow, now_ns);
      }
    }
    return;
  }

  if (SeqGt(ack_value, flow.snd_nxt)) {
    // Acknowledges data we never sent.
    stats_shard_[stat_shard].unexpected_ack_count.fetch_add(1, std::memory_order_relaxed);
    stats_shard_[stat_shard].unexpected_rx.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  // New data acknowledged: ack_value in (snd_una, snd_nxt]. Retire fully-acked
  // segments from the front of the queue; trim the head if it is partially acked.
  const uint32_t acked_bytes = ack_value - flow.snd_una;
  bool partial = false;
  uint64_t rtt_sample_ns = 0;  // newest first-transmission time among fully-acked segs (Karn)
  size_t pop_count = 0;
  for (size_t idx = 0; idx < flow.unacked.size(); ++idx) {
    OutstandingTx& seg = flow.unacked[idx];
    const uint32_t seg_end = seg.seq + SegSeqLen(seg.flags, seg.payload_len);
    if (SeqLeq(seg_end, ack_value)) {
      if (seg.xmit_count == 1 && seg.sent_ns > rtt_sample_ns) rtt_sample_ns = seg.sent_ns;
      RecycleSegBuf(flow, std::move(seg.data));  // reclaim storage before the element dies
      pop_count++;  // fully acknowledged
    } else if (SeqGt(ack_value, seg.seq)) {
      const uint32_t drop = ack_value - seg.seq;
      if (drop < seg.payload_len) {
        seg.data.erase(seg.data.begin(), seg.data.begin() + static_cast<std::ptrdiff_t>(drop));
        seg.payload_len -= drop;
        seg.seq = ack_value;
        partial = true;
      }
      break;
    } else {
      break;
    }
  }
  if (pop_count > 0) {
    if (pop_count == flow.unacked.size()) {
      flow.unacked.clear();
    } else {
      flow.unacked.erase(flow.unacked.begin(), flow.unacked.begin() + static_cast<std::ptrdiff_t>(pop_count));
    }
  }
  flow.snd_una = ack_value;
  if (partial) {
    stats_shard_[stat_shard].partial_ack_count.fetch_add(1, std::memory_order_relaxed);
  }
  // Round-trip sample from a non-retransmitted segment (Karn's algorithm) refreshes
  // the RTO estimate and clears any prior backoff.
  if (rtt_sample_ns != 0) {
    UpdateRtt(flow, rtt_sample_ns);
  }

  // Congestion control on forward progress.
  if (flow.sack_recovery) {
    // RFC 6675: a cumulative ACK reaching the recovery point ends the episode; a
    // partial ACK keeps us in recovery (no window growth) and SackRecoveryTransmit
    // (via PumpSend below) clocks the next hole + new data under pipe.
    if (!SeqLt(ack_value, flow.recovery_point)) {
      flow.sack_recovery = false;
      flow.cwnd = flow.ssthresh;
      flow.rescue_rxt = 0;
      flow.high_sack = 0;
    }
  } else if (flow.in_fast_recovery) {
    flow.in_fast_recovery = false;
    flow.cwnd = flow.ssthresh;  // deflate on recovery exit
  } else if (flow.cwnd < flow.ssthresh) {
    flow.cwnd = std::min(flow.cwnd + std::min(acked_bytes, mss), kMaxCwnd);  // slow start
  } else {
    const uint32_t inc = std::max<uint32_t>(
        1u, static_cast<uint32_t>((static_cast<uint64_t>(mss) * mss) / (flow.cwnd ? flow.cwnd : 1u)));
    flow.cwnd = std::min(flow.cwnd + inc, kMaxCwnd);  // congestion avoidance (Reno)
  }

  flow.dup_ack_streak = 0;
  flow.retransmit_count = 0;
  // RTO backoff is cleared only by a valid RTT sample (Karn); UpdateRtt above did so
  // when a non-retransmitted segment was acked.

  // Restart / disarm the single connection RTO timer (RFC 6298).
  flow.rto_deadline_ns = flow.unacked.empty() ? 0 : now_ns + CurrentRtoNs(flow);

  // The window may have opened; clock any buffered data onto the wire.
  PumpSend(flow, now_ns);
}

void TcpDataplaneCore::CloseTimedOutFlow(FlowEntry& flow, TcpDpState terminal_state, const char* event) {
  const size_t stat_shard = FlowLockShardForFlowId(flow.flow_id);
  SetFlowState(flow, terminal_state);
  flow.unacked.clear();
  flow.sndbuf.clear();
  flow.sndbuf_head = 0;
  flow.rto_deadline_ns = 0;
  flow.cur_rto_ms = 0;
  flow.rx_oo_queue.clear();
  flow.rx_oo_bytes = 0;
  flow.pending_fin_seq.reset();
  flow.sack_blocks.clear();
  stats_shard_[stat_shard].timeout_close_count.fetch_add(1, std::memory_order_relaxed);
  if (event != nullptr) {
    if (std::strcmp(event, "connect_timeout") == 0) {
      stats_shard_[stat_shard].connect_timeout_count.fetch_add(1, std::memory_order_relaxed);
    } else if (std::strcmp(event, "idle_timeout") == 0) {
      stats_shard_[stat_shard].idle_timeout_count.fetch_add(1, std::memory_order_relaxed);
    } else if (std::strcmp(event, "retransmit_exhausted") == 0) {
      stats_shard_[stat_shard].retransmit_exhausted_count.fetch_add(1, std::memory_order_relaxed);
    }
  }
  PushCompletion(flow.flow_id, flow.state, false, event);
}

uint32_t TcpDataplaneCore::IngestDpdkRxBurst(void** mbufs, uint16_t count) {
  if (!mbufs || count == 0) return 0;
  uint32_t ingested = 0;
#ifdef SAMURAI_WITH_DPDK
  for (uint16_t i = 0; i < count; ++i) {
    rte_mbuf* mbuf = reinterpret_cast<rte_mbuf*>(mbufs[i]);
    if (!mbuf) continue;
    const uint8_t* data = rte_pktmbuf_mtod(mbuf, const uint8_t*);
    const uint32_t len = rte_pktmbuf_pkt_len(mbuf);
    if (data && len > 0) {
      ingested += IngestRxFrame(data, len);
    }
    rte_pktmbuf_free(mbuf);
  }
#else
  (void)mbufs;
  (void)count;
#endif
  return ingested;
}

uint32_t TcpDataplaneCore::DrainDpdkTxBurst(void* mempool_ptr, void** out_mbufs, uint16_t max_burst) {
  if (!out_mbufs || max_burst == 0) return 0;
  uint32_t produced = 0;
#ifdef SAMURAI_WITH_DPDK
  rte_mempool* mp = reinterpret_cast<rte_mempool*>(mempool_ptr);
  if (!mp) return 0;

  const uint8_t* base = nullptr;
  uint32_t count = 0;
  size_t pkt_size = 0;
  size_t stride = 0;

  if (PeekTxPacketsStrided(max_burst, &base, &count, &pkt_size, &stride) && count > 0 && base) {
    if (count > max_burst) {
      count = max_burst;
    }
    const uint16_t alloc_count = static_cast<uint16_t>(count);
    if (rte_pktmbuf_alloc_bulk(mp, reinterpret_cast<rte_mbuf**>(out_mbufs), alloc_count) == 0) {
      for (uint32_t i = 0; i < count; ++i) {
        rte_mbuf* mbuf = reinterpret_cast<rte_mbuf*>(out_mbufs[i]);
        const uint8_t* src = base + i * stride;
        uint8_t* dst = rte_pktmbuf_mtod(mbuf, uint8_t*);
        std::memcpy(dst, src, pkt_size);
        mbuf->pkt_len = static_cast<uint32_t>(pkt_size);
        mbuf->data_len = static_cast<uint16_t>(pkt_size);
      }
      produced = count;
    } else {
      for (uint32_t i = 0; i < count; ++i) {
        rte_mbuf* mbuf = rte_pktmbuf_alloc(mp);
        if (!mbuf) break;
        const uint8_t* src = base + i * stride;
        uint8_t* dst = rte_pktmbuf_mtod(mbuf, uint8_t*);
        std::memcpy(dst, src, pkt_size);
        mbuf->pkt_len = static_cast<uint32_t>(pkt_size);
        mbuf->data_len = static_cast<uint16_t>(pkt_size);
        out_mbufs[produced++] = mbuf;
      }
    }
    if (produced > 0) {
      ConsumeTxPackets(produced);
    }
  }
#else
  (void)mempool_ptr;
  (void)out_mbufs;
  (void)max_burst;
#endif
  return produced;
}

std::vector<uint8_t> TcpDataplaneCore::BuildNativeTlsClientHello(const std::string& sni) const {
  std::vector<uint8_t> record;
  const std::string hostname = sni.empty() ? "localhost" : sni;
  std::vector<uint8_t> hs;
  hs.push_back(0x01); // Handshake Type: ClientHello
  hs.push_back(0x00); hs.push_back(0x00); hs.push_back(0x00);
  hs.push_back(0x03); hs.push_back(0x03); // TLS 1.2
  for (int i = 0; i < 32; ++i) hs.push_back(static_cast<uint8_t>((i * 37 + 13) & 0xFF));
  hs.push_back(0x00); // Session ID len 0
  hs.push_back(0x00); hs.push_back(0x04); // Cipher suites len 4
  hs.push_back(0x13); hs.push_back(0x01);
  hs.push_back(0xc0); hs.push_back(0x2f);
  hs.push_back(0x01); hs.push_back(0x00); // Compression
  std::vector<uint8_t> ext;
  ext.push_back(0x00); ext.push_back(0x00); // Server name extension
  uint16_t sni_list_len = static_cast<uint16_t>(hostname.size() + 3);
  uint16_t sni_ext_len = static_cast<uint16_t>(sni_list_len + 2);
  ext.push_back(static_cast<uint8_t>((sni_ext_len >> 8) & 0xFF));
  ext.push_back(static_cast<uint8_t>(sni_ext_len & 0xFF));
  ext.push_back(static_cast<uint8_t>((sni_list_len >> 8) & 0xFF));
  ext.push_back(static_cast<uint8_t>(sni_list_len & 0xFF));
  ext.push_back(0x00);
  ext.push_back(static_cast<uint8_t>((hostname.size() >> 8) & 0xFF));
  ext.push_back(static_cast<uint8_t>(hostname.size() & 0xFF));
  ext.insert(ext.end(), hostname.begin(), hostname.end());
  uint16_t total_ext_len = static_cast<uint16_t>(ext.size());
  hs.push_back(static_cast<uint8_t>((total_ext_len >> 8) & 0xFF));
  hs.push_back(static_cast<uint8_t>(total_ext_len & 0xFF));
  hs.insert(hs.end(), ext.begin(), ext.end());
  uint32_t hs_body_len = static_cast<uint32_t>(hs.size() - 4);
  hs[1] = static_cast<uint8_t>((hs_body_len >> 16) & 0xFF);
  hs[2] = static_cast<uint8_t>((hs_body_len >> 8) & 0xFF);
  hs[3] = static_cast<uint8_t>(hs_body_len & 0xFF);
  record.push_back(0x16);
  record.push_back(0x03); record.push_back(0x01);
  uint16_t rec_len = static_cast<uint16_t>(hs.size());
  record.push_back(static_cast<uint8_t>((rec_len >> 8) & 0xFF));
  record.push_back(static_cast<uint8_t>(rec_len & 0xFF));
  record.insert(record.end(), hs.begin(), hs.end());
  return record;
}

bool TcpDataplaneCore::ParseNativeTlsServerHello(const uint8_t* payload, size_t len) const {
  if (!payload || len < 9) return false;
  if (payload[0] != 0x16) return false;
  if (payload[5] != 0x02) return false;
  stats_shard_[0].native_tls_handshakes_completed.fetch_add(1, std::memory_order_relaxed);
  return true;
}

}  // namespace samurai::tcpdp
