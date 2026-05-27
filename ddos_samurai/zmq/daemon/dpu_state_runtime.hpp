#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

#include "wire_protocol.h"

namespace samurai::dpu {

inline constexpr std::uint8_t kTcpStateClosed = 0u;
inline constexpr std::uint8_t kTcpStateSynSent = 1u;
inline constexpr std::uint8_t kTcpStateSynReceived = 2u;
inline constexpr std::uint8_t kTcpStateListen = 3u;
inline constexpr std::uint8_t kTcpStateEstablished = 4u;
inline constexpr std::uint8_t kTcpStateFinWait = 5u;
inline constexpr std::uint8_t kTcpStateCloseWait = 6u;
inline constexpr std::uint8_t kTcpStateLastAck = 7u;
inline constexpr std::uint8_t kTcpStateTimeWait = 8u;
inline constexpr std::uint8_t kTcpStateMigrating = 250u;
inline constexpr std::uint8_t kTcpStatePoisoned = 255u;
inline constexpr std::uint8_t kProtoTcp = 6u;
inline constexpr std::uint8_t kProtoUdp = 17u;
inline constexpr std::uint16_t kTcpFlagFin = 0x01u;
inline constexpr std::uint16_t kTcpFlagSyn = 0x02u;
inline constexpr std::uint16_t kTcpFlagRst = 0x04u;
inline constexpr std::uint16_t kTcpFlagPsh = 0x08u;
inline constexpr std::uint16_t kTcpFlagAck = 0x10u;
inline constexpr std::uint16_t kTcpFlagUrg = 0x20u;
inline constexpr std::uint16_t kTcpFlagEce = 0x40u;
inline constexpr std::uint16_t kTcpFlagCwr = 0x80u;
inline constexpr std::uint32_t kTcpDefaultMss = 1460u;
inline constexpr std::uint32_t kTcpMinMss = 536u;
inline constexpr std::uint32_t kTcpDefaultPmtu = 1500u;
inline constexpr std::uint64_t kTcpInitialRtoNs = 1'000'000'000ull;
inline constexpr std::uint64_t kTcpMinRtoNs = 200'000'000ull;
inline constexpr std::uint64_t kTcpMaxRtoNs = 60'000'000'000ull;
inline constexpr std::uint64_t kTcpTimeWaitNs = 120'000'000'000ull;
inline constexpr std::size_t kTcpMaxRetransmitEntries = 256u;
inline constexpr std::size_t kTcpMaxOutOfOrderSegments = 64u;
inline constexpr std::size_t kTcpMaxSackBlocks = 4u;
inline constexpr std::uint32_t kGpuStreamPolicyTemplateValid = 0x80000000u;
inline constexpr std::uint32_t kGpuStreamPolicyRetransmit = 0x40000000u;
inline constexpr std::uint32_t kGpuStreamPolicyZeroWindowProbe = 0x20000000u;
inline constexpr std::uint32_t kGpuStreamPolicyPause = 0x10000000u;

struct FlowState {
  std::uint32_t flow_id{0};
  std::uint32_t src_ip{0};
  std::uint32_t dst_ip{0};
  std::uint32_t seq_num{0};
  std::uint32_t ack_num{0};
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint8_t tcp_state{kTcpStateClosed};
  std::uint16_t flags{0};
  std::uint32_t rtt_us{0};
  std::uint64_t last_tx_ts{0};
  std::uint64_t last_ack_ts{0};
  std::uint64_t epoch{1};
  std::uint8_t proto{kProtoTcp};
  std::uint64_t version{0};
  bool poisoned{false};
  bool migrating{false};
};

inline std::uint32_t PublicationBudgetUs(std::uint32_t rtt_us) {
  const std::uint32_t target = rtt_us / 10u;
  if (target < 50u) return 50u;
  if (target > 1000u) return 1000u;
  return target;
}

inline std::uint64_t NextCommittedVersion(std::uint64_t current_version) {
  if ((current_version & 1ull) != 0ull) {
    current_version += 1ull;
  }
  return current_version + 2ull;
}

inline std::uint16_t ReadBe16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]));
}

inline std::uint32_t ReadBe32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline bool TcpSeqBefore(std::uint32_t a, std::uint32_t b) {
  return static_cast<std::int32_t>(a - b) < 0;
}

inline bool TcpSeqAfter(std::uint32_t a, std::uint32_t b) {
  return TcpSeqBefore(b, a);
}

inline bool TcpSeqBeforeEq(std::uint32_t a, std::uint32_t b) {
  return a == b || TcpSeqBefore(a, b);
}

inline bool TcpSeqAfterEq(std::uint32_t a, std::uint32_t b) {
  return a == b || TcpSeqAfter(a, b);
}

inline std::uint32_t TcpClampMssFromPmtu(std::uint32_t pmtu) {
  if (pmtu <= 40u) {
    return kTcpMinMss;
  }
  const std::uint32_t mss = pmtu - 40u;
  if (mss < kTcpMinMss) {
    return kTcpMinMss;
  }
  return mss;
}

struct TcpFlowKey {
  std::uint32_t src_ip{0};
  std::uint32_t dst_ip{0};
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint8_t proto{kProtoTcp};

  bool operator==(const TcpFlowKey& other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port && proto == other.proto;
  }
};

struct TcpFlowKeyHash {
  std::size_t operator()(const TcpFlowKey& key) const {
    std::size_t h = std::hash<std::uint32_t>{}(key.src_ip);
    h ^= std::hash<std::uint32_t>{}(key.dst_ip) + 0x9e3779b97f4a7c15ull + (h << 6u) + (h >> 2u);
    h ^= std::hash<std::uint32_t>{}(
             (static_cast<std::uint32_t>(key.src_port) << 16u) | static_cast<std::uint32_t>(key.dst_port)) +
         0x9e3779b97f4a7c15ull + (h << 6u) + (h >> 2u);
    h ^= std::hash<std::uint8_t>{}(key.proto) + 0x9e3779b97f4a7c15ull + (h << 6u) + (h >> 2u);
    return h;
  }
};

inline TcpFlowKey ForwardKeyFromState(const FlowState& st) {
  return TcpFlowKey{st.src_ip, st.dst_ip, st.src_port, st.dst_port, st.proto};
}

inline TcpFlowKey ReverseKeyFromObservation(
    std::uint32_t local_src_ip,
    std::uint32_t local_dst_ip,
    std::uint16_t local_src_port,
    std::uint16_t local_dst_port) {
  return TcpFlowKey{local_dst_ip, local_src_ip, local_dst_port, local_src_port, kProtoTcp};
}

struct TcpSegmentObservation {
  std::uint32_t src_ip{0};
  std::uint32_t dst_ip{0};
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint32_t seq{0};
  std::uint32_t ack{0};
  std::uint16_t flags{0};
  std::uint16_t window{0};
  std::uint32_t payload_len{0};
  bool has_mss{false};
  std::uint16_t mss{0};
  bool has_window_scale{false};
  std::uint8_t window_scale{0};
  bool sack_permitted{false};
  std::uint8_t sack_block_count{0};
  std::array<std::pair<std::uint32_t, std::uint32_t>, kTcpMaxSackBlocks> sack_blocks{};
  bool has_timestamp{false};
  std::uint32_t tsval{0};
  std::uint32_t tsecr{0};
};

struct TcpRetransmitEntry {
  std::uint32_t seq{0};
  std::uint32_t end_seq{0};
  std::uint32_t len{0};
  std::uint64_t first_tx_ns{0};
  std::uint64_t last_tx_ns{0};
  std::uint32_t retransmits{0};
  bool acked{false};
};

struct TcpOutOfOrderSegment {
  std::uint32_t seq{0};
  std::uint32_t end_seq{0};
};

struct TcpControlBlock {
  std::uint32_t iss{0};
  std::uint32_t irs{0};
  std::uint32_t snd_una{0};
  std::uint32_t snd_nxt{0};
  std::uint32_t rcv_nxt{0};
  std::uint32_t snd_wnd{65535u};
  std::uint32_t rcv_wnd{65535u};
  std::uint32_t cwnd_bytes{kTcpDefaultMss * 10u};
  std::uint32_t ssthresh_bytes{kTcpDefaultMss * 64u};
  std::uint32_t mss{kTcpDefaultMss};
  std::uint32_t peer_mss{kTcpDefaultMss};
  std::uint32_t pmtu{kTcpDefaultPmtu};
  std::uint8_t window_scale{0};
  std::uint8_t peer_window_scale{0};
  bool sack_permitted{false};
  bool timestamp_enabled{false};
  std::uint32_t ts_recent{0};
  std::uint32_t ts_last_ack_sent{0};
  std::uint32_t last_ack{0};
  std::uint32_t dup_ack_count{0};
  bool fast_recovery{false};
  bool zero_window{false};
  bool retransmit_pending{false};
  bool zero_window_probe_pending{false};
  std::uint64_t invalid_ack_count{0};
  std::uint64_t old_segment_count{0};
  std::uint64_t out_of_order_drop_count{0};
  std::uint64_t retransmit_queue_overflow_count{0};
  std::uint64_t srtt_us{0};
  std::uint64_t rttvar_us{0};
  std::uint64_t rto_ns{kTcpInitialRtoNs};
  std::uint64_t next_rto_deadline_ns{0};
  std::uint64_t zero_window_probe_deadline_ns{0};
  std::uint64_t time_wait_deadline_ns{0};
  std::deque<TcpRetransmitEntry> retransmit_queue{};
  std::vector<TcpOutOfOrderSegment> out_of_order{};
};

struct GpuStreamPolicy {
  std::uint32_t quota{1};
  std::uint16_t payload_len{0};
  std::uint64_t tx_ipg_ns{0};
  std::uint32_t template_id{kGpuStreamPolicyTemplateValid};
  bool pause{false};
  bool retransmit{false};
  bool zero_window_probe{false};
};

inline bool ParseTcpSegmentObservation(
    const std::uint8_t* packet,
    std::size_t len,
    TcpSegmentObservation* out) {
  if (!packet || !out || len < 40u) {
    return false;
  }
  std::size_t ip_off = 0u;
  if (len >= 14u) {
    std::uint16_t eth_type = ReadBe16(packet + 12);
    if ((eth_type == 0x8100u || eth_type == 0x88A8u) && len >= 18u) {
      eth_type = ReadBe16(packet + 16);
      ip_off = 18u;
    } else if (eth_type == 0x0800u) {
      ip_off = 14u;
    }
    if (ip_off != 0u && eth_type != 0x0800u) {
      return false;
    }
  }
  if (len < ip_off + 20u || ((packet[ip_off] >> 4u) != 4u)) {
    return false;
  }
  const std::size_t ihl = static_cast<std::size_t>(packet[ip_off] & 0x0Fu) * 4u;
  if (ihl < 20u || len < ip_off + ihl + 20u || packet[ip_off + 9u] != kProtoTcp) {
    return false;
  }
  const std::uint16_t ip_total_len = ReadBe16(packet + ip_off + 2u);
  if (ip_total_len < ihl + 20u || ip_off + static_cast<std::size_t>(ip_total_len) > len) {
    return false;
  }
  const std::uint16_t frag = ReadBe16(packet + ip_off + 6u);
  if ((frag & 0x3FFFu) != 0u) {
    return false;
  }
  const std::size_t tcp_off = ip_off + ihl;
  const std::size_t tcp_hlen = static_cast<std::size_t>((packet[tcp_off + 12u] >> 4u) & 0x0Fu) * 4u;
  if (tcp_hlen < 20u || tcp_off + tcp_hlen > ip_off + static_cast<std::size_t>(ip_total_len)) {
    return false;
  }
  TcpSegmentObservation obs{};
  obs.src_ip = ReadBe32(packet + ip_off + 12u);
  obs.dst_ip = ReadBe32(packet + ip_off + 16u);
  obs.src_port = ReadBe16(packet + tcp_off);
  obs.dst_port = ReadBe16(packet + tcp_off + 2u);
  obs.seq = ReadBe32(packet + tcp_off + 4u);
  obs.ack = ReadBe32(packet + tcp_off + 8u);
  obs.flags = static_cast<std::uint16_t>(packet[tcp_off + 13u]);
  obs.window = ReadBe16(packet + tcp_off + 14u);
  obs.payload_len = static_cast<std::uint32_t>(
      static_cast<std::size_t>(ip_total_len) - ihl - tcp_hlen);
  std::size_t opt = tcp_off + 20u;
  const std::size_t opt_end = tcp_off + tcp_hlen;
  while (opt < opt_end) {
    const std::uint8_t kind = packet[opt];
    if (kind == 0u) {
      break;
    }
    if (kind == 1u) {
      ++opt;
      continue;
    }
    if (opt + 1u >= opt_end) {
      break;
    }
    const std::uint8_t opt_len = packet[opt + 1u];
    if (opt_len < 2u || opt + opt_len > opt_end) {
      break;
    }
    switch (kind) {
      case 2u:
        if (opt_len == 4u) {
          obs.has_mss = true;
          obs.mss = ReadBe16(packet + opt + 2u);
        }
        break;
      case 3u:
        if (opt_len == 3u) {
          obs.has_window_scale = true;
          obs.window_scale =
              static_cast<std::uint8_t>(std::min<std::uint8_t>(packet[opt + 2u], static_cast<std::uint8_t>(14u)));
        }
        break;
      case 4u:
        if (opt_len == 2u) {
          obs.sack_permitted = true;
        }
        break;
      case 5u: {
        if (opt_len >= 10u && ((opt_len - 2u) % 8u) == 0u) {
          const std::uint8_t block_count =
              static_cast<std::uint8_t>(std::min<std::size_t>((opt_len - 2u) / 8u, kTcpMaxSackBlocks));
          obs.sack_block_count = block_count;
          for (std::uint8_t i = 0; i < block_count; ++i) {
            const std::size_t block = opt + 2u + static_cast<std::size_t>(i) * 8u;
            obs.sack_blocks[i] = {ReadBe32(packet + block), ReadBe32(packet + block + 4u)};
          }
        }
        break;
      }
      case 8u:
        if (opt_len == 10u) {
          obs.has_timestamp = true;
          obs.tsval = ReadBe32(packet + opt + 2u);
          obs.tsecr = ReadBe32(packet + opt + 6u);
        }
        break;
      default:
        break;
    }
    opt += opt_len;
  }
  *out = obs;
  return true;
}

class FlowStateTable {
 public:
  FlowState& Upsert(const FlowState& in) {
    FlowState next = in;
    auto it = flows_.find(next.flow_id);
    next.version = NextCommittedVersion(it == flows_.end() ? 0ull : it->second.version);
    if (it != flows_.end()) {
      EraseFlowKeys(it->second);
    }
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& Transition(const FlowState& in) {
    auto it = flows_.find(in.flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    if (in.epoch < it->second.epoch) {
      throw std::invalid_argument("dpu flow epoch rollback");
    }
    FlowState next = in;
    next.version = NextCommittedVersion(it->second.version);
    next.poisoned = next.tcp_state == kTcpStatePoisoned;
    next.migrating = next.tcp_state == kTcpStateMigrating;
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& Migrate(std::uint32_t flow_id, std::uint64_t new_epoch) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    if (new_epoch <= it->second.epoch) {
      throw std::invalid_argument("migration epoch must increase");
    }
    FlowState next = it->second;
    next.epoch = new_epoch;
    next.tcp_state = kTcpStateMigrating;
    next.version = NextCommittedVersion(it->second.version);
    next.migrating = true;
    next.poisoned = false;
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& CompleteMigration(std::uint32_t flow_id, std::uint64_t owner_epoch) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    if (!it->second.migrating && it->second.tcp_state != kTcpStateMigrating) {
      throw std::invalid_argument("flow is not migrating");
    }
    if (owner_epoch < it->second.epoch) {
      throw std::invalid_argument("migration completion epoch rollback");
    }
    FlowState next = it->second;
    next.epoch = owner_epoch;
    next.tcp_state = kTcpStateEstablished;
    next.version = NextCommittedVersion(it->second.version);
    next.migrating = false;
    next.poisoned = false;
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& Resync(const FlowState& snapshot) {
    auto it = flows_.find(snapshot.flow_id);
    if (it != flows_.end() && snapshot.epoch < it->second.epoch) {
      throw std::invalid_argument("resync epoch rollback");
    }
    FlowState next = snapshot;
    next.version = NextCommittedVersion(it == flows_.end() ? 0ull : it->second.version);
    next.poisoned = next.tcp_state == kTcpStatePoisoned;
    next.migrating = next.tcp_state == kTcpStateMigrating;
    if (it != flows_.end()) {
      EraseFlowKeys(it->second);
    }
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& Poison(std::uint32_t flow_id) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    FlowState next = it->second;
    next.tcp_state = kTcpStatePoisoned;
    next.version = NextCommittedVersion(it->second.version);
    next.poisoned = true;
    next.migrating = false;
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    EnsureTcb(out->second);
    return out->second;
  }

  FlowState& Listen(
      std::uint32_t flow_id,
      std::uint32_t local_ip,
      std::uint16_t local_port,
      std::uint64_t epoch = 1u) {
    FlowState st{};
    st.flow_id = flow_id;
    st.src_ip = local_ip;
    st.dst_ip = 0u;
    st.src_port = local_port;
    st.dst_port = 0u;
    st.proto = kProtoTcp;
    st.tcp_state = kTcpStateListen;
    st.flags = 0u;
    st.epoch = epoch;
    return Upsert(st);
  }

  FlowState& AcceptPassiveOpen(
      std::uint32_t listen_flow_id,
      std::uint32_t child_flow_id,
      const TcpSegmentObservation& syn,
      std::uint32_t iss,
      std::uint64_t now_ns) {
    const FlowState* listener = Find(listen_flow_id);
    if (!listener || listener->tcp_state != kTcpStateListen) {
      throw std::invalid_argument("passive open requires listening flow");
    }
    if ((syn.flags & kTcpFlagSyn) == 0u || (syn.flags & kTcpFlagAck) != 0u) {
      throw std::invalid_argument("passive open requires inbound SYN");
    }
    FlowState child{};
    child.flow_id = child_flow_id;
    child.src_ip = listener->src_ip;
    child.dst_ip = syn.src_ip;
    child.src_port = listener->src_port;
    child.dst_port = syn.src_port;
    child.seq_num = iss;
    child.ack_num = syn.seq + 1u;
    child.tcp_state = kTcpStateSynReceived;
    child.flags = static_cast<std::uint16_t>(kTcpFlagSyn | kTcpFlagAck);
    child.rtt_us = listener->rtt_us;
    child.last_ack_ts = now_ns;
    child.epoch = listener->epoch;
    child.proto = kProtoTcp;
    FlowState& out = Upsert(child);
    TcpControlBlock& tcb = EnsureTcb(out);
    tcb.iss = iss;
    tcb.snd_una = iss;
    tcb.snd_nxt = iss + 1u;
    tcb.irs = syn.seq;
    tcb.rcv_nxt = syn.seq + 1u;
    ApplyPeerOptions(tcb, syn);
    UpdatePeerWindow(tcb, syn, now_ns);
    return out;
  }

  FlowState& ObserveTcpSegment(
      std::uint32_t flow_id,
      const TcpSegmentObservation& seg,
      std::uint64_t now_ns) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    FlowState next = it->second;
    if (next.proto != kProtoTcp) {
      throw std::invalid_argument("tcp segment observed for non-tcp flow");
    }
    if (seg.src_port != next.dst_port || seg.dst_port != next.src_port) {
      throw std::invalid_argument("tcp segment ports do not match reverse flow");
    }
    if ((next.src_ip != 0u && seg.dst_ip != next.src_ip) || (next.dst_ip != 0u && seg.src_ip != next.dst_ip)) {
      throw std::invalid_argument("tcp segment addresses do not match reverse flow");
    }
    TcpControlBlock& tcb = EnsureTcb(next);
    ApplyPeerOptions(tcb, seg);
    UpdatePeerWindow(tcb, seg, now_ns);
    if ((seg.flags & kTcpFlagRst) != 0u) {
      next.tcp_state = kTcpStatePoisoned;
      next.flags = kTcpFlagRst;
      next.poisoned = true;
      next.migrating = false;
      next.last_ack_ts = now_ns;
    } else {
      const std::uint32_t seg_end = SegmentEndSeq(seg);
      ApplyReceiveOrdering(tcb, seg, seg_end);
      if ((seg.flags & kTcpFlagAck) != 0u) {
        ApplyAck(tcb, seg, now_ns);
        if (next.last_tx_ts != 0u && now_ns > next.last_tx_ts) {
          const std::uint64_t sample_us = (now_ns - next.last_tx_ts) / 1000ull;
          next.rtt_us = static_cast<std::uint32_t>(
              sample_us > 0xFFFFFFFFull ? 0xFFFFFFFFull : sample_us);
        }
      }
      if (next.tcp_state == kTcpStateSynSent && (seg.flags & kTcpFlagSyn) != 0u &&
          (seg.flags & kTcpFlagAck) != 0u) {
        next.tcp_state = kTcpStateEstablished;
        next.flags = kTcpFlagAck;
      } else if (next.tcp_state == kTcpStateSynReceived && (seg.flags & kTcpFlagAck) != 0u &&
                 TcpSeqAfterEq(seg.ack, tcb.snd_nxt)) {
        next.tcp_state = kTcpStateEstablished;
        next.flags = kTcpFlagAck;
      } else if ((seg.flags & kTcpFlagFin) != 0u) {
        if (next.tcp_state == kTcpStateFinWait) {
          next.tcp_state = kTcpStateTimeWait;
          tcb.time_wait_deadline_ns = now_ns + kTcpTimeWaitNs;
        } else {
          next.tcp_state = kTcpStateCloseWait;
        }
        next.flags = kTcpFlagAck;
      } else if (next.tcp_state == kTcpStateLastAck && (seg.flags & kTcpFlagAck) != 0u &&
                 TcpSeqAfterEq(seg.ack, tcb.snd_nxt)) {
        next.tcp_state = kTcpStateClosed;
        next.flags = 0u;
      } else if (next.tcp_state != kTcpStatePoisoned) {
        next.tcp_state = kTcpStateEstablished;
        next.flags = kTcpFlagAck | (((seg.flags & kTcpFlagPsh) != 0u) ? kTcpFlagPsh : 0u);
      }
      next.seq_num = tcb.fast_recovery ? tcb.snd_una : tcb.snd_nxt;
      next.ack_num = tcb.rcv_nxt;
      next.rtt_us = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(tcb.srtt_us != 0u ? tcb.srtt_us : next.rtt_us, 0xFFFFFFFFull));
      next.last_ack_ts = now_ns;
      next.poisoned = false;
      next.migrating = false;
    }
    next.version = NextCommittedVersion(it->second.version);
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    return out->second;
  }

  FlowState& ObserveTcpPacket(
      std::uint32_t flow_id,
      const std::uint8_t* packet,
      std::size_t len,
      std::uint64_t now_ns) {
    TcpSegmentObservation seg{};
    if (!ParseTcpSegmentObservation(packet, len, &seg)) {
      throw std::invalid_argument("invalid tcp packet observation");
    }
    return ObserveTcpSegment(flow_id, seg, now_ns);
  }

  FlowState& ObserveTcpPacketByTuple(
      const std::uint8_t* packet,
      std::size_t len,
      std::uint64_t now_ns) {
    TcpSegmentObservation seg{};
    if (!ParseTcpSegmentObservation(packet, len, &seg)) {
      throw std::invalid_argument("invalid tcp packet observation");
    }
    const TcpFlowKey key{seg.src_ip, seg.dst_ip, seg.src_port, seg.dst_port, kProtoTcp};
    auto it = flow_lookup_.find(key);
    if (it == flow_lookup_.end()) {
      throw std::out_of_range("unknown dpu tcp tuple");
    }
    return ObserveTcpSegment(it->second, seg, now_ns);
  }

  FlowState& TrackTransmit(
      std::uint32_t flow_id,
      std::uint32_t seq,
      std::uint32_t payload_len,
      std::uint16_t flags,
      std::uint64_t now_ns) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    FlowState next = it->second;
    TcpControlBlock& tcb = EnsureTcb(next);
    const std::uint32_t end_seq = seq + payload_len +
        (((flags & kTcpFlagSyn) != 0u) ? 1u : 0u) +
        (((flags & kTcpFlagFin) != 0u) ? 1u : 0u);
    if (end_seq != seq) {
      tcb.snd_nxt = TcpSeqAfter(end_seq, tcb.snd_nxt) ? end_seq : tcb.snd_nxt;
      if (tcb.retransmit_queue.size() >= kTcpMaxRetransmitEntries) {
        tcb.retransmit_queue_overflow_count += 1u;
        tcb.retransmit_queue.pop_front();
      }
      tcb.retransmit_queue.push_back(TcpRetransmitEntry{seq, end_seq, payload_len, now_ns, now_ns, 0u, false});
      if (tcb.next_rto_deadline_ns == 0u) {
        tcb.next_rto_deadline_ns = now_ns + tcb.rto_ns;
      }
    }
    next.seq_num = tcb.snd_nxt;
    next.last_tx_ts = now_ns;
    next.flags = flags;
    next.version = NextCommittedVersion(it->second.version);
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    return out->second;
  }

  FlowState& TrackTransmitBatch(
      std::uint32_t flow_id,
      std::uint32_t first_seq,
      std::uint32_t payload_len,
      std::uint16_t flags,
      std::uint32_t packet_count,
      std::uint32_t seq_stride,
      std::uint64_t now_ns) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    if (packet_count == 0u) {
      return it->second;
    }
    FlowState next = it->second;
    TcpControlBlock& tcb = EnsureTcb(next);
    const std::uint32_t control_advance =
        (((flags & kTcpFlagSyn) != 0u) ? 1u : 0u) +
        (((flags & kTcpFlagFin) != 0u) ? 1u : 0u);
    const std::uint32_t segment_advance = payload_len + control_advance;
    if (segment_advance != 0u) {
      const std::uint32_t stride = seq_stride != 0u ? seq_stride : segment_advance;
      const std::size_t need = std::min<std::size_t>(static_cast<std::size_t>(packet_count), kTcpMaxRetransmitEntries);
      while (tcb.retransmit_queue.size() + need > kTcpMaxRetransmitEntries && !tcb.retransmit_queue.empty()) {
        tcb.retransmit_queue_overflow_count += 1u;
        tcb.retransmit_queue.pop_front();
      }
      const std::uint32_t tracked_count = static_cast<std::uint32_t>(need);
      if (tracked_count < packet_count) {
        tcb.retransmit_queue_overflow_count += static_cast<std::uint64_t>(packet_count - tracked_count);
      }
      for (std::uint32_t i = 0; i < tracked_count; ++i) {
        const std::uint32_t seq = first_seq + (i * stride);
        const std::uint32_t end_seq = seq + segment_advance;
        tcb.snd_nxt = TcpSeqAfter(end_seq, tcb.snd_nxt) ? end_seq : tcb.snd_nxt;
        tcb.retransmit_queue.push_back(TcpRetransmitEntry{seq, end_seq, payload_len, now_ns, now_ns, 0u, false});
      }
      if (tcb.next_rto_deadline_ns == 0u) {
        tcb.next_rto_deadline_ns = now_ns + tcb.rto_ns;
      }
    }
    next.seq_num = tcb.snd_nxt;
    next.last_tx_ts = now_ns;
    next.flags = flags;
    next.version = NextCommittedVersion(it->second.version);
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    return out->second;
  }

  FlowState& TickTcpTimers(std::uint32_t flow_id, std::uint64_t now_ns) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    FlowState next = it->second;
    TcpControlBlock& tcb = EnsureTcb(next);
    bool changed = false;
    if (tcb.next_rto_deadline_ns != 0u && now_ns >= tcb.next_rto_deadline_ns && HasUnackedData(tcb)) {
      tcb.ssthresh_bytes = std::max<std::uint32_t>(2u * tcb.mss, tcb.cwnd_bytes / 2u);
      tcb.cwnd_bytes = tcb.mss;
      tcb.dup_ack_count = 0u;
      tcb.fast_recovery = false;
      tcb.rto_ns = std::min<std::uint64_t>(kTcpMaxRtoNs, std::max<std::uint64_t>(kTcpMinRtoNs, tcb.rto_ns * 2u));
      tcb.next_rto_deadline_ns = now_ns + tcb.rto_ns;
      MarkOldestRetransmit(tcb, now_ns);
      tcb.retransmit_pending = true;
      next.seq_num = tcb.snd_una;
      next.flags = kTcpFlagAck | ((next.tcp_state == kTcpStateEstablished) ? kTcpFlagPsh : 0u);
      changed = true;
    }
    if (tcb.zero_window && tcb.zero_window_probe_deadline_ns != 0u && now_ns >= tcb.zero_window_probe_deadline_ns) {
      next.seq_num = tcb.snd_una;
      next.flags = kTcpFlagAck;
      tcb.zero_window_probe_pending = true;
      tcb.zero_window_probe_deadline_ns = now_ns + std::min<std::uint64_t>(kTcpMaxRtoNs, tcb.rto_ns);
      changed = true;
    }
    if (next.tcp_state == kTcpStateTimeWait && tcb.time_wait_deadline_ns != 0u && now_ns >= tcb.time_wait_deadline_ns) {
      next.tcp_state = kTcpStateClosed;
      next.flags = 0u;
      next.poisoned = false;
      changed = true;
    }
    if (!changed) {
      return it->second;
    }
    next.version = NextCommittedVersion(it->second.version);
    EraseFlowKeys(it->second);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    RegisterFlowKeys(out->second);
    return out->second;
  }

  void UpdatePathMtu(std::uint32_t flow_id, std::uint32_t pmtu) {
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    TcpControlBlock& tcb = EnsureTcb(it->second);
    tcb.pmtu = std::max<std::uint32_t>(pmtu, 576u);
    tcb.mss = std::min<std::uint32_t>(tcb.peer_mss, TcpClampMssFromPmtu(tcb.pmtu));
  }

  const TcpControlBlock* FindTcb(std::uint32_t flow_id) const {
    auto it = tcbs_.find(flow_id);
    return it == tcbs_.end() ? nullptr : &it->second;
  }

  std::uint32_t ClampPayloadToMss(std::uint32_t flow_id, std::uint32_t desired_payload_len) const {
    auto it = tcbs_.find(flow_id);
    if (it == tcbs_.end()) {
      return std::min<std::uint32_t>(desired_payload_len, kTcpDefaultMss);
    }
    return std::min<std::uint32_t>(desired_payload_len, it->second.mss);
  }

  GpuStreamPolicy BuildGpuStreamPolicy(
      std::uint32_t flow_id,
      std::uint32_t requested_quota,
      std::uint32_t requested_payload_len,
      std::uint64_t requested_tx_ipg_ns) const {
    GpuStreamPolicy policy{};
    policy.tx_ipg_ns = requested_tx_ipg_ns;
    const FlowState* st = Find(flow_id);
    const TcpControlBlock* tcb = FindTcb(flow_id);
    if (!st || !tcb || st->proto != kProtoTcp || st->tcp_state == kTcpStatePoisoned ||
        st->tcp_state == kTcpStateMigrating || st->tcp_state == kTcpStateClosed ||
        st->tcp_state == kTcpStateTimeWait) {
      policy.quota = 0u;
      policy.payload_len = 0u;
      policy.pause = true;
      policy.template_id |= kGpuStreamPolicyPause;
      return policy;
    }

    std::uint32_t payload_len = std::min<std::uint32_t>(requested_payload_len, tcb->mss);
    if (tcb->zero_window) {
      policy.quota = 0u;
      policy.payload_len = 0u;
      policy.pause = true;
      policy.template_id |= kGpuStreamPolicyPause;
      if (tcb->zero_window_probe_pending) {
        policy.quota = 1u;
        policy.payload_len = static_cast<std::uint16_t>(requested_payload_len > 0u ? 1u : 0u);
        policy.pause = false;
        policy.zero_window_probe = true;
        policy.template_id &= ~kGpuStreamPolicyPause;
        policy.template_id |= kGpuStreamPolicyZeroWindowProbe;
      }
      return policy;
    }

    const bool retransmit = tcb->retransmit_pending;
    const std::uint32_t window_bytes = std::min<std::uint32_t>(tcb->cwnd_bytes, tcb->snd_wnd);
    if (window_bytes == 0u) {
      policy.quota = 0u;
      policy.payload_len = 0u;
      policy.pause = true;
      policy.template_id |= kGpuStreamPolicyPause;
      return policy;
    }
    const std::uint32_t effective_payload = payload_len > 0u ? payload_len : tcb->mss;
    const std::uint32_t window_quota = std::max<std::uint32_t>(1u, window_bytes / effective_payload);
    policy.quota = std::max<std::uint32_t>(1u, std::min<std::uint32_t>(requested_quota, window_quota));
    policy.payload_len = static_cast<std::uint16_t>(std::min<std::uint32_t>(payload_len, 0xFFFFu));
    if (retransmit) {
      policy.retransmit = true;
      policy.quota = 1u;
      policy.template_id |= kGpuStreamPolicyRetransmit;
    }
    return policy;
  }

  const FlowState* Find(std::uint32_t flow_id) const {
    auto it = flows_.find(flow_id);
    return it == flows_.end() ? nullptr : &it->second;
  }

  std::size_t Size() const {
    return flows_.size();
  }

  samurai::wire::FlowUpdateEventV1 BuildUpdateEvent(std::uint32_t flow_id, std::uint64_t dpu_ts_ns) const {
    const FlowState* st = Find(flow_id);
    if (!st) {
      throw std::out_of_range("unknown dpu flow_id");
    }
    samurai::wire::FlowUpdateEventV1 ev{};
    ev.version = st->version;
    ev.epoch = st->epoch;
    ev.flow_id = st->flow_id;
    ev.tcp_seq = st->seq_num;
    ev.tcp_ack = st->ack_num;
    ev.src_port = st->src_port;
    ev.dst_port = st->dst_port;
    ev.tcp_state = st->tcp_state;
    ev.proto = st->proto;
    ev.flags = st->flags;
    ev.rtt_us = st->rtt_us;
    ev.dpu_ts_ns = dpu_ts_ns;
    return ev;
  }

 private:
  TcpControlBlock& EnsureTcb(const FlowState& st) {
    auto [it, inserted] = tcbs_.try_emplace(st.flow_id);
    TcpControlBlock& tcb = it->second;
    if (inserted) {
      tcb.iss = st.seq_num;
      tcb.snd_una = st.seq_num;
      tcb.snd_nxt = st.seq_num;
      tcb.rcv_nxt = st.ack_num;
      tcb.last_ack = st.seq_num;
      tcb.mss = kTcpDefaultMss;
      tcb.peer_mss = kTcpDefaultMss;
      tcb.pmtu = kTcpDefaultPmtu;
      tcb.cwnd_bytes = 10u * tcb.mss;
      tcb.ssthresh_bytes = 64u * tcb.mss;
    }
    return tcb;
  }

  void EraseFlowKeys(const FlowState& st) {
    if (st.src_ip == 0u || st.dst_ip == 0u || st.src_port == 0u || st.dst_port == 0u) {
      return;
    }
    flow_lookup_.erase(ForwardKeyFromState(st));
    flow_lookup_.erase(TcpFlowKey{st.dst_ip, st.src_ip, st.dst_port, st.src_port, st.proto});
  }

  void RegisterFlowKeys(const FlowState& st) {
    if (st.src_ip == 0u || st.dst_ip == 0u || st.src_port == 0u || st.dst_port == 0u) {
      return;
    }
    flow_lookup_[ForwardKeyFromState(st)] = st.flow_id;
    flow_lookup_[TcpFlowKey{st.dst_ip, st.src_ip, st.dst_port, st.src_port, st.proto}] = st.flow_id;
  }

  static std::uint32_t SegmentEndSeq(const TcpSegmentObservation& seg) {
    return seg.seq + seg.payload_len +
        (((seg.flags & kTcpFlagSyn) != 0u) ? 1u : 0u) +
        (((seg.flags & kTcpFlagFin) != 0u) ? 1u : 0u);
  }

  static bool HasUnackedData(const TcpControlBlock& tcb) {
    for (const TcpRetransmitEntry& entry : tcb.retransmit_queue) {
      if (!entry.acked) {
        return true;
      }
    }
    return false;
  }

  static void MarkOldestRetransmit(TcpControlBlock& tcb, std::uint64_t now_ns) {
    for (TcpRetransmitEntry& entry : tcb.retransmit_queue) {
      if (!entry.acked) {
        entry.last_tx_ns = now_ns;
        entry.retransmits += 1u;
        return;
      }
    }
  }

  static void ApplyPeerOptions(TcpControlBlock& tcb, const TcpSegmentObservation& seg) {
    if ((seg.flags & kTcpFlagSyn) != 0u) {
      if (seg.has_mss && seg.mss >= kTcpMinMss) {
        tcb.peer_mss = seg.mss;
        tcb.mss = std::min<std::uint32_t>(tcb.peer_mss, TcpClampMssFromPmtu(tcb.pmtu));
      }
      if (seg.has_window_scale) {
        tcb.peer_window_scale = seg.window_scale;
      }
      if (seg.sack_permitted) {
        tcb.sack_permitted = true;
      }
    }
    if (seg.has_timestamp) {
      tcb.timestamp_enabled = true;
      tcb.ts_recent = seg.tsval;
    }
  }

  static void UpdatePeerWindow(TcpControlBlock& tcb, const TcpSegmentObservation& seg, std::uint64_t now_ns) {
    const std::uint32_t scaled = static_cast<std::uint32_t>(seg.window) << tcb.peer_window_scale;
    tcb.snd_wnd = scaled;
    tcb.zero_window = scaled == 0u;
    if (tcb.zero_window && tcb.zero_window_probe_deadline_ns == 0u) {
      tcb.zero_window_probe_deadline_ns = now_ns + tcb.rto_ns;
    } else if (!tcb.zero_window) {
      tcb.zero_window_probe_deadline_ns = 0u;
    }
  }

  static void InsertOutOfOrder(TcpControlBlock& tcb, std::uint32_t seq, std::uint32_t end_seq) {
    if (seq == end_seq) {
      return;
    }
    if (tcb.out_of_order.size() >= kTcpMaxOutOfOrderSegments) {
      tcb.out_of_order_drop_count += 1u;
      tcb.out_of_order.erase(tcb.out_of_order.begin());
    }
    tcb.out_of_order.push_back(TcpOutOfOrderSegment{seq, end_seq});
    std::sort(tcb.out_of_order.begin(), tcb.out_of_order.end(), [](const auto& a, const auto& b) {
      return TcpSeqBefore(a.seq, b.seq);
    });
  }

  static void DrainOutOfOrder(TcpControlBlock& tcb) {
    bool advanced = true;
    while (advanced) {
      advanced = false;
      for (auto it = tcb.out_of_order.begin(); it != tcb.out_of_order.end();) {
        if (TcpSeqBeforeEq(it->seq, tcb.rcv_nxt) && TcpSeqAfter(it->end_seq, tcb.rcv_nxt)) {
          tcb.rcv_nxt = it->end_seq;
          it = tcb.out_of_order.erase(it);
          advanced = true;
        } else if (TcpSeqBeforeEq(it->end_seq, tcb.rcv_nxt)) {
          it = tcb.out_of_order.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  static void ApplyReceiveOrdering(
      TcpControlBlock& tcb,
      const TcpSegmentObservation& seg,
      std::uint32_t seg_end) {
    if ((seg.flags & kTcpFlagSyn) != 0u) {
      tcb.irs = seg.seq;
      if (tcb.rcv_nxt == 0u || TcpSeqBefore(tcb.rcv_nxt, seg_end)) {
        tcb.rcv_nxt = seg_end;
      }
      return;
    }
    if (seg_end == seg.seq) {
      return;
    }
    if (seg.seq == tcb.rcv_nxt) {
      tcb.rcv_nxt = seg_end;
      DrainOutOfOrder(tcb);
    } else if (TcpSeqAfter(seg.seq, tcb.rcv_nxt)) {
      InsertOutOfOrder(tcb, seg.seq, seg_end);
    } else {
      tcb.old_segment_count += 1u;
    }
  }

  static void UpdateRto(TcpControlBlock& tcb, std::uint64_t sample_us) {
    if (sample_us == 0u) {
      sample_us = 1u;
    }
    if (tcb.srtt_us == 0u) {
      tcb.srtt_us = sample_us;
      tcb.rttvar_us = sample_us / 2u;
    } else {
      const std::uint64_t abs_err = tcb.srtt_us > sample_us ? tcb.srtt_us - sample_us : sample_us - tcb.srtt_us;
      tcb.rttvar_us = ((3u * tcb.rttvar_us) + abs_err) / 4u;
      tcb.srtt_us = ((7u * tcb.srtt_us) + sample_us) / 8u;
    }
    const std::uint64_t rto_us = tcb.srtt_us + std::max<std::uint64_t>(1'000u, 4u * tcb.rttvar_us);
    tcb.rto_ns = std::min<std::uint64_t>(
        kTcpMaxRtoNs,
        std::max<std::uint64_t>(kTcpMinRtoNs, rto_us * 1000ull));
  }

  static bool AckRetransmitQueue(TcpControlBlock& tcb, std::uint32_t ack, std::uint64_t now_ns) {
    bool advanced = false;
    for (TcpRetransmitEntry& entry : tcb.retransmit_queue) {
      if (!entry.acked && TcpSeqAfterEq(ack, entry.end_seq)) {
        entry.acked = true;
        advanced = true;
        if (entry.retransmits == 0u && now_ns > entry.first_tx_ns) {
          UpdateRto(tcb, (now_ns - entry.first_tx_ns) / 1000ull);
        }
      }
    }
    while (!tcb.retransmit_queue.empty() && tcb.retransmit_queue.front().acked) {
      tcb.retransmit_queue.pop_front();
    }
    return advanced;
  }

  static void ApplySackBlocks(TcpControlBlock& tcb, const TcpSegmentObservation& seg) {
    if (!tcb.sack_permitted || seg.sack_block_count == 0u) {
      return;
    }
    for (std::uint8_t i = 0; i < seg.sack_block_count; ++i) {
      const auto [left, right] = seg.sack_blocks[i];
      if (!TcpSeqBefore(left, right)) {
        continue;
      }
      for (TcpRetransmitEntry& entry : tcb.retransmit_queue) {
        if (!entry.acked && TcpSeqAfterEq(left, entry.seq) && TcpSeqBeforeEq(right, entry.end_seq)) {
          entry.acked = true;
        }
      }
    }
  }

  static void CongestionOnNewAck(TcpControlBlock& tcb) {
    if (tcb.fast_recovery) {
      tcb.cwnd_bytes = tcb.ssthresh_bytes;
      tcb.fast_recovery = false;
      return;
    }
    if (tcb.cwnd_bytes < tcb.ssthresh_bytes) {
      tcb.cwnd_bytes += tcb.mss;
    } else {
      tcb.cwnd_bytes += std::max<std::uint32_t>(1u, (tcb.mss * tcb.mss) / std::max<std::uint32_t>(tcb.cwnd_bytes, 1u));
    }
  }

  static void CongestionOnDuplicateAck(TcpControlBlock& tcb) {
    tcb.dup_ack_count += 1u;
    if (tcb.dup_ack_count == 3u) {
      tcb.ssthresh_bytes = std::max<std::uint32_t>(2u * tcb.mss, tcb.cwnd_bytes / 2u);
      tcb.cwnd_bytes = tcb.ssthresh_bytes + (3u * tcb.mss);
      tcb.fast_recovery = true;
      MarkOldestRetransmit(tcb, 0u);
    } else if (tcb.fast_recovery) {
      tcb.cwnd_bytes += tcb.mss;
    }
  }

  static void ApplyAck(TcpControlBlock& tcb, const TcpSegmentObservation& seg, std::uint64_t now_ns) {
    if (TcpSeqAfter(seg.ack, tcb.snd_nxt)) {
      tcb.invalid_ack_count += 1u;
      return;
    }
    ApplySackBlocks(tcb, seg);
    if (TcpSeqAfter(seg.ack, tcb.snd_una)) {
      tcb.snd_una = seg.ack;
      tcb.last_ack = seg.ack;
      tcb.dup_ack_count = 0u;
      tcb.retransmit_pending = false;
      tcb.zero_window_probe_pending = false;
      (void)AckRetransmitQueue(tcb, seg.ack, now_ns);
      CongestionOnNewAck(tcb);
      tcb.next_rto_deadline_ns = HasUnackedData(tcb) ? now_ns + tcb.rto_ns : 0u;
    } else if (seg.ack == tcb.snd_una) {
      CongestionOnDuplicateAck(tcb);
    }
  }

  std::unordered_map<std::uint32_t, FlowState> flows_{};
  std::unordered_map<std::uint32_t, TcpControlBlock> tcbs_{};
  std::unordered_map<TcpFlowKey, std::uint32_t, TcpFlowKeyHash> flow_lookup_{};
};

}  // namespace samurai::dpu
