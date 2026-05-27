#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

#include "wire_protocol.h"

namespace samurai::dpu {

inline constexpr std::uint8_t kTcpStateClosed = 0u;
inline constexpr std::uint8_t kTcpStateSynSent = 1u;
inline constexpr std::uint8_t kTcpStateSynReceived = 2u;
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

struct FlowState {
  std::uint32_t flow_id{0};
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

struct TcpSegmentObservation {
  std::uint32_t src_ip{0};
  std::uint32_t dst_ip{0};
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  std::uint32_t seq{0};
  std::uint32_t ack{0};
  std::uint16_t flags{0};
  std::uint32_t payload_len{0};
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
  obs.payload_len = static_cast<std::uint32_t>(
      static_cast<std::size_t>(ip_total_len) - ihl - tcp_hlen);
  *out = obs;
  return true;
}

class FlowStateTable {
 public:
  FlowState& Upsert(const FlowState& in) {
    FlowState next = in;
    auto it = flows_.find(next.flow_id);
    next.version = NextCommittedVersion(it == flows_.end() ? 0ull : it->second.version);
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
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
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
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
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
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
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
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
    auto [out, _inserted] = flows_.insert_or_assign(next.flow_id, next);
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
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
    return out->second;
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
    if ((seg.flags & kTcpFlagRst) != 0u) {
      next.tcp_state = kTcpStatePoisoned;
      next.flags = kTcpFlagRst;
      next.poisoned = true;
      next.migrating = false;
      next.last_ack_ts = now_ns;
    } else {
      std::uint32_t next_ack = seg.seq + seg.payload_len;
      if ((seg.flags & kTcpFlagSyn) != 0u || (seg.flags & kTcpFlagFin) != 0u) {
        next_ack += 1u;
      }
      if (next_ack != seg.seq || (seg.flags & (kTcpFlagSyn | kTcpFlagFin)) != 0u) {
        next.ack_num = next_ack;
      }
      if ((seg.flags & kTcpFlagAck) != 0u) {
        next.seq_num = seg.ack;
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
      } else if ((seg.flags & kTcpFlagFin) != 0u) {
        next.tcp_state = kTcpStateCloseWait;
        next.flags = kTcpFlagAck;
      } else if (next.tcp_state != kTcpStatePoisoned) {
        next.tcp_state = kTcpStateEstablished;
        next.flags = kTcpFlagAck | (((seg.flags & kTcpFlagPsh) != 0u) ? kTcpFlagPsh : 0u);
      }
      next.last_ack_ts = now_ns;
      next.poisoned = false;
      next.migrating = false;
    }
    next.version = NextCommittedVersion(it->second.version);
    auto [out, _inserted] = flows_.insert_or_assign(flow_id, next);
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
  std::unordered_map<std::uint32_t, FlowState> flows_{};
};

}  // namespace samurai::dpu
