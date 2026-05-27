#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

#include "wire_protocol.h"

namespace samurai::dpu {

inline constexpr std::uint8_t kTcpStateClosed = 0u;
inline constexpr std::uint8_t kTcpStateSynSent = 1u;
inline constexpr std::uint8_t kTcpStateEstablished = 4u;
inline constexpr std::uint8_t kTcpStateMigrating = 250u;
inline constexpr std::uint8_t kTcpStatePoisoned = 255u;
inline constexpr std::uint8_t kProtoTcp = 6u;
inline constexpr std::uint8_t kProtoUdp = 17u;

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
