#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>

namespace ddos_samurai::tcpdp {

namespace {
constexpr uint8_t kTcpFlagFin = 0x01;
constexpr uint8_t kTcpFlagSyn = 0x02;
constexpr uint8_t kTcpFlagRst = 0x04;
constexpr uint8_t kTcpFlagPsh = 0x08;
constexpr uint8_t kTcpFlagAck = 0x10;

inline uint16_t ReadBe16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

inline uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t InternetChecksum(const uint8_t* ptr, size_t nbytes) {
  uint32_t sum = 0;
  for (size_t i = 0; i < nbytes; i += 2) {
    if (i + 1 < nbytes) {
      sum += (static_cast<uint32_t>(ptr[i]) << 8) | static_cast<uint32_t>(ptr[i + 1]);
    } else {
      sum += static_cast<uint32_t>(ptr[i]) << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

uint16_t TcpChecksum(const uint8_t* ip_header, const uint8_t* tcp_header, size_t tcp_len) {
  uint32_t sum = 0;
  const uint8_t* src_ip = ip_header + 12;
  const uint8_t* dst_ip = ip_header + 16;

  sum += (static_cast<uint32_t>(src_ip[0]) << 8) | static_cast<uint32_t>(src_ip[1]);
  sum += (static_cast<uint32_t>(src_ip[2]) << 8) | static_cast<uint32_t>(src_ip[3]);
  sum += (static_cast<uint32_t>(dst_ip[0]) << 8) | static_cast<uint32_t>(dst_ip[1]);
  sum += (static_cast<uint32_t>(dst_ip[2]) << 8) | static_cast<uint32_t>(dst_ip[3]);
  sum += 6;
  sum += static_cast<uint32_t>(tcp_len);

  for (size_t i = 0; i < tcp_len; i += 2) {
    if (i + 1 < tcp_len) {
      sum += (static_cast<uint32_t>(tcp_header[i]) << 8) | static_cast<uint32_t>(tcp_header[i + 1]);
    } else {
      sum += static_cast<uint32_t>(tcp_header[i]) << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}
}  // namespace

TcpDataplaneCore::TcpDataplaneCore() = default;

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
  std::lock_guard<std::mutex> guard(mu_);
  config_ = config;
  next_flow_id_ = 1;
  next_ephemeral_port_ = 40000;
  seq_seed_ = 0x10203040U;
  flows_by_id_.clear();
  flow_index_.clear();
  tx_packets_.clear();
  completions_.clear();
  rx_payloads_.clear();
  stats_ = TcpDpStatsSnapshot{};
  return true;
}

uint32_t TcpDataplaneCore::IngestTxPackets(const uint8_t* packets, size_t packet_size, size_t count) {
  if (!packets || packet_size == 0 || count == 0) {
    return 0;
  }
  std::lock_guard<std::mutex> guard(mu_);
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
    auto idx = flow_index_.find(key);
    FlowEntry* flow = nullptr;
    if (idx == flow_index_.end()) {
      FlowEntry created;
      created.flow_id = next_flow_id_++;
      created.key = key;
      created.iss = seq;
      created.snd_una = seq;
      created.snd_nxt = seq;
      created.rcv_nxt = ack;
      created.peer_window = 0;
      created.local_window = window > 0 ? window : config_.local_window;
      created.mss = config_.default_mss;
      created.ttl = ttl > 0 ? ttl : config_.default_ttl;
      created.last_activity_ns = DefaultNowNs();
      const auto inserted = flows_by_id_.emplace(created.flow_id, created);
      flow_index_[key] = created.flow_id;
      flow = &inserted.first->second;
    } else {
      flow = &flows_by_id_[idx->second];
      flow->last_activity_ns = DefaultNowNs();
    }

    if ((flags & kTcpFlagSyn) != 0 && (flags & kTcpFlagAck) == 0) {
      SetFlowState(*flow, TcpDpState::kSynSent);
      flow->iss = seq;
      flow->snd_una = seq;
      flow->snd_nxt = AdvanceSeq(seq, 1U);
      flow->rcv_nxt = 0;
      flow->retransmit_count = 0;
      OutstandingTx out;
      out.seq = seq;
      out.ack = 0;
      out.payload_len = 0;
      out.rto_ms = config_.initial_rto_ms;
      out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
      out.packet.assign(pkt, pkt + packet_size);
      flow->outstanding = std::move(out);
      flow->rto_deadline_ns = flow->outstanding->deadline_ns;
      stats_.connect_attempts++;
      updated++;
      continue;
    }

    if ((flags & kTcpFlagAck) != 0 && payload_len == 0 && flow->state == TcpDpState::kSynAckRcvd) {
      SetFlowState(*flow, TcpDpState::kEstablished);
      flow->snd_una = ack;
      flow->snd_nxt = seq;
      flow->outstanding.reset();
      flow->rto_deadline_ns = 0;
      stats_.connect_established++;
      updated++;
      continue;
    }

    if ((flags & kTcpFlagAck) != 0 && payload_len > 0) {
      SetFlowState(*flow, TcpDpState::kEstablished);
      flow->snd_una = ack;
      flow->snd_nxt = AdvanceSeq(seq, payload_len);
      flow->rcv_nxt = ack;
      flow->local_window = window > 0 ? window : flow->local_window;
      flow->retransmit_count = 0;
      OutstandingTx out;
      out.seq = seq;
      out.ack = ack;
      out.payload_len = payload_len;
      out.rto_ms = config_.initial_rto_ms;
      out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
      out.packet.assign(pkt, pkt + packet_size);
      flow->outstanding = std::move(out);
      flow->rto_deadline_ns = flow->outstanding->deadline_ns;
      stats_.tx_data_bytes += payload_len;
      updated++;
      continue;
    }

    if ((flags & kTcpFlagFin) != 0) {
      SetFlowState(*flow, TcpDpState::kFinWait);
      flow->snd_nxt = AdvanceSeq(seq, 1U);
      updated++;
      continue;
    }
  }
  return updated;
}

uint64_t TcpDataplaneCore::EnqueueConnect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
  if (src_ip == 0 || dst_ip == 0 || dst_port == 0) {
    return 0;
  }
  std::lock_guard<std::mutex> guard(mu_);
  if (src_port == 0) {
    src_port = static_cast<uint16_t>(next_ephemeral_port_++);
  }
  const uint64_t flow_id = next_flow_id_++;
  const uint64_t now_ns = DefaultNowNs();
  FlowEntry flow;
  flow.flow_id = flow_id;
  flow.key = FlowKey{src_ip, dst_ip, src_port, dst_port};
  flow.iss = seq_seed_;
  flow.snd_una = seq_seed_;
  flow.snd_nxt = seq_seed_;
  flow.rcv_nxt = 0;
  flow.peer_window = 0;
  flow.local_window = config_.local_window;
  flow.mss = config_.default_mss;
  flow.ttl = config_.default_ttl;
  flow.state = TcpDpState::kSynSent;
  flow.last_activity_ns = now_ns;
  seq_seed_ += 0x01010101U;

  auto syn = BuildPacket(flow, flow.snd_nxt, 0, kTcpFlagSyn, nullptr, 0);
  flow.snd_nxt = AdvanceSeq(flow.snd_nxt, 1);
  QueuePacket(flow, std::move(syn), flow.iss, 0, 0, true);
  flow.rto_deadline_ns = flow.outstanding ? flow.outstanding->deadline_ns : 0;

  flows_by_id_[flow_id] = flow;
  flow_index_[flow.key] = flow_id;
  stats_.flows_active++;
  stats_.connect_attempts++;
  return flow_id;
}

uint32_t TcpDataplaneCore::EnqueueSend(uint64_t flow_id, const uint8_t* payload, size_t payload_len) {
  if (!payload || payload_len == 0 || payload_len > 65535U) {
    return 0;
  }
  std::lock_guard<std::mutex> guard(mu_);
  auto it = flows_by_id_.find(flow_id);
  if (it == flows_by_id_.end()) {
    return 0;
  }
  FlowEntry& flow = it->second;
  if (flow.state != TcpDpState::kEstablished || flow.outstanding.has_value()) {
    return 0;
  }
  auto pkt = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, static_cast<uint8_t>(kTcpFlagAck | kTcpFlagPsh), payload, payload_len);
  const uint32_t seq = flow.snd_nxt;
  flow.snd_nxt = AdvanceSeq(flow.snd_nxt, static_cast<uint32_t>(payload_len));
  flow.last_activity_ns = DefaultNowNs();
  QueuePacket(flow, std::move(pkt), seq, flow.rcv_nxt, static_cast<uint32_t>(payload_len), true);
  flow.rto_deadline_ns = flow.outstanding ? flow.outstanding->deadline_ns : 0;
  stats_.tx_data_bytes += static_cast<uint64_t>(payload_len);
  return static_cast<uint32_t>(payload_len);
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
          frame, frame_len, &src_ip, &dst_ip, &src_port, &dst_port, &seq, &ack, &flags, &window, &payload_len, &ttl)) {
    return 0;
  }

  std::lock_guard<std::mutex> guard(mu_);
  stats_.rx_frames++;
  const FlowKey key{dst_ip, src_ip, dst_port, src_port};
  auto idx = flow_index_.find(key);
  if (idx == flow_index_.end()) {
    stats_.unexpected_rx++;
    return 0;
  }
  FlowEntry& flow = flows_by_id_[idx->second];
  flow.last_activity_ns = DefaultNowNs();
  if (window > 0) {
    flow.peer_window = window;
  }

  if ((flags & kTcpFlagRst) != 0) {
    SetFlowState(flow, TcpDpState::kRstSeen);
    flow.outstanding.reset();
    flow.rto_deadline_ns = 0;
    stats_.peer_rst_count++;
    PushCompletion(flow.flow_id, flow.state, false, "peer_rst");
    return 1;
  }

  if ((flags & (kTcpFlagSyn | kTcpFlagAck)) == (kTcpFlagSyn | kTcpFlagAck) && flow.state == TcpDpState::kSynSent) {
    if (ack != flow.snd_nxt) {
      stats_.unexpected_rx++;
      return 0;
    }
    flow.snd_una = ack;
    flow.rcv_nxt = seq + 1U;
    SetFlowState(flow, TcpDpState::kSynAckRcvd);
    flow.outstanding.reset();
    flow.rto_deadline_ns = 0;
    auto ack_pkt = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(flow, std::move(ack_pkt), flow.snd_nxt, flow.rcv_nxt, 0, false);
    SetFlowState(flow, TcpDpState::kEstablished);
    stats_.connect_established++;
    PushCompletion(flow.flow_id, flow.state, true, "connect_established");
    return 1;
  }

  if ((flags & kTcpFlagAck) != 0) {
    HandleAck(flow, ack);
    stats_.rx_ack_count++;
  }

  if (payload_len > 0) {
    if (flow.rcv_nxt != 0 && seq != flow.rcv_nxt) {
      stats_.out_of_order_rx_count++;
      stats_.unexpected_rx++;
      auto dup_ack_pkt = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0);
      QueuePacket(flow, std::move(dup_ack_pkt), flow.snd_nxt, flow.rcv_nxt, 0, false);
      return 1;
    }
    flow.rcv_nxt = AdvanceSeq(seq, payload_len);
    stats_.rx_data_bytes += payload_len;
    rx_payloads_.push_back(TcpDpRxPayload{flow.flow_id, ExtractIpv4TcpPayload(frame, frame_len)});
    auto ack_pkt = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(flow, std::move(ack_pkt), flow.snd_nxt, flow.rcv_nxt, 0, false);
  }

  if ((flags & kTcpFlagFin) != 0) {
    flow.rcv_nxt = AdvanceSeq(flow.rcv_nxt, 1U);
    auto ack_pkt = BuildPacket(flow, flow.snd_nxt, flow.rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(flow, std::move(ack_pkt), flow.snd_nxt, flow.rcv_nxt, 0, false);
    SetFlowState(flow, TcpDpState::kTimeWait);
    stats_.peer_fin_count++;
    PushCompletion(flow.flow_id, flow.state, true, "peer_fin");
  }
  (void)ttl;
  return 1;
}

uint32_t TcpDataplaneCore::Poll(uint64_t now_ns, uint32_t budget) {
  if (budget == 0) {
    budget = 1024;
  }
  std::lock_guard<std::mutex> guard(mu_);
  if (now_ns == 0) {
    now_ns = DefaultNowNs();
  }
  stats_.poll_calls++;
  uint32_t actions = 0;
  for (auto& [flow_id, flow] : flows_by_id_) {
    (void)flow_id;
    if (actions >= budget) {
      break;
    }
    if (flow.state == TcpDpState::kClosed || flow.state == TcpDpState::kRstSeen || flow.state == TcpDpState::kTimeWait) {
      continue;
    }
    if (flow.outstanding.has_value() && flow.outstanding->deadline_ns > 0 && now_ns >= flow.outstanding->deadline_ns) {
      if (flow.retransmit_count >= config_.max_retransmits) {
        CloseTimedOutFlow(flow, TcpDpState::kClosed, "retransmit_exhausted");
        actions++;
        continue;
      }
      flow.retransmit_count++;
      stats_.retransmit_count++;
      flow.outstanding->rto_ms = std::min(flow.outstanding->rto_ms * 2U, config_.connect_timeout_ms);
      flow.outstanding->deadline_ns = now_ns + NsFromMs(flow.outstanding->rto_ms);
      flow.rto_deadline_ns = flow.outstanding->deadline_ns;
      tx_packets_.push_back(flow.outstanding->packet);
      stats_.tx_packets_queued++;
      actions++;
    } else if (flow.outstanding.has_value() && flow.state == TcpDpState::kSynSent &&
               now_ns - flow.last_activity_ns >= NsFromMs(config_.connect_timeout_ms)) {
      CloseTimedOutFlow(flow, TcpDpState::kClosed, "connect_timeout");
      actions++;
    } else if (!flow.outstanding.has_value() && flow.state == TcpDpState::kEstablished &&
               now_ns - flow.last_activity_ns >= NsFromMs(config_.idle_timeout_ms)) {
      CloseTimedOutFlow(flow, TcpDpState::kTimeWait, "idle_timeout");
      actions++;
    }
  }
  return actions;
}

std::vector<std::vector<uint8_t>> TcpDataplaneCore::DrainTxPackets(uint32_t max_packets) {
  std::lock_guard<std::mutex> guard(mu_);
  if (max_packets == 0 || max_packets > tx_packets_.size()) {
    max_packets = static_cast<uint32_t>(tx_packets_.size());
  }
  std::vector<std::vector<uint8_t>> out;
  out.reserve(max_packets);
  for (uint32_t i = 0; i < max_packets; ++i) {
    out.push_back(std::move(tx_packets_.front()));
    tx_packets_.pop_front();
    stats_.tx_packets_drained++;
    stats_.tx_packets_sent++;
  }
  return out;
}

std::vector<TcpDpCompletion> TcpDataplaneCore::CollectCompletions() {
  std::lock_guard<std::mutex> guard(mu_);
  std::vector<TcpDpCompletion> out;
  out.reserve(completions_.size());
  while (!completions_.empty()) {
    out.push_back(completions_.front());
    completions_.pop_front();
  }
  return out;
}

std::vector<TcpDpRxPayload> TcpDataplaneCore::CollectRxPayloads() {
  std::lock_guard<std::mutex> guard(mu_);
  std::vector<TcpDpRxPayload> out;
  out.reserve(rx_payloads_.size());
  while (!rx_payloads_.empty()) {
    out.push_back(std::move(rx_payloads_.front()));
    rx_payloads_.pop_front();
  }
  return out;
}

TcpDpStatsSnapshot TcpDataplaneCore::SnapshotStats() const {
  std::lock_guard<std::mutex> guard(mu_);
  return stats_;
}

TcpDpFlowSnapshot TcpDataplaneCore::GetFlow(uint64_t flow_id) const {
  std::lock_guard<std::mutex> guard(mu_);
  TcpDpFlowSnapshot out;
  auto it = flows_by_id_.find(flow_id);
  if (it == flows_by_id_.end()) {
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
  out.mss = flow.mss;
  out.ttl = flow.ttl;
  out.state = static_cast<uint8_t>(flow.state);
  out.retransmit_count = flow.retransmit_count;
  out.rto_deadline_ns = flow.rto_deadline_ns;
  out.last_activity_ns = flow.last_activity_ns;
  out.found = true;
  return out;
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
    uint8_t* out_ttl) {
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
  const size_t payload_len = total_len >= static_cast<uint16_t>(ihl + data_off) ? total_len - ihl - data_off : 0U;

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

std::vector<uint8_t> TcpDataplaneCore::BuildPacket(
    const FlowEntry& flow,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t* payload,
    size_t payload_len) const {
  const size_t l2_len = 14;
  const size_t ip_len = 20;
  const size_t tcp_len = 20;
  std::vector<uint8_t> pkt(l2_len + ip_len + tcp_len + payload_len, 0);

  pkt[12] = 0x08;
  pkt[13] = 0x00;
  uint8_t* ip = pkt.data() + l2_len;
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
  tcp[12] = 0x50;
  tcp[13] = flags;
  const uint16_t win_be = htons(flow.local_window > 0 ? flow.local_window : config_.local_window);
  std::memcpy(tcp + 14, &win_be, sizeof(win_be));
  if (payload_len > 0) {
    std::memcpy(tcp + tcp_len, payload, payload_len);
  }

  const uint16_t ip_cksum = htons(InternetChecksum(ip, ip_len));
  std::memcpy(ip + 10, &ip_cksum, sizeof(ip_cksum));
  const uint16_t tcp_cksum = htons(TcpChecksum(ip, tcp, tcp_len + payload_len));
  std::memcpy(tcp + 16, &tcp_cksum, sizeof(tcp_cksum));
  return pkt;
}

void TcpDataplaneCore::QueuePacket(
    FlowEntry& flow,
    std::vector<uint8_t>&& packet,
    uint32_t seq,
    uint32_t ack,
    uint32_t payload_len,
    bool arm_rto) {
  tx_packets_.push_back(packet);
  stats_.tx_packets_queued++;
  if (!arm_rto) {
    return;
  }
  OutstandingTx out;
  out.seq = seq;
  out.ack = ack;
  out.payload_len = payload_len;
  out.rto_ms = config_.initial_rto_ms;
  out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
  out.packet = tx_packets_.back();
  flow.outstanding = std::move(out);
}

void TcpDataplaneCore::PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event) {
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
  if (was_active == now_active) {
    return;
  }
  if (now_active) {
    stats_.flows_active++;
  } else if (stats_.flows_active > 0) {
    stats_.flows_active--;
  }
}

void TcpDataplaneCore::HandleAck(FlowEntry& flow, uint32_t ack_value) {
  if (!flow.outstanding.has_value()) {
    return;
  }
  if (ack_value == flow.snd_una) {
    stats_.dup_ack_count++;
    flow.dup_ack_streak++;
    if (flow.dup_ack_streak == 3 && flow.outstanding->packet.size() > 0) {
      tx_packets_.push_back(flow.outstanding->packet);
      stats_.tx_packets_queued++;
      stats_.retransmit_count++;
      stats_.fast_retransmit_count++;
      flow.retransmit_count++;
      flow.outstanding->deadline_ns = DefaultNowNs() + NsFromMs(flow.outstanding->rto_ms);
      flow.rto_deadline_ns = flow.outstanding->deadline_ns;
    }
    return;
  }
  flow.dup_ack_streak = 0;
  const uint32_t covered = flow.outstanding->payload_len == 0 ? 1U : flow.outstanding->payload_len;
  const uint32_t outstanding_end = AdvanceSeq(flow.outstanding->seq, covered);
  if (ack_value > flow.snd_nxt) {
    stats_.unexpected_ack_count++;
    stats_.unexpected_rx++;
    return;
  }
  if (ack_value <= flow.outstanding->seq) {
    stats_.unexpected_ack_count++;
    stats_.unexpected_rx++;
    return;
  }
  if (ack_value < outstanding_end && flow.outstanding->payload_len > 1U) {
    const uint32_t newly_acked = ack_value - flow.outstanding->seq;
    if (newly_acked == 0 || newly_acked >= flow.outstanding->payload_len) {
      stats_.unexpected_ack_count++;
      stats_.unexpected_rx++;
      return;
    }
    auto payload = ExtractIpv4TcpPayload(flow.outstanding->packet.data(), flow.outstanding->packet.size());
    if (payload.size() != flow.outstanding->payload_len) {
      stats_.unexpected_ack_count++;
      stats_.unexpected_rx++;
      return;
    }
    const uint8_t* unacked_payload = payload.data() + newly_acked;
    const uint32_t unacked_len = flow.outstanding->payload_len - newly_acked;
    flow.outstanding->packet =
        BuildPacket(flow, ack_value, flow.rcv_nxt, static_cast<uint8_t>(kTcpFlagAck | kTcpFlagPsh), unacked_payload, unacked_len);
    flow.outstanding->seq = ack_value;
    flow.outstanding->payload_len = unacked_len;
    flow.outstanding->deadline_ns = DefaultNowNs() + NsFromMs(flow.outstanding->rto_ms);
    flow.rto_deadline_ns = flow.outstanding->deadline_ns;
    flow.snd_una = ack_value;
    flow.retransmit_count = 0;
    stats_.partial_ack_count++;
    return;
  }
  flow.snd_una = ack_value;
  flow.outstanding.reset();
  flow.rto_deadline_ns = 0;
  flow.retransmit_count = 0;
}

void TcpDataplaneCore::CloseTimedOutFlow(FlowEntry& flow, TcpDpState terminal_state, const char* event) {
  SetFlowState(flow, terminal_state);
  flow.outstanding.reset();
  flow.rto_deadline_ns = 0;
  stats_.timeout_close_count++;
  if (event != nullptr) {
    if (std::strcmp(event, "connect_timeout") == 0) {
      stats_.connect_timeout_count++;
    } else if (std::strcmp(event, "idle_timeout") == 0) {
      stats_.idle_timeout_count++;
    } else if (std::strcmp(event, "retransmit_exhausted") == 0) {
      stats_.retransmit_exhausted_count++;
    }
  }
  PushCompletion(flow.flow_id, flow.state, false, event);
}

}  // namespace ddos_samurai::tcpdp
