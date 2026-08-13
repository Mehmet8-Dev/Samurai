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
  std::lock_guard<std::mutex> sguard(state_mu_);
  std::lock_guard<std::mutex> qguard(tx_mu_);
  config_ = config;
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
    std::lock_guard<std::mutex> fguard(flow_shard_mu_[i]);
    flows_by_id_shard_[i].clear();
  }
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<std::mutex> iguard(flow_index_shard_mu_[i]);
    flow_index_shard_[i].clear();
  }
  for (size_t i = 0; i < kFlowLockShards; ++i) {
    std::lock_guard<std::mutex> tguard(timer_shard_mu_[i]);
    active_flow_ids_shard_[i].clear();
    timer_heap_shard_[i] = std::priority_queue<TimerEntry, std::vector<TimerEntry>, TimerEntryMin>();
  }
  tx_ring_storage_.assign(tx_ring_capacity_ * tx_ring_slot_size_, 0U);
  tx_ring_lengths_.assign(tx_ring_capacity_, 0U);
  tx_ring_head_ = 0;
  tx_ring_tail_ = 0;
  tx_ring_count_ = 0;
  tx_pin_active_ = false;
  tx_pin_head_ = 0;
  tx_pin_count_ = 0;
  tx_pin_packet_size_ = 0;
  tx_pin_stride_ = 0;
  tx_packets_overflow_.clear();
  completions_.clear();
  rx_payloads_.clear();
  stats_.Reset();
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
      std::lock_guard<std::mutex> iguard(flow_index_shard_mu_[index_shard]);
      auto idx = flow_index_shard_[index_shard].find(key);
      if (idx == flow_index_shard_[index_shard].end()) {
        FlowEntry created;
        {
          std::lock_guard<std::mutex> sguard(state_mu_);
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
        created.ttl = ttl > 0 ? ttl : config_.default_ttl;
        created.last_activity_ns = DefaultNowNs();
        const size_t flow_shard = FlowLockShardForFlowId(created.flow_id);
        {
          std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
          flows_by_id_shard_[flow_shard].emplace(created.flow_id, created);
        }
        flow_index_shard_[index_shard][key] = created.flow_id;
        flow_id = created.flow_id;
      } else {
        flow_id = idx->second;
      }
    }

    const size_t flow_shard = FlowLockShardForFlowId(flow_id);
    std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
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
      OutstandingTx out;
      out.seq = seq;
      out.ack = 0;
      out.payload_len = 0;
      out.flags = kTcpFlagSyn;
      out.rto_ms = config_.initial_rto_ms;
      out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
      out.payload_offset = 0;
      flow->outstanding = std::move(out);
      flow->rto_deadline_ns = flow->outstanding->deadline_ns;
      stats_.connect_attempts.fetch_add(1, std::memory_order_relaxed);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
      updated++;
      continue;
    }

    if ((flags & kTcpFlagAck) != 0 && payload_len == 0 && flow->state == TcpDpState::kSynAckRcvd) {
      SetFlowState(*flow, TcpDpState::kEstablished);
      flow->snd_una = ack;
      flow->snd_nxt = seq;
      flow->outstanding.reset();
      flow->rto_deadline_ns = 0;
      stats_.connect_established.fetch_add(1, std::memory_order_relaxed);
      ScheduleFlowTimers(*flow, flow->last_activity_ns);
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
      out.flags = static_cast<uint8_t>(flags & static_cast<uint8_t>(kTcpFlagFin | kTcpFlagPsh | kTcpFlagAck));
      out.rto_ms = config_.initial_rto_ms;
      out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
      out.payload_offset = 0;
      const uint8_t* ip = pkt + 14;
      const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
      const uint8_t* tcp = ip + ihl;
      const size_t data_off = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4U;
      const uint8_t* payload = tcp + data_off;
      out.payload.assign(payload, payload + payload_len);
      flow->outstanding = std::move(out);
      flow->rto_deadline_ns = flow->outstanding->deadline_ns;
      stats_.tx_data_bytes.fetch_add(static_cast<uint64_t>(payload_len), std::memory_order_relaxed);
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

uint64_t TcpDataplaneCore::EnqueueConnect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
  if (src_ip == 0 || dst_ip == 0 || dst_port == 0) {
    return 0;
  }
  uint64_t flow_id = 0;
  uint32_t flow_iss = 0;
  if (src_port == 0) {
    std::lock_guard<std::mutex> sguard(state_mu_);
    src_port = static_cast<uint16_t>(next_ephemeral_port_++);
  }
  {
    std::lock_guard<std::mutex> sguard(state_mu_);
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
  flow.ttl = config_.default_ttl;
  flow.state = TcpDpState::kSynSent;
  flow.last_activity_ns = now_ns;

  auto syn = BuildPacket(flow, flow.snd_nxt, 0, kTcpFlagSyn, nullptr, 0);
  flow.snd_nxt = AdvanceSeq(flow.snd_nxt, 1);
  QueuePacket(flow, std::move(syn), flow.iss, 0, kTcpFlagSyn, nullptr, 0, true);
  flow.rto_deadline_ns = flow.outstanding ? flow.outstanding->deadline_ns : 0;
  {
    const size_t shard = FlowLockShardForFlowId(flow_id);
    std::lock_guard<std::mutex> tguard(timer_shard_mu_[shard]);
    active_flow_ids_shard_[shard].insert(flow_id);
  }
  ScheduleFlowTimers(flow, now_ns);

  const size_t index_shard = FlowIndexShardForKey(flow.key);
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<std::mutex> iguard(flow_index_shard_mu_[index_shard]);
  std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
  flows_by_id_shard_[flow_shard][flow_id] = flow;
  flow_index_shard_[index_shard][flow.key] = flow_id;
  stats_.flows_active.fetch_add(1, std::memory_order_relaxed);
  stats_.connect_attempts.fetch_add(1, std::memory_order_relaxed);
  return flow_id;
}

uint32_t TcpDataplaneCore::EnqueueSend(uint64_t flow_id, const uint8_t* payload, size_t payload_len) {
  if (!payload || payload_len == 0 || payload_len > 65535U) {
    return 0;
  }
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    return 0;
  }
  FlowEntry* flow = &it->second;
  if (flow->state != TcpDpState::kEstablished || flow->outstanding.has_value()) {
    return 0;
  }
  auto pkt =
      BuildPacket(*flow, flow->snd_nxt, flow->rcv_nxt, static_cast<uint8_t>(kTcpFlagAck | kTcpFlagPsh), payload, payload_len);
  const uint32_t seq = flow->snd_nxt;
  flow->snd_nxt = AdvanceSeq(flow->snd_nxt, static_cast<uint32_t>(payload_len));
  flow->last_activity_ns = DefaultNowNs();
  QueuePacket(
      *flow,
      std::move(pkt),
      seq,
      flow->rcv_nxt,
      static_cast<uint8_t>(kTcpFlagAck | kTcpFlagPsh),
      payload,
      static_cast<uint32_t>(payload_len),
      true);
  flow->rto_deadline_ns = flow->outstanding ? flow->outstanding->deadline_ns : 0;
  ScheduleFlowTimers(*flow, flow->last_activity_ns);
  stats_.tx_data_bytes.fetch_add(static_cast<uint64_t>(payload_len), std::memory_order_relaxed);
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

  uint64_t flow_id = 0;
  stats_.rx_frames.fetch_add(1, std::memory_order_relaxed);
  const FlowKey key{dst_ip, src_ip, dst_port, src_port};
  const size_t index_shard = FlowIndexShardForKey(key);
  {
    std::lock_guard<std::mutex> iguard(flow_index_shard_mu_[index_shard]);
    auto idx = flow_index_shard_[index_shard].find(key);
    if (idx == flow_index_shard_[index_shard].end()) {
      stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return 0;
    }
    flow_id = idx->second;
  }

  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
  auto it = flows_by_id_shard_[flow_shard].find(flow_id);
  if (it == flows_by_id_shard_[flow_shard].end()) {
    stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
    return 0;
  }
  FlowEntry* flow = &it->second;

  flow->last_activity_ns = DefaultNowNs();
  const auto finish = [&](uint32_t rc) -> uint32_t {
    ScheduleFlowTimers(*flow, flow->last_activity_ns);
    return rc;
  };
  if (window > 0) {
    flow->peer_window = window;
  }

  if ((flags & kTcpFlagRst) != 0) {
    SetFlowState(*flow, TcpDpState::kRstSeen);
    flow->outstanding.reset();
    flow->rto_deadline_ns = 0;
    stats_.peer_rst_count.fetch_add(1, std::memory_order_relaxed);
    PushCompletion(flow->flow_id, flow->state, false, "peer_rst");
    return finish(1);
  }

  if ((flags & (kTcpFlagSyn | kTcpFlagAck)) == (kTcpFlagSyn | kTcpFlagAck) && flow->state == TcpDpState::kSynSent) {
    if (ack != flow->snd_nxt) {
      stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return finish(0);
    }
    flow->snd_una = ack;
    flow->rcv_nxt = seq + 1U;
    SetFlowState(*flow, TcpDpState::kSynAckRcvd);
    flow->outstanding.reset();
    flow->rto_deadline_ns = 0;
    auto ack_pkt = BuildPacket(*flow, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(*flow, std::move(ack_pkt), flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, false);
    SetFlowState(*flow, TcpDpState::kEstablished);
    stats_.connect_established.fetch_add(1, std::memory_order_relaxed);
    PushCompletion(flow->flow_id, flow->state, true, "connect_established");
    return finish(1);
  }

  if ((flags & kTcpFlagAck) != 0) {
    HandleAck(*flow, ack);
    stats_.rx_ack_count.fetch_add(1, std::memory_order_relaxed);
  }

  if (payload_len > 0) {
    if (flow->rcv_nxt != 0 && seq != flow->rcv_nxt) {
      stats_.out_of_order_rx_count.fetch_add(1, std::memory_order_relaxed);
      stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      auto dup_ack_pkt = BuildPacket(*flow, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0);
      QueuePacket(*flow, std::move(dup_ack_pkt), flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, false);
      return finish(1);
    }
    flow->rcv_nxt = AdvanceSeq(seq, payload_len);
    stats_.rx_data_bytes.fetch_add(static_cast<uint64_t>(payload_len), std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> qguard(tx_mu_);
      rx_payloads_.push_back(TcpDpRxPayload{flow->flow_id, ExtractIpv4TcpPayload(frame, frame_len)});
    }
    auto ack_pkt = BuildPacket(*flow, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(*flow, std::move(ack_pkt), flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, false);
  }

  if ((flags & kTcpFlagFin) != 0) {
    flow->rcv_nxt = AdvanceSeq(flow->rcv_nxt, 1U);
    auto ack_pkt = BuildPacket(*flow, flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0);
    QueuePacket(*flow, std::move(ack_pkt), flow->snd_nxt, flow->rcv_nxt, kTcpFlagAck, nullptr, 0, false);
    SetFlowState(*flow, TcpDpState::kTimeWait);
    stats_.peer_fin_count.fetch_add(1, std::memory_order_relaxed);
    PushCompletion(flow->flow_id, flow->state, true, "peer_fin");
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
  stats_.poll_calls.fetch_add(1, std::memory_order_relaxed);
  uint32_t actions = 0;
  while (actions < budget) {
    TimerEntry entry{};
    size_t selected_shard = kFlowLockShards;
    bool have_entry = false;
    {
      bool scanned_any = false;
      for (size_t probe = 0; probe < kFlowLockShards; ++probe) {
        const size_t shard = static_cast<size_t>((poll_rr_shard_ + probe) % static_cast<uint32_t>(kFlowLockShards));
        std::lock_guard<std::mutex> tguard(timer_shard_mu_[shard]);
        if (timer_heap_shard_[shard].empty()) {
          continue;
        }
        scanned_any = true;
        const TimerEntry top = timer_heap_shard_[shard].top();
        if (top.due_ns == 0 || top.due_ns > now_ns) {
          continue;
        }
        timer_heap_shard_[shard].pop();
        if (active_flow_ids_shard_[shard].find(top.flow_id) == active_flow_ids_shard_[shard].end()) {
          continue;
        }
        entry = top;
        selected_shard = shard;
        have_entry = true;
        poll_rr_shard_ = static_cast<uint32_t>((shard + 1) % kFlowLockShards);
        break;
      }
      if (!scanned_any || !have_entry) {
        break;
      }
    }
    if (selected_shard >= kFlowLockShards) {
      break;
    }

    std::lock_guard<std::mutex> fguard(flow_shard_mu_[selected_shard]);
    auto it = flows_by_id_shard_[selected_shard].find(entry.flow_id);
    if (it == flows_by_id_shard_[selected_shard].end()) {
      continue;
    }
    FlowEntry* flow = &it->second;
    switch (entry.kind) {
      case TimerKind::kRto: {
        if (entry.generation != flow->rto_timer_gen || !flow->outstanding.has_value() || flow->rto_deadline_ns == 0 ||
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
        stats_.retransmit_count.fetch_add(1, std::memory_order_relaxed);
        flow->outstanding->rto_ms = std::min(flow->outstanding->rto_ms * 2U, config_.connect_timeout_ms);
        flow->outstanding->deadline_ns = now_ns + NsFromMs(flow->outstanding->rto_ms);
        flow->rto_deadline_ns = flow->outstanding->deadline_ns;
        auto pkt = BuildOutstandingPacket(*flow, *flow->outstanding);
        (void)EnqueueTxPacketBytes(pkt.data(), pkt.size());
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
        if (flow->state == TcpDpState::kSynSent && flow->outstanding.has_value() && now_ns >= flow->connect_deadline_ns) {
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
        if (flow->state == TcpDpState::kEstablished && !flow->outstanding.has_value() && now_ns >= flow->idle_deadline_ns) {
          CloseTimedOutFlow(*flow, TcpDpState::kTimeWait, "idle_timeout");
          ScheduleFlowTimers(*flow, now_ns);
          actions++;
        }
        break;
      }
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

  std::lock_guard<std::mutex> guard(tx_mu_);
  if (tx_pin_active_) {
    if (tx_pin_count_ == 0) {
      tx_pin_active_ = false;
      tx_pin_head_ = 0;
      tx_pin_packet_size_ = 0;
      tx_pin_stride_ = 0;
      return true;
    }
    const size_t base = static_cast<size_t>(tx_pin_head_) * tx_ring_slot_size_;
    *out_base = tx_ring_storage_.data() + base;
    *out_count = tx_pin_count_;
    *out_packet_size = tx_pin_packet_size_;
    *out_stride = tx_pin_stride_;
    return true;
  }
  if (tx_ring_count_ == 0 || !tx_packets_overflow_.empty()) {
    return true;
  }

  const uint32_t linear_available =
      std::min<uint32_t>(tx_ring_count_, static_cast<uint32_t>(tx_ring_capacity_) - tx_ring_head_);
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

  const size_t first_len = static_cast<size_t>(tx_ring_lengths_[tx_ring_head_]);
  if (first_len == 0) {
    return true;
  }

  uint32_t uniform_count = 1;
  for (; uniform_count < take; ++uniform_count) {
    const uint32_t idx = tx_ring_head_ + uniform_count;
    if (static_cast<size_t>(tx_ring_lengths_[idx]) != first_len) {
      break;
    }
  }
  if (uniform_count == 0) {
    return true;
  }

  const size_t base = static_cast<size_t>(tx_ring_head_) * tx_ring_slot_size_;
  *out_base = tx_ring_storage_.data() + base;
  *out_count = uniform_count;
  *out_packet_size = first_len;
  *out_stride = tx_ring_slot_size_;
  tx_pin_active_ = true;
  tx_pin_head_ = tx_ring_head_;
  tx_pin_count_ = uniform_count;
  tx_pin_packet_size_ = first_len;
  tx_pin_stride_ = tx_ring_slot_size_;
  return true;
}

uint32_t TcpDataplaneCore::ConsumeTxPackets(uint32_t max_packets) {
  std::lock_guard<std::mutex> guard(tx_mu_);
  if (max_packets == 0) {
    return 0;
  }

  if (tx_pin_active_) {
    if (tx_pin_count_ == 0) {
      tx_pin_active_ = false;
      tx_pin_head_ = 0;
      tx_pin_packet_size_ = 0;
      tx_pin_stride_ = 0;
      return 0;
    }
    if (max_packets > tx_pin_count_) {
      max_packets = tx_pin_count_;
    }
    for (uint32_t i = 0; i < max_packets; ++i) {
      tx_ring_lengths_[tx_ring_head_] = 0;
      tx_ring_head_ = (tx_ring_head_ + 1U) % static_cast<uint32_t>(tx_ring_capacity_);
    }
    tx_ring_count_ -= max_packets;
    tx_pin_count_ -= max_packets;
    if (tx_pin_count_ == 0) {
      tx_pin_active_ = false;
      tx_pin_head_ = 0;
      tx_pin_packet_size_ = 0;
      tx_pin_stride_ = 0;
    } else {
      tx_pin_head_ = tx_ring_head_;
    }
    tx_packets_drained_.fetch_add(max_packets, std::memory_order_relaxed);
    tx_packets_sent_.fetch_add(max_packets, std::memory_order_relaxed);
    tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
    return max_packets;
  }

  const uint32_t total_available =
      tx_ring_count_ + static_cast<uint32_t>(tx_packets_overflow_.size());
  if (max_packets > total_available) {
    max_packets = total_available;
  }
  if (max_packets == 0) {
    return 0;
  }

  const uint32_t take_ring = std::min<uint32_t>(max_packets, tx_ring_count_);
  for (uint32_t i = 0; i < take_ring; ++i) {
    tx_ring_lengths_[tx_ring_head_] = 0;
    tx_ring_head_ = (tx_ring_head_ + 1U) % static_cast<uint32_t>(tx_ring_capacity_);
  }
  tx_ring_count_ -= take_ring;

  const uint32_t take_overflow = max_packets - take_ring;
  for (uint32_t i = 0; i < take_overflow; ++i) {
    tx_packets_overflow_.pop_front();
  }

  tx_packets_drained_.fetch_add(max_packets, std::memory_order_relaxed);
  tx_packets_sent_.fetch_add(max_packets, std::memory_order_relaxed);
  tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
  return max_packets;
}

std::vector<TcpDpCompletion> TcpDataplaneCore::CollectCompletions() {
  std::lock_guard<std::mutex> guard(tx_mu_);
  std::vector<TcpDpCompletion> out;
  out.reserve(completions_.size());
  while (!completions_.empty()) {
    out.push_back(completions_.front());
    completions_.pop_front();
  }
  return out;
}

std::vector<TcpDpRxPayload> TcpDataplaneCore::CollectRxPayloads() {
  std::lock_guard<std::mutex> guard(tx_mu_);
  std::vector<TcpDpRxPayload> out;
  out.reserve(rx_payloads_.size());
  while (!rx_payloads_.empty()) {
    out.push_back(std::move(rx_payloads_.front()));
    rx_payloads_.pop_front();
  }
  return out;
}

TcpDpStatsSnapshot TcpDataplaneCore::SnapshotStats() const {
  TcpDpStatsSnapshot out;
  out.flows_active = stats_.flows_active.load(std::memory_order_relaxed);
  out.connect_attempts = stats_.connect_attempts.load(std::memory_order_relaxed);
  out.connect_established = stats_.connect_established.load(std::memory_order_relaxed);
  out.retransmit_count = stats_.retransmit_count.load(std::memory_order_relaxed);
  out.timeout_close_count = stats_.timeout_close_count.load(std::memory_order_relaxed);
  out.connect_timeout_count = stats_.connect_timeout_count.load(std::memory_order_relaxed);
  out.idle_timeout_count = stats_.idle_timeout_count.load(std::memory_order_relaxed);
  out.retransmit_exhausted_count = stats_.retransmit_exhausted_count.load(std::memory_order_relaxed);
  out.rx_ack_count = stats_.rx_ack_count.load(std::memory_order_relaxed);
  out.dup_ack_count = stats_.dup_ack_count.load(std::memory_order_relaxed);
  out.partial_ack_count = stats_.partial_ack_count.load(std::memory_order_relaxed);
  out.fast_retransmit_count = stats_.fast_retransmit_count.load(std::memory_order_relaxed);
  out.unexpected_ack_count = stats_.unexpected_ack_count.load(std::memory_order_relaxed);
  out.tx_data_bytes = stats_.tx_data_bytes.load(std::memory_order_relaxed);
  out.rx_data_bytes = stats_.rx_data_bytes.load(std::memory_order_relaxed);
  out.poll_calls = stats_.poll_calls.load(std::memory_order_relaxed);
  out.rx_frames = stats_.rx_frames.load(std::memory_order_relaxed);
  out.unexpected_rx = stats_.unexpected_rx.load(std::memory_order_relaxed);
  out.out_of_order_rx_count = stats_.out_of_order_rx_count.load(std::memory_order_relaxed);
  out.peer_rst_count = stats_.peer_rst_count.load(std::memory_order_relaxed);
  out.peer_fin_count = stats_.peer_fin_count.load(std::memory_order_relaxed);
  out.tx_packets_queued = tx_packets_queued_.load(std::memory_order_relaxed);
  out.tx_packets_drained = tx_packets_drained_.load(std::memory_order_relaxed);
  out.tx_packets_sent = tx_packets_sent_.load(std::memory_order_relaxed);
  return out;
}

TcpDpFlowSnapshot TcpDataplaneCore::GetFlow(uint64_t flow_id) const {
  TcpDpFlowSnapshot out;
  const size_t flow_shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<std::mutex> fguard(flow_shard_mu_[flow_shard]);
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
  // Lockless read path: avoids mutex contention by attempting lock-free lookup
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

bool TcpDataplaneCore::EnqueueTxPacketBytes(const uint8_t* data, size_t len) {
  if (!data || len == 0) {
    return false;
  }
  std::vector<uint8_t> pkt_prebuilt;
  if (len > tx_ring_slot_size_) {
    pkt_prebuilt.assign(data, data + len);
  }
  std::lock_guard<std::mutex> guard(tx_mu_);
  if (len <= tx_ring_slot_size_ && tx_ring_count_ < static_cast<uint32_t>(tx_ring_capacity_)) {
    const uint32_t idx = tx_ring_tail_;
    const size_t base = static_cast<size_t>(idx) * tx_ring_slot_size_;
    std::memcpy(tx_ring_storage_.data() + base, data, len);
    tx_ring_lengths_[idx] = static_cast<uint16_t>(len);
    tx_ring_tail_ = (tx_ring_tail_ + 1U) % static_cast<uint32_t>(tx_ring_capacity_);
    tx_ring_count_++;
    tx_packets_queued_.fetch_add(1, std::memory_order_relaxed);
    tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
    return true;
  }
  std::vector<uint8_t> pkt = std::move(pkt_prebuilt);
  if (pkt.empty()) {
    pkt.assign(data, data + len);
  }
  if (tx_packets_overflow_.size() >= tx_overflow_capacity_) {
    tx_packets_overflow_.pop_front();
  }
  tx_packets_overflow_.push_back(std::move(pkt));
  tx_packets_queued_.fetch_add(1, std::memory_order_relaxed);
  tx_queue_epoch_.fetch_add(1, std::memory_order_relaxed);
  return true;
}

void TcpDataplaneCore::PushTimer(uint64_t flow_id, TimerKind kind, uint64_t due_ns, uint32_t generation) {
  if (flow_id == 0 || due_ns == 0 || generation == 0) {
    return;
  }
  const size_t shard = FlowLockShardForFlowId(flow_id);
  std::lock_guard<std::mutex> tguard(timer_shard_mu_[shard]);
  timer_heap_shard_[shard].push(TimerEntry{due_ns, flow_id, kind, generation});
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

  if (flow.outstanding.has_value() && flow.outstanding->deadline_ns > 0) {
    flow.rto_deadline_ns = flow.outstanding->deadline_ns;
    flow.rto_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kRto, flow.rto_deadline_ns, flow.rto_timer_gen);
  } else {
    flow.rto_deadline_ns = 0;
    flow.rto_timer_gen++;
  }

  if (flow.state == TcpDpState::kSynSent && flow.outstanding.has_value()) {
    flow.connect_deadline_ns = flow.last_activity_ns + NsFromMs(config_.connect_timeout_ms);
    flow.connect_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kConnectTimeout, flow.connect_deadline_ns, flow.connect_timer_gen);
  } else {
    flow.connect_deadline_ns = 0;
    flow.connect_timer_gen++;
  }

  if (flow.state == TcpDpState::kEstablished && !flow.outstanding.has_value()) {
    flow.idle_deadline_ns = flow.last_activity_ns + NsFromMs(config_.idle_timeout_ms);
    flow.idle_timer_gen++;
    PushTimer(flow.flow_id, TimerKind::kIdleTimeout, flow.idle_deadline_ns, flow.idle_timer_gen);
  } else {
    flow.idle_deadline_ns = 0;
    flow.idle_timer_gen++;
  }
}

void TcpDataplaneCore::QueuePacket(
    FlowEntry& flow,
    std::vector<uint8_t>&& packet,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t* payload,
    uint32_t payload_len,
    bool arm_rto) {
  if (!packet.empty()) {
    (void)EnqueueTxPacketBytes(packet.data(), packet.size());
  }
  if (!arm_rto) {
    return;
  }
  OutstandingTx out;
  out.seq = seq;
  out.ack = ack;
  out.flags = flags;
  out.payload_len = payload_len;
  out.rto_ms = config_.initial_rto_ms;
  out.deadline_ns = DefaultNowNs() + NsFromMs(out.rto_ms);
  out.payload_offset = 0;
  if (payload != nullptr && payload_len > 0) {
    out.payload.assign(payload, payload + payload_len);
  }
  flow.outstanding = std::move(out);
  flow.rto_deadline_ns = flow.outstanding ? flow.outstanding->deadline_ns : 0;
}

std::vector<uint8_t> TcpDataplaneCore::BuildOutstandingPacket(const FlowEntry& flow, const OutstandingTx& out) const {
  const uint8_t* payload_ptr = nullptr;
  size_t payload_size = 0;
  if (out.payload_len > 0 &&
      out.payload.size() >= static_cast<size_t>(out.payload_offset) + static_cast<size_t>(out.payload_len)) {
    payload_ptr = out.payload.data() + out.payload_offset;
    payload_size = static_cast<size_t>(out.payload_len);
  }
  return BuildPacket(flow, out.seq, out.ack, out.flags, payload_ptr, payload_size);
}

void TcpDataplaneCore::PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event) {
  std::lock_guard<std::mutex> guard(tx_mu_);
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
  {
    const size_t shard = FlowLockShardForFlowId(flow.flow_id);
    std::lock_guard<std::mutex> tguard(timer_shard_mu_[shard]);
    if (now_active) {
      active_flow_ids_shard_[shard].insert(flow.flow_id);
    } else {
      active_flow_ids_shard_[shard].erase(flow.flow_id);
    }
  }
  if (was_active == now_active) {
    return;
  }
  if (now_active) {
    stats_.flows_active.fetch_add(1, std::memory_order_relaxed);
  } else {
    SaturatingDecrement(stats_.flows_active);
  }
}

void TcpDataplaneCore::HandleAck(FlowEntry& flow, uint32_t ack_value) {
  if (!flow.outstanding.has_value()) {
    return;
  }
  if (ack_value == flow.snd_una) {
    stats_.dup_ack_count.fetch_add(1, std::memory_order_relaxed);
    flow.dup_ack_streak++;
    if (flow.dup_ack_streak == 3) {
      auto pkt = BuildOutstandingPacket(flow, *flow.outstanding);
      (void)EnqueueTxPacketBytes(pkt.data(), pkt.size());
      stats_.retransmit_count.fetch_add(1, std::memory_order_relaxed);
      stats_.fast_retransmit_count.fetch_add(1, std::memory_order_relaxed);
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
    stats_.unexpected_ack_count.fetch_add(1, std::memory_order_relaxed);
    stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (ack_value <= flow.outstanding->seq) {
    stats_.unexpected_ack_count.fetch_add(1, std::memory_order_relaxed);
    stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (ack_value < outstanding_end && flow.outstanding->payload_len > 1U) {
    const uint32_t newly_acked = ack_value - flow.outstanding->seq;
    if (newly_acked == 0 || newly_acked >= flow.outstanding->payload_len) {
      stats_.unexpected_ack_count.fetch_add(1, std::memory_order_relaxed);
      stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (flow.outstanding->payload.size() <
        static_cast<size_t>(flow.outstanding->payload_offset) + static_cast<size_t>(flow.outstanding->payload_len)) {
      stats_.unexpected_ack_count.fetch_add(1, std::memory_order_relaxed);
      stats_.unexpected_rx.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    const uint32_t unacked_len = flow.outstanding->payload_len - newly_acked;
    flow.outstanding->payload_offset += newly_acked;
    flow.outstanding->seq = ack_value;
    flow.outstanding->ack = flow.rcv_nxt;
    flow.outstanding->flags = static_cast<uint8_t>(kTcpFlagAck | kTcpFlagPsh);
    flow.outstanding->payload_len = unacked_len;
    flow.outstanding->deadline_ns = DefaultNowNs() + NsFromMs(flow.outstanding->rto_ms);
    flow.rto_deadline_ns = flow.outstanding->deadline_ns;
    flow.snd_una = ack_value;
    flow.retransmit_count = 0;
    stats_.partial_ack_count.fetch_add(1, std::memory_order_relaxed);
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
  stats_.timeout_close_count.fetch_add(1, std::memory_order_relaxed);
  if (event != nullptr) {
    if (std::strcmp(event, "connect_timeout") == 0) {
      stats_.connect_timeout_count.fetch_add(1, std::memory_order_relaxed);
    } else if (std::strcmp(event, "idle_timeout") == 0) {
      stats_.idle_timeout_count.fetch_add(1, std::memory_order_relaxed);
    } else if (std::strcmp(event, "retransmit_exhausted") == 0) {
      stats_.retransmit_exhausted_count.fetch_add(1, std::memory_order_relaxed);
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

}  // namespace ddos_samurai::tcpdp
