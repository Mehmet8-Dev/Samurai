#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddos_samurai::tcpdp {

enum class TcpDpState : uint8_t {
  kClosed = 0,
  kSynSent = 1,
  kSynAckRcvd = 2,
  kEstablished = 3,
  kFinWait = 4,
  kTimeWait = 5,
  kRstSeen = 6,
};

struct TcpDpConfig {
  std::string mode = "off";
  std::string backend = "af_xdp";
  uint32_t initial_rto_ms = 250;
  uint32_t max_retransmits = 5;
  uint32_t connect_timeout_ms = 3000;
  uint32_t idle_timeout_ms = 30000;
  uint16_t local_window = 64240;
  uint16_t default_mss = 1460;
  uint8_t default_ttl = 64;
};

struct TcpDpFlowSnapshot {
  uint64_t flow_id = 0;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t iss = 0;
  uint32_t snd_una = 0;
  uint32_t snd_nxt = 0;
  uint32_t rcv_nxt = 0;
  uint16_t peer_window = 0;
  uint16_t local_window = 0;
  uint16_t mss = 0;
  uint8_t ttl = 0;
  uint8_t state = 0;
  uint32_t retransmit_count = 0;
  uint64_t rto_deadline_ns = 0;
  uint64_t last_activity_ns = 0;
  bool found = false;
};

struct TcpDpStatsSnapshot {
  uint64_t flows_active = 0;
  uint64_t connect_attempts = 0;
  uint64_t connect_established = 0;
  uint64_t retransmit_count = 0;
  uint64_t timeout_close_count = 0;
  uint64_t connect_timeout_count = 0;
  uint64_t idle_timeout_count = 0;
  uint64_t retransmit_exhausted_count = 0;
  uint64_t rx_ack_count = 0;
  uint64_t dup_ack_count = 0;
  uint64_t partial_ack_count = 0;
  uint64_t fast_retransmit_count = 0;
  uint64_t unexpected_ack_count = 0;
  uint64_t tx_data_bytes = 0;
  uint64_t rx_data_bytes = 0;
  uint64_t tx_packets_queued = 0;
  uint64_t tx_packets_drained = 0;
  uint64_t tx_packets_sent = 0;
  uint64_t poll_calls = 0;
  uint64_t rx_frames = 0;
  uint64_t unexpected_rx = 0;
  uint64_t out_of_order_rx_count = 0;
  uint64_t peer_rst_count = 0;
  uint64_t peer_fin_count = 0;
};

struct TcpDpCompletion {
  uint64_t flow_id = 0;
  uint8_t state = 0;
  uint8_t success = 0;
  const char* event = nullptr;
};

struct TcpDpRxPayload {
  uint64_t flow_id = 0;
  std::vector<uint8_t> payload{};
};

class TcpDataplaneCore {
 public:
  TcpDataplaneCore();

  bool Configure(const TcpDpConfig& config);
  uint32_t IngestTxPackets(const uint8_t* packets, size_t packet_size, size_t count);
  uint64_t EnqueueConnect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
  uint32_t EnqueueSend(uint64_t flow_id, const uint8_t* payload, size_t payload_len);
  uint32_t IngestRxFrame(const uint8_t* frame, size_t frame_len);
  uint32_t Poll(uint64_t now_ns, uint32_t budget);
  bool DrainTxPacketsConcatAlloc(
      uint32_t max_packets,
      uint8_t** out_buffer,
      size_t* out_total_len,
      uint32_t* out_count,
      size_t* out_packet_size,
      bool* out_uniform,
      bool require_uniform);
  bool PeekTxPacketsStrided(
      uint32_t max_packets,
      const uint8_t** out_base,
      uint32_t* out_count,
      size_t* out_packet_size,
      size_t* out_stride);
  uint32_t ConsumeTxPackets(uint32_t max_packets);
  std::vector<std::vector<uint8_t>> DrainTxPackets(uint32_t max_packets);
  std::vector<TcpDpCompletion> CollectCompletions();
  std::vector<TcpDpRxPayload> CollectRxPayloads();
  TcpDpStatsSnapshot SnapshotStats() const;
  TcpDpFlowSnapshot GetFlow(uint64_t flow_id) const;

 private:
  struct FlowKey {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    bool operator==(const FlowKey& other) const;
  };

  struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const;
  };

  struct OutstandingTx {
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint32_t payload_len = 0;
    uint32_t rto_ms = 0;
    uint64_t deadline_ns = 0;
    std::vector<uint8_t> packet;
  };

  struct FlowEntry {
    uint64_t flow_id = 0;
    FlowKey key;
    uint32_t iss = 0;
    uint32_t snd_una = 0;
    uint32_t snd_nxt = 0;
    uint32_t rcv_nxt = 0;
    uint16_t peer_window = 0;
    uint16_t local_window = 0;
    uint16_t mss = 0;
    uint8_t ttl = 0;
    TcpDpState state = TcpDpState::kClosed;
    uint32_t retransmit_count = 0;
    uint32_t dup_ack_streak = 0;
    uint64_t rto_deadline_ns = 0;
    uint64_t connect_deadline_ns = 0;
    uint64_t idle_deadline_ns = 0;
    uint32_t rto_timer_gen = 0;
    uint32_t connect_timer_gen = 0;
    uint32_t idle_timer_gen = 0;
    uint64_t last_activity_ns = 0;
    std::optional<OutstandingTx> outstanding;
  };

  enum class TimerKind : uint8_t {
    kRto = 1,
    kConnectTimeout = 2,
    kIdleTimeout = 3,
  };

  struct TimerEntry {
    uint64_t due_ns = 0;
    uint64_t flow_id = 0;
    TimerKind kind = TimerKind::kRto;
    uint32_t generation = 0;
  };

  struct TimerEntryMin {
    bool operator()(const TimerEntry& lhs, const TimerEntry& rhs) const {
      if (lhs.due_ns != rhs.due_ns) {
        return lhs.due_ns > rhs.due_ns;
      }
      if (lhs.flow_id != rhs.flow_id) {
        return lhs.flow_id > rhs.flow_id;
      }
      if (lhs.kind != rhs.kind) {
        return static_cast<uint8_t>(lhs.kind) > static_cast<uint8_t>(rhs.kind);
      }
      return lhs.generation > rhs.generation;
    }
  };


  static bool ParseIpv4TcpFrame(
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
      uint8_t* out_ttl);
  static uint64_t DefaultNowNs();
  static uint64_t NsFromMs(uint32_t ms);
  static uint32_t AdvanceSeq(uint32_t seq, uint32_t amount);
  static std::vector<uint8_t> ExtractIpv4TcpPayload(const uint8_t* pkt, size_t pkt_len);
  static constexpr size_t kFlowLockShards = 16;
  size_t FlowLockShardForFlowId(uint64_t flow_id) const;
  std::vector<uint8_t> BuildPacket(
      const FlowEntry& flow,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      size_t payload_len) const;
  bool EnqueueTxPacketBytes(const uint8_t* data, size_t len);
  void PushTimer(uint64_t flow_id, TimerKind kind, uint64_t due_ns, uint32_t generation);
  void ScheduleFlowTimers(FlowEntry& flow, uint64_t now_ns);
  void QueuePacket(FlowEntry& flow, std::vector<uint8_t>&& packet, uint32_t seq, uint32_t ack, uint32_t payload_len, bool arm_rto);
  void PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event);
  void HandleAck(FlowEntry& flow, uint32_t ack_value);
  void CloseTimedOutFlow(FlowEntry& flow, TcpDpState terminal_state, const char* event);
  bool IsCountedActive(TcpDpState state) const;
  void SetFlowState(FlowEntry& flow, TcpDpState next_state);

  mutable std::mutex state_mu_;
  mutable std::mutex tx_mu_;
  std::array<std::mutex, kFlowLockShards> flow_shard_mu_{};
  std::array<std::mutex, kFlowLockShards> timer_shard_mu_{};
  std::array<std::set<uint64_t>, kFlowLockShards> active_flow_ids_shard_{};
  std::array<std::priority_queue<TimerEntry, std::vector<TimerEntry>, TimerEntryMin>, kFlowLockShards> timer_heap_shard_{};
  uint32_t poll_rr_shard_ = 0;
  TcpDpConfig config_;
  uint64_t next_flow_id_ = 1;
  uint32_t next_ephemeral_port_ = 40000;
  uint32_t seq_seed_ = 0x10203040U;
  std::unordered_map<uint64_t, FlowEntry> flows_by_id_;
  std::unordered_map<FlowKey, uint64_t, FlowKeyHash> flow_index_;
  size_t tx_ring_slot_size_ = 2048;
  size_t tx_ring_capacity_ = 8192;
  std::vector<uint8_t> tx_ring_storage_;
  std::vector<uint16_t> tx_ring_lengths_;
  uint32_t tx_ring_head_ = 0;
  uint32_t tx_ring_tail_ = 0;
  uint32_t tx_ring_count_ = 0;
  std::deque<std::vector<uint8_t>> tx_packets_overflow_;
  std::deque<TcpDpCompletion> completions_;
  std::deque<TcpDpRxPayload> rx_payloads_;
  std::atomic<uint64_t> tx_packets_queued_{0};
  std::atomic<uint64_t> tx_packets_drained_{0};
  std::atomic<uint64_t> tx_packets_sent_{0};
  TcpDpStatsSnapshot stats_{};
};

}  // namespace ddos_samurai::tcpdp
