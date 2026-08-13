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
  uint16_t dpdk_port_id = 0;
  uint16_t dpdk_queue_id = 0;
  uint16_t dpdk_burst_size = 64;
};

struct TcpDpSackBlock {
  uint32_t left = 0;
  uint32_t right = 0;
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
  uint32_t peer_window = 0;
  uint16_t local_window = 0;
  uint8_t snd_wscale = 0;
  uint8_t rcv_wscale = 0;
  bool sack_permitted = false;
  uint32_t cwnd = 0;
  uint32_t ssthresh = 0;
  uint32_t srtt_ms = 0;
  bool zero_window_probing = false;
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
  uint64_t sack_blocks_rx_count = 0;
  uint64_t zero_window_probes_sent = 0;
  uint64_t congestion_window_reductions = 0;
  uint64_t native_tls_handshakes_completed = 0;
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
  bool PeekTxPacketsStrided(
      uint32_t max_packets,
      const uint8_t** out_base,
      uint32_t* out_count,
      size_t* out_packet_size,
      size_t* out_stride);
  uint32_t ConsumeTxPackets(uint32_t max_packets);
  uint32_t IngestDpdkRxBurst(void** mbufs, uint16_t count);
  uint32_t DrainDpdkTxBurst(void* mempool, void** out_mbufs, uint16_t max_burst);
  std::vector<TcpDpCompletion> CollectCompletions();
  std::vector<TcpDpRxPayload> CollectRxPayloads();
  TcpDpStatsSnapshot SnapshotStats() const;
  TcpDpFlowSnapshot GetFlow(uint64_t flow_id) const;
  TcpDpFlowSnapshot GetFlowLockless(uint64_t flow_id) const;

  // Native TLS handshake generator helper for user-space dataplane
  std::vector<uint8_t> BuildNativeTlsClientHello(const std::string& sni) const;
  bool ParseNativeTlsServerHello(const uint8_t* payload, size_t len) const;

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
    uint8_t flags = 0;
    uint32_t rto_ms = 0;
    uint64_t deadline_ns = 0;
    uint32_t payload_offset = 0;
    std::vector<uint8_t> payload;
  };

  struct FlowEntry {
    uint64_t flow_id = 0;
    FlowKey key;
    uint32_t iss = 0;
    uint32_t snd_una = 0;
    uint32_t snd_nxt = 0;
    uint32_t rcv_nxt = 0;
    uint32_t peer_window = 0;
    uint16_t local_window = 0;
    uint8_t snd_wscale = 7;
    uint8_t rcv_wscale = 0;
    bool sack_permitted = false;
    std::vector<TcpDpSackBlock> sack_blocks{};
    bool zero_window_probing = false;
    uint32_t zero_window_probe_count = 0;
    uint64_t zero_window_probe_deadline_ns = 0;
    uint32_t cwnd = 1460;
    uint32_t ssthresh = 65535;
    uint32_t srtt_ms = 100;
    uint32_t rttvar_ms = 50;
    bool in_fast_recovery = false;
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
    bool tls_native_active = false;
    uint8_t tls_state = 0;
    std::optional<OutstandingTx> outstanding;
  };

  enum class TimerKind : uint8_t {
    kRto = 1,
    kConnectTimeout = 2,
    kIdleTimeout = 3,
    kZeroWindowProbe = 4,
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

  struct TcpDpStatsCounters {
    std::atomic<uint64_t> flows_active{0};
    std::atomic<uint64_t> connect_attempts{0};
    std::atomic<uint64_t> connect_established{0};
    std::atomic<uint64_t> retransmit_count{0};
    std::atomic<uint64_t> timeout_close_count{0};
    std::atomic<uint64_t> connect_timeout_count{0};
    std::atomic<uint64_t> idle_timeout_count{0};
    std::atomic<uint64_t> retransmit_exhausted_count{0};
    std::atomic<uint64_t> rx_ack_count{0};
    std::atomic<uint64_t> dup_ack_count{0};
    std::atomic<uint64_t> partial_ack_count{0};
    std::atomic<uint64_t> fast_retransmit_count{0};
    std::atomic<uint64_t> unexpected_ack_count{0};
    std::atomic<uint64_t> tx_data_bytes{0};
    std::atomic<uint64_t> rx_data_bytes{0};
    std::atomic<uint64_t> poll_calls{0};
    std::atomic<uint64_t> rx_frames{0};
    std::atomic<uint64_t> unexpected_rx{0};
    std::atomic<uint64_t> out_of_order_rx_count{0};
    std::atomic<uint64_t> peer_rst_count{0};
    std::atomic<uint64_t> peer_fin_count{0};
    std::atomic<uint64_t> sack_blocks_rx_count{0};
    std::atomic<uint64_t> zero_window_probes_sent{0};
    std::atomic<uint64_t> congestion_window_reductions{0};
    std::atomic<uint64_t> native_tls_handshakes_completed{0};

    void Reset() {
      flows_active.store(0, std::memory_order_relaxed);
      connect_attempts.store(0, std::memory_order_relaxed);
      connect_established.store(0, std::memory_order_relaxed);
      retransmit_count.store(0, std::memory_order_relaxed);
      timeout_close_count.store(0, std::memory_order_relaxed);
      connect_timeout_count.store(0, std::memory_order_relaxed);
      idle_timeout_count.store(0, std::memory_order_relaxed);
      retransmit_exhausted_count.store(0, std::memory_order_relaxed);
      rx_ack_count.store(0, std::memory_order_relaxed);
      dup_ack_count.store(0, std::memory_order_relaxed);
      partial_ack_count.store(0, std::memory_order_relaxed);
      fast_retransmit_count.store(0, std::memory_order_relaxed);
      unexpected_ack_count.store(0, std::memory_order_relaxed);
      tx_data_bytes.store(0, std::memory_order_relaxed);
      rx_data_bytes.store(0, std::memory_order_relaxed);
      poll_calls.store(0, std::memory_order_relaxed);
      rx_frames.store(0, std::memory_order_relaxed);
      unexpected_rx.store(0, std::memory_order_relaxed);
      out_of_order_rx_count.store(0, std::memory_order_relaxed);
      peer_rst_count.store(0, std::memory_order_relaxed);
      peer_fin_count.store(0, std::memory_order_relaxed);
      sack_blocks_rx_count.store(0, std::memory_order_relaxed);
      zero_window_probes_sent.store(0, std::memory_order_relaxed);
      congestion_window_reductions.store(0, std::memory_order_relaxed);
      native_tls_handshakes_completed.store(0, std::memory_order_relaxed);
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
  static constexpr size_t kFlowLockShards = 64;
  size_t FlowLockShardForFlowId(uint64_t flow_id) const;
  size_t FlowIndexShardForKey(const FlowKey& key) const;
  std::vector<uint8_t> BuildPacket(
      const FlowEntry& flow,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      size_t payload_len) const;
  std::vector<uint8_t> BuildOutstandingPacket(const FlowEntry& flow, const OutstandingTx& out) const;
  bool EnqueueTxPacketBytes(const uint8_t* data, size_t len);
  void PushTimer(uint64_t flow_id, TimerKind kind, uint64_t due_ns, uint32_t generation);
  void ScheduleFlowTimers(FlowEntry& flow, uint64_t now_ns);
  void QueuePacket(
      FlowEntry& flow,
      std::vector<uint8_t>&& packet,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      uint32_t payload_len,
      bool arm_rto);
  void PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event);
  void HandleAck(FlowEntry& flow, uint32_t ack_value);
  void CloseTimedOutFlow(FlowEntry& flow, TcpDpState terminal_state, const char* event);
  bool IsCountedActive(TcpDpState state) const;
  void SetFlowState(FlowEntry& flow, TcpDpState next_state);

  mutable std::mutex state_mu_;
  mutable std::mutex tx_mu_;
  mutable std::array<std::mutex, kFlowLockShards> flow_shard_mu_{};
  mutable std::array<std::mutex, kFlowLockShards> flow_index_shard_mu_{};
  mutable std::array<std::mutex, kFlowLockShards> timer_shard_mu_{};
  std::array<std::set<uint64_t>, kFlowLockShards> active_flow_ids_shard_{};
  std::array<std::priority_queue<TimerEntry, std::vector<TimerEntry>, TimerEntryMin>, kFlowLockShards> timer_heap_shard_{};
  uint32_t poll_rr_shard_ = 0;
  TcpDpConfig config_;
  uint64_t next_flow_id_ = 1;
  uint32_t next_ephemeral_port_ = 40000;
  uint32_t seq_seed_ = 0x10203040U;
  std::array<std::unordered_map<uint64_t, FlowEntry>, kFlowLockShards> flows_by_id_shard_{};
  std::array<std::unordered_map<FlowKey, uint64_t, FlowKeyHash>, kFlowLockShards> flow_index_shard_{};
  size_t tx_ring_slot_size_ = 2048;
  size_t tx_ring_capacity_ = 8192;
  size_t tx_overflow_capacity_ = 8192;
  std::vector<uint8_t> tx_ring_storage_;
  std::vector<uint16_t> tx_ring_lengths_;
  uint32_t tx_ring_head_ = 0;
  uint32_t tx_ring_tail_ = 0;
  uint32_t tx_ring_count_ = 0;
  bool tx_pin_active_ = false;
  uint32_t tx_pin_head_ = 0;
  uint32_t tx_pin_count_ = 0;
  size_t tx_pin_packet_size_ = 0;
  size_t tx_pin_stride_ = 0;
  std::deque<std::vector<uint8_t>> tx_packets_overflow_;
  std::deque<TcpDpCompletion> completions_;
  std::deque<TcpDpRxPayload> rx_payloads_;
  std::atomic<uint64_t> tx_packets_queued_{0};
  std::atomic<uint64_t> tx_packets_drained_{0};
  std::atomic<uint64_t> tx_packets_sent_{0};
  std::atomic<uint64_t> tx_queue_epoch_{0};
  mutable TcpDpStatsCounters stats_{};
};

}  // namespace ddos_samurai::tcpdp
