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
#include "spinlock.hpp"
#include <unordered_map>
#include <ankerl/unordered_dense.h>
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
  // TCP maturity toggles. RFC6675 SACK loss recovery is a strict improvement over
  // the NewReno fallback and defaults ON (only active on SACK-negotiated flows).
  // delayed-ACK / Nagle / timestamps change the default aggressive load-gen
  // behaviour and default OFF; each is also overridable via env in Configure()
  // (SAMURAI_TCPDP_DELAYED_ACK / _NAGLE / _TIMESTAMPS / _RFC6675).
  bool enable_rfc6675_recovery = true;
  bool enable_delayed_ack = false;
  bool enable_nagle = false;
  bool enable_timestamps = false;
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
  // Set the base for auto-assigned ephemeral source ports (used when
  // EnqueueConnect is called with src_port == 0). Shared-nothing per-shard
  // cores set disjoint bases so each shard owns a distinct src-port range,
  // enabling deterministic per-shard RX demux on the wire.
  void SetEphemeralPortBase(uint16_t base);
  // Set the stride for auto-assigned ephemeral source ports (default 1). With a
  // stride s and base b every auto-assigned port satisfies (port - b) % s == 0, so
  // choosing b ≡ shard (mod s) keeps a shard's ports in one residue class. That
  // lets a single mask-based rte_flow rule (dst-port & (s-1) == shard) steer a
  // flow's return traffic to the owning shard's DPDK queue (per-core demux).
  // Ports wrap back to the base within [base, 65536) to preserve the residue.
  void SetEphemeralPortStride(uint16_t stride);
  // Set the base for auto-assigned flow ids. Shared-nothing per-shard cores set
  // disjoint bases so flow ids stay globally unique across shards, keeping any
  // flow_id-keyed lookup (e.g. the L7 flow-binding registry) collision-free.
  void SetFlowIdBase(uint64_t base);
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
    uint32_t xmit_count = 0;
    uint64_t sent_ns = 0;   // first-transmission time; RTT sampled only when xmit_count==1 (Karn)
    bool sacked = false;    // covered by a received SACK block -> skip on selective retransmit
    bool retransmitted = false;  // RFC6675: this segment has been resent (counts toward pipe)
    // Owned payload bytes for this in-flight segment (empty for pure SYN/FIN/ACK).
    // Held per-segment so a retransmit is a straight rebuild with no shared cursor.
    std::vector<uint8_t> data;
    // TCP options to replay on retransmit (e.g. the SYN's MSS/SACK-perm/WScale).
    // Empty for ordinary data/ACK segments; timestamp options are regenerated fresh
    // per (re)transmission in the build path so they are not stored here.
    std::vector<uint8_t> opts;
  };

  // Parsed TCP option fields we care about (from SYN-ACK negotiation and per-ACK SACK).
  struct TcpOptionInfo {
    bool has_mss = false;
    uint16_t mss = 0;
    bool sack_permitted = false;
    bool has_wscale = false;
    uint8_t wscale = 0;
    uint32_t sack_left[4] = {0, 0, 0, 0};
    uint32_t sack_right[4] = {0, 0, 0, 0};
    int sack_block_count = 0;
    bool has_ts = false;      // RFC 7323 TCP timestamp option present
    uint32_t ts_val = 0;      // sender's timestamp
    uint32_t ts_ecr = 0;      // echoed timestamp
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
    bool rtt_sampled = false;  // false until the first valid RTT measurement (RFC 6298 init)
    bool in_fast_recovery = false;      // NewReno fallback recovery (non-SACK flows)
    // RFC 6675 SACK loss recovery scoreboard state (SACK-negotiated flows only).
    bool sack_recovery = false;         // in an RFC6675 recovery episode
    uint32_t recovery_point = 0;        // snd_nxt captured at recovery entry; exit when acked
    uint32_t high_rxt = 0;              // highest seq (re)transmitted during recovery
    // RFC 7323 timestamps / PAWS (only when negotiated on both sides).
    bool ts_ok = false;                 // TS negotiated (we offered + peer echoed on SYN-ACK)
    uint32_t ts_recent = 0;             // most recent in-order peer TSval (echoed back)
    // Delayed-ACK state (opt-in). pending_ack_bytes accrues un-ACKed in-order data;
    // an ACK is forced every 2nd full-MSS segment or when the delACK timer fires.
    uint32_t pending_ack_segs = 0;
    uint64_t delack_deadline_ns = 0;
    uint32_t delack_timer_gen = 0;
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
    uint32_t cur_rto_ms = 0;  // current retransmit timeout (0 => config_.initial_rto_ms); doubles on RTO, resets on new ACK.
    // Sliding-window sender state (replaces the legacy single-outstanding model).
    // sndbuf holds application bytes accepted by EnqueueSend but not yet placed on
    // the wire; PumpSend drains it into MSS segments as the effective window opens.
    // unacked holds sent-but-unacknowledged segments in ascending seq order
    // (front == snd_una edge); ACKs pop/trim the front, RTO retransmits it.
    std::vector<uint8_t> sndbuf;
    size_t sndbuf_head = 0;  // consumed offset into sndbuf (compacted lazily)
    std::deque<OutstandingTx> unacked;
    // Free list of segment payload buffers recycled between emit and cumulative
    // ACK. In steady state a flow emits N segments and retires N, so reusing the
    // backing storage here turns the per-segment malloc/free churn into zero
    // heap traffic. Capacity is bounded by kSegBufPoolCap.
    std::vector<std::vector<uint8_t>> seg_buf_pool;
  };

  enum class TimerKind : uint8_t {
    kRto = 1,
    kConnectTimeout = 2,
    kIdleTimeout = 3,
    kZeroWindowProbe = 4,
    kDelayedAck = 5,
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
  size_t BuildPacket(
      const FlowEntry& flow,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      size_t payload_len,
      uint8_t* out_buffer) const;
  // Same as BuildPacket but injects TCP options (opts_len must be a multiple of 4).
  size_t BuildPacketOpt(
      const FlowEntry& flow,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      size_t payload_len,
      const uint8_t* opts,
      size_t opts_len,
      uint8_t* out_buffer) const;
  // Build our SYN option block (MSS, SACK-permitted, window scale, optional TS).
  // Returns length (multiple of 4). ts_enabled adds the RFC 7323 timestamp option.
  size_t BuildSynOptions(uint8_t* out, uint8_t wscale, bool ts_enabled, uint32_t ts_val) const;
  static bool ParseTcpOptions(const uint8_t* frame, size_t frame_len, TcpOptionInfo* out);
  // Timestamp/PAWS helpers (RFC 7323). BuildSegmentOptions emits the per-segment TS
  // option (fresh TSval, echoing ts_recent) when the flow negotiated timestamps;
  // returns option length (0 or 12). BuildSeg routes an ordinary segment through
  // BuildPacketOpt with those options so every data/ACK carries TS when enabled.
  size_t BuildSegmentOptions(const FlowEntry& flow, uint8_t* out) const;
  size_t BuildSeg(const FlowEntry& flow, uint32_t seq, uint32_t ack, uint8_t flags,
                  const uint8_t* payload, size_t payload_len, uint8_t* out_buffer) const;
  static uint32_t TimestampMs();
  // PAWS: reject an in-window segment whose TSval regressed vs ts_recent.
  bool PawsReject(const FlowEntry& flow, const TcpOptionInfo* opt) const;
  void UpdateRtt(FlowEntry& flow, uint64_t sample_ns);
  size_t BuildOutstandingPacket(const FlowEntry& flow, const OutstandingTx& out, uint8_t* out_buffer) const;
  bool EnqueueTxPacketBytes(const uint8_t* data, size_t len);
  void PushTimer(uint64_t flow_id, TimerKind kind, uint64_t due_ns, uint32_t generation);
  // Recompute the lock-free due-hint for a shard. Caller must hold timer_shard_mu_[shard].
  void RefreshTimerHint(size_t shard);
  void ScheduleFlowTimers(FlowEntry& flow, uint64_t now_ns);
  void QueuePacket(
      FlowEntry& flow,
      const uint8_t* packet_data,
      size_t packet_len,
      uint32_t seq,
      uint32_t ack,
      uint8_t flags,
      const uint8_t* payload,
      uint32_t payload_len,
      bool arm_rto);
  void PushCompletion(uint64_t flow_id, TcpDpState state, bool success, const char* event);
  // Drain sndbuf into MSS-sized segments under the effective window
  // min(cwnd, peer_window); emit each, append to unacked, advance snd_nxt, arm RTO.
  void PumpSend(FlowEntry& flow, uint64_t now_ns);
  // Rebuild + re-emit the oldest unacked segment (RTO / fast retransmit).
  void RetransmitOldest(FlowEntry& flow);
  // RFC 6675 SACK loss recovery. IsLostSeg: >= DupThresh SACKed segments (or bytes)
  // above the segment. ComputePipe: bytes estimated in flight. EnterSackRecovery /
  // SackRecoveryTransmit: enter an episode and clock (re)transmissions while
  // pipe < cwnd, retransmitting lost holes first (NextSeg), then new data, then a
  // single rescue retransmit.
  bool IsLostSeg(const FlowEntry& flow, uint32_t seg_seq) const;
  uint32_t ComputePipe(const FlowEntry& flow) const;
  void EnterSackRecovery(FlowEntry& flow, uint64_t now_ns);
  void SackRecoveryTransmit(FlowEntry& flow, uint64_t now_ns);
  // Emit a single fresh data segment from sndbuf (shared by PumpSend + recovery).
  // Returns bytes emitted (0 if window/buffer/Nagle blocked).
  uint32_t EmitOneDataSegment(FlowEntry& flow, uint64_t now_ns, uint32_t window_room);
  // Segment-payload buffer recycling (see FlowEntry::seg_buf_pool). AcquireSegBuf
  // hands back a cleared-capacity buffer; RecycleSegBuf returns a retired one.
  std::vector<uint8_t> AcquireSegBuf(FlowEntry& flow);
  void RecycleSegBuf(FlowEntry& flow, std::vector<uint8_t>&& buf);
  // Delayed-ACK: account an in-order data segment; send an ACK now or arm the timer.
  void OnDataReceivedAck(FlowEntry& flow, uint64_t now_ns, bool force_now);
  void SendAckNow(FlowEntry& flow);
  uint32_t EffectiveMss(const FlowEntry& flow) const;
  uint64_t CurrentRtoNs(const FlowEntry& flow) const;
  void HandleAck(FlowEntry& flow, uint32_t ack_value, const TcpOptionInfo* opt);
  void CloseTimedOutFlow(FlowEntry& flow, TcpDpState terminal_state, const char* event);
  bool IsCountedActive(TcpDpState state) const;
  void SetFlowState(FlowEntry& flow, TcpDpState next_state);

  // Cache-line-aligned spinlock wrapper to prevent false-sharing (HITM) across
  // adjacent shards. Each AlignedSpinLock occupies its own 64-byte L1 cache
  // line, eliminating cross-core cache invalidation when different threads
  // access different shards concurrently.
  // See: TASK-CORE-01 in test_task.md — Relates to #4
  struct alignas(64) AlignedSpinLock : public SpinLock {};

  mutable SpinLock state_mu_;
  mutable SpinLock tx_mu_;
  mutable std::array<AlignedSpinLock, kFlowLockShards> flow_shard_mu_{};
  mutable std::array<AlignedSpinLock, kFlowLockShards> flow_index_shard_mu_{};
  mutable std::array<AlignedSpinLock, kFlowLockShards> timer_shard_mu_{};
  std::array<std::set<uint64_t>, kFlowLockShards> active_flow_ids_shard_{};
  std::array<std::priority_queue<TimerEntry, std::vector<TimerEntry>, TimerEntryMin>, kFlowLockShards> timer_heap_shard_{};
  // Lock-free hint of each shard's earliest due_ns (UINT64_MAX = empty). Lets Poll
  // skip shards with nothing due without taking their timer spinlock.
  std::array<std::atomic<uint64_t>, kFlowLockShards> timer_shard_min_due_ns_{};
  uint32_t poll_rr_shard_ = 0;
  TcpDpConfig config_;
  uint64_t next_flow_id_ = 1;
  uint32_t next_ephemeral_port_ = 40000;
  uint16_t ephemeral_port_base_ = 40000;
  uint16_t ephemeral_port_stride_ = 1;
  uint32_t seq_seed_ = 0x10203040U;
  // flows_by_id_shard_ stays node-based (std::unordered_map): FlowEntry is a
  // heavy value and callers hold `FlowEntry*` across mutations — a dense/flat
  // map would move entries on rehash and invalidate those pointers.
  std::array<std::unordered_map<uint64_t, FlowEntry>, kFlowLockShards> flows_by_id_shard_{};
  // flow_index_shard_ is the per-packet RX 4-tuple->flow_id lookup: tiny value,
  // no reference-stability requirement (the id is copied out immediately), so a
  // flat/dense map wins on cache locality with no aliasing hazard.
  std::array<ankerl::unordered_dense::map<FlowKey, uint64_t, FlowKeyHash>, kFlowLockShards> flow_index_shard_{};
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
  mutable std::array<TcpDpStatsCounters, kFlowLockShards> stats_shard_{};
};

}  // namespace ddos_samurai::tcpdp
