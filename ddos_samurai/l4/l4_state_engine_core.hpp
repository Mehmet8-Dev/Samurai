#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

namespace ddos_samurai::l4se {

enum class TcpStateCode : uint8_t {
  kClosed = 0,
  kSynSent = 1,
  kSynAckRcvd = 2,
  kEstablished = 3,
  kFinWait = 4,
  kTimeWait = 5,
  kRstSeen = 6,
};

enum class TcpEventCode : uint8_t {
  kTxSyn = 0,
  kRxSynAck = 1,
  kTxAck = 2,
  kTxData = 3,
  kRxFin = 4,
  kRxRst = 5,
  kTimeout = 6,
};

struct TcpStateSnapshot {
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t state = 0;  // legacy projection (0/1/2)
  uint16_t window = 0;
  uint16_t mss = 0;
  uint8_t ttl = 0;
  bool found = false;
};

struct EngineStatsSnapshot {
  uint32_t table_size = 0;
  uint32_t lock_count = 0;
  uint32_t timeout_sec = 0;
  uint64_t active_entries = 0;
  uint64_t timeout_evictions = 0;
  uint64_t overwrites = 0;
  uint64_t sweeps = 0;
  uint64_t last_sweep_removed = 0;
  uint32_t sweep_cursor = 0;
  uint64_t transition_total = 0;
  std::array<uint64_t, 7> state_counts{};
};

struct IngestResult {
  uint32_t updated = 0;
};

class L4StateEngineCore {
 public:
  L4StateEngineCore();

  bool Configure(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec);
  void SetMimicry(uint16_t window, uint16_t mss, uint8_t ttl);

  IngestResult IngestTxPackets(const uint8_t* packets, size_t packet_size, size_t count);
  IngestResult IngestRxFrame(const uint8_t* frame, size_t frame_len);

  uint32_t GetStatesBatch(
      uint32_t src_ip,
      uint16_t start_port,
      uint32_t count,
      uint32_t* out_seq,
      uint32_t* out_ack,
      uint8_t* out_state,
      uint16_t* out_window,
      uint16_t* out_mss,
      uint8_t* out_ttl);

  TcpStateSnapshot GetTcpState(uint32_t src_ip, uint16_t src_port);
  uint32_t Sweep(uint32_t max_scan);
  EngineStatsSnapshot Snapshot() const;

 private:
  struct Entry {
    uint32_t src_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    TcpStateCode state = TcpStateCode::kClosed;
    uint32_t last_seen = 0;
    uint16_t window = 0;
    uint16_t mss = 0;
    uint8_t ttl = 0;
    bool in_use = false;
  };

  static uint32_t HashKey(uint32_t src_ip, uint16_t src_port);
  static uint32_t MonotonicSeconds();
  static uint8_t ToLegacyState(TcpStateCode state);

  std::optional<TcpStateCode> ApplyTransition(TcpStateCode current, TcpEventCode event) const;
  uint32_t SegmentSize() const;

  void ResetStorage(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec);
  void UpsertState(
      uint32_t src_ip,
      uint16_t src_port,
      uint16_t dst_port,
      uint32_t seq,
      uint32_t ack,
      TcpEventCode event,
      uint16_t window,
      uint16_t mss,
      uint8_t ttl,
      uint32_t now_sec = 0);

  static bool ParseIpv4TcpView(
      const uint8_t* pkt,
      size_t pkt_len,
      int* out_ip_offset,
      int* out_transport_offset,
      uint32_t* out_src_ip,
      uint32_t* out_dst_ip,
      uint16_t* out_src_port,
      uint16_t* out_dst_port,
      uint32_t* out_seq,
      uint32_t* out_ack,
      uint8_t* out_flags,
      uint16_t* out_window,
      uint16_t* out_mss,
      uint8_t* out_ttl);

  struct alignas(64) PaddedMutex : public std::mutex {};

  mutable std::mutex meta_mu_;
  std::vector<Entry> table_;
  std::vector<PaddedMutex> locks_;
  uint32_t table_size_ = 65536;
  uint32_t lock_count_ = 256;
  uint32_t timeout_sec_ = 60;
  uint32_t sweep_cursor_ = 0;
  std::atomic<uint64_t> active_entries_{0};
  std::atomic<uint64_t> timeout_evictions_{0};
  std::atomic<uint64_t> overwrites_{0};
  std::atomic<uint64_t> sweeps_{0};
  std::atomic<uint64_t> last_sweep_removed_{0};
  std::atomic<uint64_t> transition_total_{0};
  std::array<std::atomic<uint64_t>, 7> state_counts_{};
  uint16_t mimicry_window_ = 64240;
  uint16_t mimicry_mss_ = 1460;
  uint8_t mimicry_ttl_ = 64;
};

}  // namespace ddos_samurai::l4se
