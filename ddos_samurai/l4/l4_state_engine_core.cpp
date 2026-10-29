#include "l4_state_engine_core.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>

namespace ddos_samurai::l4se {

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

inline uint16_t ReadUnalignedU16(const uint8_t* p) {
  uint16_t v = 0;
  std::memcpy(&v, p, sizeof(v));
  return v;
}

inline uint32_t ReadUnalignedU32(const uint8_t* p) {
  uint32_t v = 0;
  std::memcpy(&v, p, sizeof(v));
  return v;
}

inline void SaturatingDecrement(std::atomic<uint64_t>& counter) {
  uint64_t cur = counter.load(std::memory_order_relaxed);
  while (cur > 0) {
    if (counter.compare_exchange_weak(cur, cur - 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
      return;
    }
  }
}
}  // namespace

L4StateEngineCore::L4StateEngineCore() { ResetStorage(table_size_, lock_count_, timeout_sec_); }

uint32_t L4StateEngineCore::HashKey(uint32_t src_ip, uint16_t src_port) {
  uint32_t h = src_ip;
  h ^= (h >> 16);
  h *= 0x85ebca6bU;
  h ^= (h >> 13);
  h *= 0xc2b2ae35U;
  h ^= (h >> 16);
  h ^= static_cast<uint32_t>(src_port);
  return h;
}

uint32_t L4StateEngineCore::MonotonicSeconds() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
  if (sec < 0) {
    return 0;
  }
  return static_cast<uint32_t>(sec);
}

uint8_t L4StateEngineCore::ToLegacyState(TcpStateCode state) {
  switch (state) {
    case TcpStateCode::kClosed:
      return 0;
    case TcpStateCode::kSynSent:
      return 1;
    case TcpStateCode::kSynAckRcvd:
    case TcpStateCode::kEstablished:
    case TcpStateCode::kFinWait:
    case TcpStateCode::kTimeWait:
      return 2;
    case TcpStateCode::kRstSeen:
      return 0;
  }
  return 0;
}

std::optional<TcpStateCode> L4StateEngineCore::ApplyTransition(TcpStateCode current, TcpEventCode event) const {
  switch (event) {
    case TcpEventCode::kRxRst:
      return TcpStateCode::kRstSeen;
    case TcpEventCode::kTimeout:
      if (current == TcpStateCode::kFinWait) {
        return TcpStateCode::kTimeWait;
      }
      if (current == TcpStateCode::kSynSent || current == TcpStateCode::kRstSeen) {
        return TcpStateCode::kClosed;
      }
      return std::nullopt;
    case TcpEventCode::kTxSyn:
      return TcpStateCode::kSynSent;
    case TcpEventCode::kRxSynAck:
      if (current == TcpStateCode::kSynSent || current == TcpStateCode::kClosed) {
        return TcpStateCode::kSynAckRcvd;
      }
      return std::nullopt;
    case TcpEventCode::kTxAck:
      if (current == TcpStateCode::kSynAckRcvd || current == TcpStateCode::kSynSent) {
        return TcpStateCode::kEstablished;
      }
      return std::nullopt;
    case TcpEventCode::kTxData:
      if (current == TcpStateCode::kEstablished || current == TcpStateCode::kSynAckRcvd) {
        return TcpStateCode::kEstablished;
      }
      return std::nullopt;
    case TcpEventCode::kRxFin:
      if (current == TcpStateCode::kEstablished) {
        return TcpStateCode::kFinWait;
      }
      return std::nullopt;
  }
  return std::nullopt;
}

uint32_t L4StateEngineCore::SegmentSize() const {
  if (lock_count_ == 0) {
    return 0;
  }
  return table_size_ / lock_count_;
}

void L4StateEngineCore::ResetStorage(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec) {
  std::lock_guard<std::mutex> guard(meta_mu_);
  table_size_ = table_size;
  lock_count_ = lock_count;
  timeout_sec_ = timeout_sec;
  table_.assign(static_cast<size_t>(table_size_), Entry{});
  std::vector<PaddedMutex> new_locks(static_cast<size_t>(lock_count_));
  locks_.swap(new_locks);
  sweep_cursor_ = 0;
  active_entries_.store(0, std::memory_order_relaxed);
  timeout_evictions_.store(0, std::memory_order_relaxed);
  overwrites_.store(0, std::memory_order_relaxed);
  sweeps_.store(0, std::memory_order_relaxed);
  last_sweep_removed_.store(0, std::memory_order_relaxed);
  transition_total_.store(0, std::memory_order_relaxed);
  for (auto& v : state_counts_) {
    v.store(0, std::memory_order_relaxed);
  }
}

bool L4StateEngineCore::Configure(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec) {
  if (table_size == 0 || lock_count == 0 || timeout_sec == 0) {
    return false;
  }
  if (table_size % lock_count != 0) {
    return false;
  }
  ResetStorage(table_size, lock_count, timeout_sec);
  return true;
}

void L4StateEngineCore::SetMimicry(uint16_t window, uint16_t mss, uint8_t ttl) {
  std::lock_guard<std::mutex> guard(meta_mu_);
  mimicry_window_ = window;
  mimicry_mss_ = mss;
  mimicry_ttl_ = ttl;
}

void L4StateEngineCore::UpsertState(
    uint32_t src_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq,
    uint32_t ack,
    TcpEventCode event,
    uint16_t window,
    uint16_t mss,
    uint8_t ttl,
    uint32_t now_sec) {
  if (src_ip == 0 || src_port == 0 || table_.empty() || locks_.empty()) {
    return;
  }
  const uint32_t h = HashKey(src_ip, src_port);
  const uint32_t segment_size = SegmentSize();
  if (segment_size == 0) {
    return;
  }
  const uint32_t segment = h % lock_count_;
  const uint32_t segment_start = segment * segment_size;
  const uint32_t start_idx = segment_start + ((h / lock_count_) % segment_size);
  const uint32_t now = (now_sec != 0) ? now_sec : MonotonicSeconds();

  std::lock_guard<std::mutex> guard(locks_[segment]);
  uint32_t idx = start_idx;
  Entry* chosen = nullptr;
  for (uint32_t i = 0; i < segment_size; ++i) {
    Entry& e = table_[idx];
    const bool timed_out =
        e.in_use && static_cast<uint32_t>(now - e.last_seen) > static_cast<uint32_t>(timeout_sec_);
    const bool same_key = e.in_use && e.src_ip == src_ip && e.src_port == src_port;
    if (!e.in_use || timed_out || same_key) {
      if (!e.in_use) {
        active_entries_.fetch_add(1, std::memory_order_relaxed);
      } else if (timed_out && !same_key) {
        timeout_evictions_.fetch_add(1, std::memory_order_relaxed);
      }
      chosen = &e;
      break;
    }
    idx = segment_start + ((idx - segment_start + 1U) % segment_size);
  }

  if (chosen == nullptr) {
    Entry& e = table_[start_idx];
    if (e.in_use) {
      overwrites_.fetch_add(1, std::memory_order_relaxed);
    } else {
      active_entries_.fetch_add(1, std::memory_order_relaxed);
    }
    chosen = &e;
  }

  TcpStateCode current = chosen->in_use ? chosen->state : TcpStateCode::kClosed;
  auto transitioned = ApplyTransition(current, event);
  TcpStateCode next_state = transitioned.value_or(current);
  if (!chosen->in_use) {
    next_state = transitioned.value_or(TcpStateCode::kSynSent);
  }

  if (chosen->in_use) {
    const auto cur_idx = static_cast<size_t>(chosen->state);
    if (cur_idx < state_counts_.size()) {
      SaturatingDecrement(state_counts_[cur_idx]);
    }
  }

  chosen->src_ip = src_ip;
  chosen->src_port = src_port;
  chosen->dst_port = dst_port;
  chosen->seq = seq;
  chosen->ack = ack;
  chosen->state = next_state;
  chosen->last_seen = now;
  chosen->window = window;
  chosen->mss = mss;
  chosen->ttl = ttl;
  chosen->in_use = true;

  const auto next_idx = static_cast<size_t>(next_state);
  if (next_idx < state_counts_.size()) {
    state_counts_[next_idx].fetch_add(1, std::memory_order_relaxed);
  }
  transition_total_.fetch_add(1, std::memory_order_relaxed);
}

bool L4StateEngineCore::ParseIpv4TcpView(
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
  if (ip_offset < 0) {
    if (((pkt[0] >> 4) & 0x0F) == 4) {
      ip_offset = 0;
    }
  }
  if (ip_offset < 0 || pkt_len < static_cast<size_t>(ip_offset + 20)) {
    return false;
  }
  const uint8_t ver = (pkt[ip_offset] >> 4) & 0x0F;
  if (ver != 4) {
    return false;
  }
  const uint8_t ihl = (pkt[ip_offset] & 0x0F) * 4;
  if (ihl < 20 || pkt_len < static_cast<size_t>(ip_offset + ihl + 20)) {
    return false;
  }
  if (pkt[ip_offset + 9] != 6) {
    return false;
  }
  const int transport_offset = ip_offset + ihl;
  const uint8_t* tcp = pkt + transport_offset;
  const uint8_t data_off = static_cast<uint8_t>((tcp[12] >> 4) * 4);
  if (data_off < 20 || pkt_len < static_cast<size_t>(transport_offset + data_off)) {
    return false;
  }

  if (out_ip_offset) {
    *out_ip_offset = ip_offset;
  }
  if (out_transport_offset) {
    *out_transport_offset = transport_offset;
  }
  if (out_src_ip) {
    *out_src_ip = ReadBe32(pkt + ip_offset + 12);
  }
  if (out_dst_ip) {
    *out_dst_ip = ReadBe32(pkt + ip_offset + 16);
  }
  if (out_src_port) {
    *out_src_port = ReadBe16(pkt + transport_offset);
  }
  if (out_dst_port) {
    *out_dst_port = ReadBe16(pkt + transport_offset + 2);
  }
  if (out_seq) {
    *out_seq = ReadBe32(pkt + transport_offset + 4);
  }
  if (out_ack) {
    *out_ack = ReadBe32(pkt + transport_offset + 8);
  }
  if (out_flags) {
    *out_flags = pkt[transport_offset + 13];
  }
  if (out_window) {
    *out_window = ReadBe16(pkt + transport_offset + 14);
  }
  if (out_ttl) {
    *out_ttl = pkt[ip_offset + 8];
  }
  if (out_mss) {
    uint16_t mss = 0;
    int cur = transport_offset + 20;
    const int end = transport_offset + data_off;
    while (cur < end) {
      const uint8_t kind = pkt[cur];
      if (kind == 0) {
        break;
      }
      if (kind == 1) {
        cur += 1;
        continue;
      }
      if (cur + 1 >= end) {
        break;
      }
      const uint8_t len = pkt[cur + 1];
      if (len < 2 || cur + len > end) {
        break;
      }
      if (kind == 2 && len >= 4) {
        mss = ReadBe16(pkt + cur + 2);
      }
      cur += len;
    }
    *out_mss = mss;
  }
  return true;
}

IngestResult L4StateEngineCore::IngestTxPackets(const uint8_t* packets, size_t packet_size, size_t count) {
  IngestResult out;
  uint16_t mimicry_window = 0;
  uint16_t mimicry_mss = 0;
  uint8_t mimicry_ttl = 0;
  if (!packets || packet_size == 0 || count == 0) {
    return out;
  }
  {
    std::lock_guard<std::mutex> guard(meta_mu_);
    mimicry_window = mimicry_window_;
    mimicry_mss = mimicry_mss_;
    mimicry_ttl = mimicry_ttl_;
  }
  const uint32_t batch_now = MonotonicSeconds();
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* pkt = packets + (i * packet_size);
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    uint16_t win = 0;
    uint16_t mss = 0;
    uint8_t ttl = 0;
    if (!ParseIpv4TcpView(
            pkt,
            packet_size,
            nullptr,
            nullptr,
            &src_ip,
            &dst_ip,
            &src_port,
            &dst_port,
            &seq,
            &ack,
            &flags,
            &win,
            &mss,
            &ttl)) {
      continue;
    }

    TcpEventCode event = TcpEventCode::kTxSyn;
    uint32_t next_seq = seq;
    uint32_t next_ack = ack;
    if ((flags & kTcpFlagRst) != 0) {
      event = TcpEventCode::kRxRst;
    } else if ((flags & kTcpFlagFin) != 0) {
      event = TcpEventCode::kRxFin;
    } else if ((flags & kTcpFlagSyn) != 0 && (flags & kTcpFlagAck) == 0) {
      event = TcpEventCode::kTxSyn;
      next_seq = seq + 1U;
      next_ack = 0U;
    } else if ((flags & kTcpFlagPsh) != 0 && (flags & kTcpFlagAck) != 0) {
      event = TcpEventCode::kTxData;
    } else if ((flags & kTcpFlagAck) != 0) {
      event = TcpEventCode::kTxAck;
    }

    const uint16_t final_win = win > 0 ? win : mimicry_window;
    const uint16_t final_mss = mss > 0 ? mss : mimicry_mss;
    const uint8_t final_ttl = ttl > 0 ? ttl : mimicry_ttl;
    UpsertState(src_ip, src_port, dst_port, next_seq, next_ack, event, final_win, final_mss, final_ttl, batch_now);
    out.updated++;
  }
  return out;
}

IngestResult L4StateEngineCore::IngestRxFrame(const uint8_t* frame, size_t frame_len) {
  IngestResult out;
  uint16_t mimicry_window = 0;
  uint16_t mimicry_mss = 0;
  uint8_t mimicry_ttl = 0;
  if (!frame || frame_len == 0) {
    return out;
  }
  {
    std::lock_guard<std::mutex> guard(meta_mu_);
    mimicry_window = mimicry_window_;
    mimicry_mss = mimicry_mss_;
    mimicry_ttl = mimicry_ttl_;
  }
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t flags = 0;
  uint16_t win = 0;
  uint16_t mss = 0;
  uint8_t ttl = 0;
  if (!ParseIpv4TcpView(
          frame,
          frame_len,
          nullptr,
          nullptr,
          &src_ip,
          &dst_ip,
          &src_port,
          &dst_port,
          &seq,
          &ack,
          &flags,
          &win,
          &mss,
          &ttl)) {
    return out;
  }
  if ((flags & (kTcpFlagSyn | kTcpFlagAck)) != (kTcpFlagSyn | kTcpFlagAck)) {
    return out;
  }
  const uint32_t next_seq = ack;
  const uint32_t next_ack = seq + 1U;
  const uint16_t final_win = win > 0 ? win : mimicry_window;
  const uint16_t final_mss = mss > 0 ? mss : mimicry_mss;
  const uint8_t final_ttl = ttl > 0 ? ttl : mimicry_ttl;
  const uint32_t rx_now = MonotonicSeconds();
  UpsertState(dst_ip, dst_port, src_port, next_seq, next_ack, TcpEventCode::kRxSynAck, final_win, final_mss, final_ttl, rx_now);
  out.updated = 1;
  return out;
}

uint32_t L4StateEngineCore::GetStatesBatch(
    uint32_t src_ip,
    uint16_t start_port,
    uint32_t count,
    uint32_t* out_seq,
    uint32_t* out_ack,
    uint8_t* out_state,
    uint16_t* out_window,
    uint16_t* out_mss,
    uint8_t* out_ttl) {
  if (count == 0 || !out_seq || !out_ack || !out_state || !out_window || !out_mss || !out_ttl) {
    return 0;
  }
  uint32_t found = 0;
  const uint32_t segment_size = SegmentSize();
  if (segment_size == 0) {
    std::fill_n(out_seq, count, 0U);
    std::fill_n(out_ack, count, 0U);
    std::fill_n(out_state, count, static_cast<uint8_t>(0));
    std::fill_n(out_window, count, static_cast<uint16_t>(0));
    std::fill_n(out_mss, count, static_cast<uint16_t>(0));
    std::fill_n(out_ttl, count, static_cast<uint8_t>(0));
    return 0;
  }
  for (uint32_t i = 0; i < count; ++i) {
    out_seq[i] = 0;
    out_ack[i] = 0;
    out_state[i] = 0;
    out_window[i] = 0;
    out_mss[i] = 0;
    out_ttl[i] = 0;

    const uint16_t port = static_cast<uint16_t>(start_port + (i % 64512U));
    const uint32_t h = HashKey(src_ip, port);
    const uint32_t segment = h % lock_count_;
    const uint32_t segment_start = segment * segment_size;
    const uint32_t start_idx = segment_start + ((h / lock_count_) % segment_size);

    std::lock_guard<std::mutex> guard(locks_[segment]);
    uint32_t idx = start_idx;
    for (uint32_t j = 0; j < segment_size; ++j) {
      const Entry& e = table_[idx];
      if (!e.in_use) {
        break;
      }
      if (e.src_ip == src_ip && e.src_port == port) {
        out_seq[i] = e.seq;
        out_ack[i] = e.ack;
        out_state[i] = ToLegacyState(e.state);
        out_window[i] = e.window;
        out_mss[i] = e.mss;
        out_ttl[i] = e.ttl;
        found++;
        break;
      }
      idx = segment_start + ((idx - segment_start + 1U) % segment_size);
    }
  }
  return found;
}

TcpStateSnapshot L4StateEngineCore::GetTcpState(uint32_t src_ip, uint16_t src_port) {
  TcpStateSnapshot out;
  const uint32_t segment_size = SegmentSize();
  if (segment_size == 0) {
    return out;
  }
  const uint32_t h = HashKey(src_ip, src_port);
  const uint32_t segment = h % lock_count_;
  const uint32_t segment_start = segment * segment_size;
  const uint32_t start_idx = segment_start + ((h / lock_count_) % segment_size);
  std::lock_guard<std::mutex> guard(locks_[segment]);
  uint32_t idx = start_idx;
  for (uint32_t i = 0; i < segment_size; ++i) {
    const Entry& e = table_[idx];
    if (!e.in_use) {
      break;
    }
    if (e.src_ip == src_ip && e.src_port == src_port) {
      out.seq = e.seq;
      out.ack = e.ack;
      out.state = ToLegacyState(e.state);
      out.window = e.window;
      out.mss = e.mss;
      out.ttl = e.ttl;
      out.found = true;
      break;
    }
    idx = segment_start + ((idx - segment_start + 1U) % segment_size);
  }
  return out;
}

uint32_t L4StateEngineCore::Sweep(uint32_t max_scan) {
  const uint32_t segment_size = SegmentSize();
  if (segment_size == 0) {
    return 0;
  }
  if (max_scan == 0 || max_scan > table_size_) {
    max_scan = table_size_;
  }
  const uint32_t now = MonotonicSeconds();
  uint32_t removed = 0;
  uint32_t remaining = max_scan;
  uint32_t cursor = sweep_cursor_ % table_size_;
  constexpr uint32_t kSweepChunkMax = 64;

  while (remaining > 0) {
    const uint32_t segment = cursor / segment_size;
    const uint32_t segment_start = segment * segment_size;
    const uint32_t segment_offset = cursor - segment_start;
    const uint32_t segment_remaining = segment_size - segment_offset;
    const uint32_t run_len = std::min<uint32_t>(remaining, std::min<uint32_t>(segment_remaining, kSweepChunkMax));

    {
      std::lock_guard<std::mutex> guard(locks_[segment]);
      for (uint32_t j = 0; j < run_len; ++j) {
        const uint32_t idx = cursor + j;
        Entry& e = table_[idx];
        if (!e.in_use) {
          continue;
        }
        if (static_cast<uint32_t>(now - e.last_seen) > timeout_sec_) {
          const auto cur_idx = static_cast<size_t>(e.state);
          if (cur_idx < state_counts_.size()) {
            SaturatingDecrement(state_counts_[cur_idx]);
          }
          e = Entry{};
          removed++;
          SaturatingDecrement(active_entries_);
          timeout_evictions_.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }

    remaining -= run_len;
    cursor += run_len;
    if (cursor >= table_size_) {
      cursor -= table_size_;
    }
  }

  sweep_cursor_ = cursor;
  sweeps_.fetch_add(1, std::memory_order_relaxed);
  last_sweep_removed_.store(removed, std::memory_order_relaxed);
  return removed;
}

EngineStatsSnapshot L4StateEngineCore::Snapshot() const {
  std::lock_guard<std::mutex> guard(meta_mu_);
  EngineStatsSnapshot out;
  out.table_size = table_size_;
  out.lock_count = lock_count_;
  out.timeout_sec = timeout_sec_;
  out.active_entries = active_entries_.load(std::memory_order_relaxed);
  out.timeout_evictions = timeout_evictions_.load(std::memory_order_relaxed);
  out.overwrites = overwrites_.load(std::memory_order_relaxed);
  out.sweeps = sweeps_.load(std::memory_order_relaxed);
  out.last_sweep_removed = last_sweep_removed_.load(std::memory_order_relaxed);
  out.sweep_cursor = sweep_cursor_;
  out.transition_total = transition_total_.load(std::memory_order_relaxed);
  for (size_t i = 0; i < out.state_counts.size(); ++i) {
    out.state_counts[i] = state_counts_[i].load(std::memory_order_relaxed);
  }
  return out;
}

}  // namespace ddos_samurai::l4se
