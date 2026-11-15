#include "engine_internal.hpp"

namespace samurai::l7_emu_native {

thread_local DataplanePerfStats* g_perf_stats = nullptr;
thread_local std::vector<ScenarioStepResult> g_last_scenario_step_results{};
thread_local int g_worker_idle_passes = 0;

void record_scenario_step_result(
    const std::string& protocol,
    const std::string& flow,
    const std::string& vu_id,
    const std::string& on_failure,
    bool success,
    bool timeout,
    int status_code,
    double latency_ms) {
  ScenarioStepResult row;
  row.protocol = protocol;
  row.flow = flow.empty() ? std::string("unknown") : flow;
  row.vu_id = vu_id;
  row.on_failure = on_failure.empty() ? std::string("retry") : on_failure;
  row.success = success;
  row.timeout = timeout;
  row.status_code = status_code;
  row.latency_ms = latency_ms;
  g_last_scenario_step_results.push_back(std::move(row));
}

void cpu_relax() {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__)
  __asm__ __volatile__("yield" ::: "memory");
#else
  std::this_thread::yield();
#endif
}

void worker_idle_reset() {
  g_worker_idle_passes = 0;
}

static bool is_fastpath_busy_poll() {
  static const bool enabled = []() {
    const char* e = std::getenv("SAMURAI_FASTPATH_BUSY_POLL");
    return e != nullptr && (std::strcmp(e, "1") == 0 || std::strcmp(e, "true") == 0);
  }();
  return enabled;
}

void worker_idle_backoff() {
  if (is_fastpath_busy_poll()) {
    cpu_relax();
    return;
  }
  const int n = g_worker_idle_passes++;
  if (n < 256) {
    cpu_relax();
  } else if (n < 1024) {
    std::this_thread::yield();
  } else {
    cpu_relax();
  }
}

void perf_alloc(std::size_t bytes) {
  if (g_perf_stats == nullptr) {
    return;
  }
  g_perf_stats->alloc_count += 1;
  g_perf_stats->alloc_bytes += bytes;
}

void perf_request_latency(double latency_ms, int sample_limit) {
  if (g_perf_stats == nullptr) {
    return;
  }
  if (sample_limit <= 0 || static_cast<int>(g_perf_stats->request_latency_samples_ms.size()) < sample_limit) {
    g_perf_stats->request_latency_samples_ms.push_back(latency_ms);
  }
}

void perf_tls_latency(double latency_ms, int sample_limit) {
  if (g_perf_stats == nullptr) {
    return;
  }
  if (sample_limit <= 0 || static_cast<int>(g_perf_stats->tls_handshake_samples_ms.size()) < sample_limit) {
    g_perf_stats->tls_handshake_samples_ms.push_back(latency_ms);
  }
}

void trim_reusable_string(std::string& value, std::size_t keep_limit) {
  value.clear();
  if (value.capacity() > keep_limit) {
    std::string compact;
    compact.reserve(std::min<std::size_t>(keep_limit, 4096));
    value.swap(compact);
  }
}

void ensure_reusable_string_capacity(std::string& value, std::size_t min_capacity) {
  if (value.capacity() >= min_capacity) {
    return;
  }
  perf_alloc(min_capacity - value.capacity());
  value.reserve(min_capacity);
}

void H1ReadBuffer::reset_reusable(std::size_t keep_limit, std::size_t min_capacity) {
  clear();
  trim_reusable_string(storage, keep_limit);
  ensure_reusable_string_capacity(storage, min_capacity);
}

std::size_t percentile_index(std::size_t sample_count, double pct) {
  if (sample_count <= 1) {
    return 0;
  }
  return std::min(
      sample_count - 1,
      static_cast<std::size_t>((pct / 100.0) * static_cast<double>(sample_count - 1) + 0.5));
}

PercentileTripletMs percentile_triplet_ms(const std::vector<double>& values) {
  if (values.empty()) {
    return {};
  }
  if (values.size() == 1) {
    const double only = values.front();
    return PercentileTripletMs{only, only, only};
  }
  std::vector<double> work = values;
  const std::size_t idx50 = percentile_index(work.size(), 50.0);
  const std::size_t idx95 = percentile_index(work.size(), 95.0);
  const std::size_t idx99 = percentile_index(work.size(), 99.0);
  auto select = [&](std::size_t idx) {
    std::nth_element(work.begin(), work.begin() + static_cast<std::ptrdiff_t>(idx), work.end());
    return work[idx];
  };
  return PercentileTripletMs{
      select(idx50),
      select(idx95),
      select(idx99),
  };
}

LaneStringArena& ensure_lane_string_arena(std::unique_ptr<LaneStringArena>& arena_ptr) {
  if (!arena_ptr) {
    arena_ptr = std::make_unique<LaneStringArena>();
    arena_ptr->buckets = {
        ArenaStringBucket{kArenaBucketTinyBytes, {}, {}},
        ArenaStringBucket{kArenaBucketSmallBytes, {}, {}},
        ArenaStringBucket{kArenaBucketMediumBytes, {}, {}},
        ArenaStringBucket{kArenaBucketPathBytes, {}, {}},
        ArenaStringBucket{kArenaBucketBodyBytes, {}, {}},
        ArenaStringBucket{kArenaBucketLargeBytes, {}, {}},
    };
    arena_ptr->overflow.capacity = 0;
    auto prewarm_bucket = [](ArenaStringBucket& bucket, std::size_t slot_count) {
      bucket.slots.resize(slot_count);
      bucket.in_use.assign(slot_count, 0);
      for (auto& slot : bucket.slots) {
        if (bucket.capacity > 0) {
          ensure_reusable_string_capacity(slot, bucket.capacity);
        }
      }
    };
    prewarm_bucket(arena_ptr->buckets[0], kArenaBucketTinySlots);
    prewarm_bucket(arena_ptr->buckets[1], kArenaBucketSmallSlots);
    prewarm_bucket(arena_ptr->buckets[2], kArenaBucketMediumSlots);
    prewarm_bucket(arena_ptr->buckets[3], kArenaBucketPathSlots);
    prewarm_bucket(arena_ptr->buckets[4], kArenaBucketBodySlots);
    prewarm_bucket(arena_ptr->buckets[5], kArenaBucketLargeSlots);
    prewarm_bucket(arena_ptr->overflow, kArenaOverflowSlots);
  }
  return *arena_ptr;
}

ArenaStringLease arena_acquire_string(LaneStringArena& arena, std::size_t min_capacity) {
  for (std::size_t bucket_idx = 0; bucket_idx < arena.buckets.size(); ++bucket_idx) {
    auto& bucket = arena.buckets[bucket_idx];
    if (bucket.capacity < min_capacity) {
      continue;
    }
    for (std::size_t slot_idx = 0; slot_idx < bucket.in_use.size(); ++slot_idx) {
      if (bucket.in_use[slot_idx] != 0) {
        continue;
      }
      bucket.in_use[slot_idx] = 1;
      bucket.slots[slot_idx].clear();
      return ArenaStringLease{&arena, &bucket.slots[slot_idx], bucket_idx, slot_idx};
    }
  }
  const std::size_t overflow_bucket_idx = arena.buckets.size();
  for (std::size_t slot_idx = 0; slot_idx < arena.overflow.in_use.size(); ++slot_idx) {
    if (arena.overflow.in_use[slot_idx] != 0) {
      continue;
    }
    arena.overflow.in_use[slot_idx] = 1;
    auto& slot = arena.overflow.slots[slot_idx];
    slot.clear();
    ensure_reusable_string_capacity(slot, min_capacity);
    return ArenaStringLease{&arena, &slot, overflow_bucket_idx, slot_idx};
  }
  return {};
}

std::string& arena_string_or_throw(ArenaStringLease& lease, const char* context) {
  if (lease.value == nullptr) {
    throw std::runtime_error(std::string("lane string arena exhausted: ") + context);
  }
  return *lease.value;
}

void reset_response_info(ResponseInfo& response) {
  response.status_code = 0;
  response.bytes_received = 0;
  trim_reusable_string(response.raw, kHotPathReusableBufferLimit);
  response.headers.clear();
  response.header_fields.clear();
  response.header_fields.reserve(kReusableResponseHeaderReserve);
  trim_reusable_string(response.body, kHotPathReusableBufferLimit);
  ensure_reusable_string_capacity(response.body, kReusableResponseBodyBytes);
  response.keep_alive = false;
  response.consumed_bytes = 0;
}

void reset_h1_lane_io(H1Lane& lane) {
  lane.parser = H1ParserState{};
  reset_response_info(lane.response);
  trim_reusable_string(lane.write_buffer);
  ensure_reusable_string_capacity(lane.write_buffer, kH1SlabWriteBytes);
  if (lane.conn) {
    lane.conn->read_buffer.reset_reusable(kHotPathReusableBufferLimit, kH1SlabReadBytes);
    if (lane.conn->fd < 0) {
      lane.conn->custom_flow_id = 0;
      lane.conn->custom_connect_ready = false;
    }
    lane.conn->custom_send_enqueued = false;
    lane.conn->custom_send_outstanding = 0;
    lane.conn->custom_send_queued_bytes = 0;
    lane.conn->custom_send_enqueue_count = 0;
    lane.conn->custom_terminal = false;
    lane.conn->custom_rx_pending = false;
  }
  lane.write_offset = 0;
  lane.request_start_ms = 0;
  lane.request_spec = H1RequestSpec{};
  lane.think_time_total_ms = 0;
  lane.expectation_failures = 0;
  lane.phase = H1LanePhase::Idle;
  lane.queued_ready = false;
  lane.tx_bytes = 0;
  lane.rx_bytes = 0;
}

long long monotonic_ms_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::string lower_copy(const std::string& in) {
  std::string out = in;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string lowercase_copy(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

std::string trim_header_value_copy(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1);
  }
  return std::string(value);
}

bool ascii_iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    const unsigned char ca = static_cast<unsigned char>(a[i]);
    const unsigned char cb = static_cast<unsigned char>(b[i]);
    if (std::tolower(ca) != std::tolower(cb)) {
      return false;
    }
  }
  return true;
}

bool ascii_icontains(std::string_view haystack, std::string_view needle) {
  if (needle.empty()) {
    return true;
  }
  if (haystack.size() < needle.size()) {
    return false;
  }
  for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
    if (ascii_iequals(haystack.substr(i, needle.size()), needle)) {
      return true;
    }
  }
  return false;
}

std::size_t find_crlf(std::string_view payload, std::size_t start) {
  return payload.find("\r\n", start);
}

}  // namespace samurai::l7_emu_native
