#ifndef SAMURAI_GPU_PACKET_CUDA_PREAMBLE_INCLUDED
#define SAMURAI_GPU_PACKET_CUDA_PREAMBLE_INCLUDED 1

#include <curand_kernel.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <list>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ddos_samurai::gpu_packet_cuda {
namespace {

constexpr int kThreadsPerBlock = 256;
constexpr uint8_t TCP_OPT_NOP = 1;
constexpr uint8_t TCP_OPT_MSS = 2;
constexpr uint8_t TCP_OPT_WSCALE = 3;
constexpr uint8_t TCP_OPT_SACK_PERM = 4;
constexpr uint8_t TCP_OPT_TIMESTAMP = 8;

#if defined(__INTELLISENSE__)
#define CUDA_KERNEL_LAUNCH(kernel, grid, block, stream, ...) ((void)0)
#else
#define CUDA_KERNEL_LAUNCH(kernel, grid, block, stream, ...) \
  kernel<<<grid, block, 0, stream>>>(__VA_ARGS__)
#endif

__constant__ uint8_t TEMPLATE_CONST_DEV[TEMPLATE_CONST_MAX];
__constant__ uint8_t POOL_CONST_DEV[POOL_CONST_MAX];

struct ConstantFingerprint {
  size_t size = 0;
  uint64_t hash = 0;

  bool operator==(const ConstantFingerprint& o) const {
    return size == o.size && hash == o.hash;
  }
};

std::mutex g_generation_lock;
std::unordered_map<std::string, std::pair<uint8_t*, size_t>> g_template_cache;
std::list<std::string> g_template_lru;
std::unordered_map<std::string, std::list<std::string>::iterator> g_template_lru_idx;

std::unordered_map<std::string, curandStatePhilox4_32_10_t*> g_rng_state_pool;
std::list<std::string> g_rng_lru;
std::unordered_map<std::string, std::list<std::string>::iterator> g_rng_lru_idx;

GenerationTelemetry g_generation_telemetry;
std::atomic<bool> g_warned_template_const_fallback{false};
std::atomic<bool> g_warned_pool_const_fallback{false};
std::atomic<bool> g_warned_pool_const_stateful_fallback{false};
std::atomic<bool> g_const_update_available{false};

ConstantFingerprint g_template_const_fp{};
ConstantFingerprint g_pool_const_fp{};

std::atomic<uint64_t> g_d2h_transfer_count{0};
std::atomic<uint64_t> g_d2h_transfer_bytes{0};

struct TemplateAcquisition {
  uint8_t* ptr = nullptr;
  size_t nbytes = 0;
  bool temporary = false;
};

struct RNGAcquisition {
  curandStatePhilox4_32_10_t* ptr = nullptr;
  bool temporary = false;
};

inline int env_int(const char* name, int defv) {
  const char* v = std::getenv(name);
  if (!v || !*v) {
    return defv;
  }
  try {
    return std::stoi(v);
  } catch (...) {
    return defv;
  }
}

inline int gpu_cache_limit() {
  return std::max(0, env_int("SAMURAI_GPU_CACHE_MAX_ENTRIES", 8));
}

inline int rng_pool_limit() {
  return std::max(0, env_int("SAMURAI_GPU_RNG_POOL_MAX_ENTRIES", 8));
}

inline bool can_use_constant_memory(size_t total_bytes, size_t constant_limit) {
  return total_bytes <= constant_limit;
}

inline int active_device_id() {
  int dev = -1;
  if (cudaGetDevice(&dev) != cudaSuccess) {
    return -1;
  }
  return dev;
}

inline std::string stream_cache_key(cudaStream_t stream) {
  if (stream == nullptr) {
    return "default";
  }
  std::ostringstream oss;
  oss << std::hex << reinterpret_cast<uintptr_t>(stream);
  return oss.str();
}

inline uint64_t fnv1a_64(const uint8_t* data, size_t n) {
  constexpr uint64_t kOff = 1469598103934665603ull;
  constexpr uint64_t kPrime = 1099511628211ull;
  uint64_t h = kOff;
  for (size_t i = 0; i < n; ++i) {
    h ^= static_cast<uint64_t>(data[i]);
    h *= kPrime;
  }
  return h;
}

inline ConstantFingerprint const_payload_fingerprint(const uint8_t* data, size_t n) {
  return ConstantFingerprint{n, fnv1a_64(data, n)};
}

inline std::string template_digest(const uint8_t* data, size_t size) {
  uint64_t h = fnv1a_64(data, size);
  std::ostringstream oss;
  oss << std::hex << h;
  return oss.str();
}

inline std::string template_digest(const std::vector<uint8_t>& data) {
  return template_digest(data.data(), data.size());
}

inline uint64_t now_seed() {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::random_device rd;
  return static_cast<uint64_t>(now) ^ (static_cast<uint64_t>(rd()) << 32);
}

inline void telemetry_inc(uint64_t& field, uint64_t value = 1) {
  field += value;
}

inline void throw_if_cuda(cudaError_t st, const std::string& msg) {
  if (st != cudaSuccess) {
    throw GPUPacketError(msg + ": " + cudaGetErrorString(st));
  }
}

__global__ void init_rng_states_kernel(curandStatePhilox4_32_10_t* states,
                                       int64_t count,
                                       uint64_t seed) {
  int64_t idx = static_cast<int64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }
  curand_init(seed, static_cast<unsigned long long>(idx), 0, &states[idx]);
}

struct GPUMemoryPool {
  explicit GPUMemoryPool(size_t initial_size = 1024ull * 1024ull * 64ull)
      : pool_size(initial_size) {}

  size_t pool_size;
  std::unordered_map<size_t, uint8_t*> buffers;
  std::unordered_map<size_t, bool> in_use;
  uint64_t hits = 0;
  uint64_t misses = 0;
  uint64_t oom_recoveries = 0;
  uint64_t peak_used_bytes = 0;
  std::mutex lock;

  ~GPUMemoryPool() {
    clear();
  }

  uint8_t* allocate(size_t size) {
    std::lock_guard<std::mutex> g(lock);
    auto it = buffers.find(size);
    if (it != buffers.end() && !in_use[size]) {
      hits++;
      in_use[size] = true;
      return it->second;
    }

    misses++;
    uint8_t* ptr = nullptr;
    cudaError_t st = cudaMalloc(&ptr, size);
    if (st == cudaErrorMemoryAllocation) {
      oom_recoveries++;
      clear_locked();
      st = cudaMalloc(&ptr, size);
    }
    throw_if_cuda(st, "GPUMemoryPool allocate failed");
    buffers[size] = ptr;
    in_use[size] = true;
    size_t used = 0;
    size_t free_b = 0;
    if (cudaMemGetInfo(&free_b, &used) == cudaSuccess) {
      peak_used_bytes = std::max<uint64_t>(peak_used_bytes, used);
    }
    return ptr;
  }

  void release(uint8_t* ptr, size_t size) {
    std::lock_guard<std::mutex> g(lock);
    auto it = buffers.find(size);
    if (it != buffers.end() && it->second == ptr) {
      in_use[size] = false;
    }
  }

  void clear() {
    std::lock_guard<std::mutex> g(lock);
    clear_locked();
  }

  GPUPoolTelemetry stats() const {
    std::lock_guard<std::mutex> g(const_cast<std::mutex&>(lock));
    GPUPoolTelemetry out;
    size_t free_b = 0;
    size_t total_b = 0;
    if (cudaMemGetInfo(&free_b, &total_b) == cudaSuccess) {
      out.total_bytes = total_b;
      out.used_bytes = total_b - free_b;
    }
    out.peak_used_bytes = peak_used_bytes;
    out.buffers_allocated = buffers.size();
    uint64_t in_use_count = 0;
    for (const auto& kv : in_use) {
      if (kv.second) {
        ++in_use_count;
      }
    }
    out.buffers_in_use = in_use_count;
    out.pool_hits = hits;
    out.pool_misses = misses;
    out.oom_recoveries = oom_recoveries;
    out.hit_rate_pct = (hits + misses) ? (100.0 * static_cast<double>(hits) / static_cast<double>(hits + misses)) : 0.0;
    return out;
  }

 private:
  void clear_locked() {
    for (auto& kv : buffers) {
      if (kv.second) {
        cudaFree(kv.second);
      }
    }
    buffers.clear();
    in_use.clear();
  }
};

struct HostBuffer {
  uint8_t* ptr = nullptr;
  size_t nbytes = 0;
  bool pinned = false;
};

struct PinnedHostBufferPool {
  explicit PinnedHostBufferPool(std::optional<size_t> max_bytes = std::nullopt) {
    int env_mb = std::max(1, env_int("SAMURAI_GPU_PINNED_MAX_MB", 512));
    size_t default_limit = static_cast<size_t>(env_mb) * 1024ull * 1024ull;
    max_bytes_ = max_bytes.value_or(default_limit);
    limit_mb_seen_ = env_mb;
  }

  ~PinnedHostBufferPool() {
    clear();
  }

  void configure(size_t max_bytes) {
    std::lock_guard<std::mutex> g(lock_);
    max_bytes_ = std::max<size_t>(1, max_bytes);
    limit_mb_seen_ = static_cast<int>(max_bytes_ / (1024ull * 1024ull));
    evict_until_fit_locked(0, "");
  }

  void refresh_limit_from_env() {
    int env_mb = std::max(1, env_int("SAMURAI_GPU_PINNED_MAX_MB", limit_mb_seen_ > 0 ? limit_mb_seen_ : 512));
    if (env_mb != limit_mb_seen_) {
      configure(static_cast<size_t>(env_mb) * 1024ull * 1024ull);
    }
  }

  HostBuffer acquire(size_t nbytes, const std::string& key) {
    std::lock_guard<std::mutex> g(lock_);
    refresh_limit_from_env();

    auto it = buffers_.find(key);
    if (it != buffers_.end() && it->second.buf.nbytes >= nbytes) {
      hits_++;
      lru_.erase(it->second.it);
      lru_.push_back(key);
      it->second.it = std::prev(lru_.end());
      return it->second.buf;
    }

    misses_++;
    if (it != buffers_.end()) {
      total_nbytes_ -= it->second.buf.nbytes;
      free_host_buffer(it->second.buf);
      lru_.erase(it->second.it);
      buffers_.erase(it);
    }

    if (max_bytes_ > 0 && nbytes > max_bytes_) {
      oversize_bypass_++;
      return allocate_host_buffer(nbytes);
    }

    evict_until_fit_locked(nbytes, key);
    HostBuffer hb = allocate_host_buffer(nbytes);
    lru_.push_back(key);
    Entry e;
    e.buf = hb;
    e.it = std::prev(lru_.end());
    buffers_[key] = e;
    total_nbytes_ += hb.nbytes;
    high_watermark_bytes_ = std::max(high_watermark_bytes_, total_nbytes_);
    return hb;
  }

  void clear() {
    std::lock_guard<std::mutex> g(lock_);
    for (auto& kv : buffers_) {
      free_host_buffer(kv.second.buf);
    }
    buffers_.clear();
    lru_.clear();
    total_nbytes_ = 0;
  }

  PinnedPoolTelemetry stats() const {
    std::lock_guard<std::mutex> g(const_cast<std::mutex&>(lock_));
    PinnedPoolTelemetry out;
    out.buffers_allocated = buffers_.size();
    out.total_nbytes = total_nbytes_;
    out.max_bytes = max_bytes_;
    out.high_watermark_bytes = high_watermark_bytes_;
    out.pinned_enabled = 1;
    out.pool_hits = hits_;
    out.pool_misses = misses_;
    out.pool_evictions = evictions_;
    out.alloc_fallbacks = alloc_fallbacks_;
    out.oversize_bypass = oversize_bypass_;
    out.hit_rate_pct = (hits_ + misses_) ? (100.0 * static_cast<double>(hits_) / static_cast<double>(hits_ + misses_)) : 0.0;
    return out;
  }

 private:
  struct Entry {
    HostBuffer buf;
    std::list<std::string>::iterator it;
  };

  HostBuffer allocate_host_buffer(size_t nbytes) {
    HostBuffer hb;
    hb.nbytes = nbytes;
    hb.pinned = true;
    if (cudaHostAlloc(reinterpret_cast<void**>(&hb.ptr), nbytes, cudaHostAllocPortable) != cudaSuccess) {
      alloc_fallbacks_++;
      hb.pinned = false;
      hb.ptr = static_cast<uint8_t*>(std::malloc(nbytes));
      if (!hb.ptr) {
        throw GPUMemoryError("PinnedHostBufferPool host allocation failed");
      }
    }
    return hb;
  }

  void free_host_buffer(const HostBuffer& hb) {
    if (!hb.ptr) {
      return;
    }
    if (hb.pinned) {
      cudaFreeHost(hb.ptr);
    } else {
      std::free(hb.ptr);
    }
  }

  void evict_until_fit_locked(size_t extra_nbytes, const std::string& protect_slot) {
    if (max_bytes_ <= 0) {
      return;
    }
    while (!lru_.empty() && (total_nbytes_ + extra_nbytes) > max_bytes_) {
      const std::string victim = lru_.front();
      if (!protect_slot.empty() && victim == protect_slot) {
        break;
      }
      auto it = buffers_.find(victim);
      if (it == buffers_.end()) {
        lru_.pop_front();
        continue;
      }
      total_nbytes_ -= it->second.buf.nbytes;
      free_host_buffer(it->second.buf);
      lru_.erase(it->second.it);
      buffers_.erase(it);
      evictions_++;
    }
  }

  mutable std::mutex lock_;
  size_t max_bytes_ = 0;
  int limit_mb_seen_ = 0;
  std::unordered_map<std::string, Entry> buffers_;
  std::list<std::string> lru_;
  size_t total_nbytes_ = 0;
  uint64_t hits_ = 0;
  uint64_t misses_ = 0;
  uint64_t evictions_ = 0;
  uint64_t alloc_fallbacks_ = 0;
  uint64_t oversize_bypass_ = 0;
  uint64_t high_watermark_bytes_ = 0;
};

std::unique_ptr<GPUMemoryPool> g_gpu_memory_pool;
std::unique_ptr<PinnedHostBufferPool> g_pinned_host_pool;

GPUMemoryPool& get_memory_pool_impl() {
  if (!g_gpu_memory_pool) {
    g_gpu_memory_pool = std::make_unique<GPUMemoryPool>();
  }
  return *g_gpu_memory_pool;
}

PinnedHostBufferPool& get_pinned_pool_impl() {
  if (!g_pinned_host_pool) {
    g_pinned_host_pool = std::make_unique<PinnedHostBufferPool>();
  }
  return *g_pinned_host_pool;
}

bool update_gpu_constant_template(const uint8_t* host_data, size_t nbytes) {
  g_const_update_available.store(true);
  if (nbytes > TEMPLATE_CONST_MAX) {
    return false;
  }

  ConstantFingerprint fp = const_payload_fingerprint(host_data, nbytes);
  if (fp == g_template_const_fp) {
    return true;
  }

  throw_if_cuda(cudaMemcpyToSymbol(TEMPLATE_CONST_DEV, host_data, nbytes, 0, cudaMemcpyHostToDevice),
                "cudaMemcpyToSymbol TEMPLATE_CONST_DEV failed");
  if (nbytes < TEMPLATE_CONST_MAX) {
    static std::vector<uint8_t> zeros(TEMPLATE_CONST_MAX, 0);
    throw_if_cuda(cudaMemcpyToSymbol(
                     TEMPLATE_CONST_DEV,
                     zeros.data(),
                     TEMPLATE_CONST_MAX - nbytes,
                     nbytes,
                     cudaMemcpyHostToDevice),
                 "cudaMemcpyToSymbol TEMPLATE_CONST_DEV zero-fill failed");
  }
  g_template_const_fp = fp;
  return true;
}

bool update_gpu_constant_pool(const uint8_t* host_data, size_t nbytes) {
  g_const_update_available.store(true);
  if (nbytes > POOL_CONST_MAX) {
    return false;
  }

  ConstantFingerprint fp = const_payload_fingerprint(host_data, nbytes);
  if (fp == g_pool_const_fp) {
    return true;
  }

  throw_if_cuda(cudaMemcpyToSymbol(POOL_CONST_DEV, host_data, nbytes, 0, cudaMemcpyHostToDevice),
                "cudaMemcpyToSymbol POOL_CONST_DEV failed");
  if (nbytes < POOL_CONST_MAX) {
    static std::vector<uint8_t> zeros(POOL_CONST_MAX, 0);
    throw_if_cuda(cudaMemcpyToSymbol(
                     POOL_CONST_DEV,
                     zeros.data(),
                     POOL_CONST_MAX - nbytes,
                     nbytes,
                     cudaMemcpyHostToDevice),
                 "cudaMemcpyToSymbol POOL_CONST_DEV zero-fill failed");
  }
  g_pool_const_fp = fp;
  return true;
}

TemplateAcquisition acquire_template_gpu(const uint8_t* host_data,
                                         size_t nbytes,
                                         int packet_size,
                                         cudaStream_t stream) {
  if (nbytes > 0 && !host_data) {
    throw std::invalid_argument("template data pointer is null");
  }
  const int dev = active_device_id();
  const std::string key =
      std::to_string(dev) + ":" + template_digest(host_data, nbytes) + ":" + std::to_string(packet_size);
  const int limit = gpu_cache_limit();

  {
    std::lock_guard<std::mutex> lock(g_generation_lock);
    if (limit > 0) {
      auto it = g_template_cache.find(key);
      if (it != g_template_cache.end()) {
        auto lit = g_template_lru_idx.find(key);
        if (lit != g_template_lru_idx.end()) {
          g_template_lru.erase(lit->second);
        }
        g_template_lru.push_back(key);
        g_template_lru_idx[key] = std::prev(g_template_lru.end());
        telemetry_inc(g_generation_telemetry.gpu_template_cache_hit_count);
        return TemplateAcquisition{it->second.first, it->second.second, false};
      }
      telemetry_inc(g_generation_telemetry.gpu_template_cache_miss_count);
    } else {
      telemetry_inc(g_generation_telemetry.gpu_template_cache_miss_count);
    }
  }

  uint8_t* dptr = nullptr;
  throw_if_cuda(cudaMalloc(&dptr, nbytes), "cudaMalloc template_gpu failed");
  throw_if_cuda(cudaMemcpyAsync(dptr, host_data, nbytes, cudaMemcpyHostToDevice, stream),
                "cudaMemcpyAsync template_gpu failed");

  TemplateAcquisition out{dptr, nbytes, false};
  {
    std::lock_guard<std::mutex> lock(g_generation_lock);
    telemetry_inc(g_generation_telemetry.gpu_template_h2d_copy_count);
    telemetry_inc(g_generation_telemetry.gpu_template_h2d_copy_bytes, nbytes);

    if (limit > 0) {
      g_template_cache[key] = {dptr, nbytes};
      g_template_lru.push_back(key);
      g_template_lru_idx[key] = std::prev(g_template_lru.end());

      while (static_cast<int>(g_template_cache.size()) > limit && !g_template_lru.empty()) {
        const std::string evict_key = g_template_lru.front();
        g_template_lru.pop_front();
        g_template_lru_idx.erase(evict_key);
        auto eit = g_template_cache.find(evict_key);
        if (eit != g_template_cache.end()) {
          if (eit->second.first) {
            cudaFree(eit->second.first);
          }
          g_template_cache.erase(eit);
        }
      }
    } else {
      out.temporary = true;
    }
  }

  return out;
}

TemplateAcquisition acquire_template_gpu(const std::vector<uint8_t>& host_array,
                                         int packet_size,
                                         cudaStream_t stream) {
  return acquire_template_gpu(host_array.data(), host_array.size(), packet_size, stream);
}

RNGAcquisition acquire_rng_states(int64_t count, cudaStream_t stream) {
  count = std::max<int64_t>(1, count);
  const int dev = active_device_id();
  const std::string skey = stream_cache_key(stream);
  const std::string key = std::to_string(dev) + ":" + std::to_string(count) + ":" + skey;
  const int limit = rng_pool_limit();

  {
    std::lock_guard<std::mutex> lock(g_generation_lock);
    if (limit > 0) {
      auto it = g_rng_state_pool.find(key);
      if (it != g_rng_state_pool.end()) {
        auto lit = g_rng_lru_idx.find(key);
        if (lit != g_rng_lru_idx.end()) {
          g_rng_lru.erase(lit->second);
        }
        g_rng_lru.push_back(key);
        g_rng_lru_idx[key] = std::prev(g_rng_lru.end());
        telemetry_inc(g_generation_telemetry.gpu_rng_state_reuse_count);
        return RNGAcquisition{it->second, false};
      }
    }
  }

  curandStatePhilox4_32_10_t* states = nullptr;
  throw_if_cuda(cudaMalloc(&states, sizeof(curandStatePhilox4_32_10_t) * static_cast<size_t>(count)),
                "cudaMalloc rng_states failed");

  const int blocks = static_cast<int>((count + kThreadsPerBlock - 1) / kThreadsPerBlock);
  CUDA_KERNEL_LAUNCH(init_rng_states_kernel, blocks, kThreadsPerBlock, stream, states, count, now_seed());
  safe_kernel_launch("init_rng_states_kernel", cudaPeekAtLastError(), stream, false);

  RNGAcquisition out{states, false};
  {
    std::lock_guard<std::mutex> lock(g_generation_lock);
    telemetry_inc(g_generation_telemetry.gpu_rng_state_alloc_count);
    if (limit > 0) {
      g_rng_state_pool[key] = states;
      g_rng_lru.push_back(key);
      g_rng_lru_idx[key] = std::prev(g_rng_lru.end());
      while (static_cast<int>(g_rng_state_pool.size()) > limit && !g_rng_lru.empty()) {
        const std::string evict_key = g_rng_lru.front();
        g_rng_lru.pop_front();
        g_rng_lru_idx.erase(evict_key);
        auto eit = g_rng_state_pool.find(evict_key);
        if (eit != g_rng_state_pool.end()) {
          cudaFree(eit->second);
          g_rng_state_pool.erase(eit);
        }
      }
    } else {
      out.temporary = true;
    }
  }

  return out;
}

__device__ __forceinline__ uint16_t read_uint16_be(const uint8_t* buffer, int64_t offset) {
  return static_cast<uint16_t>((static_cast<uint16_t>(buffer[offset]) << 8) |
                               static_cast<uint16_t>(buffer[offset + 1]));
}

__device__ __forceinline__ uint32_t read_uint32_be(const uint8_t* buffer, int64_t offset) {
  return (static_cast<uint32_t>(buffer[offset]) << 24) |
         (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
         (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
         static_cast<uint32_t>(buffer[offset + 3]);
}

__device__ __forceinline__ uint32_t read_uint32_le(const uint8_t* buffer, int64_t offset) {
  return static_cast<uint32_t>(buffer[offset]) |
         (static_cast<uint32_t>(buffer[offset + 1]) << 8) |
         (static_cast<uint32_t>(buffer[offset + 2]) << 16) |
         (static_cast<uint32_t>(buffer[offset + 3]) << 24);
}

__device__ __forceinline__ void write_uint16_be(uint8_t* buffer, int64_t offset, uint16_t value) {
  buffer[offset] = static_cast<uint8_t>((value >> 8) & 0xFF);
  buffer[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

__device__ __forceinline__ void write_uint32_be(uint8_t* buffer, int64_t offset, uint32_t value) {
  buffer[offset] = static_cast<uint8_t>((value >> 24) & 0xFF);
  buffer[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  buffer[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  buffer[offset + 3] = static_cast<uint8_t>(value & 0xFF);
}

__device__ __forceinline__ void write_uint32_le(uint8_t* buffer, int64_t offset, uint32_t value) {
  buffer[offset] = static_cast<uint8_t>(value & 0xFF);
  buffer[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  buffer[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
  buffer[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

__device__ __forceinline__ uint16_t fold_ones_complement(uint64_t sum32) {
  uint64_t acc = sum32 & 0xFFFFFFFFull;
  while ((acc >> 16) > 0) {
    acc = (acc & 0xFFFFull) + (acc >> 16);
  }
  return static_cast<uint16_t>(acc & 0xFFFFull);
}

__device__ uint16_t calculate_checksum(const uint8_t* buffer, int64_t offset, int64_t length) {
  uint64_t checksum = 0;

  int64_t num_chunks = length / 4;
  for (int64_t i = 0; i < num_chunks; ++i) {
    int64_t base = offset + (i * 4);
    uint8_t b0 = buffer[base];
    uint8_t b1 = buffer[base + 1];
    uint8_t b2 = buffer[base + 2];
    uint8_t b3 = buffer[base + 3];
    checksum += (static_cast<uint16_t>(b0) << 8) | b1;
    checksum += (static_cast<uint16_t>(b2) << 8) | b3;
  }

  int64_t rem_offset = offset + (num_chunks * 4);
  int64_t remainder = length % 4;
  if (remainder >= 2) {
    checksum += (static_cast<uint16_t>(buffer[rem_offset]) << 8) | buffer[rem_offset + 1];
    if (remainder == 3) {
      checksum += static_cast<uint16_t>(buffer[rem_offset + 2]) << 8;
    }
  } else if (remainder == 1) {
    checksum += static_cast<uint16_t>(buffer[rem_offset]) << 8;
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFFull) + (checksum >> 16);
  }

  return static_cast<uint16_t>((~checksum) & 0xFFFFull);
}

__device__ uint16_t rfc1624_update_word(uint16_t old_checksum, uint16_t old_word, uint16_t new_word) {
  uint64_t old_c = old_checksum & 0xFFFFu;
  uint64_t old_w = old_word & 0xFFFFu;
  uint64_t new_w = new_word & 0xFFFFu;
  uint64_t sum32 = (old_c ^ 0xFFFFu) + (old_w ^ 0xFFFFu) + new_w;
  uint16_t folded = fold_ones_complement(sum32);
  return static_cast<uint16_t>((folded ^ 0xFFFFu) & 0xFFFFu);
}

__device__ uint16_t rfc1624_update_dword(uint16_t old_checksum, uint32_t old_dword, uint32_t new_dword) {
  uint16_t csum = old_checksum;
  csum = rfc1624_update_word(csum, static_cast<uint16_t>((old_dword >> 16) & 0xFFFFu),
                             static_cast<uint16_t>((new_dword >> 16) & 0xFFFFu));
  csum = rfc1624_update_word(csum, static_cast<uint16_t>(old_dword & 0xFFFFu),
                             static_cast<uint16_t>(new_dword & 0xFFFFu));
  return csum;
}

__device__ __forceinline__ uint32_t calculate_pseudo_header_sum(uint32_t src_ip,
                                                                 uint32_t dst_ip,
                                                                 uint8_t protocol,
                                                                 uint16_t length) {
  uint32_t checksum = 0;
  checksum += (src_ip >> 16) & 0xFFFFu;
  checksum += src_ip & 0xFFFFu;
  checksum += (dst_ip >> 16) & 0xFFFFu;
  checksum += dst_ip & 0xFFFFu;
  checksum += protocol;
  checksum += length;
  return checksum;
}

__device__ uint16_t calculate_tcp_checksum_optimized(const uint8_t* buffer,
                                                     int64_t offset,
                                                     int64_t length,
                                                     uint32_t src_ip,
                                                     uint32_t dst_ip) {
  uint64_t checksum = calculate_pseudo_header_sum(src_ip, dst_ip, TCP_PROTOCOL, static_cast<uint16_t>(length));

  int64_t num_chunks = length / 4;
  for (int64_t i = 0; i < num_chunks; ++i) {
    int64_t base = offset + (i * 4);
    uint8_t b0 = buffer[base];
    uint8_t b1 = buffer[base + 1];
    uint8_t b2 = buffer[base + 2];
    uint8_t b3 = buffer[base + 3];
    checksum += (static_cast<uint16_t>(b0) << 8) | b1;
    checksum += (static_cast<uint16_t>(b2) << 8) | b3;
  }

  int64_t rem_offset = offset + (num_chunks * 4);
  int64_t remainder = length % 4;
  if (remainder >= 2) {
    checksum += (static_cast<uint16_t>(buffer[rem_offset]) << 8) | buffer[rem_offset + 1];
    if (remainder == 3) {
      checksum += static_cast<uint16_t>(buffer[rem_offset + 2]) << 8;
    }
  } else if (remainder == 1) {
    checksum += static_cast<uint16_t>(buffer[rem_offset]) << 8;
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFFull) + (checksum >> 16);
  }
  return static_cast<uint16_t>((~checksum) & 0xFFFFull);
}

__device__ uint16_t calculate_udp_checksum_optimized(const uint8_t* buffer,
                                                     int64_t offset,
                                                     int64_t length,
                                                     uint32_t src_ip,
                                                     uint32_t dst_ip) {
  uint64_t checksum = calculate_pseudo_header_sum(src_ip, dst_ip, UDP_PROTOCOL, static_cast<uint16_t>(length));

  int64_t num_chunks = length / 4;
  for (int64_t i = 0; i < num_chunks; ++i) {
    int64_t base = offset + (i * 4);
    uint8_t b0 = buffer[base];
    uint8_t b1 = buffer[base + 1];
    uint8_t b2 = buffer[base + 2];
    uint8_t b3 = buffer[base + 3];
    checksum += (static_cast<uint16_t>(b0) << 8) | b1;
    checksum += (static_cast<uint16_t>(b2) << 8) | b3;
  }

  int64_t rem_offset = offset + (num_chunks * 4);
  int64_t remainder = length % 4;
  if (remainder >= 2) {
    checksum += (static_cast<uint16_t>(buffer[rem_offset]) << 8) | buffer[rem_offset + 1];
    if (remainder == 3) {
      checksum += static_cast<uint16_t>(buffer[rem_offset + 2]) << 8;
    }
  } else if (remainder == 1) {
    checksum += static_cast<uint16_t>(buffer[rem_offset]) << 8;
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFFull) + (checksum >> 16);
  }
  uint16_t res = static_cast<uint16_t>((~checksum) & 0xFFFFull);
  return (res == 0) ? 0xFFFFu : res;
}

__device__ uint16_t calculate_icmp_checksum(const uint8_t* buffer, int64_t offset, int64_t length) {
  uint64_t checksum = 0;
  int64_t num_words = length / 2;
  for (int64_t i = 0; i < num_words; ++i) {
    int64_t base = offset + (i * 2);
    uint16_t word = static_cast<uint16_t>((buffer[base] << 8) | buffer[base + 1]);
    checksum += word;
  }

  if (length % 2 == 1) {
    checksum += static_cast<uint16_t>(buffer[offset + length - 1] << 8);
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFFull) + (checksum >> 16);
  }

  return static_cast<uint16_t>((~checksum) & 0xFFFFull);
}

__device__ uint16_t calculate_tcp_checksum_from_header_and_payload(
    const uint8_t* packet_buffer,
    int64_t tcp_offset,
    int64_t tcp_header_len,
    const uint8_t* payload_buffer,
    int64_t payload_size,
    int64_t payload_total_len,
    uint32_t src_ip,
    uint32_t dst_ip) {
  uint64_t checksum = calculate_pseudo_header_sum(
      src_ip, dst_ip, TCP_PROTOCOL, static_cast<uint16_t>(tcp_header_len + payload_total_len));

  for (int64_t i = 0; i < tcp_header_len; i += 2) {
    checksum += (packet_buffer[tcp_offset + i] << 8) | packet_buffer[tcp_offset + i + 1];
  }

  for (int64_t i = 0; i < payload_total_len; i += 2) {
    uint8_t b0 = (i < payload_size) ? payload_buffer[i] : 0;
    if (i + 1 < payload_total_len) {
      uint8_t b1 = (i + 1 < payload_size) ? payload_buffer[i + 1] : 0;
      checksum += (static_cast<uint16_t>(b0) << 8) | b1;
    } else {
      checksum += static_cast<uint16_t>(b0) << 8;
    }
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFFull) + (checksum >> 16);
  }

  return static_cast<uint16_t>((~checksum) & 0xFFFFull);
}

__device__ __forceinline__ float rng_uniform(curandStatePhilox4_32_10_t& local_state) {
  return curand_uniform(&local_state);
}

__device__ uint16_t select_tcp_window(int64_t user_tcp_window,
                                      curandStatePhilox4_32_10_t& local_state) {
  if (user_tcp_window >= 0) {
    return static_cast<uint16_t>(user_tcp_window & 0xFFFF);
  }
  int os_selector = static_cast<int>(rng_uniform(local_state) * 6.0f);
  if (os_selector == 0) {
    return 64240;
  }
  if (os_selector == 1) {
    return 65535;
  }
  if (os_selector == 2) {
    return 29200;
  }
  if (os_selector == 3) {
    return 65535;
  }
  if (os_selector == 4) {
    return 65535;
  }
  return 32768;
}

__device__ void write_l2_l3_ipv4_header(uint8_t* packets_buffer,
                                        int64_t packet_offset,
                                        int64_t has_ethernet,
                                        uint64_t gateway_mac,
                                        uint16_t ip_total_len,
                                        uint16_t ip_id,
                                        uint8_t ip_ttl,
                                        uint8_t protocol,
                                        uint32_t src_ip_int,
                                        uint32_t target_ip_int) {
  int64_t current_offset = packet_offset;
  if (has_ethernet == 1) {
    packets_buffer[current_offset] = (gateway_mac >> 40) & 0xFF;
    packets_buffer[current_offset + 1] = (gateway_mac >> 32) & 0xFF;
    packets_buffer[current_offset + 2] = (gateway_mac >> 24) & 0xFF;
    packets_buffer[current_offset + 3] = (gateway_mac >> 16) & 0xFF;
    packets_buffer[current_offset + 4] = (gateway_mac >> 8) & 0xFF;
    packets_buffer[current_offset + 5] = gateway_mac & 0xFF;
    write_uint32_be(packets_buffer, current_offset + 6, 0x00000000u);
    write_uint16_be(packets_buffer, current_offset + 10, 0x0000u);
    write_uint16_be(packets_buffer, current_offset + 12, 0x0800u);
    current_offset += ETHERNET_HEADER_LEN;
  }

  int64_t ip_offset = current_offset;
  write_uint16_be(packets_buffer, ip_offset, 0x4500u);
  write_uint16_be(packets_buffer, ip_offset + 2, ip_total_len);
  write_uint16_be(packets_buffer, ip_offset + 4, ip_id);
  write_uint16_be(packets_buffer, ip_offset + 6, 0u);
  packets_buffer[ip_offset + 8] = ip_ttl;
  packets_buffer[ip_offset + 9] = protocol;
  write_uint16_be(packets_buffer, ip_offset + 10, 0u);
  write_uint32_be(packets_buffer, ip_offset + 12, src_ip_int);
  write_uint32_be(packets_buffer, ip_offset + 16, target_ip_int);
  uint16_t ip_csum = calculate_checksum(packets_buffer, ip_offset, IP_HEADER_LEN);
  write_uint16_be(packets_buffer, ip_offset + 10, ip_csum);
}

#if defined(__INTELLISENSE__) && !defined(SAMURAI_GPU_PACKET_CUDA_FRAGMENT_CHAIN)
}  // namespace
}  // namespace ddos_samurai::gpu_packet_cuda
#endif

#endif  // SAMURAI_GPU_PACKET_CUDA_PREAMBLE_INCLUDED
