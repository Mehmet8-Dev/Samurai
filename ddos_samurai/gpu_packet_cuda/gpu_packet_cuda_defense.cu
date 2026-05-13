#include "kernels_defense_feature.cuh"
#include "kernels_defense_rdma_adapter.cuh"
#include "kernels_defense_tensorrt.cuh"

#ifndef SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
#define SAMURAI_WITH_DOCA_GPUNETIO_DEVICE 0
#endif
#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
#include <doca_gpunetio_dev_buf.cuh>
#include <doca_gpunetio_dev_eth_rxq.cuh>
#endif

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace ddos_samurai::gpu_packet_cuda::defense {

using Clock = std::chrono::steady_clock;

enum class RdmaMode {
  kAuto = 0,
  kDirect = 1,
  kHostStaging = 2,
  kDocaGpuNetIO = 3,
};

enum class IngressPath {
  kRdmaGpuDirect = 0,
  kRdmaHostStaging = 1,
  kAfXdpHost = 2,
  kDocaGpuNetIoRx = 3,
  kFail = 4,
};

struct EngineMetadata {
  std::string sm;
  std::string trt_version;
  std::string engine_sha256;
  bool offline_built = false;
};

struct DefenseRuntime {
  bool initialized = false;
  bool strict = false;
  bool direct_active = false;
  bool host_staging_active = false;
  bool af_xdp_host_active = false;
  bool doca_rx_active = false;
  bool doca_rx_device_path_requested = false;
  bool doca_rx_device_path_active = false;
  bool doca_flow_steering_active = false;
  uint32_t doca_flow_proto_mask = 0u;
  int doca_rx_rr_cursor = 0;
  int doca_rxq_handle = -1;
  uint64_t doca_gpu_rxq_handle = 0ull;
  std::vector<int> doca_rxq_handles{};
  std::vector<uint64_t> doca_gpu_rxq_handles{};
  uint64_t* doca_gpu_rxq_handles_dev = nullptr;
  RdmaMode rdma_mode = RdmaMode::kAuto;
  IngressPath ingress_path = IngressPath::kFail;
  int64_t max_batch_size = 1024;
  int64_t flush_timeout_ms = 2;
  std::string runtime = "tensorrt";
  std::string engine_path;
  std::string expected_sm;
  std::string expected_trt_version;

  uint64_t infer_calls = 0;
  uint64_t infer_packets = 0;
  uint64_t label0_count = 0;
  uint64_t label1_count = 0;
  double confidence_sum = 0.0;
  std::string fallback_reason = "none";

  // Stream overlap + latency telemetry.
  std::vector<double> latency_ms_window;
  uint64_t queue_backpressure = 0;
  uint64_t stream_overlap_events = 0;
  uint64_t total_batches = 0;
  uint64_t doca_rx_polls = 0;
  uint64_t doca_rx_packets = 0;
  uint64_t doca_rx_poll_errors = 0;
  uint64_t doca_rx_drops = 0;
  uint64_t doca_rx_device_polls = 0;
  uint64_t doca_rx_device_packets = 0;
  uint64_t doca_rx_device_poll_errors = 0;
  uint64_t doca_rx_device_drops = 0;
  std::vector<uint64_t> ingress_packet_ptrs_scratch{};
  std::vector<uint64_t> ingress_packet_handles_scratch{};
  std::vector<uint16_t> ingress_lengths_u16_scratch{};
  std::vector<PacketView> ingress_views_scratch{};
  uint64_t* ingress_packet_ptrs_dev = nullptr;
  uint16_t* ingress_lengths_u16_dev = nullptr;
  uint32_t* ingress_device_meta_dev = nullptr;  // received, valid, drops, status
  size_t ingress_device_capacity = 0u;
  Clock::time_point first_infer_at{};
  Clock::time_point last_infer_at{};
};

thread_local std::string g_defense_last_error;
DefenseRuntime g_runtime;
std::mutex g_runtime_mu;

int set_err(const std::string& reason) {
  g_defense_last_error = reason;
  return -1;
}

const char* rdma_mode_name(RdmaMode mode) {
  switch (mode) {
    case RdmaMode::kDirect:
      return "direct";
    case RdmaMode::kHostStaging:
      return "host_staging";
    case RdmaMode::kDocaGpuNetIO:
      return "doca_gpunetio";
    case RdmaMode::kAuto:
    default:
      return "auto";
  }
}

const char* ingress_path_name(IngressPath path) {
  switch (path) {
    case IngressPath::kRdmaGpuDirect:
      return "rdma_gpu_direct";
    case IngressPath::kRdmaHostStaging:
      return "rdma_host_staging";
    case IngressPath::kAfXdpHost:
      return "af_xdp_host";
    case IngressPath::kDocaGpuNetIoRx:
      return "doca_gpunetio_rx";
    case IngressPath::kFail:
    default:
      return "fail";
  }
}

RdmaMode parse_rdma_mode(const char* mode) {
  const std::string m = (mode == nullptr) ? "auto" : std::string(mode);
  if (m == "direct") {
    return RdmaMode::kDirect;
  }
  if (m == "host_staging") {
    return RdmaMode::kHostStaging;
  }
  if (m == "doca_gpunetio") {
    return RdmaMode::kDocaGpuNetIO;
  }
  return RdmaMode::kAuto;
}

bool env_flag(const char* key, bool fallback) {
  const char* raw = std::getenv(key);
  if (raw == nullptr) {
    return fallback;
  }
  std::string s(raw);
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s == "1" || s == "true" || s == "yes" || s == "on";
}

std::string env_string(const char* key, const std::string& fallback = "") {
  const char* raw = std::getenv(key);
  if (raw == nullptr) {
    return fallback;
  }
  return std::string(raw);
}

int env_int_clamped(const char* key, int fallback, int minv, int maxv) {
  const char* raw = std::getenv(key);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }
  char* end = nullptr;
  const long parsed = std::strtol(raw, &end, 10);
  if (end == raw || (end != nullptr && *end != '\0')) {
    return fallback;
  }
  if (parsed < static_cast<long>(minv)) {
    return minv;
  }
  if (parsed > static_cast<long>(maxv)) {
    return maxv;
  }
  return static_cast<int>(parsed);
}

uint32_t env_u32(const char* key, uint32_t fallback) {
  const char* raw = std::getenv(key);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(raw, &end, 0);
  if (end == raw || (end != nullptr && *end != '\0')) {
    return fallback;
  }
  if (parsed > static_cast<unsigned long long>(std::numeric_limits<uint32_t>::max())) {
    return std::numeric_limits<uint32_t>::max();
  }
  return static_cast<uint32_t>(parsed);
}

void release_ingress_device_buffers(DefenseRuntime* rt) {
  if (rt == nullptr) {
    return;
  }
  if (rt->ingress_packet_ptrs_dev != nullptr) {
    (void)cudaFree(rt->ingress_packet_ptrs_dev);
    rt->ingress_packet_ptrs_dev = nullptr;
  }
  if (rt->ingress_lengths_u16_dev != nullptr) {
    (void)cudaFree(rt->ingress_lengths_u16_dev);
    rt->ingress_lengths_u16_dev = nullptr;
  }
  if (rt->ingress_device_meta_dev != nullptr) {
    (void)cudaFree(rt->ingress_device_meta_dev);
    rt->ingress_device_meta_dev = nullptr;
  }
  if (rt->doca_gpu_rxq_handles_dev != nullptr) {
    (void)cudaFree(rt->doca_gpu_rxq_handles_dev);
    rt->doca_gpu_rxq_handles_dev = nullptr;
  }
  rt->ingress_device_capacity = 0u;
}

#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
__global__ void doca_rx_receive_burst_kernel(
    const uint64_t* gpu_rxq_handles,
    uint32_t gpu_rxq_handle_count,
    uint32_t rr_cursor,
    uint32_t max_packets,
    uint32_t max_packet_size,
    uint64_t timeout_ns,
    uint64_t* out_packet_ptrs,
    uint16_t* out_lengths,
    uint32_t* out_meta) {
  // out_meta layout: [0]=received, [1]=valid, [2]=drops, [3]=status
  if (blockIdx.x != 0) {
    return;
  }
  __shared__ uint32_t rx_pkt_num;
  __shared__ uint64_t rx_buf_idx;
  __shared__ uint32_t rx_status;
  __shared__ uint64_t selected_gpu_rxq_handle;
  if (threadIdx.x == 0) {
    rx_pkt_num = 0u;
    rx_buf_idx = 0u;
    rx_status = 0u;
    selected_gpu_rxq_handle = 0ull;
    if (gpu_rxq_handles != nullptr && gpu_rxq_handle_count > 0u) {
      const uint32_t idx = rr_cursor % gpu_rxq_handle_count;
      selected_gpu_rxq_handle = gpu_rxq_handles[idx];
    }
    out_meta[0] = 0u;
    out_meta[1] = 0u;
    out_meta[2] = 0u;
    out_meta[3] = 0u;
  }
  __syncthreads();

  if (selected_gpu_rxq_handle == 0ull) {
    if (threadIdx.x == 0) {
      out_meta[3] = std::numeric_limits<uint32_t>::max();
    }
    return;
  }

  auto* rxq = reinterpret_cast<doca_gpu_eth_rxq*>(selected_gpu_rxq_handle);
  const doca_error_t rc = doca_gpu_dev_eth_rxq_receive_block(rxq, max_packets, timeout_ns, &rx_pkt_num, &rx_buf_idx);
  if (threadIdx.x == 0 && rc != 0) {
    rx_status = static_cast<uint32_t>(rc);
  }
  __syncthreads();

  if (rx_status != 0u) {
    if (threadIdx.x == 0) {
      out_meta[3] = rx_status;
    }
    return;
  }
  const uint32_t received = rx_pkt_num;
  if (received == 0u) {
    return;
  }

  for (uint32_t i = static_cast<uint32_t>(threadIdx.x); i < received; i += static_cast<uint32_t>(blockDim.x)) {
    doca_gpu_buf* buf_ptr = nullptr;
    const doca_error_t rc_buf = doca_gpu_dev_eth_rxq_get_buf(rxq, rx_buf_idx + static_cast<uint64_t>(i), &buf_ptr);
    if (rc_buf != 0 || buf_ptr == nullptr) {
      atomicAdd(&out_meta[2], 1u);
      continue;
    }
    uintptr_t pkt_addr = 0u;
    const doca_error_t rc_addr = doca_gpu_dev_buf_get_addr(buf_ptr, &pkt_addr);
    if (rc_addr != 0 || pkt_addr == 0u) {
      atomicAdd(&out_meta[2], 1u);
      continue;
    }

    out_packet_ptrs[i] = static_cast<uint64_t>(pkt_addr);
    out_lengths[i] = static_cast<uint16_t>(max_packet_size > 65535u ? 65535u : max_packet_size);
    atomicAdd(&out_meta[1], 1u);
  }
  __syncthreads();
  if (threadIdx.x == 0) {
    out_meta[0] = received;
  }
}
#endif

std::optional<std::string> extract_json_string(const std::string& json_text, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  const size_t k = json_text.find(needle);
  if (k == std::string::npos) {
    return std::nullopt;
  }
  const size_t colon = json_text.find(':', k + needle.size());
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  size_t q1 = json_text.find('"', colon + 1);
  if (q1 == std::string::npos) {
    return std::nullopt;
  }
  size_t q2 = json_text.find('"', q1 + 1);
  if (q2 == std::string::npos || q2 <= q1) {
    return std::nullopt;
  }
  return json_text.substr(q1 + 1, q2 - q1 - 1);
}

std::optional<bool> extract_json_bool(const std::string& json_text, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  const size_t k = json_text.find(needle);
  if (k == std::string::npos) {
    return std::nullopt;
  }
  const size_t colon = json_text.find(':', k + needle.size());
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  size_t p = colon + 1;
  while (p < json_text.size() && std::isspace(static_cast<unsigned char>(json_text[p])) != 0) {
    ++p;
  }
  if (json_text.compare(p, 4, "true") == 0) {
    return true;
  }
  if (json_text.compare(p, 5, "false") == 0) {
    return false;
  }
  return std::nullopt;
}

std::optional<EngineMetadata> load_engine_metadata(const std::string& engine_path) {
  const std::string meta_path = engine_path + ".meta.json";
  std::ifstream in(meta_path);
  if (!in.good()) {
    return std::nullopt;
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  const std::string text = oss.str();

  EngineMetadata m;
  m.sm = extract_json_string(text, "sm").value_or("");
  m.trt_version = extract_json_string(text, "trt_version").value_or("");
  m.engine_sha256 = extract_json_string(text, "engine_sha256").value_or("");
  m.offline_built = extract_json_bool(text, "offline_built").value_or(false);
  return m;
}

std::string percentile_ms(std::vector<double> values, double p) {
  if (values.empty()) {
    return "0";
  }
  std::sort(values.begin(), values.end());
  const double rank = (p / 100.0) * static_cast<double>(values.size() - 1);
  const size_t idx = static_cast<size_t>(rank);
  std::ostringstream oss;
  oss << values[idx];
  return oss.str();
}

struct RdmaDecision {
  IngressPath ingress = IngressPath::kFail;
  bool direct_active = false;
  bool host_staging_active = false;
  bool af_xdp_host_active = false;
  bool doca_rx_active = false;
  std::string reason = "none";
};

using DocaCreateRxqFn = int (*)(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len);
using DocaDestroyRxqFn = int (*)(int handle, char* err, size_t err_len);
using DocaReceiveBurstFn = int (*)(
    int handle,
    uint8_t* out_packets_flat,
    uint32_t out_packets_flat_len,
    uint16_t* out_lengths,
    int max_packets,
    int* out_received,
    char* err,
    size_t err_len);
using DocaReceiveBurstViewFn = int (*)(
    int handle,
    uint64_t* out_packet_ptrs,
    uint16_t* out_lengths,
    uint64_t* out_packet_handles,
    int max_packets,
    int* out_received,
    char* err,
    size_t err_len);
using DocaReleaseBurstViewFn = int (*)(
    int handle,
    const uint64_t* packet_handles,
    int packet_count,
    int* out_rearmed,
    char* err,
    size_t err_len);
using DocaGetGpuRxqHandleFn = int (*)(int handle, uint64_t* out_gpu_rxq_handle, char* err, size_t err_len);
using DocaConfigureFlowSteeringFn = int (*)(
    const char* iface,
    const char* device_name,
    const int* rxq_handles,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    int strict,
    char* err,
    size_t err_len);

struct DocaRxDispatch {
  void* handle = nullptr;
  bool load_attempted = false;
  std::string load_error;
  DocaCreateRxqFn create_rxq = nullptr;
  DocaDestroyRxqFn destroy_rxq = nullptr;
  DocaReceiveBurstFn receive_burst = nullptr;
  DocaReceiveBurstViewFn receive_burst_view = nullptr;
  DocaReleaseBurstViewFn release_burst_view = nullptr;
  DocaGetGpuRxqHandleFn get_gpu_rxq_handle = nullptr;
  DocaConfigureFlowSteeringFn configure_flow_steering = nullptr;
};

DocaRxDispatch g_doca_rx{};

inline bool resolve_doca_rx_symbol(void* so, const char* name, void** out, std::string* why) {
  if (!so || !name || !out) {
    if (why != nullptr) {
      *why = "invalid doca rx symbol resolve inputs";
    }
    return false;
  }
  dlerror();
  void* sym = dlsym(so, name);
  const char* sym_err = dlerror();
  if (!sym || sym_err) {
    if (why != nullptr) {
      *why = std::string("dlsym(") + name + ") failed: " + (sym_err ? sym_err : "unknown");
    }
    return false;
  }
  *out = sym;
  return true;
}

bool ensure_doca_rx_dispatch(std::string* reason) {
  if (g_doca_rx.handle != nullptr && g_doca_rx.create_rxq != nullptr && g_doca_rx.destroy_rxq != nullptr &&
      g_doca_rx.receive_burst != nullptr && g_doca_rx.receive_burst_view != nullptr &&
      g_doca_rx.release_burst_view != nullptr && g_doca_rx.get_gpu_rxq_handle != nullptr) {
    return true;
  }
  if (g_doca_rx.load_attempted) {
    if (reason != nullptr) {
      *reason = g_doca_rx.load_error.empty() ? "doca_rx_unavailable" : g_doca_rx.load_error;
    }
    return false;
  }
  g_doca_rx.load_attempted = true;

  const std::string so_path = env_string("SAMURAI_GPU_DOCA_SHIM_SO", "libsamurai_doca_gpunetio_backend.so");
  dlerror();
  g_doca_rx.handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (g_doca_rx.handle == nullptr) {
    const char* err = dlerror();
    g_doca_rx.load_error = std::string("dlopen failed for DOCA RX backend: ") + (err ? err : "unknown");
    if (reason != nullptr) {
      *reason = g_doca_rx.load_error;
    }
    return false;
  }

  void* p_create_rxq = nullptr;
  void* p_destroy_rxq = nullptr;
  void* p_receive_burst = nullptr;
  void* p_receive_burst_view = nullptr;
  void* p_release_burst_view = nullptr;
  void* p_get_gpu_rxq_handle = nullptr;
  void* p_configure_flow_steering = nullptr;
  std::string sym_reason;
  if (!resolve_doca_rx_symbol(g_doca_rx.handle, "samurai_doca_backend_create_rxq", &p_create_rxq, &sym_reason) ||
      !resolve_doca_rx_symbol(g_doca_rx.handle, "samurai_doca_backend_destroy_rxq", &p_destroy_rxq, &sym_reason) ||
      !resolve_doca_rx_symbol(g_doca_rx.handle, "samurai_doca_backend_receive_burst", &p_receive_burst, &sym_reason) ||
      !resolve_doca_rx_symbol(
          g_doca_rx.handle,
          "samurai_doca_backend_receive_burst_view",
          &p_receive_burst_view,
          &sym_reason) ||
      !resolve_doca_rx_symbol(
          g_doca_rx.handle,
          "samurai_doca_backend_release_burst_view",
          &p_release_burst_view,
          &sym_reason) ||
      !resolve_doca_rx_symbol(
          g_doca_rx.handle,
          "samurai_doca_backend_get_gpu_rxq_handle",
          &p_get_gpu_rxq_handle,
          &sym_reason)) {
    g_doca_rx.load_error = sym_reason;
    dlclose(g_doca_rx.handle);
    g_doca_rx.handle = nullptr;
    if (reason != nullptr) {
      *reason = g_doca_rx.load_error;
    }
    return false;
  }
  g_doca_rx.create_rxq = reinterpret_cast<DocaCreateRxqFn>(p_create_rxq);
  g_doca_rx.destroy_rxq = reinterpret_cast<DocaDestroyRxqFn>(p_destroy_rxq);
  g_doca_rx.receive_burst = reinterpret_cast<DocaReceiveBurstFn>(p_receive_burst);
  g_doca_rx.receive_burst_view = reinterpret_cast<DocaReceiveBurstViewFn>(p_receive_burst_view);
  g_doca_rx.release_burst_view = reinterpret_cast<DocaReleaseBurstViewFn>(p_release_burst_view);
  g_doca_rx.get_gpu_rxq_handle = reinterpret_cast<DocaGetGpuRxqHandleFn>(p_get_gpu_rxq_handle);
  if (resolve_doca_rx_symbol(
          g_doca_rx.handle,
          "samurai_doca_backend_configure_flow_steering",
          &p_configure_flow_steering,
          nullptr)) {
    g_doca_rx.configure_flow_steering = reinterpret_cast<DocaConfigureFlowSteeringFn>(p_configure_flow_steering);
  } else {
    g_doca_rx.configure_flow_steering = nullptr;
  }
  return true;
}

bool try_activate_doca_rx(DefenseRuntime* rt, std::string* reason) {
  if (rt == nullptr) {
    if (reason != nullptr) {
      *reason = "doca_rx_init_failed";
    }
    return false;
  }
  std::string why;
  if (!ensure_doca_rx_dispatch(&why)) {
    if (reason != nullptr) {
      *reason = why.empty() ? "doca_rx_init_failed" : why;
    }
    return false;
  }
  const std::string iface = env_string("SAMURAI_GPU_RX_IFACE", "");
  const std::string device = env_string("SAMURAI_GPU_DOCA_DEVICE", "");
  const int gpu_id = [&]() {
    const char* raw = std::getenv("SAMURAI_GPU_DOCA_GPU_ID");
    if (!raw || !*raw) return 0;
    try {
      return std::max(0, std::stoi(raw));
    } catch (...) {
      return 0;
    }
  }();
  const int queue_id_base = env_int_clamped("SAMURAI_GPU_DOCA_RX_QUEUE_ID", 0, 0, 65535);
  const int queue_count = env_int_clamped("SAMURAI_GPU_DOCA_RX_QUEUE_COUNT", 1, 1, 64);
  const bool want_flow_steering = env_flag("SAMURAI_GPU_DOCA_FLOW_STEERING", queue_count > 1);
  const bool flow_steering_strict = env_flag("SAMURAI_GPU_DOCA_FLOW_STEERING_STRICT", rt->strict);
  const uint32_t flow_proto_mask = env_u32("SAMURAI_GPU_DOCA_FLOW_PROTO_MASK", 0x7u);
  if (iface.empty() || device.empty()) {
    if (reason != nullptr) {
      *reason = "doca_rx_init_failed";
    }
    return false;
  }
  if (rt->doca_gpu_rxq_handles_dev != nullptr) {
    (void)cudaFree(rt->doca_gpu_rxq_handles_dev);
    rt->doca_gpu_rxq_handles_dev = nullptr;
  }
  rt->doca_rxq_handles.clear();
  rt->doca_gpu_rxq_handles.clear();
  std::vector<int> queue_ids;
  queue_ids.reserve(static_cast<size_t>(queue_count));
  char errbuf[192];

  auto destroy_created = [&]() {
    if (g_doca_rx.destroy_rxq == nullptr) {
      return;
    }
    for (int h : rt->doca_rxq_handles) {
      if (h < 0) {
        continue;
      }
      char destroy_err[128];
      std::memset(destroy_err, 0, sizeof(destroy_err));
      (void)g_doca_rx.destroy_rxq(h, destroy_err, sizeof(destroy_err));
    }
  };

  for (int i = 0; i < queue_count; ++i) {
    const int queue_id = queue_id_base + i;
    int handle = -1;
    std::memset(errbuf, 0, sizeof(errbuf));
    const int rc = g_doca_rx.create_rxq(
        iface.c_str(),
        device.c_str(),
        gpu_id,
        queue_id,
        &handle,
        errbuf,
        sizeof(errbuf));
    if (rc < 0 || handle < 0) {
      destroy_created();
      rt->doca_rxq_handles.clear();
      rt->doca_gpu_rxq_handles.clear();
      if (reason != nullptr) {
        *reason = (errbuf[0] != '\0') ? std::string(errbuf) : "doca_rx_init_failed";
      }
      return false;
    }
    uint64_t gpu_rxq_handle = 0ull;
    std::memset(errbuf, 0, sizeof(errbuf));
    const int gpu_rc =
        g_doca_rx.get_gpu_rxq_handle(handle, &gpu_rxq_handle, errbuf, sizeof(errbuf));
    if (gpu_rc < 0 || gpu_rxq_handle == 0ull) {
      char destroy_err[128];
      std::memset(destroy_err, 0, sizeof(destroy_err));
      (void)g_doca_rx.destroy_rxq(handle, destroy_err, sizeof(destroy_err));
      destroy_created();
      rt->doca_rxq_handles.clear();
      rt->doca_gpu_rxq_handles.clear();
      if (reason != nullptr) {
        *reason = (errbuf[0] != '\0') ? std::string(errbuf) : "doca_rx_gpu_handle_unavailable";
      }
      return false;
    }
    rt->doca_rxq_handles.push_back(handle);
    rt->doca_gpu_rxq_handles.push_back(gpu_rxq_handle);
    queue_ids.push_back(queue_id);
  }
  rt->doca_flow_steering_active = false;
  rt->doca_flow_proto_mask = 0u;
  if (want_flow_steering && queue_count > 1 && flow_proto_mask != 0u) {
    if (g_doca_rx.configure_flow_steering == nullptr) {
      if (flow_steering_strict) {
        destroy_created();
        rt->doca_rxq_handles.clear();
        rt->doca_gpu_rxq_handles.clear();
        if (reason != nullptr) {
          *reason = "doca_flow_steering_unavailable";
        }
        return false;
      }
    } else {
      std::memset(errbuf, 0, sizeof(errbuf));
      const int flow_rc = g_doca_rx.configure_flow_steering(
          iface.c_str(),
          device.c_str(),
          rt->doca_rxq_handles.data(),
          queue_ids.data(),
          queue_count,
          flow_proto_mask,
          flow_steering_strict ? 1 : 0,
          errbuf,
          sizeof(errbuf));
      if (flow_rc < 0) {
        if (flow_steering_strict) {
          destroy_created();
          rt->doca_rxq_handles.clear();
          rt->doca_gpu_rxq_handles.clear();
          if (reason != nullptr) {
            *reason = (errbuf[0] != '\0') ? std::string(errbuf) : "doca_flow_steering_failed";
          }
          return false;
        }
      } else if (flow_rc == 0) {
        rt->doca_flow_steering_active = true;
        rt->doca_flow_proto_mask = flow_proto_mask;
      }
    }
  }

  if (rt->doca_rxq_handles.empty() || rt->doca_gpu_rxq_handles.empty()) {
    if (reason != nullptr) {
      *reason = "doca_rx_init_failed";
    }
    return false;
  }
  const size_t gpu_handle_count = rt->doca_gpu_rxq_handles.size();
  const size_t gpu_handles_bytes = sizeof(uint64_t) * gpu_handle_count;
  if (cudaMalloc(reinterpret_cast<void**>(&rt->doca_gpu_rxq_handles_dev), gpu_handles_bytes) != cudaSuccess ||
      rt->doca_gpu_rxq_handles_dev == nullptr ||
      cudaMemcpy(
          rt->doca_gpu_rxq_handles_dev,
          rt->doca_gpu_rxq_handles.data(),
          gpu_handles_bytes,
          cudaMemcpyHostToDevice) != cudaSuccess) {
    destroy_created();
    rt->doca_rxq_handles.clear();
    rt->doca_gpu_rxq_handles.clear();
    if (rt->doca_gpu_rxq_handles_dev != nullptr) {
      (void)cudaFree(rt->doca_gpu_rxq_handles_dev);
      rt->doca_gpu_rxq_handles_dev = nullptr;
    }
    if (reason != nullptr) {
      *reason = "doca_rx_device_unavailable";
    }
    return false;
  }
  rt->doca_rx_active = true;
  rt->doca_rxq_handle = rt->doca_rxq_handles.front();
  rt->doca_gpu_rxq_handle = rt->doca_gpu_rxq_handles.front();
  rt->doca_rx_rr_cursor = 0;
  return true;
}

RdmaDecision resolve_rdma_ingress(RdmaMode mode, bool strict) {
  const bool direct_available = env_flag("SAMURAI_GPU_RDMA_DIRECT_AVAILABLE", false);
  const bool host_staging_available = env_flag("SAMURAI_GPU_RDMA_HOST_STAGING_AVAILABLE", true);
  const bool af_xdp_available = env_flag("SAMURAI_GPU_RDMA_AFXDP_AVAILABLE", true);

  RdmaDecision d;
  if (mode == RdmaMode::kDocaGpuNetIO) {
    d.ingress = IngressPath::kDocaGpuNetIoRx;
    d.doca_rx_active = true;
    return d;
  }
  if (mode == RdmaMode::kDirect) {
    if (direct_available) {
      d.ingress = IngressPath::kRdmaGpuDirect;
      d.direct_active = true;
      return d;
    }
    if (strict) {
      d.reason = "rdma_strict_fail";
      return d;
    }
    if (host_staging_available) {
      d.ingress = IngressPath::kRdmaHostStaging;
      d.host_staging_active = true;
      d.reason = "rdma_unavailable";
      return d;
    }
    if (af_xdp_available) {
      d.ingress = IngressPath::kAfXdpHost;
      d.af_xdp_host_active = true;
      d.reason = "rdma_unavailable";
      return d;
    }
    d.reason = "rdma_unavailable";
    return d;
  }

  if (mode == RdmaMode::kHostStaging) {
    if (host_staging_available) {
      d.ingress = IngressPath::kRdmaHostStaging;
      d.host_staging_active = true;
      return d;
    }
    if (strict) {
      d.reason = "rdma_strict_fail";
      return d;
    }
    if (af_xdp_available) {
      d.ingress = IngressPath::kAfXdpHost;
      d.af_xdp_host_active = true;
      d.reason = "rdma_unavailable";
      return d;
    }
    d.reason = "rdma_unavailable";
    return d;
  }

  // auto: direct -> host_staging -> af_xdp_host -> fail
  if (direct_available) {
    d.ingress = IngressPath::kRdmaGpuDirect;
    d.direct_active = true;
    return d;
  }
  if (host_staging_available) {
    d.ingress = IngressPath::kRdmaHostStaging;
    d.host_staging_active = true;
    d.reason = "rdma_unavailable";
    return d;
  }
  if (af_xdp_available) {
    d.ingress = IngressPath::kAfXdpHost;
    d.af_xdp_host_active = true;
    d.reason = "rdma_unavailable";
    return d;
  }
  if (strict) {
    d.reason = "rdma_strict_fail";
  } else {
    d.reason = "rdma_unavailable";
  }
  return d;
}

bool try_activate_direct_rdma(std::string* reason) {
  static GpuDirectRdmaAdapter adapter;
  GpuDirectRdmaConfig cfg;
  cfg.ibv_device_name = env_string("SAMURAI_GPUDIRECT_IBV_DEVICE", "");
  cfg.ib_port = 1;
  if (!adapter.init(cfg, reason)) {
    return false;
  }
  void* dptr = nullptr;
  constexpr size_t kProbeBytes = 4096;
  const cudaError_t alloc_st = cudaMalloc(&dptr, kProbeBytes);
  if (alloc_st != cudaSuccess || dptr == nullptr) {
    if (reason != nullptr) {
      *reason = "rdma_unavailable";
    }
    return false;
  }
  const bool ok = adapter.register_gpu_buffer(dptr, kProbeBytes, reason);
  cudaFree(dptr);
  return ok;
}

bool validate_engine_compat(const std::string& engine_path, std::string* out_reason) {
  std::ifstream engine(engine_path, std::ios::binary);
  if (!engine.good()) {
    if (out_reason != nullptr) {
      *out_reason = "engine_load_failed";
    }
    return false;
  }

  auto meta = load_engine_metadata(engine_path);
  if (!meta.has_value()) {
    if (out_reason != nullptr) {
      *out_reason = "engine_compat_mismatch";
    }
    return false;
  }
  if (!meta->offline_built || meta->sm.empty() || meta->trt_version.empty() || meta->engine_sha256.empty()) {
    if (out_reason != nullptr) {
      *out_reason = "engine_compat_mismatch";
    }
    return false;
  }

  const std::string expected_sm = env_string("SAMURAI_GPU_EXPECTED_SM", "");
  const std::string expected_trt = env_string("SAMURAI_GPU_EXPECTED_TRT_VERSION", "");
  const std::string expected_hash = env_string("SAMURAI_GPU_EXPECTED_ENGINE_SHA256", "");

  if (!expected_sm.empty() && meta->sm != expected_sm) {
    if (out_reason != nullptr) {
      *out_reason = "engine_compat_mismatch";
    }
    return false;
  }
  if (!expected_trt.empty() && meta->trt_version != expected_trt) {
    if (out_reason != nullptr) {
      *out_reason = "engine_compat_mismatch";
    }
    return false;
  }
  if (!expected_hash.empty() && meta->engine_sha256 != expected_hash) {
    if (out_reason != nullptr) {
      *out_reason = "engine_compat_mismatch";
    }
    return false;
  }
  return true;
}

int classify_packet_views_common_locked(
    const PacketView* views,
    int64_t packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason) {
  const auto t0 = Clock::now();

  if (!g_runtime.initialized) {
    if (out_reason != nullptr) {
      *out_reason = "engine_load_failed";
    }
    return set_err("engine_load_failed");
  }
  if (views == nullptr || out_labels == nullptr || out_confidences == nullptr) {
    if (out_reason != nullptr) {
      *out_reason = "infer_enqueue_failed";
    }
    return set_err("infer_enqueue_failed");
  }
  if (packet_count <= 0) {
    if (out_reason != nullptr) {
      *out_reason = "none";
    }
    return 0;
  }

  if (packet_count > g_runtime.max_batch_size) {
    g_runtime.queue_backpressure += 1;
  }

  g_runtime.stream_overlap_events += 1;
  g_runtime.total_batches += 1;

  constexpr size_t feature_dim = 8;
  std::vector<float> features(static_cast<size_t>(packet_count) * feature_dim, 0.0f);
  extract_features_stub(views, static_cast<size_t>(packet_count), features.data(), feature_dim);
  if (enqueue_inference_stub(features.data(), static_cast<size_t>(packet_count), feature_dim, out_labels, out_confidences) != 0) {
    if (out_reason != nullptr) {
      *out_reason = "infer_enqueue_failed";
    }
    return set_err("infer_enqueue_failed");
  }

  g_runtime.infer_calls += 1;
  g_runtime.infer_packets += static_cast<uint64_t>(packet_count);
  if (g_runtime.infer_calls == 1) {
    g_runtime.first_infer_at = t0;
  }
  g_runtime.last_infer_at = Clock::now();

  for (int64_t i = 0; i < packet_count; ++i) {
    if (out_labels[i] == 1) {
      g_runtime.label1_count += 1;
    } else {
      g_runtime.label0_count += 1;
    }
    g_runtime.confidence_sum += static_cast<double>(out_confidences[i]);
  }

  const auto t1 = Clock::now();
  const auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
  const double ms = static_cast<double>(us) / 1000.0;
  g_runtime.latency_ms_window.push_back(ms);
  if (g_runtime.latency_ms_window.size() > 8192) {
    g_runtime.latency_ms_window.erase(g_runtime.latency_ms_window.begin());
  }

  if (out_reason != nullptr) {
    *out_reason = "none";
  }
  return 0;
}

int classify_batch_common_locked(
    const uint8_t* packets_flat,
    const int32_t* packet_lengths,
    int64_t packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason) {
  if (packets_flat == nullptr || packet_lengths == nullptr || out_labels == nullptr || out_confidences == nullptr) {
    if (out_reason != nullptr) {
      *out_reason = "infer_enqueue_failed";
    }
    return set_err("infer_enqueue_failed");
  }
  if (packet_count <= 0) {
    if (out_reason != nullptr) {
      *out_reason = "none";
    }
    return 0;
  }
  std::vector<PacketView> views(static_cast<size_t>(packet_count));
  size_t cursor = 0u;
  for (int64_t i = 0; i < packet_count; ++i) {
    const int32_t len = packet_lengths[i];
    if (len < 0) {
      if (out_reason != nullptr) {
        *out_reason = "infer_enqueue_failed";
      }
      return set_err("infer_enqueue_failed");
    }
    views[static_cast<size_t>(i)] = PacketView{packets_flat + cursor, static_cast<size_t>(len)};
    cursor += static_cast<size_t>(len);
  }
  return classify_packet_views_common_locked(
      views.data(),
      packet_count,
      out_labels,
      out_confidences,
      out_reason);
}

bool ensure_ingress_device_buffers(DefenseRuntime* rt, size_t packet_capacity, std::string* reason) {
  if (rt == nullptr || packet_capacity == 0u) {
    if (reason != nullptr) {
      *reason = "doca_rx_device_unavailable";
    }
    return false;
  }
  if (rt->ingress_device_capacity >= packet_capacity &&
      rt->ingress_packet_ptrs_dev != nullptr &&
      rt->ingress_lengths_u16_dev != nullptr &&
      rt->ingress_device_meta_dev != nullptr) {
    return true;
  }

  release_ingress_device_buffers(rt);
  const size_t ptr_bytes = sizeof(uint64_t) * packet_capacity;
  const size_t len_bytes = sizeof(uint16_t) * packet_capacity;
  const size_t meta_bytes = sizeof(uint32_t) * 4u;
  if (cudaMalloc(reinterpret_cast<void**>(&rt->ingress_packet_ptrs_dev), ptr_bytes) != cudaSuccess ||
      cudaMalloc(reinterpret_cast<void**>(&rt->ingress_lengths_u16_dev), len_bytes) != cudaSuccess ||
      cudaMalloc(reinterpret_cast<void**>(&rt->ingress_device_meta_dev), meta_bytes) != cudaSuccess) {
    release_ingress_device_buffers(rt);
    if (reason != nullptr) {
      *reason = "doca_rx_device_unavailable";
    }
    return false;
  }
  rt->ingress_device_capacity = packet_capacity;
  return true;
}

int classify_from_ingress_doca_device_locked(
    int32_t max_packets,
    int32_t max_packet_size,
    int32_t* out_packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason) {
#if !SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
  (void)max_packets;
  (void)max_packet_size;
  (void)out_packet_count;
  (void)out_labels;
  (void)out_confidences;
  if (out_reason != nullptr) {
    *out_reason = "doca_rx_device_unavailable";
  }
  return set_err("doca_rx_device_unavailable");
#else
  if (g_runtime.doca_gpu_rxq_handles_dev == nullptr || g_runtime.doca_gpu_rxq_handles.empty()) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err("doca_rx_device_unavailable");
  }
  const uint32_t rxq_count_u = static_cast<uint32_t>(g_runtime.doca_gpu_rxq_handles.size());
  const uint32_t rr_cursor_u = static_cast<uint32_t>(
      std::max(0, g_runtime.doca_rx_rr_cursor) % static_cast<int>(std::max<size_t>(1u, g_runtime.doca_gpu_rxq_handles.size())));
  g_runtime.doca_rx_rr_cursor = static_cast<int>((rr_cursor_u + 1u) % std::max<uint32_t>(1u, rxq_count_u));
  const size_t max_packets_sz = static_cast<size_t>(max_packets);
  std::string alloc_reason;
  if (!ensure_ingress_device_buffers(&g_runtime, max_packets_sz, &alloc_reason)) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err(alloc_reason.empty() ? "doca_rx_device_unavailable" : alloc_reason);
  }
  if (g_runtime.ingress_packet_ptrs_scratch.size() < max_packets_sz) {
    g_runtime.ingress_packet_ptrs_scratch.resize(max_packets_sz, 0u);
  }
  if (g_runtime.ingress_lengths_u16_scratch.size() < max_packets_sz) {
    g_runtime.ingress_lengths_u16_scratch.resize(max_packets_sz, 0u);
  }
  if (g_runtime.ingress_views_scratch.size() < max_packets_sz) {
    g_runtime.ingress_views_scratch.resize(max_packets_sz);
  }

  uint32_t host_meta[4] = {0u, 0u, 0u, 0u};
  const uint32_t threads = static_cast<uint32_t>(std::min<int32_t>(std::max<int32_t>(max_packets, 32), 256));
  const uint64_t timeout_ns = static_cast<uint64_t>(std::max<int64_t>(1000, g_runtime.flush_timeout_ms * 1000 * 1000));
  doca_rx_receive_burst_kernel<<<1, threads>>>(
      g_runtime.doca_gpu_rxq_handles_dev,
      rxq_count_u,
      rr_cursor_u,
      static_cast<uint32_t>(max_packets),
      static_cast<uint32_t>(max_packet_size),
      timeout_ns,
      g_runtime.ingress_packet_ptrs_dev,
      g_runtime.ingress_lengths_u16_dev,
      g_runtime.ingress_device_meta_dev);
  if (cudaGetLastError() != cudaSuccess || cudaDeviceSynchronize() != cudaSuccess) {
    g_runtime.doca_rx_device_poll_errors += 1u;
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err("doca_rx_device_unavailable");
  }
  if (cudaMemcpy(host_meta, g_runtime.ingress_device_meta_dev, sizeof(host_meta), cudaMemcpyDeviceToHost) != cudaSuccess) {
    g_runtime.doca_rx_device_poll_errors += 1u;
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err("doca_rx_device_unavailable");
  }

  g_runtime.doca_rx_device_polls += 1u;
  if (host_meta[3] != 0u) {
    g_runtime.doca_rx_device_poll_errors += 1u;
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_receive_failed";
    }
    return set_err("doca_rx_receive_failed");
  }
  const int received = static_cast<int>(host_meta[0]);
  const int valid = static_cast<int>(host_meta[1]);
  const int drops = static_cast<int>(host_meta[2]);
  if (drops > 0) {
    g_runtime.doca_rx_device_drops += static_cast<uint64_t>(drops);
  }
  if (received <= 0 || valid <= 0) {
    if (out_reason != nullptr) {
      *out_reason = "none";
    }
    *out_packet_count = 0;
    return 0;
  }
  const int n = std::min(valid, max_packets);
  if (cudaMemcpy(
          g_runtime.ingress_packet_ptrs_scratch.data(),
          g_runtime.ingress_packet_ptrs_dev,
          sizeof(uint64_t) * static_cast<size_t>(n),
          cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(
          g_runtime.ingress_lengths_u16_scratch.data(),
          g_runtime.ingress_lengths_u16_dev,
          sizeof(uint16_t) * static_cast<size_t>(n),
          cudaMemcpyDeviceToHost) != cudaSuccess) {
    g_runtime.doca_rx_device_poll_errors += 1u;
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err("doca_rx_device_unavailable");
  }

  bool invalid_pkt_view = false;
  for (int i = 0; i < n; ++i) {
    const uint64_t ptr_raw = g_runtime.ingress_packet_ptrs_scratch[static_cast<size_t>(i)];
    const uint16_t len_u16 = g_runtime.ingress_lengths_u16_scratch[static_cast<size_t>(i)];
    if (ptr_raw == 0u || len_u16 == 0u || len_u16 > static_cast<uint16_t>(max_packet_size)) {
      g_runtime.doca_rx_device_drops += 1u;
      invalid_pkt_view = true;
      break;
    }
    g_runtime.ingress_views_scratch[static_cast<size_t>(i)] = PacketView{
        reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(ptr_raw)),
        static_cast<size_t>(len_u16)};
  }
  if (invalid_pkt_view) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_receive_failed";
    }
    return set_err("doca_rx_receive_failed");
  }
  const int cls_rc = classify_packet_views_common_locked(
      g_runtime.ingress_views_scratch.data(),
      static_cast<int64_t>(n),
      out_labels,
      out_confidences,
      out_reason);
  if (cls_rc != 0) {
    return cls_rc;
  }
  g_runtime.doca_rx_device_packets += static_cast<uint64_t>(n);
  if (out_reason != nullptr) {
    *out_reason = "none";
  }
  *out_packet_count = n;
  return 0;
#endif
}

}  // namespace ddos_samurai::gpu_packet_cuda::defense

extern "C" int samurai_gpu_packet_defense_init(
    const char* runtime,
    const char* engine_path,
    const char* rdma_mode,
    int rdma_strict,
    int64_t max_batch_size,
    int64_t flush_timeout_ms) {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  g_defense_last_error.clear();

  release_ingress_device_buffers(&g_runtime);
  g_runtime = DefenseRuntime{};
  g_runtime.runtime = (runtime == nullptr || std::string(runtime).empty()) ? "tensorrt" : std::string(runtime);
  g_runtime.engine_path = (engine_path == nullptr) ? "" : std::string(engine_path);
  g_runtime.rdma_mode = parse_rdma_mode(rdma_mode);
  g_runtime.strict = (rdma_strict != 0);
  g_runtime.max_batch_size = (max_batch_size > 0) ? max_batch_size : 1024;
  g_runtime.flush_timeout_ms = (flush_timeout_ms > 0) ? flush_timeout_ms : 2;
  g_runtime.doca_rx_device_path_requested = env_flag("SAMURAI_GPU_DOCA_RX_DEVICE_PATH", true);

  if (g_runtime.engine_path.empty()) {
    return set_err("engine_load_failed");
  }
  if (!kTensorRtEnabled) {
    return set_err("engine_compat_mismatch");
  }

  std::string compat_reason;
  if (!validate_engine_compat(g_runtime.engine_path, &compat_reason)) {
    return set_err(compat_reason.empty() ? "engine_compat_mismatch" : compat_reason);
  }

  RdmaDecision rdma = resolve_rdma_ingress(g_runtime.rdma_mode, g_runtime.strict);
  if (rdma.ingress == IngressPath::kRdmaGpuDirect) {
    std::string direct_reason;
    if (!try_activate_direct_rdma(&direct_reason)) {
      // Real direct path failed at GPUDirect integration layer; deterministic fallback.
      if (g_runtime.strict) {
        return set_err("rdma_strict_fail");
      }
      rdma = resolve_rdma_ingress(RdmaMode::kHostStaging, false);
      if (rdma.ingress == IngressPath::kFail) {
        return set_err("rdma_unavailable");
      }
      rdma.reason = "rdma_unavailable";
    }
  }
  if (rdma.ingress == IngressPath::kDocaGpuNetIoRx) {
    std::string doca_reason;
    if (!try_activate_doca_rx(&g_runtime, &doca_reason)) {
      if (g_runtime.strict) {
        return set_err("rdma_strict_fail");
      }
      return set_err(doca_reason.empty() ? "rdma_unavailable" : doca_reason);
    }
    const bool device_path_strict = env_flag("SAMURAI_GPU_DOCA_RX_DEVICE_PATH_STRICT", true);
    if (g_runtime.doca_rx_device_path_requested) {
#if SAMURAI_WITH_DOCA_GPUNETIO_DEVICE
      g_runtime.doca_rx_device_path_active = true;
#else
      g_runtime.doca_rx_device_path_active = false;
      if (device_path_strict || g_runtime.strict) {
        return set_err("doca_rx_device_unavailable");
      }
#endif
    }
  }
  g_runtime.ingress_path = rdma.ingress;
  g_runtime.direct_active = rdma.direct_active;
  g_runtime.host_staging_active = rdma.host_staging_active;
  g_runtime.af_xdp_host_active = rdma.af_xdp_host_active;
  g_runtime.doca_rx_active = rdma.doca_rx_active;
  g_runtime.fallback_reason = rdma.reason;

  if (g_runtime.ingress_path == IngressPath::kFail) {
    if (rdma.reason == "rdma_strict_fail") {
      return set_err("rdma_strict_fail");
    }
    return set_err("rdma_unavailable");
  }

  g_runtime.initialized = true;
  return 0;
}

extern "C" int samurai_gpu_packet_classify_batch(
    const uint8_t* packets_flat,
    const int32_t* packet_lengths,
    int64_t packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason) {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  g_defense_last_error.clear();
  return classify_batch_common_locked(
      packets_flat,
      packet_lengths,
      packet_count,
      out_labels,
      out_confidences,
      out_reason);
}

extern "C" int samurai_gpu_packet_classify_from_ingress(
    int32_t max_packets,
    int32_t max_packet_size,
    int32_t* out_packet_count,
    int32_t* out_labels,
    float* out_confidences,
    const char** out_reason) {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  g_defense_last_error.clear();

  if (!g_runtime.initialized) {
    if (out_reason != nullptr) {
      *out_reason = "engine_load_failed";
    }
    return set_err("engine_load_failed");
  }
  if (!g_runtime.doca_rx_active || g_runtime.doca_rxq_handle < 0) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_unavailable";
    }
    return set_err("doca_rx_unavailable");
  }
  if (max_packets <= 0 || max_packet_size <= 0 || out_packet_count == nullptr || out_labels == nullptr ||
      out_confidences == nullptr) {
    if (out_reason != nullptr) {
      *out_reason = "infer_enqueue_failed";
    }
    return set_err("infer_enqueue_failed");
  }
  *out_packet_count = 0;

  if (g_runtime.doca_rx_device_path_active) {
    return classify_from_ingress_doca_device_locked(
        max_packets,
        max_packet_size,
        out_packet_count,
        out_labels,
        out_confidences,
        out_reason);
  }
  if (g_runtime.doca_rx_device_path_requested && !g_runtime.doca_rx_device_path_active) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_device_unavailable";
    }
    return set_err("doca_rx_device_unavailable");
  }
  if (g_doca_rx.receive_burst_view == nullptr || g_doca_rx.release_burst_view == nullptr) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_unavailable";
    }
    return set_err("doca_rx_unavailable");
  }

  const size_t max_packets_sz = static_cast<size_t>(max_packets);
  if (max_packets_sz == 0u || max_packets_sz > 1048576u) {
    if (out_reason != nullptr) {
      *out_reason = "infer_enqueue_failed";
    }
    return set_err("infer_enqueue_failed");
  }

  if (g_runtime.ingress_packet_ptrs_scratch.size() < max_packets_sz) {
    g_runtime.ingress_packet_ptrs_scratch.resize(max_packets_sz, 0u);
  }
  if (g_runtime.ingress_packet_handles_scratch.size() < max_packets_sz) {
    g_runtime.ingress_packet_handles_scratch.resize(max_packets_sz, 0u);
  }
  if (g_runtime.ingress_lengths_u16_scratch.size() < max_packets_sz) {
    g_runtime.ingress_lengths_u16_scratch.resize(max_packets_sz, 0u);
  }
  if (g_runtime.ingress_views_scratch.size() < max_packets_sz) {
    g_runtime.ingress_views_scratch.resize(max_packets_sz);
  }

  std::memset(g_runtime.ingress_packet_ptrs_scratch.data(), 0, sizeof(uint64_t) * max_packets_sz);
  std::memset(g_runtime.ingress_packet_handles_scratch.data(), 0, sizeof(uint64_t) * max_packets_sz);
  std::memset(g_runtime.ingress_lengths_u16_scratch.data(), 0, sizeof(uint16_t) * max_packets_sz);

  int selected_rxq_handle = g_runtime.doca_rxq_handle;
  if (!g_runtime.doca_rxq_handles.empty()) {
    const size_t qcount = g_runtime.doca_rxq_handles.size();
    const size_t idx = static_cast<size_t>(std::max(0, g_runtime.doca_rx_rr_cursor) % static_cast<int>(qcount));
    selected_rxq_handle = g_runtime.doca_rxq_handles[idx];
    g_runtime.doca_rx_rr_cursor = static_cast<int>((idx + 1u) % qcount);
  }
  int received = 0;
  char errbuf[192];
  std::memset(errbuf, 0, sizeof(errbuf));
  const int rx_rc = g_doca_rx.receive_burst_view(
      selected_rxq_handle,
      g_runtime.ingress_packet_ptrs_scratch.data(),
      g_runtime.ingress_lengths_u16_scratch.data(),
      g_runtime.ingress_packet_handles_scratch.data(),
      static_cast<int>(max_packets),
      &received,
      errbuf,
      sizeof(errbuf));
  g_runtime.doca_rx_polls += 1u;
  if (rx_rc != 0) {
    g_runtime.doca_rx_poll_errors += 1u;
    if (out_reason != nullptr) {
      *out_reason = (errbuf[0] != '\0') ? errbuf : "doca_rx_receive_failed";
    }
    return set_err((errbuf[0] != '\0') ? std::string(errbuf) : "doca_rx_receive_failed");
  }
  if (received <= 0) {
    if (out_reason != nullptr) {
      *out_reason = "none";
    }
    return 0;
  }

  if (received > max_packets) {
    received = max_packets;
  }
  bool invalid_pkt_view = false;
  for (int i = 0; i < received; ++i) {
    const uint64_t ptr_raw = g_runtime.ingress_packet_ptrs_scratch[static_cast<size_t>(i)];
    const uint16_t len_u16 = g_runtime.ingress_lengths_u16_scratch[static_cast<size_t>(i)];
    if (ptr_raw == 0u || len_u16 == 0u || len_u16 > static_cast<uint16_t>(max_packet_size)) {
      g_runtime.doca_rx_drops += 1u;
      invalid_pkt_view = true;
      break;
    }
    g_runtime.ingress_views_scratch[static_cast<size_t>(i)] = PacketView{
        reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(ptr_raw)),
        static_cast<size_t>(len_u16)};
  }
  g_runtime.doca_rx_packets += static_cast<uint64_t>(received);

  int cls_rc = 0;
  if (!invalid_pkt_view) {
    cls_rc = classify_packet_views_common_locked(
        g_runtime.ingress_views_scratch.data(),
        static_cast<int64_t>(received),
        out_labels,
        out_confidences,
        out_reason);
  }
  int rearmed = 0;
  std::memset(errbuf, 0, sizeof(errbuf));
  const int release_rc = g_doca_rx.release_burst_view(
      selected_rxq_handle,
      g_runtime.ingress_packet_handles_scratch.data(),
      received,
      &rearmed,
      errbuf,
      sizeof(errbuf));
  if (release_rc != 0 || rearmed < received) {
    g_runtime.doca_rx_poll_errors += 1u;
    if (rearmed < received) {
      g_runtime.doca_rx_drops += static_cast<uint64_t>(received - rearmed);
    }
    if (out_reason != nullptr) {
      *out_reason = (errbuf[0] != '\0') ? errbuf : "doca_rx_receive_failed";
    }
    return set_err((errbuf[0] != '\0') ? std::string(errbuf) : "doca_rx_receive_failed");
  }
  if (invalid_pkt_view) {
    if (out_reason != nullptr) {
      *out_reason = "doca_rx_receive_failed";
    }
    return set_err("doca_rx_receive_failed");
  }
  if (cls_rc != 0) {
    return cls_rc;
  }
  *out_packet_count = received;
  return 0;
}

extern "C" const char* samurai_gpu_packet_read_classifier_stats() {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  thread_local std::string stats;

  const double confidence_mean = (g_runtime.infer_packets > 0)
      ? (g_runtime.confidence_sum / static_cast<double>(g_runtime.infer_packets))
      : 0.0;

  double qps = 0.0;
  if (g_runtime.infer_calls > 1) {
    const auto dt_us = std::chrono::duration_cast<std::chrono::microseconds>(g_runtime.last_infer_at - g_runtime.first_infer_at).count();
    if (dt_us > 0) {
      qps = static_cast<double>(g_runtime.infer_packets) / (static_cast<double>(dt_us) / 1000000.0);
    }
  }

  const double overlap_ratio = (g_runtime.total_batches > 0)
      ? static_cast<double>(g_runtime.stream_overlap_events) / static_cast<double>(g_runtime.total_batches)
      : 0.0;

  std::ostringstream oss;
  oss << "{";
  oss << "\"gpu_cls_infer_qps\":" << qps << ",";
  oss << "\"gpu_cls_latency_p50_ms\":" << percentile_ms(g_runtime.latency_ms_window, 50.0) << ",";
  oss << "\"gpu_cls_latency_p95_ms\":" << percentile_ms(g_runtime.latency_ms_window, 95.0) << ",";
  oss << "\"gpu_cls_latency_p99_ms\":" << percentile_ms(g_runtime.latency_ms_window, 99.0) << ",";
  oss << "\"gpu_cls_batch_size_effective\":" << g_runtime.max_batch_size << ",";
  oss << "\"gpu_cls_queue_backpressure\":" << g_runtime.queue_backpressure << ",";
  oss << "\"gpu_rdma_direct_active\":" << (g_runtime.direct_active ? 1 : 0) << ",";
  oss << "\"gpu_doca_rx_active\":" << (g_runtime.doca_rx_active ? 1 : 0) << ",";
  oss << "\"gpu_doca_rx_polls\":" << g_runtime.doca_rx_polls << ",";
  oss << "\"gpu_doca_rx_packets\":" << g_runtime.doca_rx_packets << ",";
  oss << "\"gpu_doca_rx_poll_errors\":" << g_runtime.doca_rx_poll_errors << ",";
  oss << "\"gpu_doca_rx_drops\":" << g_runtime.doca_rx_drops << ",";
  oss << "\"gpu_doca_rx_device_path_requested\":" << (g_runtime.doca_rx_device_path_requested ? 1 : 0) << ",";
  oss << "\"gpu_doca_rx_device_path_active\":" << (g_runtime.doca_rx_device_path_active ? 1 : 0) << ",";
  oss << "\"gpu_doca_rx_device_polls\":" << g_runtime.doca_rx_device_polls << ",";
  oss << "\"gpu_doca_rx_device_packets\":" << g_runtime.doca_rx_device_packets << ",";
  oss << "\"gpu_doca_rx_device_poll_errors\":" << g_runtime.doca_rx_device_poll_errors << ",";
  oss << "\"gpu_doca_rx_device_drops\":" << g_runtime.doca_rx_device_drops << ",";
  oss << "\"gpu_doca_rx_queue_count\":" << g_runtime.doca_rxq_handles.size() << ",";
  oss << "\"gpu_doca_rx_rr_cursor\":" << g_runtime.doca_rx_rr_cursor << ",";
  oss << "\"gpu_doca_flow_steering_active\":" << (g_runtime.doca_flow_steering_active ? 1 : 0) << ",";
  oss << "\"gpu_doca_flow_proto_mask\":" << g_runtime.doca_flow_proto_mask << ",";
  oss << "\"gpu_doca_rx_gpu_handle_ready\":" << (g_runtime.doca_gpu_rxq_handle != 0ull ? 1 : 0) << ",";
  oss << "\"gpu_doca_rx_gpu_handle\":" << g_runtime.doca_gpu_rxq_handle << ",";
  oss << "\"gpu_rdma_mode\":\"" << rdma_mode_name(g_runtime.rdma_mode) << "\",";
  oss << "\"gpu_rdma_ingress_path\":\"" << ingress_path_name(g_runtime.ingress_path) << "\",";
  oss << "\"gpu_rdma_fallback_reason\":\"" << g_runtime.fallback_reason << "\",";
  oss << "\"gpu_cls_label_0_count\":" << g_runtime.label0_count << ",";
  oss << "\"gpu_cls_label_1_count\":" << g_runtime.label1_count << ",";
  oss << "\"gpu_cls_confidence_mean\":" << confidence_mean << ",";
  oss << "\"gpu_stream_overlap_ratio\":" << overlap_ratio;
  oss << "}";
  stats = oss.str();
  return stats.c_str();
}

extern "C" int samurai_gpu_packet_defense_get_doca_rx_gpu_handle(uint64_t* out_gpu_rxq_handle) {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  g_defense_last_error.clear();
  if (out_gpu_rxq_handle == nullptr) {
    return set_err("invalid_argument");
  }
  if (!g_runtime.initialized || !g_runtime.doca_rx_active || g_runtime.doca_rxq_handle < 0 ||
      g_runtime.doca_gpu_rxq_handle == 0ull) {
    return set_err("doca_rx_gpu_handle_unavailable");
  }
  if (!g_runtime.doca_gpu_rxq_handles.empty()) {
    *out_gpu_rxq_handle = g_runtime.doca_gpu_rxq_handles.front();
  } else {
    *out_gpu_rxq_handle = g_runtime.doca_gpu_rxq_handle;
  }
  return 0;
}

extern "C" int samurai_gpu_packet_defense_shutdown() {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  if (g_runtime.doca_rx_active && g_doca_rx.destroy_rxq != nullptr) {
    if (!g_runtime.doca_rxq_handles.empty()) {
      for (int handle : g_runtime.doca_rxq_handles) {
        if (handle < 0) {
          continue;
        }
        char errbuf[128];
        std::memset(errbuf, 0, sizeof(errbuf));
        (void)g_doca_rx.destroy_rxq(handle, errbuf, sizeof(errbuf));
      }
    } else if (g_runtime.doca_rxq_handle >= 0) {
      char errbuf[128];
      std::memset(errbuf, 0, sizeof(errbuf));
      (void)g_doca_rx.destroy_rxq(g_runtime.doca_rxq_handle, errbuf, sizeof(errbuf));
    }
  }
  release_ingress_device_buffers(&g_runtime);
  g_runtime = DefenseRuntime{};
  g_defense_last_error.clear();
  return 0;
}

extern "C" const char* samurai_gpu_packet_defense_last_error() {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  return g_defense_last_error.c_str();
}
