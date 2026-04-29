#include "kernels_defense_feature.cuh"
#include "kernels_defense_rdma_adapter.cuh"
#include "kernels_defense_tensorrt.cuh"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
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
};

enum class IngressPath {
  kRdmaGpuDirect = 0,
  kRdmaHostStaging = 1,
  kAfXdpHost = 2,
  kFail = 3,
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
  std::string reason = "none";
};

RdmaDecision resolve_rdma_ingress(RdmaMode mode, bool strict) {
  const bool direct_available = env_flag("SAMURAI_GPU_RDMA_DIRECT_AVAILABLE", false);
  const bool host_staging_available = env_flag("SAMURAI_GPU_RDMA_HOST_STAGING_AVAILABLE", true);
  const bool af_xdp_available = env_flag("SAMURAI_GPU_RDMA_AFXDP_AVAILABLE", true);

  RdmaDecision d;
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

  g_runtime = DefenseRuntime{};
  g_runtime.runtime = (runtime == nullptr || std::string(runtime).empty()) ? "tensorrt" : std::string(runtime);
  g_runtime.engine_path = (engine_path == nullptr) ? "" : std::string(engine_path);
  g_runtime.rdma_mode = parse_rdma_mode(rdma_mode);
  g_runtime.strict = (rdma_strict != 0);
  g_runtime.max_batch_size = (max_batch_size > 0) ? max_batch_size : 1024;
  g_runtime.flush_timeout_ms = (flush_timeout_ms > 0) ? flush_timeout_ms : 2;

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
  g_runtime.ingress_path = rdma.ingress;
  g_runtime.direct_active = rdma.direct_active;
  g_runtime.host_staging_active = rdma.host_staging_active;
  g_runtime.af_xdp_host_active = rdma.af_xdp_host_active;
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

  const auto t0 = Clock::now();

  if (!g_runtime.initialized) {
    if (out_reason != nullptr) {
      *out_reason = "engine_load_failed";
    }
    return set_err("engine_load_failed");
  }
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

  if (packet_count > g_runtime.max_batch_size) {
    g_runtime.queue_backpressure += 1;
  }

  // Simulated stream overlap event for telemetry: ingest + feature + trt + postprocess
  g_runtime.stream_overlap_events += 1;
  g_runtime.total_batches += 1;

  std::vector<PacketView> views(static_cast<size_t>(packet_count));
  size_t cursor = 0;
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

  constexpr size_t feature_dim = 8;
  std::vector<float> features(static_cast<size_t>(packet_count) * feature_dim, 0.0f);
  extract_features_stub(views.data(), static_cast<size_t>(packet_count), features.data(), feature_dim);
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

extern "C" int samurai_gpu_packet_defense_shutdown() {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  std::lock_guard<std::mutex> lk(g_runtime_mu);
  g_runtime = DefenseRuntime{};
  g_defense_last_error.clear();
  return 0;
}

extern "C" const char* samurai_gpu_packet_defense_last_error() {
  using namespace ddos_samurai::gpu_packet_cuda::defense;
  return g_defense_last_error.c_str();
}
