#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <zmq.h>

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace {

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_defense";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_defense";
constexpr const char* kDefaultDefenseLib = "ddos_samurai/libgpu_packet_cuda_defense.so";

using fn_defense_init_t = int (*)(const char*, const char*, const char*, int, std::int64_t, std::int64_t);
using fn_classify_batch_t = int (*)(const std::uint8_t*, const std::int32_t*, std::int64_t, std::int32_t*, float*, const char**);
using fn_classify_from_ingress_t = int (*)(std::int32_t, std::int32_t, std::int32_t*, std::int32_t*, float*, const char**);
using fn_read_stats_t = const char* (*)();
using fn_shutdown_t = int (*)();
using fn_last_error_t = const char* (*)();

struct DefenseNativeApi {
  void* handle{nullptr};
  fn_defense_init_t defense_init{nullptr};
  fn_classify_batch_t classify_batch{nullptr};
  fn_classify_from_ingress_t classify_from_ingress{nullptr};
  fn_read_stats_t read_stats{nullptr};
  fn_shutdown_t shutdown{nullptr};
  fn_last_error_t last_error{nullptr};
  std::string lib_path;
};

std::string ReadFixed(const char* raw, std::size_t n) {
  return std::string(raw, strnlen(raw, n));
}

std::optional<int> OptionalIntFromWire(std::uint64_t raw) {
  if (raw == 0ull) return std::nullopt;
  return static_cast<int>(raw);
}

std::string ResolveDefenseLibPath() {
  const char* env = std::getenv("SAMURAI_GPU_DEFENSE_LIB");
  if (env && *env) return std::string(env);
  return std::string(kDefaultDefenseLib);
}

bool LoadDefenseNative(DefenseNativeApi& api, std::string& err) {
  if (api.handle != nullptr) return true;

  api.lib_path = ResolveDefenseLibPath();
  api.handle = dlopen(api.lib_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!api.handle) {
    api.lib_path = "libgpu_packet_cuda_defense.so";
    api.handle = dlopen(api.lib_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  }
  if (!api.handle) {
    err = "defense_native_lib_unavailable";
    return false;
  }

  api.defense_init = reinterpret_cast<fn_defense_init_t>(dlsym(api.handle, "samurai_gpu_packet_defense_init"));
  api.classify_batch = reinterpret_cast<fn_classify_batch_t>(dlsym(api.handle, "samurai_gpu_packet_classify_batch"));
  api.classify_from_ingress =
      reinterpret_cast<fn_classify_from_ingress_t>(dlsym(api.handle, "samurai_gpu_packet_classify_from_ingress"));
  api.read_stats = reinterpret_cast<fn_read_stats_t>(dlsym(api.handle, "samurai_gpu_packet_read_classifier_stats"));
  api.shutdown = reinterpret_cast<fn_shutdown_t>(dlsym(api.handle, "samurai_gpu_packet_defense_shutdown"));
  api.last_error = reinterpret_cast<fn_last_error_t>(dlsym(api.handle, "samurai_gpu_packet_defense_last_error"));

  if (!api.defense_init || !api.classify_batch || !api.read_stats || !api.shutdown || !api.last_error) {
    err = "defense_native_symbol_missing";
    dlclose(api.handle);
    api = DefenseNativeApi{};
    return false;
  }
  return true;
}

std::string NativeLastError(const DefenseNativeApi& api) {
  if (!api.last_error) return "";
  const char* p = api.last_error();
  if (!p) return "";
  return std::string(p);
}

std::vector<std::uint8_t> JsonError(const std::string& reason) {
  const std::string json = "{\"status\":\"error\",\"error\":\"" + reason + "\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

int SendFrame(
    void* event_socket,
    std::uint8_t msg_type,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id,
    const std::vector<std::uint8_t>& payload = {}) {
  samurai::wire::SamuraiWireHeaderV1 header = samurai::daemon::MakeHeader(
      msg_type,
      static_cast<std::uint32_t>(payload.size()),
      correlation_id,
      worker_kind,
      job_id);

  zmq_msg_t msg;
  const std::size_t total = sizeof(header) + payload.size();
  if (zmq_msg_init_size(&msg, total) != 0) return -1;
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (!payload.empty()) std::memcpy(p + sizeof(header), payload.data(), payload.size());
  const int rc = zmq_msg_send(&msg, event_socket, 0);
  zmq_msg_close(&msg);
  return rc;
}

int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::DEFENSE, job_id);
}

PacketConfig ConfigFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  PacketConfig cfg;
  cfg.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  cfg.target_port = static_cast<int>(env.target_port);
  cfg.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  if (cfg.protocol.empty()) cfg.protocol = "tcp";
  cfg.spoof = env.spoof_enabled != 0u;
  cfg.spoof_opts = SpoofOptions{
      .mode = ReadFixed(env.spoof_mode, sizeof(env.spoof_mode)),
      .subnet = [&]() -> std::optional<std::string> {
        const std::string v = ReadFixed(env.spoof_subnet, sizeof(env.spoof_subnet));
        return v.empty() ? std::nullopt : std::optional<std::string>(v);
      }(),
      .list_file = [&]() -> std::optional<std::string> {
        const std::string v = ReadFixed(env.spoof_list_file, sizeof(env.spoof_list_file));
        return v.empty() ? std::nullopt : std::optional<std::string>(v);
      }(),
  };
  cfg.has_payload = env.has_payload != 0u;
  cfg.tcp_flags = ReadFixed(env.tcp_flags, sizeof(env.tcp_flags));
  if (cfg.tcp_flags.empty()) cfg.tcp_flags = "S";
  cfg.ttl = OptionalIntFromWire(env.ttl);
  cfg.tos = OptionalIntFromWire(env.tos);
  cfg.window = OptionalIntFromWire(env.window);
  cfg.fragment_enabled = env.fragment_enabled != 0u;
  cfg.fragment_size = static_cast<int>(env.fragment_size);
  cfg.pad_size = static_cast<int>(env.pad_size);
  cfg.attack_vector = ReadFixed(env.attack_vector, sizeof(env.attack_vector));
  if (cfg.attack_vector.empty()) cfg.attack_vector = "basic";
  cfg.dns_name = ReadFixed(env.dns_name, sizeof(env.dns_name));
  if (cfg.dns_name.empty()) cfg.dns_name = "example.com";
  cfg.dns_edns = env.dns_edns != 0u;
  cfg.dns_recursive = env.dns_recursive != 0u;
  const std::string qtypes_raw = ReadFixed(env.dns_qtype, sizeof(env.dns_qtype));
  if (!qtypes_raw.empty()) {
    cfg.dns_qtypes.clear();
    std::size_t start = 0;
    while (start < qtypes_raw.size()) {
      const std::size_t comma = qtypes_raw.find(',', start);
      const std::size_t end = (comma == std::string::npos) ? qtypes_raw.size() : comma;
      const std::string part = qtypes_raw.substr(start, end - start);
      if (!part.empty()) cfg.dns_qtypes.push_back(part);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
  }

  const std::string payload_ref = ReadFixed(env.payload_ref, sizeof(env.payload_ref));
  if (cfg.has_payload && !payload_ref.empty()) {
    std::ifstream f(payload_ref, std::ios::binary);
    if (f) {
      f.seekg(0, std::ios::end);
      const std::streamoff sz = f.tellg();
      f.seekg(0, std::ios::beg);
      if (sz > 0) {
        cfg.payload.resize(static_cast<std::size_t>(sz));
        (void)f.read(reinterpret_cast<char*>(cfg.payload.data()), static_cast<std::streamsize>(cfg.payload.size()));
      }
    }
  }
  return cfg;
}

samurai_pacing_config_t PacingFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  samurai_pacing_config_t out{};
  out.mode = env.pacing_mode;
  out.target_rps = env.target_rps;
  out.ipg_ns = env.ipg_ns;
  out.burst_size = env.burst_size > 0u ? env.burst_size : 1u;
  out.burst_gap_ns = env.burst_gap_ns;
  return out;
}

samurai::wire::MetricSnapshotV1 BuildSnapshot(
    std::uint64_t now_ns,
    std::uint64_t start_ns,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    const samurai_pacing_config_t& pace_cfg,
    const samurai_pacing_state_t& pace_state) {
  const double duration_s = std::max(1e-9, static_cast<double>(now_ns - start_ns) / 1e9);
  const double actual_rps = static_cast<double>(packets_sent) / duration_s;
  double rate_accuracy_pct = 100.0;
  if (pace_cfg.mode == SAMURAI_PACING_RPS && pace_cfg.target_rps > 0.0) {
    const double err_abs = std::abs(actual_rps - pace_cfg.target_rps);
    rate_accuracy_pct = std::max(0.0, 100.0 - ((err_abs * 100.0) / pace_cfg.target_rps));
  }
  samurai::wire::MetricSnapshotV1 snap{};
  snap.timestamp_ns = now_ns;
  snap.packets_sent = packets_sent;
  snap.packets_errors = packets_errors;
  snap.bytes_sent = bytes_sent;
  snap.actual_rps = actual_rps;
  snap.jitter_p99_ns = 0.0;
  snap.rate_accuracy_pct = rate_accuracy_pct;
  snap.busywait_cycles = 0;
  snap.sleep_calls = static_cast<std::uint32_t>(pace_state.sleep_calls & 0xFFFFFFFFu);
  return snap;
}

std::vector<std::uint8_t> SerializeSnapshot(const samurai::wire::MetricSnapshotV1& snap) {
  std::vector<std::uint8_t> payload(sizeof(snap));
  std::memcpy(payload.data(), &snap, sizeof(snap));
  return payload;
}

std::string JsonEscape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 16);
  for (char c : in) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    std::uint64_t classified_total,
    std::uint64_t suspicious_total,
    double mean_confidence,
    const std::string& reason_last,
    const std::string& classifier_stats_json,
    double actual_rps,
    double rate_accuracy_pct) {
  std::ostringstream oss;
  oss
      << "{\"status\":\"ok\",\"worker_kind\":\"defense\""
      << ",\"correlation_id\":" << correlation_id
      << ",\"job_id\":\"" << job_id << "\""
      << ",\"packets_sent\":" << packets_sent
      << ",\"packets_errors\":" << packets_errors
      << ",\"bytes_sent\":" << bytes_sent
      << ",\"gpu_classifier_total\":" << classified_total
      << ",\"gpu_classifier_suspicious\":" << suspicious_total
      << ",\"gpu_classifier_benign\":" << (classified_total >= suspicious_total ? classified_total - suspicious_total : 0u)
      << ",\"gpu_classifier_confidence_mean\":" << mean_confidence
      << ",\"gpu_classifier_reason_last\":\"" << JsonEscape(reason_last) << "\""
      << ",\"gpu_classifier_stats_raw\":\"" << JsonEscape(classifier_stats_json) << "\""
      << ",\"actual_rps\":" << actual_rps
      << ",\"rate_accuracy_pct\":" << rate_accuracy_pct
      << ",\"note\":\"gpu_defense_native+cpu_native+pacing_static\"}";
  const std::string json = oss.str();
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_max_batch = 1024;
  int cli_flush_timeout_ms = 2;
  std::string cli_runtime = "tensorrt";
  std::string cli_engine_path;
  std::string cli_rdma_mode = "auto";
  bool cli_rdma_strict = false;
  bool cli_use_ingress = false;
  int cli_ingress_max_packets = 1024;
  int cli_ingress_max_packet_size = 2048;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--job-endpoint" && i + 1 < argc) {
      jobs_ep = argv[++i];
    } else if (arg == "--event-endpoint" && i + 1 < argc) {
      events_ep = argv[++i];
    } else if (arg == "--jobs-mode" && i + 1 < argc) {
      bind_jobs = std::string(argv[++i]) == "bind";
    } else if (arg == "--events-mode" && i + 1 < argc) {
      bind_events = std::string(argv[++i]) == "bind";
    } else if (arg == "--defense-max-batch-size" && i + 1 < argc) {
      cli_max_batch = std::max(1, std::stoi(argv[++i]));
    } else if (arg == "--defense-flush-timeout-ms" && i + 1 < argc) {
      cli_flush_timeout_ms = std::max(1, std::stoi(argv[++i]));
    } else if (arg == "--defense-runtime" && i + 1 < argc) {
      cli_runtime = argv[++i];
    } else if (arg == "--defense-engine-path" && i + 1 < argc) {
      cli_engine_path = argv[++i];
    } else if (arg == "--defense-rdma-mode" && i + 1 < argc) {
      cli_rdma_mode = argv[++i];
    } else if (arg == "--defense-rdma-strict") {
      cli_rdma_strict = true;
    } else if (arg == "--defense-use-ingress") {
      cli_use_ingress = true;
    } else if (arg == "--defense-ingress-max-packets" && i + 1 < argc) {
      cli_ingress_max_packets = std::max(1, std::stoi(argv[++i]));
    } else if (arg == "--defense-ingress-max-packet-size" && i + 1 < argc) {
      cli_ingress_max_packet_size = std::max(64, std::stoi(argv[++i]));
    }
  }

  void* ctx = zmq_ctx_new();
  if (!ctx) {
    std::cerr << "zmq_ctx_new failed\n";
    return 1;
  }

  void* pull = zmq_socket(ctx, ZMQ_PULL);
  void* push = zmq_socket(ctx, ZMQ_PUSH);
  if (!pull || !push) {
    std::cerr << "zmq_socket failed\n";
    if (pull) zmq_close(pull);
    if (push) zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }

  if ((bind_jobs ? zmq_bind(pull, jobs_ep.c_str()) : zmq_connect(pull, jobs_ep.c_str())) != 0) {
    std::cerr << "jobs socket init failed: " << jobs_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }
  if ((bind_events ? zmq_bind(push, events_ep.c_str()) : zmq_connect(push, events_ep.c_str())) != 0) {
    std::cerr << "events socket init failed: " << events_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }

  DefenseNativeApi defense{};
  bool running = true;
  while (running) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    const int n = zmq_msg_recv(&msg, pull, 0);
    if (n <= 0) {
      zmq_msg_close(&msg);
      continue;
    }

    const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
    if (sz < sizeof(samurai::wire::SamuraiWireHeaderV1)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto* raw = static_cast<const std::uint8_t*>(zmq_msg_data(&msg));
    samurai::wire::SamuraiWireHeaderV1 header{};
    std::memcpy(&header, raw, sizeof(header));
    const std::size_t payload_len = sz - sizeof(header);
    const std::uint8_t* payload_ptr = raw + sizeof(header);

    if (!samurai::wire::IsHeaderV1Compatible(header)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto msg_type = static_cast<samurai::wire::MessageType>(header.msg_type);
    const std::string job_id = samurai::daemon::ReadJobId(header);

    if (msg_type == samurai::wire::MessageType::SHUTDOWN) {
      (void)SendAck(push, header.correlation_id, job_id);
      running = false;
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::STOP_JOB) {
      zmq_msg_close(&msg);
      (void)SendAck(push, header.correlation_id, job_id);
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"defense\"}";
      (void)SendFrame(
          push,
          static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
          header.correlation_id,
          samurai::wire::WorkerKind::DEFENSE,
          job_id,
          std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::DEFENSE,
            job_id,
            JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }
      samurai::wire::JobEnvelopeV1 env{};
      std::memcpy(&env, payload_ptr, sizeof(env));
      (void)SendAck(push, header.correlation_id, job_id);
      zmq_msg_close(&msg);

      try {
        std::string native_err;
        if (!LoadDefenseNative(defense, native_err)) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::DEFENSE,
              job_id,
              JsonError(native_err));
          continue;
        }

        const char* env_runtime = std::getenv("SAMURAI_GPU_CLASSIFIER_RUNTIME");
        const char* env_engine = std::getenv("SAMURAI_GPU_CLASSIFIER_ENGINE_PATH");
        const char* env_rdma = std::getenv("SAMURAI_GPU_RDMA_MODE");
        const char* env_rdma_strict = std::getenv("SAMURAI_GPU_RDMA_STRICT");
        const char* env_use_ingress = std::getenv("SAMURAI_GPU_RX_PIPELINE");

        const std::string runtime = (env_runtime && *env_runtime) ? std::string(env_runtime) : cli_runtime;
        const std::string engine_path = (env_engine && *env_engine) ? std::string(env_engine) : cli_engine_path;
        const std::string rdma_mode = (env_rdma && *env_rdma) ? std::string(env_rdma) : cli_rdma_mode;
        const bool rdma_strict = cli_rdma_strict || (env_rdma_strict && std::string(env_rdma_strict) == "1");
        const bool use_ingress = cli_use_ingress || (env_use_ingress && std::string(env_use_ingress) == "on");

        if (defense.defense_init(
                runtime.c_str(),
                engine_path.c_str(),
                rdma_mode.c_str(),
                rdma_strict ? 1 : 0,
                static_cast<std::int64_t>(cli_max_batch),
                static_cast<std::int64_t>(cli_flush_timeout_ms)) != 0) {
          const std::string msg = NativeLastError(defense).empty() ? "defense_init_failed" : NativeLastError(defense);
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::DEFENSE,
              job_id,
              JsonError(msg));
          continue;
        }

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t classified_total = 0;
        std::uint64_t suspicious_total = 0;
        double confidence_sum = 0.0;
        std::string reason_last = "none";

        if (use_ingress && defense.classify_from_ingress) {
          std::vector<std::int32_t> labels(static_cast<std::size_t>(cli_ingress_max_packets), 0);
          std::vector<float> confidences(static_cast<std::size_t>(cli_ingress_max_packets), 0.0f);
          std::int32_t out_count = 0;
          const char* out_reason = nullptr;
          const int rc = defense.classify_from_ingress(
              static_cast<std::int32_t>(cli_ingress_max_packets),
              static_cast<std::int32_t>(cli_ingress_max_packet_size),
              &out_count,
              labels.data(),
              confidences.data(),
              &out_reason);
          if (out_reason) reason_last = std::string(out_reason);
          if (rc != 0) {
            const std::string msg = reason_last.empty() ? (NativeLastError(defense).empty() ? "defense_classify_ingress_failed" : NativeLastError(defense)) : reason_last;
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::DEFENSE,
                job_id,
                JsonError(msg));
            (void)defense.shutdown();
            continue;
          }
          const int n_cls = std::max(0, std::min<int>(out_count, cli_ingress_max_packets));
          classified_total += static_cast<std::uint64_t>(n_cls);
          packets_sent += static_cast<std::uint64_t>(n_cls);
          for (int i = 0; i < n_cls; ++i) {
            if (labels[static_cast<std::size_t>(i)] != 0) suspicious_total += 1u;
            confidence_sum += static_cast<double>(confidences[static_cast<std::size_t>(i)]);
          }
        } else {
          PacketConfig cfg = ConfigFromEnvelope(env);
          const int packet_count = std::max(1, static_cast<int>(env.packet_count));
          const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
          const std::size_t stride = pool.packet_size;
          if (stride == 0 || pool.size() < stride) {
            packets_errors = static_cast<std::uint64_t>(packet_count);
          } else {
            const int batch_size = std::max(1, cli_max_batch);
            std::vector<std::int32_t> lengths(static_cast<std::size_t>(batch_size), 0);
            std::vector<std::int32_t> labels(static_cast<std::size_t>(batch_size), 0);
            std::vector<float> confidences(static_cast<std::size_t>(batch_size), 0.0f);

            int offset = 0;
            while (offset < packet_count) {
              const int n_this = std::min(batch_size, packet_count - offset);
              std::size_t flat_bytes = 0;
              for (int i = 0; i < n_this; ++i) {
                samurai_pacing_wait_next(&pace_state, &pace_cfg);
                const std::size_t off = static_cast<std::size_t>(offset + i) * stride;
                if (off + stride > pool.size()) {
                  lengths[static_cast<std::size_t>(i)] = 0;
                  packets_errors += 1u;
                  continue;
                }
                lengths[static_cast<std::size_t>(i)] = static_cast<std::int32_t>(std::min<std::size_t>(stride, static_cast<std::size_t>(0x7FFFFFFF)));
                flat_bytes += static_cast<std::size_t>(lengths[static_cast<std::size_t>(i)]);
              }

              std::vector<std::uint8_t> flat(flat_bytes);
              std::size_t cursor = 0;
              for (int i = 0; i < n_this; ++i) {
                const std::int32_t len = lengths[static_cast<std::size_t>(i)];
                if (len <= 0) continue;
                const std::size_t off = static_cast<std::size_t>(offset + i) * stride;
                const std::size_t ulen = static_cast<std::size_t>(len);
                std::memcpy(flat.data() + cursor, pool.data() + off, ulen);
                cursor += ulen;
              }

              const char* out_reason = nullptr;
              const int rc = defense.classify_batch(
                  flat.empty() ? nullptr : flat.data(),
                  lengths.data(),
                  static_cast<std::int64_t>(n_this),
                  labels.data(),
                  confidences.data(),
                  &out_reason);
              if (out_reason) reason_last = std::string(out_reason);
              if (rc != 0) {
                const std::string msg = reason_last.empty() ? (NativeLastError(defense).empty() ? "defense_classify_failed" : NativeLastError(defense)) : reason_last;
                (void)SendFrame(
                    push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                    header.correlation_id,
                    samurai::wire::WorkerKind::DEFENSE,
                    job_id,
                    JsonError(msg));
                packets_errors += static_cast<std::uint64_t>(n_this);
                break;
              }

              for (int i = 0; i < n_this; ++i) {
                const std::int32_t len = lengths[static_cast<std::size_t>(i)];
                if (len <= 0) continue;
                packets_sent += 1u;
                bytes_sent += static_cast<std::uint64_t>(len);
                classified_total += 1u;
                if (labels[static_cast<std::size_t>(i)] != 0) suspicious_total += 1u;
                confidence_sum += static_cast<double>(confidences[static_cast<std::size_t>(i)]);
              }

              const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
              if (now_ns - last_hb_ns >= 1'000'000'000ull) {
                (void)SendFrame(
                    push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                    header.correlation_id,
                    samurai::wire::WorkerKind::DEFENSE,
                    job_id);
                last_hb_ns = now_ns;
              }
              if (now_ns - last_metric_ns >= 2'000'000'000ull) {
                const samurai::wire::MetricSnapshotV1 snap =
                    BuildSnapshot(now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
                (void)SendFrame(
                    push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                    header.correlation_id,
                    samurai::wire::WorkerKind::DEFENSE,
                    job_id,
                    SerializeSnapshot(snap));
                last_metric_ns = now_ns;
                last_hb_ns = now_ns;
              }

              offset += n_this;
            }
          }
        }

        std::string classifier_stats = "{}";
        if (defense.read_stats) {
          const char* raw_stats = defense.read_stats();
          if (raw_stats && *raw_stats) classifier_stats = std::string(raw_stats);
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap =
            BuildSnapshot(end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::DEFENSE,
            job_id,
            SerializeSnapshot(snap));

        (void)defense.shutdown();
        const double mean_conf = classified_total > 0 ? (confidence_sum / static_cast<double>(classified_total)) : 0.0;
        const std::vector<std::uint8_t> done = JsonDone(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            classified_total,
            suspicious_total,
            mean_conf,
            reason_last,
            classifier_stats,
            snap.actual_rps,
            snap.rate_accuracy_pct);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::DEFENSE,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::DEFENSE,
            job_id,
            JsonError(exc.what()));
      }
      continue;
    }

    zmq_msg_close(&msg);
    (void)SendFrame(
        push,
        static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
        header.correlation_id,
        samurai::wire::WorkerKind::DEFENSE,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  if (defense.handle != nullptr) dlclose(defense.handle);
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
