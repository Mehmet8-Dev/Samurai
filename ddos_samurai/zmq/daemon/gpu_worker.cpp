#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <dlfcn.h>
#include <exception>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <zmq.h>

#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace {

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_gpu";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_gpu";
constexpr const char* kDefaultGpuLib = "ddos_samurai/libgpu_packet_cuda.so";
constexpr std::uint64_t kDefaultGatewayMac = 0xFFFFFFFFFFFFull;

using fn_generate_packets_t = int (*)(std::int64_t, const char*, std::int64_t, const char*, int, const char*, std::int64_t, int, std::int64_t, std::uint64_t, std::uint64_t, const char*, std::uint8_t**, std::size_t*, int*);
using fn_generate_icmp_packets_t = int (*)(std::int64_t, const char*, const char*, int, int, std::int64_t, std::int64_t, std::int64_t, std::uint64_t, std::uint64_t, const char*, std::uint8_t**, std::size_t*, int*);
using fn_contract_publish_flow_update_t = int (*)(const samurai::wire::FlowUpdateEventV1*);
using fn_set_kernel_mode_t = int (*)(int);
using fn_start_stream_t = int (*)(const char*, std::int64_t*);
using fn_update_stream_t = int (*)(std::int64_t, const char*);
using fn_stop_stream_t = int (*)(std::int64_t);
using fn_free_t = void (*)(void*);
using fn_last_error_t = const char* (*)();

struct GpuNativeApi {
  void* handle{nullptr};
  fn_generate_packets_t generate_packets{nullptr};
  fn_generate_icmp_packets_t generate_icmp_packets{nullptr};
  fn_contract_publish_flow_update_t contract_publish_flow_update{nullptr};
  fn_set_kernel_mode_t set_kernel_mode{nullptr};
  fn_start_stream_t start_stream{nullptr};
  fn_update_stream_t update_stream{nullptr};
  fn_stop_stream_t stop_stream{nullptr};
  fn_free_t free_fn{nullptr};
  fn_last_error_t last_error{nullptr};
  std::string lib_path;
};

std::string ReadFixed(const char* raw, std::size_t n) {
  return std::string(raw, strnlen(raw, n));
}

std::uint8_t ParseTcpFlags(const std::string& flags_raw) {
  std::uint8_t flags = 0u;
  for (char c : flags_raw) {
    switch (std::toupper(static_cast<unsigned char>(c))) {
      case 'F':
        flags |= 0x01u;
        break;
      case 'S':
        flags |= 0x02u;
        break;
      case 'R':
        flags |= 0x04u;
        break;
      case 'P':
        flags |= 0x08u;
        break;
      case 'A':
        flags |= 0x10u;
        break;
      case 'U':
        flags |= 0x20u;
        break;
      case 'E':
        flags |= 0x40u;
        break;
      case 'C':
        flags |= 0x80u;
        break;
      default:
        break;
    }
  }
  return flags == 0u ? 0x02u : flags;
}

std::string ResolveGpuLibPath() {
  const char* env = std::getenv("SAMURAI_GPU_NATIVE_LIB");
  if (env && *env) {
    return std::string(env);
  }
  return std::string(kDefaultGpuLib);
}

bool LoadGpuNative(GpuNativeApi& api, std::string& err) {
  if (api.handle != nullptr) {
    return true;
  }
  api.lib_path = ResolveGpuLibPath();
  api.handle = dlopen(api.lib_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!api.handle) {
    err = "gpu_native_lib_unavailable";
    return false;
  }

  api.generate_packets = reinterpret_cast<fn_generate_packets_t>(dlsym(api.handle, "samurai_gpu_packet_generate_packets"));
  api.generate_icmp_packets = reinterpret_cast<fn_generate_icmp_packets_t>(dlsym(api.handle, "samurai_gpu_packet_generate_icmp_packets"));
  api.contract_publish_flow_update = reinterpret_cast<fn_contract_publish_flow_update_t>(
      dlsym(api.handle, "samurai_gpu_packet_contract_publish_flow_update_v1"));
  api.set_kernel_mode = reinterpret_cast<fn_set_kernel_mode_t>(dlsym(api.handle, "samurai_gpu_packet_set_kernel_mode"));
  api.start_stream = reinterpret_cast<fn_start_stream_t>(dlsym(api.handle, "samurai_gpu_packet_start_stream"));
  api.update_stream = reinterpret_cast<fn_update_stream_t>(dlsym(api.handle, "samurai_gpu_packet_update_stream"));
  api.stop_stream = reinterpret_cast<fn_stop_stream_t>(dlsym(api.handle, "samurai_gpu_packet_stop_stream"));
  api.free_fn = reinterpret_cast<fn_free_t>(dlsym(api.handle, "samurai_gpu_packet_free"));
  api.last_error = reinterpret_cast<fn_last_error_t>(dlsym(api.handle, "samurai_gpu_packet_last_error"));
  if (!api.generate_packets || !api.generate_icmp_packets || !api.free_fn || !api.last_error) {
    err = "gpu_native_symbol_missing";
    dlclose(api.handle);
    api = GpuNativeApi{};
    return false;
  }
  return true;
}

std::string NativeLastError(const GpuNativeApi& api) {
  if (!api.last_error) {
    return "";
  }
  const char* p = api.last_error();
  if (!p) {
    return "";
  }
  return std::string(p);
}

bool EnvFlag(const char* name, bool default_value) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return default_value;
  }
  std::string value(raw);
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return !(value == "0" || value == "off" || value == "false" || value == "no");
}

std::int64_t EnvI64(const char* name, std::int64_t default_value) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return default_value;
  }
  try {
    return std::stoll(raw);
  } catch (...) {
    return default_value;
  }
}

std::string EnvString(const char* name, const std::string& default_value) {
  const char* raw = std::getenv(name);
  return (raw && *raw) ? std::string(raw) : default_value;
}

std::string JsonEscape(const std::string& raw) {
  std::string out;
  out.reserve(raw.size() + 8);
  for (char c : raw) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
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
        out += c;
        break;
    }
  }
  return out;
}

const char* ProtocolNameFromEvent(std::uint8_t proto) {
  if (proto == 17u) return "udp";
  if (proto == 1u) return "icmp";
  return "tcp";
}

struct FlowLifecycleConfig {
  bool enabled{true};
  bool require_target_ip{false};
  std::string target_ip{"127.0.0.1"};
  std::int64_t quota{1024};
  std::int64_t tx_ipg_ns{0};
  std::int64_t payload_len{0};
  std::int64_t payload_byte{0};
  int weight{1};
};

FlowLifecycleConfig LoadFlowLifecycleConfig() {
  FlowLifecycleConfig cfg{};
  cfg.enabled = EnvFlag("SAMURAI_GPU_FLOW_UPDATE_STREAM_LIFECYCLE", true);
  cfg.require_target_ip = EnvFlag("SAMURAI_GPU_FLOW_UPDATE_REQUIRE_TARGET_IP", false);
  cfg.target_ip = EnvString("SAMURAI_GPU_FLOW_UPDATE_TARGET_IP", "127.0.0.1");
  cfg.quota = std::max<std::int64_t>(1, EnvI64("SAMURAI_GPU_FLOW_UPDATE_STREAM_QUOTA", 1024));
  cfg.tx_ipg_ns = std::max<std::int64_t>(0, EnvI64("SAMURAI_GPU_FLOW_UPDATE_TX_IPG_NS", 0));
  cfg.payload_len = std::max<std::int64_t>(0, EnvI64("SAMURAI_GPU_FLOW_UPDATE_PAYLOAD_LEN", 0));
  cfg.payload_byte = std::max<std::int64_t>(0, std::min<std::int64_t>(255, EnvI64("SAMURAI_GPU_FLOW_UPDATE_PAYLOAD_BYTE", 0)));
  cfg.weight = static_cast<int>(std::max<std::int64_t>(1, std::min<std::int64_t>(32, EnvI64("SAMURAI_GPU_FLOW_UPDATE_STREAM_WEIGHT", 1))));
  return cfg;
}

std::string FlowEventStreamJson(const samurai::wire::FlowUpdateEventV1& event, const FlowLifecycleConfig& cfg) {
  std::ostringstream oss;
  const bool is_icmp = event.proto == 1u;
  oss << "{"
      << "\"stream_type\":\"l4\","
      << "\"flow_id\":" << event.flow_id << ","
      << "\"dpu_epoch\":" << event.epoch << ","
      << "\"dpu_version\":" << event.version << ","
      << "\"protocol\":\"" << ProtocolNameFromEvent(event.proto) << "\","
      << "\"target_ip\":\"" << JsonEscape(cfg.target_ip) << "\","
      << "\"target_port\":" << (is_icmp ? 0u : static_cast<unsigned int>(event.dst_port)) << ","
      << "\"source_port\":" << static_cast<unsigned int>(event.src_port) << ","
      << "\"source_port_mode\":" << (event.src_port != 0u ? 1 : 0) << ","
      << "\"tcp_flags\":" << static_cast<unsigned int>(event.flags & 0xFFu) << ","
      << "\"quota\":" << cfg.quota << ","
      << "\"weight\":" << cfg.weight << ","
      << "\"tx_ipg_ns\":" << cfg.tx_ipg_ns << ","
      << "\"payload_len\":" << cfg.payload_len << ","
      << "\"payload_byte\":" << cfg.payload_byte
      << "}";
  return oss.str();
}

std::string ReadStreamTargetIp(const samurai::wire::FlowStreamUpsertV1& upsert) {
  return ReadFixed(upsert.target_ip, sizeof(upsert.target_ip));
}

samurai::wire::FlowUpdateEventV1 FlowUpdateFromStreamUpsert(const samurai::wire::FlowStreamUpsertV1& upsert) {
  samurai::wire::FlowUpdateEventV1 ev{};
  ev.version = upsert.version;
  ev.epoch = upsert.epoch;
  ev.flow_id = upsert.flow_id;
  ev.tcp_seq = upsert.tcp_seq;
  ev.tcp_ack = upsert.tcp_ack;
  ev.src_port = upsert.src_port;
  ev.dst_port = upsert.dst_port;
  ev.tcp_state = upsert.tcp_state;
  ev.proto = upsert.proto;
  ev.flags = upsert.flags;
  ev.rtt_us = upsert.rtt_us;
  ev.dpu_ts_ns = upsert.dpu_ts_ns;
  return ev;
}

std::string FlowStreamUpsertJson(const samurai::wire::FlowStreamUpsertV1& upsert, const FlowLifecycleConfig& cfg) {
  std::ostringstream oss;
  const bool is_icmp = upsert.proto == 1u;
  const std::string target_ip = ReadStreamTargetIp(upsert);
  const std::uint32_t quota = upsert.quota > 0u ? upsert.quota : static_cast<std::uint32_t>(cfg.quota);
  const std::uint64_t tx_ipg_ns = upsert.tx_ipg_ns;
  const std::uint16_t payload_len = upsert.payload_len;
  const std::uint8_t weight = upsert.weight > 0u ? upsert.weight : static_cast<std::uint8_t>(cfg.weight);
  oss << "{"
      << "\"stream_type\":\"l4\","
      << "\"flow_id\":" << upsert.flow_id << ","
      << "\"template_id\":" << upsert.template_id << ","
      << "\"dpu_epoch\":" << upsert.epoch << ","
      << "\"dpu_version\":" << upsert.version << ","
      << "\"protocol\":\"" << ProtocolNameFromEvent(upsert.proto) << "\","
      << "\"target_ip\":\"" << JsonEscape(target_ip) << "\","
      << "\"target_port\":" << (is_icmp ? 0u : static_cast<unsigned int>(upsert.dst_port)) << ","
      << "\"source_port\":" << static_cast<unsigned int>(upsert.src_port) << ","
      << "\"source_port_mode\":" << (upsert.src_port != 0u ? 1 : 0) << ","
      << "\"tcp_flags\":" << static_cast<unsigned int>(upsert.flags & 0xFFu) << ","
      << "\"quota\":" << quota << ","
      << "\"weight\":" << static_cast<unsigned int>(weight) << ","
      << "\"tx_ipg_ns\":" << tx_ipg_ns << ","
      << "\"payload_len\":" << payload_len << ","
      << "\"payload_byte\":" << static_cast<unsigned int>(upsert.payload_byte)
      << "}";
  return oss.str();
}

bool EnsureFlowLifecycleSymbols(const GpuNativeApi& api, bool need_stop, std::string& err) {
  if (!api.set_kernel_mode || !api.start_stream || !api.update_stream || (need_stop && !api.stop_stream)) {
    err = "gpu_native_stream_lifecycle_symbol_missing";
    return false;
  }
  return true;
}

bool UpsertFlowStreamFromStreamUpsert(
    GpuNativeApi& api,
    const samurai::wire::FlowStreamUpsertV1& upsert,
    const FlowLifecycleConfig& cfg,
    std::unordered_map<std::uint32_t, std::int64_t>& flow_streams,
    std::string& err) {
  if (!cfg.enabled) {
    return true;
  }
  const bool poison = upsert.tcp_state == 255u;
  if (!EnsureFlowLifecycleSymbols(api, poison, err)) {
    return false;
  }
  const std::string target_ip = ReadStreamTargetIp(upsert);
  if (target_ip.empty() && !poison) {
    err = "gpu_flow_stream_upsert_target_ip_required";
    return false;
  }
  if (upsert.proto != 1u && upsert.dst_port == 0u && !poison) {
    err = "gpu_flow_update_target_port_required";
    return false;
  }

  auto it = flow_streams.find(upsert.flow_id);
  if (poison) {
    if (it != flow_streams.end()) {
      if (api.stop_stream(it->second) != 0) {
        err = NativeLastError(api);
        if (err.empty()) err = "gpu_flow_update_stop_stream_failed";
        return false;
      }
      flow_streams.erase(it);
    }
    return true;
  }

  if (api.set_kernel_mode(1) != 0) {
    err = NativeLastError(api);
    if (err.empty()) err = "gpu_flow_update_set_persistent_mode_failed";
    return false;
  }

  const std::string json = FlowStreamUpsertJson(upsert, cfg);
  if (it == flow_streams.end()) {
    std::int64_t stream_id = 0;
    if (api.start_stream(json.c_str(), &stream_id) != 0 || stream_id == 0) {
      err = NativeLastError(api);
      if (err.empty()) err = "gpu_flow_update_start_stream_failed";
      return false;
    }
    flow_streams[upsert.flow_id] = stream_id;
    return true;
  }

  if (api.update_stream(it->second, json.c_str()) != 0) {
    err = NativeLastError(api);
    if (err.empty()) err = "gpu_flow_update_update_stream_failed";
    return false;
  }
  return true;
}

bool UpsertFlowStreamFromEvent(
    GpuNativeApi& api,
    const samurai::wire::FlowUpdateEventV1& event,
    const FlowLifecycleConfig& cfg,
    std::unordered_map<std::uint32_t, std::int64_t>& flow_streams,
    std::string& err) {
  if (!cfg.enabled) {
    return true;
  }
  const bool poison = event.tcp_state == 255u;
  if (!EnsureFlowLifecycleSymbols(api, poison, err)) {
    return false;
  }
  if (cfg.require_target_ip && cfg.target_ip.empty()) {
    err = "gpu_flow_update_target_ip_required";
    return false;
  }
  if (event.proto != 1u && event.dst_port == 0u && !poison) {
    err = "gpu_flow_update_target_port_required";
    return false;
  }

  auto it = flow_streams.find(event.flow_id);
  if (poison) {
    if (it != flow_streams.end()) {
      if (api.stop_stream(it->second) != 0) {
        err = NativeLastError(api);
        if (err.empty()) err = "gpu_flow_update_stop_stream_failed";
        return false;
      }
      flow_streams.erase(it);
    }
    return true;
  }

  if (api.set_kernel_mode(1) != 0) {
    err = NativeLastError(api);
    if (err.empty()) err = "gpu_flow_update_set_persistent_mode_failed";
    return false;
  }

  const std::string json = FlowEventStreamJson(event, cfg);
  if (it == flow_streams.end()) {
    std::int64_t stream_id = 0;
    if (api.start_stream(json.c_str(), &stream_id) != 0 || stream_id == 0) {
      err = NativeLastError(api);
      if (err.empty()) err = "gpu_flow_update_start_stream_failed";
      return false;
    }
    flow_streams[event.flow_id] = stream_id;
    return true;
  }

  if (api.update_stream(it->second, json.c_str()) != 0) {
    err = NativeLastError(api);
    if (err.empty()) err = "gpu_flow_update_update_stream_failed";
    return false;
  }
  return true;
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

std::vector<std::uint8_t> JsonError(const std::string& reason) {
  const std::string json = "{\"status\":\"error\",\"error\":\"" + reason + "\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct,
    const std::string& note) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"gpu\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"note\":\"" + note + "\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
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

int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::GPU, job_id);
}

struct NativeResult {
  std::size_t bytes_total{0};
  int packet_size{0};
};

bool RunGpuNativeBatch(
    GpuNativeApi& api,
    const samurai::wire::JobEnvelopeV1& env,
    int batch_count,
    NativeResult& out,
    std::string& err) {
  std::uint8_t* ptr = nullptr;
  std::size_t out_size = 0;
  int out_packet_size = 0;
  const std::string protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  const std::string spoof_subnet = ReadFixed(env.spoof_subnet, sizeof(env.spoof_subnet));
  const char* spoof_subnet_ptr = spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet.c_str();
  const std::string target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  const std::string target_ip_norm = target_ip.empty() ? "127.0.0.1" : target_ip;
  const std::string tcp_flags = ReadFixed(env.tcp_flags, sizeof(env.tcp_flags));
  const std::int64_t tcp_flags_int = static_cast<std::int64_t>(ParseTcpFlags(tcp_flags));

  const bool is_icmp = (protocol == "icmp" || protocol == "ICMP");
  int rc = 0;
  if (is_icmp) {
    rc = api.generate_icmp_packets(
        static_cast<std::int64_t>(batch_count),
        target_ip_norm.c_str(),
        "192.168.1.100",
        env.spoof_enabled != 0u ? 1 : 0,
        1,
        8,
        0,
        std::max<std::int64_t>(0, static_cast<std::int64_t>(env.packet_size) - 42),
        0ull,
        kDefaultGatewayMac,
        spoof_subnet_ptr,
        &ptr,
        &out_size,
        &out_packet_size);
  } else {
    const std::string proto = protocol.empty() ? "tcp" : protocol;
    rc = api.generate_packets(
        static_cast<std::int64_t>(batch_count),
        target_ip_norm.c_str(),
        static_cast<std::int64_t>(env.target_port),
        proto.c_str(),
        env.spoof_enabled != 0u ? 1 : 0,
        "192.168.1.100",
        tcp_flags_int,
        1,
        env.window == 0ull ? -1 : static_cast<std::int64_t>(env.window),
        0ull,
        kDefaultGatewayMac,
        spoof_subnet_ptr,
        &ptr,
        &out_size,
        &out_packet_size);
  }

  if (rc != 0) {
    err = NativeLastError(api);
    if (err.empty()) {
      err = "gpu_native_generate_failed";
    }
    if (ptr && api.free_fn) {
      api.free_fn(ptr);
    }
    return false;
  }
  if (ptr && api.free_fn) {
    api.free_fn(ptr);
  }
  if (out_packet_size <= 0) {
    err = "gpu_native_packet_size_invalid";
    return false;
  }
  out.bytes_total = out_size;
  out.packet_size = out_packet_size;
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_batch_size = 8192;

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
    } else if (arg == "--gpu-batch-size" && i + 1 < argc) {
      cli_batch_size = std::max(1, std::stoi(argv[++i]));
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

  GpuNativeApi api{};
  FlowLifecycleConfig flow_lifecycle_cfg = LoadFlowLifecycleConfig();
  std::unordered_map<std::uint32_t, std::int64_t> flow_streams;
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
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"gpu\"}";
      (void)SendFrame(
          push,
          static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
          header.correlation_id,
          samurai::wire::WorkerKind::GPU,
          job_id,
          std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::FLOW_UPDATE) {
      if (payload_len != sizeof(samurai::wire::FlowUpdateEventV1) ||
          header.payload_len != sizeof(samurai::wire::FlowUpdateEventV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError("flow_update_event_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }

      samurai::wire::FlowUpdateEventV1 event{};
      std::memcpy(&event, payload_ptr, sizeof(event));
      zmq_msg_close(&msg);

      std::string native_err;
      if (!LoadGpuNative(api, native_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(native_err));
        continue;
      }
      if (!api.contract_publish_flow_update) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError("gpu_native_contract_symbol_missing"));
        continue;
      }
      if (api.contract_publish_flow_update(&event) != 0) {
        std::string err = NativeLastError(api);
        if (err.empty()) {
          err = "gpu_contract_publish_failed";
        }
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(err));
        continue;
      }
      if (!UpsertFlowStreamFromEvent(api, event, flow_lifecycle_cfg, flow_streams, native_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(native_err));
        continue;
      }
      (void)SendAck(push, header.correlation_id, job_id);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::FLOW_STREAM_UPSERT) {
      if (payload_len != sizeof(samurai::wire::FlowStreamUpsertV1) ||
          header.payload_len != sizeof(samurai::wire::FlowStreamUpsertV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError("flow_stream_upsert_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }

      samurai::wire::FlowStreamUpsertV1 upsert{};
      std::memcpy(&upsert, payload_ptr, sizeof(upsert));
      zmq_msg_close(&msg);

      std::string native_err;
      if (!LoadGpuNative(api, native_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(native_err));
        continue;
      }
      if (!api.contract_publish_flow_update) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError("gpu_native_contract_symbol_missing"));
        continue;
      }
      const samurai::wire::FlowUpdateEventV1 event = FlowUpdateFromStreamUpsert(upsert);
      if (api.contract_publish_flow_update(&event) != 0) {
        std::string err = NativeLastError(api);
        if (err.empty()) {
          err = "gpu_contract_publish_failed";
        }
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(err));
        continue;
      }
      if (!UpsertFlowStreamFromStreamUpsert(api, upsert, flow_lifecycle_cfg, flow_streams, native_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(native_err));
        continue;
      }
      (void)SendAck(push, header.correlation_id, job_id);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) ||
          header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
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
        if (!LoadGpuNative(api, native_err)) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::GPU,
              job_id,
              JsonError(native_err));
          continue;
        }

        const int total_packets = std::max(1, static_cast<int>(env.packet_count));
        const int batch_size = std::max(1, cli_batch_size);
        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;

        int remaining = total_packets;
        while (remaining > 0) {
          const int current = std::min(batch_size, remaining);
          NativeResult gen{};
          std::string gen_err;
          if (!RunGpuNativeBatch(api, env, current, gen, gen_err)) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::GPU,
                job_id,
                JsonError(gen_err));
            packets_errors += static_cast<std::uint64_t>(current);
            break;
          }

          const std::uint64_t packet_size_u = static_cast<std::uint64_t>(std::max(1, gen.packet_size));
          for (int i = 0; i < current; ++i) {
            samurai_pacing_wait_next(&pace_state, &pace_cfg);
            packets_sent += 1u;
            bytes_sent += packet_size_u;
            if ((static_cast<std::uint32_t>(i) & 0x3FFu) == 0u) {
              const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
              if (now_ns - last_hb_ns >= 1'000'000'000ull) {
                (void)SendFrame(
                    push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                    header.correlation_id,
                    samurai::wire::WorkerKind::GPU,
                    job_id);
                last_hb_ns = now_ns;
              }
              if (now_ns - last_metric_ns >= 2'000'000'000ull) {
                const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
                    now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
                (void)SendFrame(
                    push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                    header.correlation_id,
                    samurai::wire::WorkerKind::GPU,
                    job_id,
                    SerializeSnapshot(snap));
                last_metric_ns = now_ns;
                last_hb_ns = now_ns;
              }
            }
          }
          remaining -= current;
          (void)gen.bytes_total;
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonDone(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            snap.actual_rps,
            snap.rate_accuracy_pct,
            "gpu_native_capi+pacing_static");
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
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
        samurai::wire::WorkerKind::GPU,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  if (api.handle) {
    dlclose(api.handle);
  }
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
