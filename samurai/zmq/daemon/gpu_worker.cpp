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
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <zmq.h>

extern "C" {
#include "af_packet.h"
}

#include "pacing_engine.h"
#include "wire_protocol.h"
#include "gpu_packet_cuda/zero_copy_dataplane_contract.cuh"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

namespace {
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_gpu";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_gpu";
constexpr std::uint32_t kGpuStreamPolicyTemplateValid = 0x80000000u;
constexpr const char* kDefaultGpuLib = "samurai/libgpu_packet_cuda.so";
constexpr std::uint64_t kDefaultGatewayMac = 0xFFFFFFFFFFFFull;

using fn_generate_packets_t = int (*)(std::int64_t, const char*, std::int64_t, const char*, int, const char*, std::int64_t, int, std::int64_t, std::uint64_t, std::uint64_t, const char*, std::uint8_t**, std::size_t*, int*);
using fn_generate_icmp_packets_t = int (*)(std::int64_t, const char*, const char*, int, int, std::int64_t, std::int64_t, std::int64_t, std::uint64_t, std::uint64_t, const char*, std::uint8_t**, std::size_t*, int*);
using fn_contract_publish_flow_update_t = int (*)(const samurai::wire::FlowUpdateEventV1*);
using fn_contract_heartbeat_t = int (*)(std::uint64_t);
using fn_contract_export_region_t = int (*)(char*, std::size_t);
using fn_set_kernel_mode_t = int (*)(int);
using fn_start_stream_t = int (*)(const char*, std::int64_t*);
using fn_update_stream_t = int (*)(std::int64_t, const char*);
using fn_stop_stream_t = int (*)(std::int64_t);
using fn_free_t = void (*)(void*);
using fn_last_error_t = const char* (*)();
using fn_p2p_bar1_available_t = int (*)();
using fn_p2p_get_arena_info_t = int (*)(std::uint64_t*, void**, void**, std::size_t*);
using fn_generate_gtpu_packets_t = int (*)(const char*, int, void**, std::size_t*, int*);
using fn_telco_upsert_tunnels_v1_t = int (*)(const void*, std::uint32_t);
using fn_telco_clear_tunnels_v1_t = int (*)();
using fn_telco_verify_rx_batch_v1_t = int (*)(const void*, std::uint32_t, std::uint32_t, void*);
using fn_telco_read_rx_stats_v1_t = int (*)(void*);
using fn_p2p_tx_bar1_batch_v1_t = int (*)(const std::uint32_t*, const std::uint16_t*, std::uint32_t, std::uint32_t*);
using fn_p2p_set_active_ring_v1_t = int (*)(std::uint32_t);
using fn_p2p_get_active_ring_v1_t = int (*)(std::uint32_t*);
using fn_telco_attach_cups_shm_v1_t = int (*)(const char*, std::uint32_t);
using fn_telco_detach_cups_shm_v1_t = int (*)();

struct GpuNativeApi {
  void* handle{nullptr};
  fn_generate_packets_t generate_packets{nullptr};
  fn_generate_icmp_packets_t generate_icmp_packets{nullptr};
  fn_contract_publish_flow_update_t contract_publish_flow_update{nullptr};
  fn_contract_heartbeat_t contract_heartbeat{nullptr};
  fn_contract_export_region_t contract_export_region{nullptr};
  fn_set_kernel_mode_t set_kernel_mode{nullptr};
  fn_start_stream_t start_stream{nullptr};
  fn_update_stream_t update_stream{nullptr};
  fn_stop_stream_t stop_stream{nullptr};
  fn_free_t free_fn{nullptr};
  fn_last_error_t last_error{nullptr};
  fn_p2p_bar1_available_t p2p_bar1_available{nullptr};
  fn_p2p_get_arena_info_t p2p_get_arena_info{nullptr};
  fn_generate_gtpu_packets_t generate_gtpu_packets{nullptr};
  fn_telco_upsert_tunnels_v1_t telco_upsert_tunnels_v1{nullptr};
  fn_telco_clear_tunnels_v1_t telco_clear_tunnels_v1{nullptr};
  fn_telco_verify_rx_batch_v1_t telco_verify_rx_batch_v1{nullptr};
  fn_telco_read_rx_stats_v1_t telco_read_rx_stats_v1{nullptr};
  fn_p2p_tx_bar1_batch_v1_t p2p_tx_bar1_batch{nullptr};
  fn_p2p_set_active_ring_v1_t p2p_set_active_ring_v1{nullptr};
  fn_p2p_get_active_ring_v1_t p2p_get_active_ring_v1{nullptr};
  fn_telco_attach_cups_shm_v1_t telco_attach_cups_shm_v1{nullptr};
  fn_telco_detach_cups_shm_v1_t telco_detach_cups_shm_v1{nullptr};
  std::string lib_path;
};


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
  api.contract_heartbeat = reinterpret_cast<fn_contract_heartbeat_t>(
      dlsym(api.handle, "samurai_gpu_packet_contract_heartbeat_v1"));
  api.contract_export_region = reinterpret_cast<fn_contract_export_region_t>(
      dlsym(api.handle, "samurai_gpu_packet_contract_export_region_v1"));
  api.set_kernel_mode = reinterpret_cast<fn_set_kernel_mode_t>(dlsym(api.handle, "samurai_gpu_packet_set_kernel_mode"));
  api.start_stream = reinterpret_cast<fn_start_stream_t>(dlsym(api.handle, "samurai_gpu_packet_start_stream"));
  api.update_stream = reinterpret_cast<fn_update_stream_t>(dlsym(api.handle, "samurai_gpu_packet_update_stream"));
  api.stop_stream = reinterpret_cast<fn_stop_stream_t>(dlsym(api.handle, "samurai_gpu_packet_stop_stream"));
  api.free_fn = reinterpret_cast<fn_free_t>(dlsym(api.handle, "samurai_gpu_packet_free"));
  api.last_error = reinterpret_cast<fn_last_error_t>(dlsym(api.handle, "samurai_gpu_packet_last_error"));
  api.p2p_bar1_available = reinterpret_cast<fn_p2p_bar1_available_t>(
      dlsym(api.handle, "samurai_gpu_packet_p2p_bar1_available"));
  api.p2p_get_arena_info = reinterpret_cast<fn_p2p_get_arena_info_t>(
      dlsym(api.handle, "samurai_gpu_packet_p2p_get_arena_info"));
  api.generate_gtpu_packets = reinterpret_cast<fn_generate_gtpu_packets_t>(
      dlsym(api.handle, "samurai_gpu_packet_generate_gtpu_packets"));
  api.telco_upsert_tunnels_v1 = reinterpret_cast<fn_telco_upsert_tunnels_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_upsert_tunnels_v1"));
  api.telco_clear_tunnels_v1 = reinterpret_cast<fn_telco_clear_tunnels_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_clear_tunnels_v1"));
  api.telco_verify_rx_batch_v1 = reinterpret_cast<fn_telco_verify_rx_batch_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_verify_rx_batch_v1"));
  api.telco_read_rx_stats_v1 = reinterpret_cast<fn_telco_read_rx_stats_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_read_rx_stats_v1"));
  api.p2p_tx_bar1_batch = reinterpret_cast<fn_p2p_tx_bar1_batch_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_p2p_tx_bar1_batch_v1"));
  api.p2p_set_active_ring_v1 = reinterpret_cast<fn_p2p_set_active_ring_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_p2p_set_active_ring_v1"));
  api.p2p_get_active_ring_v1 = reinterpret_cast<fn_p2p_get_active_ring_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_p2p_get_active_ring_v1"));
  api.telco_attach_cups_shm_v1 = reinterpret_cast<fn_telco_attach_cups_shm_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_attach_cups_shm_v1"));
  api.telco_detach_cups_shm_v1 = reinterpret_cast<fn_telco_detach_cups_shm_v1_t>(
      dlsym(api.handle, "samurai_gpu_packet_telco_detach_cups_shm_v1"));
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

std::string TryReadContractExportRegionSpec(const GpuNativeApi& api) {
  const char* export_on_done = std::getenv("SAMURAI_GPU_CONTRACT_EXPORT_ON_JOB_DONE");
  if (!export_on_done || !*export_on_done) {
    return "";
  }
  std::string flag(export_on_done);
  std::transform(flag.begin(), flag.end(), flag.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (flag == "0" || flag == "off" || flag == "false" || flag == "no") {
    return "";
  }
  if (!api.contract_export_region) {
    return "";
  }
  char spec[512];
  spec[0] = '\0';
  if (api.contract_export_region(spec, sizeof(spec)) != 0) {
    return "";
  }
  return ReadFixed(spec, sizeof(spec));
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
      << "\"tcp_seq\":" << event.tcp_seq << ","
      << "\"tcp_ack\":" << event.tcp_ack << ","
      << "\"tcp_state\":" << static_cast<unsigned int>(event.tcp_state) << ","
      << "\"tcp_mss\":1460,"
      << "\"tcp_window_scale\":8,"
      << "\"tcp_sack_permitted\":true,"
      << "\"tcp_timestamp_enabled\":true,"
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
  const bool policy_valid = (upsert.template_id & kGpuStreamPolicyTemplateValid) != 0u;
  const std::uint32_t quota =
      (policy_valid || upsert.quota > 0u) ? upsert.quota : static_cast<std::uint32_t>(cfg.quota);
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
      << "\"tcp_seq\":" << upsert.tcp_seq << ","
      << "\"tcp_ack\":" << upsert.tcp_ack << ","
      << "\"tcp_state\":" << static_cast<unsigned int>(upsert.tcp_state) << ","
      << "\"tcp_mss\":1460,"
      << "\"tcp_window_scale\":8,"
      << "\"tcp_sack_permitted\":true,"
      << "\"tcp_timestamp_enabled\":true,"
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
  const bool inactive_transition = upsert.tcp_state == 255u || upsert.tcp_state == 250u;
  if (!EnsureFlowLifecycleSymbols(api, inactive_transition, err)) {
    return false;
  }
  const std::string target_ip = ReadStreamTargetIp(upsert);
  if (target_ip.empty() && !inactive_transition) {
    err = "gpu_flow_stream_upsert_target_ip_required";
    return false;
  }
  if (upsert.proto != 1u && upsert.dst_port == 0u && !inactive_transition) {
    err = "gpu_flow_update_target_port_required";
    return false;
  }

  auto it = flow_streams.find(upsert.flow_id);
  if (inactive_transition) {
    if (it != flow_streams.end()) {
      if (api.stop_stream(it->second) != 0) {
        err = NativeLastError(api);
        if (err.empty()) err = "gpu_flow_update_pause_stream_failed";
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
  const bool inactive_transition = event.tcp_state == 255u || event.tcp_state == 250u;
  if (!EnsureFlowLifecycleSymbols(api, inactive_transition, err)) {
    return false;
  }
  if (cfg.require_target_ip && cfg.target_ip.empty()) {
    err = "gpu_flow_update_target_ip_required";
    return false;
  }
  if (event.proto != 1u && event.dst_port == 0u && !inactive_transition) {
    err = "gpu_flow_update_target_port_required";
    return false;
  }

  auto it = flow_streams.find(event.flow_id);
  if (inactive_transition) {
    if (it != flow_streams.end()) {
      if (api.stop_stream(it->second) != 0) {
        err = NativeLastError(api);
        if (err.empty()) err = "gpu_flow_update_pause_stream_failed";
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



std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct,
    const std::string& note,
    const std::string& contract_export_region_spec,
    std::uint64_t ipfix_exported_packets = 0,
    std::uint64_t ipfix_exported_records = 0) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"gpu\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"contract_export_region_available\":" + (contract_export_region_spec.empty() ? "0" : "1") +
      ",\"contract_export_region_spec\":\"" + JsonEscape(contract_export_region_spec) +
      "\",\"ipfix_exported_packets\":" + std::to_string(ipfix_exported_packets) +
      ",\"ipfix_exported_records\":" + std::to_string(ipfix_exported_records) +
      ",\"note\":\"" + note + "\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}




int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::GPU, job_id);
}

inline std::string FormatIpv4(std::uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." +
         std::to_string(ip & 0xFF);
}

bool HandleTelcoTunnelUpsertPayload(
    const GpuNativeApi& api,
    const std::uint8_t* payload_ptr,
    std::size_t payload_len,
    std::string& err_out) {
  if (payload_len < sizeof(samurai::wire::TelcoGpuTunnelUpsertV1)) {
    err_out = "telco_tunnel_upsert_payload_too_small";
    return false;
  }
  samurai::wire::TelcoGpuTunnelUpsertV1 upsert_hdr{};
  std::memcpy(&upsert_hdr, payload_ptr, sizeof(upsert_hdr));
  const std::uint64_t expected_entries = static_cast<std::uint64_t>(upsert_hdr.count);
  const std::uint64_t entry_size =
      static_cast<std::uint64_t>(sizeof(samurai::gpu_packet_cuda::zero_copy::TelcoGpuTunnelEntryV1));
  const std::uint64_t expected_entries_bytes = expected_entries * entry_size;
  const std::uint64_t actual_entries_bytes =
      static_cast<std::uint64_t>(payload_len - sizeof(upsert_hdr));

  if (actual_entries_bytes != expected_entries_bytes) {
    err_out = "telco_tunnel_upsert_entries_size_mismatch";
    return false;
  }

  if ((upsert_hdr.flags & samurai::wire::kTelcoTunnelUpsertFlagClearBeforeUpsert) != 0) {
    if (api.telco_clear_tunnels_v1) {
      api.telco_clear_tunnels_v1();
    }
  }

  if (upsert_hdr.count > 0 && api.telco_upsert_tunnels_v1) {
    const void* entries_ptr = payload_ptr + sizeof(upsert_hdr);
    if (api.telco_upsert_tunnels_v1(entries_ptr, upsert_hdr.count) != 0) {
      err_out = "telco_upsert_tunnels_failed";
      return false;
    }
  }
  return true;
}

struct NativeResult {
  std::size_t bytes_total{0};
  int packet_size{0};
  int packets_sent{0};
  int packets_errors{0};
  bool transmitted_on_wire{false};
  std::string tx_note;
};

bool RunGpuNativeBatch(
    GpuNativeApi& api,
    const samurai::wire::JobEnvelopeV1& env,
    int batch_count,
    long long ipg_ns,
    NativeResult& out,
    std::string& err,
    const samurai::wire::TelcoGpuJobEnvelopeV1* telco_env = nullptr) {
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

  const std::string iface = EnvString("SAMURAI_AFPACKET_IFACE", "");
  const bool tx_enabled = EnvFlag("SAMURAI_AFPACKET_TX", true);
  // L2 TX_RING requires Ethernet header (has_ethernet=1); L3 raw socket uses IPv4 payload (has_ethernet=0).
  const int has_ethernet = (!iface.empty() || !tx_enabled) ? 1 : 0;

  const bool is_gtpu = (protocol == "gtpu" || protocol == "GTPU" || protocol == "gtp-u" || protocol == "5g-gtpu" ||
                       (telco_env != nullptr && (protocol.empty() || protocol == "gtpu" || protocol == "GTPU" || protocol == "gtp-u" || protocol == "5g-gtpu")));
  const bool is_icmp = (protocol == "icmp" || protocol == "ICMP");
  int rc = 0;
  if (is_gtpu && api.generate_gtpu_packets) {
    const bool bar1_p2p_mode =
        (telco_env && (telco_env->flags & samurai::wire::kTelcoGpuJobFlagBar1P2p) != 0) ||
        EnvFlag("SAMURAI_GPU_PACKET_BAR1_P2P_OUTPUT", false) ||
        EnvString("SAMURAI_GPU_TX_BACKEND", "") == "geforce_p2p";
    const std::string ue_ip_str = (telco_env && telco_env->ue_src_ip_start != 0) ? FormatIpv4(telco_env->ue_src_ip_start) : "10.60.0.1";
    const std::string inner_dst_str = (telco_env && telco_env->inner_dst_ip != 0) ? FormatIpv4(telco_env->inner_dst_ip) : "8.8.8.8";
    const int inner_payload_len = env.packet_size > 64 ? static_cast<int>(env.packet_size) - 64 : 32;
    std::ostringstream json_cfg;
    json_cfg << "{"
             << "\"target_ip\":\"" << target_ip_norm << "\","
             << "\"src_ip\":\"192.168.1.100\","
             << "\"teid_start\":" << (telco_env ? telco_env->teid_start : 1u) << ","
             << "\"teid_count\":" << (telco_env ? telco_env->teid_count : 1u) << ","
             << "\"ue_ip_start\":\"" << ue_ip_str << "\","
             << "\"ue_ip_count\":" << (telco_env && telco_env->ue_src_ip_count > 0 ? telco_env->ue_src_ip_count : 1u) << ","
             << "\"inner_dst_ip\":\"" << inner_dst_str << "\","
             << "\"inner_src_port\":" << (telco_env ? static_cast<int>(telco_env->inner_src_port) : 0) << ","
             << "\"inner_dst_port\":" << (telco_env && telco_env->inner_dst_port != 0 ? static_cast<int>(telco_env->inner_dst_port) : 80) << ","
             << "\"qfi\":" << (telco_env ? static_cast<int>(telco_env->qfi) : 9) << ","
             << "\"pdu_type\":" << (telco_env ? static_cast<int>(telco_env->pdu_type) : 1) << ","
             << "\"with_qfi\":" << (telco_env ? (telco_env->with_qfi_ext ? "true" : "false") : "true") << ","
             << "\"with_seq\":" << (telco_env ? (telco_env->with_seq ? "true" : "false") : "true") << ","
             << "\"echo_mode\":" << (telco_env ? (telco_env->echo_mode ? "true" : "false") : "false") << ","
             << "\"payload_len\":" << inner_payload_len << ","
             << "\"inner_proto\":\"" << (telco_env && telco_env->inner_proto == 6 ? "tcp" : (telco_env && telco_env->inner_proto == 1 ? "icmp" : "udp")) << "\","
             << "\"svlan\":" << (telco_env ? telco_env->svlan_tci : 0) << ","
             << "\"cvlan\":" << (telco_env ? telco_env->cvlan_tci : 0) << ","
             << "\"vlan_depth\":" << (telco_env ? static_cast<int>(telco_env->vlan_depth) : 0) << ","
             << "\"bar1_p2p\":" << (bar1_p2p_mode ? "true" : "false")
             << "}";
    rc = api.generate_gtpu_packets(
        json_cfg.str().c_str(),
        batch_count,
        reinterpret_cast<void**>(&ptr),
        &out_size,
        &out_packet_size);
  } else if (is_icmp) {
    rc = api.generate_icmp_packets(
        static_cast<std::int64_t>(batch_count),
        target_ip_norm.c_str(),
        "192.168.1.100",
        env.spoof_enabled != 0u ? 1 : 0,
        has_ethernet,
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
        has_ethernet,
        env.window == 0ull ? -1 : static_cast<std::int64_t>(env.window),
        0ull,
        kDefaultGatewayMac,
        spoof_subnet_ptr,
        &ptr,
        &out_size,
        &out_packet_size);
  }

  std::unique_ptr<std::uint8_t, fn_free_t> ptr_guard(ptr, api.free_fn ? api.free_fn : +[](void*) {});

  if (rc != 0) {
    err = NativeLastError(api);
    if (err.empty()) {
      err = "gpu_native_generate_failed";
    }
    return false;
  }
  if (out_packet_size <= 0 || !ptr) {
    err = "gpu_native_packet_size_invalid";
    return false;
  }

  out.bytes_total = out_size;
  out.packet_size = out_packet_size;

  const bool bar1_p2p_mode =
      (telco_env && (telco_env->flags & samurai::wire::kTelcoGpuJobFlagBar1P2p) != 0) ||
      EnvFlag("SAMURAI_GPU_PACKET_BAR1_P2P_OUTPUT", false) ||
      EnvString("SAMURAI_GPU_TX_BACKEND", "") == "geforce_p2p";
  if (bar1_p2p_mode) {
    if (tx_enabled) {
      if (api.p2p_tx_bar1_batch) {
        std::uint32_t submitted = 0u;
        const int p2p_rc = api.p2p_tx_bar1_batch(nullptr, nullptr, static_cast<std::uint32_t>(batch_count), &submitted);
        if (p2p_rc != 0) {
          err = NativeLastError(api);
          if (err.empty()) err = "bar1_p2p_gpu_doorbell_tx_failed";
          return false;
        }
        out.packets_sent = static_cast<int>(submitted);
        out.packets_errors = static_cast<int>(batch_count - submitted);
        out.transmitted_on_wire = true;
        out.tx_note = "gpu_native_capi+geforce_p2p_bar1:doorbell";
        return true;
      }
      err = "bar1_p2p_tx_bar1_batch_symbol_missing";
      return false;
    }
    err = "tx_disabled_dry_run_removed";
    return false;
  }

  if (tx_enabled) {
    char tx_err[128] = {0};
    if (!iface.empty()) {
      const std::uint8_t default_src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
      int sent = 0;
      int errors = 0;
      const int tx_rc = afpkt_send_ring_bridge(
          iface.c_str(), ptr, out_size, out_packet_size, batch_count,
          default_src_mac, &sent, &errors, tx_err, sizeof(tx_err));
      if (tx_rc != 0) {
        err = tx_err[0] ? std::string(tx_err) : "gpu_afpacket_ring_tx_failed";
        return false;
      }
      out.packets_sent = std::max(0, sent);
      out.packets_errors = std::max(0, errors);
      out.transmitted_on_wire = true;
      out.tx_note = "gpu_native_capi+afpacket:tx_ring";
    } else {
      std::vector<std::uint8_t> l3_buffer;
      const std::uint8_t* tx_ptr = ptr;
      std::size_t tx_size = out_size;
      int tx_packet_size = out_packet_size;

      if (is_gtpu) {
        const std::size_t vlan_depth = telco_env ? static_cast<std::size_t>(telco_env->vlan_depth) : 0u;
        const std::size_t l2_hdr_len = 14u + vlan_depth * 4u;
        if (static_cast<std::size_t>(out_packet_size) > l2_hdr_len) {
          const std::size_t l3_pkt_sz = static_cast<std::size_t>(out_packet_size) - l2_hdr_len;
          l3_buffer.resize(static_cast<std::size_t>(batch_count) * l3_pkt_sz);
          for (int i = 0; i < batch_count; ++i) {
            const std::uint8_t* src_pkt = ptr + static_cast<std::size_t>(i) * static_cast<std::size_t>(out_packet_size) + l2_hdr_len;
            std::uint8_t* dst_pkt = l3_buffer.data() + static_cast<std::size_t>(i) * l3_pkt_sz;
            std::memcpy(dst_pkt, src_pkt, l3_pkt_sz);
          }
          tx_ptr = l3_buffer.data();
          tx_size = l3_buffer.size();
          tx_packet_size = static_cast<int>(l3_pkt_sz);
        }
      }

      afpkt_tx_metrics_t m{};
      const int tx_rc = afpkt_send_l3_ex(
          target_ip_norm.c_str(), static_cast<int>(env.target_port),
          tx_ptr, tx_size, tx_packet_size, batch_count, ipg_ns,
          nullptr, &m, tx_err, sizeof(tx_err));
      if (tx_rc != 0) {
        err = tx_err[0] ? std::string(tx_err) : "gpu_afpacket_l3_tx_failed";
        return false;
      }
      out.packets_sent = std::max(0, m.sent);
      out.packets_errors = std::max(0, m.errors);
      out.transmitted_on_wire = true;
      out.tx_note = "gpu_native_capi+afpacket:l3";
    }
  } else {
    err = "tx_disabled_dry_run_removed";
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_batch_size = 8192;
  std::string cups_shm_path = EnvString("SAMURAI_CUPS_CONTRACT_PATH", "");
  std::uint32_t active_ring_handle = static_cast<std::uint32_t>(EnvI64("SAMURAI_P2P_ACTIVE_RING", 0));

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
    } else if (arg == "--gpu-bar1-p2p") {
      setenv("SAMURAI_GPU_PACKET_BAR1_P2P_OUTPUT", "1", 1);
    } else if (arg == "--cups-shm-path" && i + 1 < argc) {
      cups_shm_path = argv[++i];
    } else if (arg == "--p2p-ring-handle" && i + 1 < argc) {
      active_ring_handle = static_cast<std::uint32_t>(std::stoul(argv[++i]));
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
  if (!cups_shm_path.empty()) {
    std::string native_err;
    if (LoadGpuNative(api, native_err) && api.telco_attach_cups_shm_v1) {
      const int attach_rc = api.telco_attach_cups_shm_v1(cups_shm_path.c_str(), 0);
      if (attach_rc == 0) {
        samurai::daemon::WorkerLogInfo("gpu", "Attached to DPU CUPS shared memory: " + cups_shm_path);
      } else {
        samurai::daemon::WorkerLogWarn(
            "gpu", "Failed to attach CUPS shared memory at " + cups_shm_path + ": " + NativeLastError(api));
      }
    }
  }
  if (active_ring_handle != 0) {
    std::string native_err;
    if (LoadGpuNative(api, native_err) && api.p2p_set_active_ring_v1) {
      api.p2p_set_active_ring_v1(active_ring_handle);
    }
  }
  FlowLifecycleConfig flow_lifecycle_cfg = LoadFlowLifecycleConfig();
  std::unordered_map<std::uint32_t, std::int64_t> flow_streams;
  samurai::daemon::TelemetrySink telemetry;
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

    if (samurai::daemon::HandleCommonIdleMessage(
            push, samurai::wire::WorkerKind::GPU, header, job_id,
            payload_ptr, payload_len, telemetry, running)) {
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::HEARTBEAT) {
      std::uint64_t dpu_ts_ns = samurai_pacing_monotonic_now_ns();
      if (payload_len == sizeof(std::uint64_t)) {
        std::memcpy(&dpu_ts_ns, payload_ptr, sizeof(dpu_ts_ns));
      }
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
      if (!api.contract_heartbeat) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError("gpu_native_contract_heartbeat_symbol_missing"));
        continue;
      }
      if (api.contract_heartbeat(dpu_ts_ns) != 0) {
        std::string err = NativeLastError(api);
        if (err.empty()) {
          err = "gpu_contract_heartbeat_failed";
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
      (void)SendAck(push, header.correlation_id, job_id);
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

    if (msg_type == samurai::wire::MessageType::TELCO_TUNNEL_UPSERT) {
      std::string native_err;
      if (!LoadGpuNative(api, native_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(native_err));
        zmq_msg_close(&msg);
        continue;
      }
      std::string upsert_err;
      if (!HandleTelcoTunnelUpsertPayload(api, payload_ptr, payload_len, upsert_err)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::GPU,
            job_id,
            JsonError(upsert_err));
        zmq_msg_close(&msg);
        continue;
      }
      (void)SendAck(push, header.correlation_id, job_id);
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      samurai::wire::JobEnvelopeV1 env{};
      samurai::wire::TelcoGpuJobEnvelopeV1 telco_env{};
      bool has_telco_env = false;

      if (payload_len == sizeof(samurai::wire::TelcoGpuJobEnvelopeV1)) {
        std::memcpy(&telco_env, payload_ptr, sizeof(telco_env));
        env = telco_env.base;
        has_telco_env = true;
      } else if (payload_len == sizeof(samurai::wire::TelcoJobPayload)) {
        samurai::wire::TelcoJobPayload tjp{};
        std::memcpy(&tjp, payload_ptr, sizeof(tjp));
        std::snprintf(env.protocol, sizeof(env.protocol), "gtpu");
        env.target_port = 2152;
        env.packet_count = tjp.subscriber_count > 0 ? tjp.subscriber_count * 10 : 1000;
        env.packet_size = 128;
        env.target_rps = static_cast<double>(tjp.rate_cps);
        telco_env.base = env;
        telco_env.teid_start = tjp.subscriber_start_idx;
        telco_env.teid_count = tjp.subscriber_count > 0 ? tjp.subscriber_count : 1;
        telco_env.svlan_tci = tjp.base_vlan_s;
        telco_env.cvlan_tci = tjp.base_vlan_c;
        telco_env.vlan_depth = (tjp.base_vlan_s && tjp.base_vlan_c) ? 2 : (tjp.base_vlan_s || tjp.base_vlan_c ? 1 : 0);
        telco_env.ue_src_ip_start = tjp.base_client_ip;
        telco_env.ue_src_ip_count = telco_env.teid_count;
        telco_env.inner_dst_ip = tjp.gateway_ip;
        has_telco_env = true;
      } else if (payload_len == sizeof(samurai::wire::JobEnvelopeV1)) {
        std::memcpy(&env, payload_ptr, sizeof(env));
      } else {
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
        telemetry.BeginJob();

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;

        std::string run_note = "gpu_native_capi+pacing_static";
        bool job_stopped = false;

        int remaining = total_packets;
        while (remaining > 0) {
          const int current = std::min(batch_size, remaining);
          const long long cur_ipg_ns =
              (pace_cfg.mode == SAMURAI_PACING_IPG) ? static_cast<long long>(pace_cfg.ipg_ns) : 0;
          NativeResult gen{};
          std::string gen_err;
          if (!RunGpuNativeBatch(api, env, current, cur_ipg_ns, gen, gen_err, has_telco_env ? &telco_env : nullptr)) {
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
          run_note = gen.tx_note;

          // Live non-blocking control messages (PING, STOP_JOB, ABORT, SHUTDOWN, SET_TELEMETRY, RECONFIGURE_JOB, TELCO_TUNNEL_UPSERT)
          zmq_msg_t cmsg;
          zmq_msg_init(&cmsg);
          while (zmq_msg_recv(&cmsg, pull, ZMQ_DONTWAIT) > 0) {
            const std::size_t c_sz = static_cast<std::size_t>(zmq_msg_size(&cmsg));
            if (c_sz >= sizeof(samurai::wire::SamuraiWireHeaderV1)) {
              const auto* c_raw = static_cast<const std::uint8_t*>(zmq_msg_data(&cmsg));
              samurai::wire::SamuraiWireHeaderV1 c_hdr{};
              std::memcpy(&c_hdr, c_raw, sizeof(c_hdr));
              const auto c_type = static_cast<samurai::wire::MessageType>(c_hdr.msg_type);
              const std::string c_job_id = samurai::daemon::ReadJobId(c_hdr);
              const std::size_t c_payload_len = c_sz - sizeof(c_hdr);
              const std::uint8_t* c_payload_ptr = c_raw + sizeof(c_hdr);
              if (c_type == samurai::wire::MessageType::PING) {
                (void)SendAck(push, c_hdr.correlation_id, c_job_id);
              } else if (c_type == samurai::wire::MessageType::STOP_JOB ||
                         c_type == samurai::wire::MessageType::ABORT) {
                job_stopped = true;
                (void)SendAck(push, c_hdr.correlation_id, c_job_id);
              } else if (c_type == samurai::wire::MessageType::SHUTDOWN) {
                job_stopped = true;
                running = false;
                (void)SendAck(push, c_hdr.correlation_id, c_job_id);
              } else if (c_type == samurai::wire::MessageType::SET_TELEMETRY) {
                (void)samurai::daemon::HandleSetTelemetryFrame(
                    c_payload_ptr, c_payload_len, telemetry, samurai_pacing_monotonic_now_ns());
                (void)SendAck(push, c_hdr.correlation_id, c_job_id);
              } else if (c_type == samurai::wire::MessageType::RECONFIGURE_JOB) {
                (void)samurai::daemon::ApplyReconfigureWindow(
                    c_payload_ptr, c_payload_len, pace_cfg, pace_state);
                (void)SendAck(push, c_hdr.correlation_id, c_job_id);
              } else if (c_type == samurai::wire::MessageType::TELCO_TUNNEL_UPSERT) {
                std::string upsert_err;
                if (HandleTelcoTunnelUpsertPayload(api, c_payload_ptr, c_payload_len, upsert_err)) {
                  (void)SendAck(push, c_hdr.correlation_id, c_job_id);
                } else {
                  (void)SendFrame(
                      push,
                      static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                      c_hdr.correlation_id,
                      samurai::wire::WorkerKind::GPU,
                      c_job_id,
                      JsonError(upsert_err));
                }
              }
            }
            zmq_msg_close(&cmsg);
            if (job_stopped) break;
            zmq_msg_init(&cmsg);
          }
          zmq_msg_close(&cmsg);
          if (job_stopped) {
            run_note = "aborted";
            break;
          }

          const std::uint64_t packet_size_u = static_cast<std::uint64_t>(std::max(1, gen.packet_size));
          if (gen.transmitted_on_wire) {
            packets_sent += static_cast<std::uint64_t>(gen.packets_sent);
            packets_errors += static_cast<std::uint64_t>(gen.packets_errors);
            bytes_sent += static_cast<std::uint64_t>(gen.packets_sent) * packet_size_u;
            const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
            samurai::daemon::RecordBatchToTelemetry(
                telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
                ReadFixed(env.protocol, sizeof(env.protocol)),
                static_cast<std::uint64_t>(gen.packets_sent),
                static_cast<std::uint32_t>(packet_size_u), now_ns);
            telemetry.TickExport(now_ns);
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
          } else {
            for (int i = 0; i < current; ++i) {
              if ((static_cast<std::uint32_t>(i) & 0xFFu) == 0u) {
                samurai::daemon::ControlPollState inner_ctrl{};
                samurai::daemon::PollControlNonBlocking(
                    pull, push, samurai::wire::WorkerKind::GPU, &telemetry, inner_ctrl);
                if (inner_ctrl.shutdown) running = false;
                if (inner_ctrl.stop_job) {
                  job_stopped = true;
                  run_note = "aborted";
                  break;
                }
                if (inner_ctrl.reconfigure) {
                  (void)samurai::daemon::ApplyReconfigureWindow(
                      reinterpret_cast<const std::uint8_t*>(&inner_ctrl.reconf),
                      sizeof(inner_ctrl.reconf), pace_cfg, pace_state);
                }
              }
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
            if (telemetry.Enabled() && packets_sent > 0) {
              const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
              samurai::daemon::RecordBatchToTelemetry(
                  telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
                  ReadFixed(env.protocol, sizeof(env.protocol)),
                  static_cast<std::uint64_t>(current),
                  static_cast<std::uint32_t>(packet_size_u), now_ns);
              telemetry.TickExport(now_ns);
            }
            if (job_stopped) break;
          }
          remaining -= current;
          (void)gen.bytes_total;
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        telemetry.FlushEnd(end_ns);
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
            run_note,
            TryReadContractExportRegionSpec(api),
            telemetry.JobExportedPackets(),
            telemetry.JobExportedRecords());
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

  if (api.telco_detach_cups_shm_v1) {
    api.telco_detach_cups_shm_v1();
  }
  if (api.handle) {
    dlclose(api.handle);
  }
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
