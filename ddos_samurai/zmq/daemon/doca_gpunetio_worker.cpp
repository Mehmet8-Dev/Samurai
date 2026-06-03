#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <exception>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <vector>

#include <zmq.h>

#include "../../ddos_samurai/gpu_packet_cuda/tx_backend_doca_gpunetio.cuh"
#include "../../gpu_packet_cuda/dpu_state_runtime.hpp"
#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace {

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

static_assert(
    sizeof(DocaFlowUpdateEventV1) == sizeof(samurai::wire::FlowUpdateEventV1),
    "DOCA contract writer event must match wire FlowUpdateEventV1");

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_doca";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_doca";
constexpr const char* kDefaultGpuJobs = "ipc:///tmp/samurai_jobs_gpu";

using fn_get_api_t = DocaGpuNetioApiV1* (*)();
using fn_backend_create_txq_t = int (*)(const char*, const char*, int, int, int*, char*, size_t);
using fn_backend_destroy_txq_t = int (*)(int, char*, size_t);
using fn_backend_send_vector_t = int (*)(int, const uint8_t**, const uint16_t*, const int32_t*, int, int*, int*, char*, size_t);
using fn_backend_get_stats_t = int (*)(int, DocaGpuNetioStats*, char*, size_t);
using fn_backend_send_vector_timed_t =
    int (*)(int, const uint8_t**, const uint16_t*, const int32_t*, const uint64_t*, int, int*, int*, char*, size_t);
using fn_backend_get_gpu_txq_handle_t = int (*)(int, uint64_t*, char*, size_t);
using fn_backend_get_txq_mkey_be_t = int (*)(int, uint32_t*, char*, size_t);
using fn_backend_create_rxq_t = int (*)(const char*, const char*, int, int, int*, char*, size_t);
using fn_backend_destroy_rxq_t = int (*)(int, char*, size_t);
using fn_backend_receive_burst_t = int (*)(int, uint8_t*, uint32_t, uint16_t*, int, int*, char*, size_t);
using fn_contract_writer_open_t = int (*)(const DocaContractWriterConfigV1*, int*, char*, size_t);
using fn_contract_writer_close_t = int (*)(int, char*, size_t);
using fn_contract_writer_publish_flow_update_t = int (*)(int, const DocaFlowUpdateEventV1*, char*, size_t);

struct DocaDispatch {
  int version{0};
  int (*create_txq)(const char*, const char*, int, int, int*, char*, size_t){nullptr};
  int (*destroy_txq)(int, char*, size_t){nullptr};
  int (*send_vector)(int, const uint8_t**, const uint16_t*, const int32_t*, int, int*, int*, char*, size_t){nullptr};
  int (*send_vector_timed)(int, const uint8_t**, const uint16_t*, const int32_t*, const uint64_t*, int, int*, int*, char*, size_t){
      nullptr};
  int (*get_stats)(int, DocaGpuNetioStats*, char*, size_t){nullptr};
  int (*get_gpu_txq_handle)(int, uint64_t*, char*, size_t){nullptr};
  int (*get_txq_mkey_be)(int, uint32_t*, char*, size_t){nullptr};
  int (*create_rxq)(const char*, const char*, int, int, int*, char*, size_t){nullptr};
  int (*destroy_rxq)(int, char*, size_t){nullptr};
  int (*receive_burst)(int, uint8_t*, uint32_t, uint16_t*, int, int*, char*, size_t){nullptr};
  int (*contract_writer_open)(const DocaContractWriterConfigV1*, int*, char*, size_t){nullptr};
  int (*contract_writer_close)(int, char*, size_t){nullptr};
  int (*contract_writer_publish_flow_update_v1)(int, const DocaFlowUpdateEventV1*, char*, size_t){nullptr};
};

struct DocaNativeBridge {
  void* handle{nullptr};
  DocaDispatch api{};
  std::string lib_path;
};

struct DocaTxqGuard {
  DocaNativeBridge* bridge{nullptr};
  int handle{-1};
  ~DocaTxqGuard() {
    if (bridge && bridge->api.destroy_txq && handle > 0) {
      char err[160];
      err[0] = '\0';
      (void)bridge->api.destroy_txq(handle, err, sizeof(err));
    }
  }
};

struct DpuContractWriterGuard {
  DocaNativeBridge* bridge{nullptr};
  int handle{-1};
  ~DpuContractWriterGuard() {
    if (bridge && bridge->api.contract_writer_close && handle > 0) {
      char err[160];
      err[0] = '\0';
      (void)bridge->api.contract_writer_close(handle, err, sizeof(err));
    }
  }
};

struct DocaRxqGuard {
  DocaNativeBridge* bridge{nullptr};
  int handle{-1};
  ~DocaRxqGuard() {
    if (bridge && bridge->api.destroy_rxq && handle > 0) {
      char err[160];
      err[0] = '\0';
      (void)bridge->api.destroy_rxq(handle, err, sizeof(err));
    }
  }
};

struct DpuTcpRxScratch {
  static constexpr int kMaxRxPackets = 32;
  static constexpr std::size_t kMaxPacket = 2048u;
  struct StreamPolicySnapshot {
    std::uint32_t quota{0};
    std::uint16_t payload_len{0};
    std::uint64_t tx_ipg_ns{0};
    std::uint32_t template_id{0};
    std::uint32_t tcp_seq{0};
    std::uint32_t tcp_ack{0};
    std::uint16_t flags{0};
    std::uint8_t tcp_state{0};
  };
  std::vector<std::uint8_t> flat;
  std::vector<std::uint16_t> lengths;
  std::unordered_map<std::uint32_t, StreamPolicySnapshot> stream_policy_cache;

  DpuTcpRxScratch()
      : flat(kMaxPacket * static_cast<std::size_t>(kMaxRxPackets)),
        lengths(static_cast<std::size_t>(kMaxRxPackets), 0u) {}
};

std::string ReadFixed(const char* raw, std::size_t n) {
  return std::string(raw, strnlen(raw, n));
}

std::optional<int> OptionalIntFromWire(std::uint64_t raw) {
  if (raw == 0ull) return std::nullopt;
  return static_cast<int>(raw);
}

std::uint32_t EnvContractU32(const char* name, std::uint32_t default_value, std::uint32_t min_value) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return default_value;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(raw, &end, 10);
  if (end == raw || (end != nullptr && *end != '\0') || parsed < min_value || parsed > UINT32_MAX) {
    return default_value;
  }
  return static_cast<std::uint32_t>(parsed);
}

bool EnvBool(const char* name, bool default_value) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return default_value;
  }
  std::string v = raw;
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return v == "1" || v == "true" || v == "on" || v == "yes";
}

std::uint32_t ParseIpv4HostOrder(const std::string& ip) {
  unsigned int a = 0, b = 0, c = 0, d = 0;
  char tail = '\0';
  if (std::sscanf(ip.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 ||
      a > 255u || b > 255u || c > 255u || d > 255u) {
    return 0u;
  }
  return (a << 24u) | (b << 16u) | (c << 8u) | d;
}

std::string Ipv4ToString(std::uint32_t ip) {
  char buf[32];
  std::snprintf(buf,
                sizeof(buf),
                "%u.%u.%u.%u",
                static_cast<unsigned int>((ip >> 24u) & 0xFFu),
                static_cast<unsigned int>((ip >> 16u) & 0xFFu),
                static_cast<unsigned int>((ip >> 8u) & 0xFFu),
                static_cast<unsigned int>(ip & 0xFFu));
  return std::string(buf);
}

std::string GpuContractExportSpecWithLayout(
    const std::string& base,
    std::uint32_t shard_count,
    std::uint32_t ring_slots_per_shard,
    std::uint32_t hot_flow_capacity) {
  return base + ",layout=1,shards=" + std::to_string(shard_count) +
      ",slots=" + std::to_string(ring_slots_per_shard) +
      ",hot=" + std::to_string(hot_flow_capacity) +
      ",event=" + std::to_string(sizeof(DocaFlowUpdateEventV1));
}

std::string DefaultGpuContractExportKind() {
  std::string kind = "file";
  if (const char* raw = std::getenv("SAMURAI_GPU_CONTRACT_EXPORT_KIND")) {
    if (*raw) {
      kind = std::string(raw);
      std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (kind == "doca-mmap") {
        kind = "doca_mmap";
      }
    }
  }
  return kind;
}

std::string DefaultGpuContractExportSpec(
    std::uint32_t shard_count,
    std::uint32_t ring_slots_per_shard,
    std::uint32_t hot_flow_capacity) {
  if (const char* raw = std::getenv("SAMURAI_GPU_CONTRACT_EXPORT_SPEC")) {
    if (*raw) return std::string(raw);
  }
  const std::string kind = DefaultGpuContractExportKind();
  if (const char* raw = std::getenv("SAMURAI_GPU_CONTRACT_EXPORT_PATH")) {
    if (*raw) {
      return GpuContractExportSpecWithLayout(
          std::string("kind=") + kind + ",file=" + raw,
          shard_count,
          ring_slots_per_shard,
          hot_flow_capacity);
    }
  }
  const char* dir = (::access("/dev/shm", W_OK) == 0) ? "/dev/shm" : "/tmp";
  return GpuContractExportSpecWithLayout(
      std::string("kind=") + kind + ",file=" + dir + "/samurai_gpu_contract_" +
          std::to_string(static_cast<long long>(::getuid())) + ".bin",
      shard_count,
      ring_slots_per_shard,
      hot_flow_capacity);
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

std::vector<std::string> CandidateDocaLibs() {
  std::set<std::string> uniq;
  auto add_if = [&](const char* v) {
    if (v && *v) uniq.insert(std::string(v));
  };
  add_if(std::getenv("SAMURAI_DOCA_API_LIB"));
  add_if(std::getenv("SAMURAI_GPU_DOCA_API_LIB"));
  add_if(std::getenv("SAMURAI_GPU_DOCA_SHIM_SO"));
  uniq.insert("libsamurai_doca_gpunetio_shim.so");
  uniq.insert("ddos_samurai/libsamurai_doca_gpunetio_shim.so");
  uniq.insert("libsamurai_doca_gpunetio_backend.so");
  uniq.insert("ddos_samurai/libsamurai_doca_gpunetio_backend.so");
  uniq.insert("ddos_samurai/libgpu_packet_cuda.so");
  return std::vector<std::string>(uniq.begin(), uniq.end());
}

bool LoadDocaNative(DocaNativeBridge& out, std::string& err) {
  if (out.handle && out.api.create_txq) return true;

  for (const std::string& cand : CandidateDocaLibs()) {
    void* h = dlopen(cand.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) continue;

    DocaDispatch api{};
    auto get_api = reinterpret_cast<fn_get_api_t>(dlsym(h, "samurai_doca_gpunetio_get_api_v1"));
    if (get_api) {
      DocaGpuNetioApiV1* in = get_api();
      if (in && in->version > 0 && in->create_txq && in->destroy_txq && in->send_vector && in->get_stats) {
        api.version = in->version;
        api.create_txq = in->create_txq;
        api.destroy_txq = in->destroy_txq;
        api.send_vector = in->send_vector;
        api.send_vector_timed = in->send_vector_timed;
        api.get_stats = in->get_stats;
        api.get_gpu_txq_handle = in->get_gpu_txq_handle;
        api.get_txq_mkey_be = in->get_txq_mkey_be;
        if (in->version >= 4) {
          api.contract_writer_open = in->contract_writer_open;
          api.contract_writer_close = in->contract_writer_close;
          api.contract_writer_publish_flow_update_v1 = in->contract_writer_publish_flow_update_v1;
        }
        if (in->version >= 5) {
          api.create_rxq = in->create_rxq;
          api.destroy_rxq = in->destroy_rxq;
          api.receive_burst = in->receive_burst;
        }
      }
    }

    if (!api.create_txq) {
      auto create_txq = reinterpret_cast<fn_backend_create_txq_t>(dlsym(h, "samurai_doca_backend_create_txq"));
      auto destroy_txq = reinterpret_cast<fn_backend_destroy_txq_t>(dlsym(h, "samurai_doca_backend_destroy_txq"));
      auto send_vector = reinterpret_cast<fn_backend_send_vector_t>(dlsym(h, "samurai_doca_backend_send_vector"));
      auto send_vector_timed = reinterpret_cast<fn_backend_send_vector_timed_t>(dlsym(h, "samurai_doca_backend_send_vector_timed"));
      auto get_stats = reinterpret_cast<fn_backend_get_stats_t>(dlsym(h, "samurai_doca_backend_get_stats"));
      auto get_gpu_txq_handle =
          reinterpret_cast<fn_backend_get_gpu_txq_handle_t>(dlsym(h, "samurai_doca_backend_get_gpu_txq_handle"));
      auto get_txq_mkey_be =
          reinterpret_cast<fn_backend_get_txq_mkey_be_t>(dlsym(h, "samurai_doca_backend_get_txq_mkey_be"));
      auto create_rxq = reinterpret_cast<fn_backend_create_rxq_t>(dlsym(h, "samurai_doca_backend_create_rxq"));
      auto destroy_rxq = reinterpret_cast<fn_backend_destroy_rxq_t>(dlsym(h, "samurai_doca_backend_destroy_rxq"));
      auto receive_burst =
          reinterpret_cast<fn_backend_receive_burst_t>(dlsym(h, "samurai_doca_backend_receive_burst"));
      auto contract_writer_open =
          reinterpret_cast<fn_contract_writer_open_t>(dlsym(h, "samurai_doca_backend_contract_writer_open"));
      auto contract_writer_close =
          reinterpret_cast<fn_contract_writer_close_t>(dlsym(h, "samurai_doca_backend_contract_writer_close"));
      auto contract_writer_publish = reinterpret_cast<fn_contract_writer_publish_flow_update_t>(
          dlsym(h, "samurai_doca_backend_contract_writer_publish_flow_update_v1"));
      if (create_txq && destroy_txq && send_vector && get_stats) {
        api.version = kDocaGpuNetioApiVersion;
        api.create_txq = create_txq;
        api.destroy_txq = destroy_txq;
        api.send_vector = send_vector;
        api.send_vector_timed = send_vector_timed;
        api.get_stats = get_stats;
        api.get_gpu_txq_handle = get_gpu_txq_handle;
        api.get_txq_mkey_be = get_txq_mkey_be;
        api.create_rxq = create_rxq;
        api.destroy_rxq = destroy_rxq;
        api.receive_burst = receive_burst;
        api.contract_writer_open = contract_writer_open;
        api.contract_writer_close = contract_writer_close;
        api.contract_writer_publish_flow_update_v1 = contract_writer_publish;
      }
    }

    // Some backend builds expose the core TX API through the versioned table but keep
    // newer RX/contract entrypoints as direct symbols to avoid breaking older shims.
    if (!api.create_rxq || !api.destroy_rxq || !api.receive_burst || !api.contract_writer_open ||
        !api.contract_writer_close || !api.contract_writer_publish_flow_update_v1) {
      auto create_rxq = reinterpret_cast<fn_backend_create_rxq_t>(dlsym(h, "samurai_doca_backend_create_rxq"));
      auto destroy_rxq = reinterpret_cast<fn_backend_destroy_rxq_t>(dlsym(h, "samurai_doca_backend_destroy_rxq"));
      auto receive_burst =
          reinterpret_cast<fn_backend_receive_burst_t>(dlsym(h, "samurai_doca_backend_receive_burst"));
      auto contract_writer_open =
          reinterpret_cast<fn_contract_writer_open_t>(dlsym(h, "samurai_doca_backend_contract_writer_open"));
      auto contract_writer_close =
          reinterpret_cast<fn_contract_writer_close_t>(dlsym(h, "samurai_doca_backend_contract_writer_close"));
      auto contract_writer_publish = reinterpret_cast<fn_contract_writer_publish_flow_update_t>(
          dlsym(h, "samurai_doca_backend_contract_writer_publish_flow_update_v1"));
      if (!api.create_rxq) api.create_rxq = create_rxq;
      if (!api.destroy_rxq) api.destroy_rxq = destroy_rxq;
      if (!api.receive_burst) api.receive_burst = receive_burst;
      if (!api.contract_writer_open) api.contract_writer_open = contract_writer_open;
      if (!api.contract_writer_close) api.contract_writer_close = contract_writer_close;
      if (!api.contract_writer_publish_flow_update_v1) {
        api.contract_writer_publish_flow_update_v1 = contract_writer_publish;
      }
    }

    if (!api.create_txq || !api.destroy_txq || !api.send_vector || !api.get_stats) {
      dlclose(h);
      continue;
    }
    out.handle = h;
    out.api = api;
    out.lib_path = cand;
    return true;
  }

  err = "doca_native_lib_unavailable";
  return false;
}

int SendFrame(
    void* event_socket,
    std::uint8_t msg_type,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id,
    const std::vector<std::uint8_t>& payload = {},
    int send_flags = 0) {
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
  const int rc = zmq_msg_send(&msg, event_socket, send_flags);
  zmq_msg_close(&msg);
  return rc;
}

std::uint8_t ProtoFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  const std::string proto = ReadFixed(env.protocol, sizeof(env.protocol));
  if (proto == "udp" || proto == "UDP") return samurai::dpu::kProtoUdp;
  return samurai::dpu::kProtoTcp;
}

std::uint16_t TcpFlagsFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  const std::string flags = ReadFixed(env.tcp_flags, sizeof(env.tcp_flags));
  std::uint16_t out = 0;
  for (const char ch : flags) {
    switch (ch) {
      case 'F':
      case 'f':
        out |= 0x01u;
        break;
      case 'S':
      case 's':
        out |= 0x02u;
        break;
      case 'R':
      case 'r':
        out |= 0x04u;
        break;
      case 'P':
      case 'p':
        out |= 0x08u;
        break;
      case 'A':
      case 'a':
        out |= 0x10u;
        break;
      case 'U':
      case 'u':
        out |= 0x20u;
        break;
      default:
        break;
    }
  }
  return out;
}

std::uint32_t TcpSequenceAdvanceFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  if (ProtoFromEnvelope(env) != samurai::dpu::kProtoTcp) {
    return 0u;
  }
  const std::uint16_t flags = TcpFlagsFromEnvelope(env);
  std::uint32_t advance = 0u;
  if ((flags & samurai::dpu::kTcpFlagSyn) != 0u) {
    advance += 1u;
  }
  if ((flags & samurai::dpu::kTcpFlagFin) != 0u) {
    advance += 1u;
  }
  if (env.has_payload != 0u) {
    advance += std::min<std::uint32_t>(env.pad_size, 1460u);
  }
  return advance;
}

std::uint16_t EstablishedTxFlagsFromEnvelope(const samurai::wire::JobEnvelopeV1& env) {
  if (ProtoFromEnvelope(env) != samurai::dpu::kProtoTcp) {
    return 0u;
  }
  const std::uint16_t requested = TcpFlagsFromEnvelope(env);
  if ((requested & samurai::dpu::kTcpFlagRst) != 0u) {
    return samurai::dpu::kTcpFlagRst;
  }
  if ((requested & samurai::dpu::kTcpFlagFin) != 0u) {
    return static_cast<std::uint16_t>(samurai::dpu::kTcpFlagFin | samurai::dpu::kTcpFlagAck);
  }
  if (env.has_payload != 0u || (requested & samurai::dpu::kTcpFlagPsh) != 0u) {
    return static_cast<std::uint16_t>(samurai::dpu::kTcpFlagPsh | samurai::dpu::kTcpFlagAck);
  }
  return samurai::dpu::kTcpFlagAck;
}

std::uint32_t FlowIdFromHeader(const samurai::wire::SamuraiWireHeaderV1& header) {
  const std::uint32_t low = static_cast<std::uint32_t>(header.correlation_id & 0xFFFFFFFFull);
  return low == 0u ? 1u : low;
}

samurai::dpu::FlowState InitialFlowStateFromEnvelope(
    const samurai::wire::SamuraiWireHeaderV1& header,
    const samurai::wire::JobEnvelopeV1& env) {
  samurai::dpu::FlowState st{};
  st.flow_id = FlowIdFromHeader(header);
  st.seq_num = 0u;
  st.ack_num = 0u;
  st.src_port = static_cast<std::uint16_t>(40000u + (st.flow_id % 20000u));
  st.dst_port = env.target_port;
  st.proto = ProtoFromEnvelope(env);
  st.flags = TcpFlagsFromEnvelope(env);
  st.tcp_state = (st.proto == samurai::dpu::kProtoTcp && (st.flags & 0x02u) != 0u)
                     ? samurai::dpu::kTcpStateSynSent
                     : samurai::dpu::kTcpStateEstablished;
  st.rtt_us = 0u;
  st.epoch = 1u;
  return st;
}

samurai::dpu::FlowState InitialFlowStateFromWirePacket(
    const samurai::wire::SamuraiWireHeaderV1& header,
    const samurai::wire::JobEnvelopeV1& env,
    const std::uint8_t* packet,
    std::size_t len) {
  samurai::dpu::FlowState st = InitialFlowStateFromEnvelope(header, env);
  samurai::dpu::TcpSegmentObservation seg{};
  if (st.proto != samurai::dpu::kProtoTcp ||
      !samurai::dpu::ParseTcpSegmentObservation(packet, len, &seg)) {
    return st;
  }
  st.src_port = seg.src_port;
  st.dst_port = seg.dst_port;
  st.src_ip = seg.src_ip;
  st.dst_ip = seg.dst_ip;
  st.seq_num = seg.seq;
  st.ack_num = seg.ack;
  st.flags = seg.flags;
  if ((seg.flags & samurai::dpu::kTcpFlagRst) != 0u) {
    st.tcp_state = samurai::dpu::kTcpStatePoisoned;
    st.poisoned = true;
  } else if ((seg.flags & samurai::dpu::kTcpFlagSyn) != 0u &&
             (seg.flags & samurai::dpu::kTcpFlagAck) == 0u) {
    st.tcp_state = samurai::dpu::kTcpStateSynSent;
  } else if ((seg.flags & samurai::dpu::kTcpFlagSyn) != 0u &&
             (seg.flags & samurai::dpu::kTcpFlagAck) != 0u) {
    st.tcp_state = samurai::dpu::kTcpStateSynReceived;
  } else if ((seg.flags & samurai::dpu::kTcpFlagFin) != 0u) {
    st.tcp_state = samurai::dpu::kTcpStateFinWait;
  } else {
    st.tcp_state = samurai::dpu::kTcpStateEstablished;
  }
  return st;
}

std::vector<std::uint8_t> SerializeFlowUpdate(const samurai::wire::FlowUpdateEventV1& ev) {
  std::vector<std::uint8_t> payload(sizeof(ev));
  std::memcpy(payload.data(), &ev, sizeof(ev));
  return payload;
}

std::vector<std::uint8_t> SerializeFlowStreamUpsert(const samurai::wire::FlowStreamUpsertV1& ev) {
  std::vector<std::uint8_t> payload(sizeof(ev));
  std::memcpy(payload.data(), &ev, sizeof(ev));
  return payload;
}

samurai::wire::FlowStreamUpsertV1 BuildFlowStreamUpsert(
    const samurai::dpu::FlowState& st,
    const samurai::wire::JobEnvelopeV1& env,
    std::uint64_t dpu_ts_ns) {
  samurai::wire::FlowStreamUpsertV1 ev{};
  ev.version = st.version;
  ev.epoch = st.epoch;
  ev.flow_id = st.flow_id;
  ev.tcp_seq = st.seq_num;
  ev.tcp_ack = st.ack_num;
  ev.src_port = st.src_port;
  ev.dst_port = st.dst_port;
  ev.tcp_state = st.tcp_state;
  ev.proto = st.proto;
  ev.flags = st.flags;
  ev.rtt_us = st.rtt_us;
  ev.quota = std::max<std::uint32_t>(1u, env.burst_size > 0u ? env.burst_size : 1024u);
  ev.tx_ipg_ns = env.ipg_ns;
  ev.dpu_ts_ns = dpu_ts_ns;
  std::memset(ev.target_ip, 0, sizeof(ev.target_ip));
  const std::string target_ip = st.dst_ip != 0u ? Ipv4ToString(st.dst_ip) : ReadFixed(env.target_ip, sizeof(env.target_ip));
  std::memcpy(ev.target_ip, target_ip.c_str(), std::min(target_ip.size(), sizeof(ev.target_ip) - 1u));
  ev.payload_len = static_cast<std::uint16_t>(
      env.has_payload != 0u ? std::min<std::uint32_t>(env.pad_size, 1460u) : 0u);
  ev.payload_byte = 0u;
  ev.weight = 1u;
  ev.template_id = 0u;
  return ev;
}

void ApplyDpuStreamPolicyToUpsert(
    const samurai::dpu::FlowStateTable& dpu_state,
    const samurai::dpu::FlowState& st,
    const samurai::wire::JobEnvelopeV1& env,
    samurai::wire::FlowStreamUpsertV1& ev) {
  const samurai::dpu::GpuStreamPolicy policy = dpu_state.BuildGpuStreamPolicy(
      st.flow_id,
      ev.quota,
      ev.payload_len,
      ev.tx_ipg_ns);
  ev.quota = policy.quota;
  ev.payload_len = policy.payload_len;
  ev.tx_ipg_ns = policy.tx_ipg_ns;
  ev.template_id = policy.template_id;
  if (policy.pause) {
    ev.payload_len = 0u;
  }
  if (policy.retransmit || policy.zero_window_probe) {
    ev.tcp_seq = st.seq_num;
    ev.tcp_ack = st.ack_num;
    ev.flags = st.flags;
  }
  (void)env;
}

bool ShouldPublishStreamPolicy(
    DpuTcpRxScratch& scratch,
    const samurai::wire::FlowStreamUpsertV1& upsert) {
  DpuTcpRxScratch::StreamPolicySnapshot next{};
  next.quota = upsert.quota;
  next.payload_len = upsert.payload_len;
  next.tx_ipg_ns = upsert.tx_ipg_ns;
  next.template_id = upsert.template_id;
  next.tcp_seq = upsert.tcp_seq;
  next.tcp_ack = upsert.tcp_ack;
  next.flags = upsert.flags;
  next.tcp_state = upsert.tcp_state;
  auto it = scratch.stream_policy_cache.find(upsert.flow_id);
  if (it != scratch.stream_policy_cache.end() &&
      it->second.quota == next.quota &&
      it->second.payload_len == next.payload_len &&
      it->second.tx_ipg_ns == next.tx_ipg_ns &&
      it->second.template_id == next.template_id &&
      it->second.tcp_seq == next.tcp_seq &&
      it->second.tcp_ack == next.tcp_ack &&
      it->second.flags == next.flags &&
      it->second.tcp_state == next.tcp_state) {
    return false;
  }
  scratch.stream_policy_cache[upsert.flow_id] = next;
  return true;
}

bool PublishDpuFlowUpdate(
    void* gpu_push,
    const samurai::wire::FlowUpdateEventV1& ev,
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::string& err) {
  if (!gpu_push) {
    err = "dpu_gpu_flow_update_socket_unavailable";
    return false;
  }
  const int rc = SendFrame(gpu_push,
                           static_cast<std::uint8_t>(samurai::wire::MessageType::FLOW_UPDATE),
                           correlation_id,
                           samurai::wire::WorkerKind::GPU,
                           job_id,
                           SerializeFlowUpdate(ev),
                           ZMQ_DONTWAIT);
  if (rc < 0) {
    err = "dpu_gpu_flow_update_publish_failed";
    return false;
  }
  return true;
}

bool PublishDpuHeartbeat(
    void* gpu_push,
    std::uint64_t dpu_ts_ns,
    std::uint64_t correlation_id,
    const std::string& job_id) {
  if (!gpu_push) {
    return false;
  }
  std::vector<std::uint8_t> payload(sizeof(dpu_ts_ns));
  std::memcpy(payload.data(), &dpu_ts_ns, sizeof(dpu_ts_ns));
  const int rc = SendFrame(gpu_push,
                           static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                           correlation_id,
                           samurai::wire::WorkerKind::GPU,
                           job_id,
                           payload,
                           ZMQ_DONTWAIT);
  return rc >= 0;
}

DocaFlowUpdateEventV1 ToDocaFlowUpdate(const samurai::wire::FlowUpdateEventV1& ev) {
  DocaFlowUpdateEventV1 out{};
  out.version = ev.version;
  out.epoch = ev.epoch;
  out.flow_id = ev.flow_id;
  out.tcp_seq = ev.tcp_seq;
  out.tcp_ack = ev.tcp_ack;
  out.src_port = ev.src_port;
  out.dst_port = ev.dst_port;
  out.tcp_state = ev.tcp_state;
  out.proto = ev.proto;
  out.flags = ev.flags;
  out.rtt_us = ev.rtt_us;
  out.dpu_ts_ns = ev.dpu_ts_ns;
  return out;
}

bool OpenDpuContractRdmaWriter(
    DocaNativeBridge& doca,
    DpuContractWriterGuard& writer,
    const std::string& region_spec,
    const std::string& device,
    std::string& err) {
  if (!doca.api.contract_writer_open || !doca.api.contract_writer_close ||
      !doca.api.contract_writer_publish_flow_update_v1) {
    err = "dpu_contract_rdma_writer_unavailable";
    return false;
  }
  DocaContractWriterConfigV1 cfg{};
  cfg.shard_count = EnvContractU32("SAMURAI_GPU_CONTRACT_SHARDS", 1u, 1u);
  cfg.ring_slots_per_shard = EnvContractU32("SAMURAI_GPU_CONTRACT_RING_SLOTS", 1024u, 64u);
  cfg.hot_flow_capacity = EnvContractU32("SAMURAI_GPU_CONTRACT_HOT_FLOW_CAPACITY", 4096u, 1u);
  const std::string effective_region_spec = region_spec.empty()
      ? DefaultGpuContractExportSpec(cfg.shard_count, cfg.ring_slots_per_shard, cfg.hot_flow_capacity)
      : region_spec;
  if (effective_region_spec.empty()) {
    err = "dpu_contract_rdma_spec_required";
    return false;
  }
  std::memcpy(
      cfg.region_spec,
      effective_region_spec.c_str(),
      std::min(effective_region_spec.size(), sizeof(cfg.region_spec) - 1u));
  std::memcpy(
      cfg.device_name,
      device.c_str(),
      std::min(device.size(), sizeof(cfg.device_name) - 1u));
  char native_err[160];
  native_err[0] = '\0';
  int handle = -1;
  if (doca.api.contract_writer_open(&cfg, &handle, native_err, sizeof(native_err)) != 0 || handle <= 0) {
    err = native_err[0] ? std::string(native_err) : "dpu_contract_rdma_writer_open_failed";
    return false;
  }
  writer.bridge = &doca;
  writer.handle = handle;
  return true;
}

bool PublishDpuFlowUpdateRdma(
    DpuContractWriterGuard& writer,
    const samurai::wire::FlowUpdateEventV1& ev,
    std::string& err) {
  if (!writer.bridge || writer.handle <= 0 || !writer.bridge->api.contract_writer_publish_flow_update_v1) {
    err = "dpu_contract_rdma_writer_unavailable";
    return false;
  }
  const DocaFlowUpdateEventV1 native_ev = ToDocaFlowUpdate(ev);
  char native_err[160];
  native_err[0] = '\0';
  if (writer.bridge->api.contract_writer_publish_flow_update_v1(
          writer.handle,
          &native_ev,
          native_err,
          sizeof(native_err)) != 0) {
    err = native_err[0] ? std::string(native_err) : "dpu_contract_rdma_publish_failed";
    return false;
  }
  return true;
}

bool PublishDpuFlowUpdateOptionalRdma(
    bool enabled,
    DpuContractWriterGuard& writer,
    const samurai::wire::FlowUpdateEventV1& ev,
    std::string& err) {
  if (!enabled) {
    return true;
  }
  return PublishDpuFlowUpdateRdma(writer, ev, err);
}

bool PublishDpuFlowStreamUpsert(
    void* gpu_push,
    const samurai::wire::FlowStreamUpsertV1& ev,
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::string& err);

bool OpenDpuTcpRxq(
    DocaNativeBridge& doca,
    DocaRxqGuard& rxq,
    const std::string& iface,
    const std::string& device,
    int gpu_id,
    int queue_id,
    std::string& err) {
  if (!doca.api.create_rxq || !doca.api.destroy_rxq || !doca.api.receive_burst) {
    err = "dpu_tcp_rx_feedback_unavailable";
    return false;
  }
  char native_err[160];
  native_err[0] = '\0';
  int handle = -1;
  if (doca.api.create_rxq(
          iface.c_str(),
          device.c_str(),
          gpu_id,
          queue_id,
          &handle,
          native_err,
          sizeof(native_err)) != 0 || handle <= 0) {
    err = native_err[0] ? std::string(native_err) : "dpu_tcp_rxq_create_failed";
    return false;
  }
  rxq.bridge = &doca;
  rxq.handle = handle;
  return true;
}

bool PollDpuTcpRxFeedback(
    DocaRxqGuard& rxq,
    samurai::dpu::FlowStateTable& dpu_state,
    std::uint32_t flow_id,
    void* gpu_push,
    bool dpu_state_publish,
    bool dpu_contract_rdma,
    DpuContractWriterGuard& contract_writer,
    std::uint16_t established_tx_flags,
    const samurai::wire::JobEnvelopeV1& env,
    DpuTcpRxScratch& scratch,
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::string& err) {
  if (!rxq.bridge || rxq.handle <= 0 || !rxq.bridge->api.receive_burst) {
    return true;
  }
  int received = 0;
  char native_err[160];
  native_err[0] = '\0';
  if (rxq.bridge->api.receive_burst(
          rxq.handle,
          scratch.flat.data(),
          static_cast<std::uint32_t>(scratch.flat.size()),
          scratch.lengths.data(),
          DpuTcpRxScratch::kMaxRxPackets,
          &received,
          native_err,
          sizeof(native_err)) != 0) {
    err = native_err[0] ? std::string(native_err) : "dpu_tcp_rx_receive_failed";
    return false;
  }
  std::size_t off = 0u;
  for (int i = 0; i < received; ++i) {
    const std::size_t len = static_cast<std::size_t>(scratch.lengths[static_cast<std::size_t>(i)]);
    if (len == 0u || off + len > scratch.flat.size()) {
      break;
    }
    try {
      const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
      const samurai::dpu::FlowState* observed = nullptr;
      try {
        observed = &dpu_state.ObserveTcpPacketByTuple(scratch.flat.data() + off, len, now_ns);
      } catch (const std::out_of_range&) {
        observed = &dpu_state.ObserveTcpPacket(flow_id, scratch.flat.data() + off, len, now_ns);
      }
      const samurai::dpu::FlowState& st = *observed;
      const samurai::dpu::FlowState* publish_state = &st;
      if (established_tx_flags != 0u && st.tcp_state == samurai::dpu::kTcpStateEstablished &&
          st.flags != established_tx_flags) {
        samurai::dpu::FlowState next = st;
        next.flags = established_tx_flags;
        publish_state = &dpu_state.Transition(next);
      }
      const samurai::wire::FlowUpdateEventV1 ev = dpu_state.BuildUpdateEvent(publish_state->flow_id, now_ns);
      if (dpu_state_publish) {
        samurai::wire::FlowStreamUpsertV1 upsert = BuildFlowStreamUpsert(*publish_state, env, now_ns);
        ApplyDpuStreamPolicyToUpsert(dpu_state, *publish_state, env, upsert);
        if (ShouldPublishStreamPolicy(scratch, upsert) &&
            !PublishDpuFlowStreamUpsert(gpu_push, upsert, correlation_id, job_id, err)) {
          return false;
        }
      }
      if (dpu_state_publish && !PublishDpuFlowUpdate(gpu_push, ev, correlation_id, job_id, err)) {
        return false;
      }
      if (!PublishDpuFlowUpdateOptionalRdma(dpu_contract_rdma, contract_writer, ev, err)) {
        return false;
      }
    } catch (const std::exception&) {
      // Ignore non-matching frames on the feedback queue; steering can be broad in lab setups.
    }
    off += len;
  }
  return true;
}

bool WaitForDpuPassiveOpen(
    DocaRxqGuard& rxq,
    samurai::dpu::FlowStateTable& dpu_state,
    std::uint32_t listen_flow_id,
    std::uint32_t child_flow_id,
    std::uint32_t local_ip,
    std::uint16_t local_port,
    std::uint64_t timeout_ns,
    samurai::dpu::FlowState& out_flow,
    std::string& err) {
  if (!rxq.bridge || rxq.handle <= 0 || !rxq.bridge->api.receive_burst) {
    err = "dpu_passive_open_rxq_required";
    return false;
  }
  constexpr int kMaxRxPackets = 32;
  constexpr std::size_t kMaxPacket = 2048u;
  std::vector<std::uint8_t> flat(kMaxPacket * static_cast<std::size_t>(kMaxRxPackets));
  std::vector<std::uint16_t> lengths(static_cast<std::size_t>(kMaxRxPackets), 0u);
  const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
  while (samurai_pacing_monotonic_now_ns() - start_ns < timeout_ns) {
    int received = 0;
    char native_err[160];
    native_err[0] = '\0';
    if (rxq.bridge->api.receive_burst(
            rxq.handle,
            flat.data(),
            static_cast<std::uint32_t>(flat.size()),
            lengths.data(),
            kMaxRxPackets,
            &received,
            native_err,
            sizeof(native_err)) != 0) {
      err = native_err[0] ? std::string(native_err) : "dpu_passive_open_receive_failed";
      return false;
    }
    std::size_t off = 0u;
    for (int i = 0; i < received; ++i) {
      const std::size_t len = static_cast<std::size_t>(lengths[static_cast<std::size_t>(i)]);
      if (len == 0u || off + len > flat.size()) {
        break;
      }
      samurai::dpu::TcpSegmentObservation syn{};
      if (samurai::dpu::ParseTcpSegmentObservation(flat.data() + off, len, &syn) &&
          (syn.flags & samurai::dpu::kTcpFlagSyn) != 0u &&
          (syn.flags & samurai::dpu::kTcpFlagAck) == 0u &&
          syn.dst_port == local_port &&
          (local_ip == 0u || syn.dst_ip == local_ip)) {
        const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
        out_flow = dpu_state.AcceptPassiveOpen(listen_flow_id, child_flow_id, syn, 0u, now_ns);
        return true;
      }
      off += len;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  err = "dpu_passive_open_timeout";
  return false;
}

bool PublishDpuFlowStreamUpsert(
    void* gpu_push,
    const samurai::wire::FlowStreamUpsertV1& ev,
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::string& err) {
  if (!gpu_push) {
    err = "dpu_gpu_flow_stream_upsert_socket_unavailable";
    return false;
  }
  const int rc = SendFrame(gpu_push,
                           static_cast<std::uint8_t>(samurai::wire::MessageType::FLOW_STREAM_UPSERT),
                           correlation_id,
                           samurai::wire::WorkerKind::GPU,
                           job_id,
                           SerializeFlowStreamUpsert(ev),
                           ZMQ_DONTWAIT);
  if (rc < 0) {
    err = "dpu_gpu_flow_stream_upsert_publish_failed";
    return false;
  }
  return true;
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
    int queue_id) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"doca\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"doca_queue_id\":" + std::to_string(queue_id) +
      ",\"note\":\"doca_gpunetio_native+cpu_native+pacing_static\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
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
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::DOCA, job_id);
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  std::string gpu_jobs_ep = kDefaultGpuJobs;
  bool bind_jobs = true;
  bool bind_events = false;
  bool dpu_state_publish = true;
  bool dpu_contract_rdma = false;
  bool dpu_tcp_rx_feedback = EnvBool("SAMURAI_DPU_TCP_RX_FEEDBACK", false);
  bool dpu_tcp_passive_open = EnvBool("SAMURAI_DPU_TCP_PASSIVE_OPEN", false);
  int cli_queue_id = -1;
  int cli_rx_queue_id = -1;
  int cli_gpu_id = -1;
  int cli_batch_size = 1024;
  std::string cli_iface;
  std::string cli_device;
  std::string cli_contract_rdma_spec;

  if (const char* raw = std::getenv("SAMURAI_DPU_STATE_PUBLISH")) {
    const std::string value = raw;
    dpu_state_publish = !(value == "0" || value == "off" || value == "false");
  }
  if (const char* raw = std::getenv("SAMURAI_DPU_CONTRACT_RDMA")) {
    const std::string value = raw;
    dpu_contract_rdma = value == "1" || value == "on" || value == "true";
  }
  if (const char* raw = std::getenv("SAMURAI_DPU_CONTRACT_RDMA_SPEC")) {
    if (*raw) cli_contract_rdma_spec = raw;
  }
  if (const char* raw = std::getenv("SAMURAI_GPU_JOB_ENDPOINT")) {
    if (*raw) gpu_jobs_ep = raw;
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--job-endpoint" && i + 1 < argc) {
      jobs_ep = argv[++i];
    } else if (arg == "--event-endpoint" && i + 1 < argc) {
      events_ep = argv[++i];
    } else if (arg == "--gpu-job-endpoint" && i + 1 < argc) {
      gpu_jobs_ep = argv[++i];
    } else if (arg == "--jobs-mode" && i + 1 < argc) {
      bind_jobs = std::string(argv[++i]) == "bind";
    } else if (arg == "--events-mode" && i + 1 < argc) {
      bind_events = std::string(argv[++i]) == "bind";
    } else if (arg == "--dpu-state-publish" && i + 1 < argc) {
      const std::string value = argv[++i];
      dpu_state_publish = !(value == "0" || value == "off" || value == "false");
    } else if (arg == "--dpu-contract-rdma") {
      dpu_contract_rdma = true;
    } else if (arg == "--dpu-contract-rdma-spec" && i + 1 < argc) {
      cli_contract_rdma_spec = argv[++i];
    } else if (arg == "--dpu-tcp-rx-feedback") {
      dpu_tcp_rx_feedback = true;
    } else if (arg == "--no-dpu-tcp-rx-feedback") {
      dpu_tcp_rx_feedback = false;
    } else if (arg == "--dpu-tcp-passive-open") {
      dpu_tcp_passive_open = true;
      dpu_tcp_rx_feedback = true;
    } else if (arg == "--doca-interface" && i + 1 < argc) {
      cli_iface = argv[++i];
    } else if (arg == "--doca-device" && i + 1 < argc) {
      cli_device = argv[++i];
    } else if (arg == "--doca-queue-id" && i + 1 < argc) {
      cli_queue_id = std::stoi(argv[++i]);
    } else if (arg == "--doca-rx-queue-id" && i + 1 < argc) {
      cli_rx_queue_id = std::stoi(argv[++i]);
    } else if (arg == "--doca-gpu-id" && i + 1 < argc) {
      cli_gpu_id = std::stoi(argv[++i]);
    } else if (arg == "--doca-batch-size" && i + 1 < argc) {
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
  void* gpu_push = nullptr;
  if (dpu_state_publish) {
    gpu_push = zmq_socket(ctx, ZMQ_PUSH);
  }
  if (!pull || !push || (dpu_state_publish && !gpu_push)) {
    std::cerr << "zmq_socket failed\n";
    if (pull) zmq_close(pull);
    if (push) zmq_close(push);
    if (gpu_push) zmq_close(gpu_push);
    zmq_ctx_term(ctx);
    return 1;
  }

  if ((bind_jobs ? zmq_bind(pull, jobs_ep.c_str()) : zmq_connect(pull, jobs_ep.c_str())) != 0) {
    std::cerr << "jobs socket init failed: " << jobs_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    if (gpu_push) zmq_close(gpu_push);
    zmq_ctx_term(ctx);
    return 1;
  }
  if ((bind_events ? zmq_bind(push, events_ep.c_str()) : zmq_connect(push, events_ep.c_str())) != 0) {
    std::cerr << "events socket init failed: " << events_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    if (gpu_push) zmq_close(gpu_push);
    zmq_ctx_term(ctx);
    return 1;
  }
  if (gpu_push && zmq_connect(gpu_push, gpu_jobs_ep.c_str()) != 0) {
    std::cerr << "gpu jobs socket init failed: " << gpu_jobs_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_close(gpu_push);
    zmq_ctx_term(ctx);
    return 1;
  }

  (void)setenv("SAMURAI_GPU_DOCA_ENABLE", "1", 0);

  DocaNativeBridge doca{};
  samurai::dpu::FlowStateTable dpu_state{};
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
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"doca\"}";
      (void)SendFrame(push,
                      static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                      header.correlation_id,
                      samurai::wire::WorkerKind::DOCA,
                      job_id,
                      std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) ||
          header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(push,
                        static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                        header.correlation_id,
                        samurai::wire::WorkerKind::DOCA,
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
        std::string load_err;
        if (!LoadDocaNative(doca, load_err)) {
          (void)SendFrame(push,
                          static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                          header.correlation_id,
                          samurai::wire::WorkerKind::DOCA,
                          job_id,
                          JsonError(load_err));
          continue;
        }

        const std::string iface_wire = ReadFixed(env.xdp_interface, sizeof(env.xdp_interface));
        const std::string iface_env =
            (std::getenv("SAMURAI_GPU_DOCA_IFACE") ? std::getenv("SAMURAI_GPU_DOCA_IFACE")
                                                   : (std::getenv("SAMURAI_XDP_IFACE") ? std::getenv("SAMURAI_XDP_IFACE") : ""));
        const std::string iface = !cli_iface.empty() ? cli_iface : (!iface_wire.empty() ? iface_wire : iface_env);
        if (iface.empty()) {
          (void)SendFrame(push,
                          static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                          header.correlation_id,
                          samurai::wire::WorkerKind::DOCA,
                          job_id,
                          JsonError("doca_interface_required"));
          continue;
        }

        const std::string dev_env = (std::getenv("SAMURAI_GPU_DOCA_DEVICE") ? std::getenv("SAMURAI_GPU_DOCA_DEVICE") : "");
        const std::string device = !cli_device.empty() ? cli_device : dev_env;
        if (device.empty()) {
          (void)SendFrame(push,
                          static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                          header.correlation_id,
                          samurai::wire::WorkerKind::DOCA,
                          job_id,
                          JsonError("doca_device_required"));
          continue;
        }

        DpuContractWriterGuard contract_writer{};
        if (dpu_contract_rdma) {
          std::string writer_err;
          if (!OpenDpuContractRdmaWriter(doca, contract_writer, cli_contract_rdma_spec, device, writer_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(writer_err));
            continue;
          }
        }

        const int queue_id = std::max(0, cli_queue_id >= 0 ? cli_queue_id : static_cast<int>(env.xdp_queue_id));
        const int gpu_id = (cli_gpu_id >= 0)
                               ? cli_gpu_id
                               : (std::getenv("SAMURAI_GPU_DOCA_GPU_ID") ? std::atoi(std::getenv("SAMURAI_GPU_DOCA_GPU_ID")) : 0);
        const bool passive_job = dpu_tcp_passive_open && ProtoFromEnvelope(env) == samurai::dpu::kProtoTcp;
        const int packet_count = passive_job ? 0 : std::max(1, static_cast<int>(env.packet_count));
        const int batch_size = std::max(1, cli_batch_size);

        char err[160];
        err[0] = '\0';
        DocaTxqGuard txq{};
        txq.bridge = &doca;
        txq.handle = -1;
        if (doca.api.create_txq(iface.c_str(), device.c_str(), gpu_id, queue_id, &txq.handle, err, sizeof(err)) != 0 ||
            txq.handle <= 0) {
          const std::string msg = err[0] ? std::string(err) : "doca_create_txq_failed";
          (void)SendFrame(push,
                          static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                          header.correlation_id,
                          samurai::wire::WorkerKind::DOCA,
                          job_id,
                          JsonError(msg));
          continue;
        }

        DocaRxqGuard rxq{};
        if (dpu_tcp_rx_feedback || passive_job) {
          const int rx_queue_id = std::max(0, cli_rx_queue_id >= 0 ? cli_rx_queue_id : queue_id);
          std::string rx_err;
          if (!OpenDpuTcpRxq(doca, rxq, iface, device, gpu_id, rx_queue_id, rx_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(rx_err));
            continue;
          }
        }

        PacketConfig cfg = ConfigFromEnvelope(env);
        ddos_samurai::cpu_native::PacketPoolBuffer pool{};
        std::size_t stride = 0u;
        if (!passive_job) {
          pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
          stride = pool.packet_size;
          if (stride == 0 || pool.size() < stride) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError("packet_pool_empty"));
            continue;
          }
        }

        samurai::dpu::FlowState initial_flow{};
        if (passive_job) {
          const std::string listen_ip_s = ReadFixed(env.target_ip, sizeof(env.target_ip));
          const std::uint32_t listen_ip = ParseIpv4HostOrder(listen_ip_s);
          const std::uint32_t listen_flow_id = FlowIdFromHeader(header);
          const std::uint32_t child_flow_id = listen_flow_id ^ 0x80000000u;
          (void)dpu_state.Listen(listen_flow_id, listen_ip, env.target_port);
          std::string passive_err;
          if (!WaitForDpuPassiveOpen(
                  rxq,
                  dpu_state,
                  listen_flow_id,
                  child_flow_id == 0u ? 1u : child_flow_id,
                  listen_ip,
                  env.target_port,
                  EnvContractU32("SAMURAI_DPU_TCP_PASSIVE_OPEN_TIMEOUT_MS", 5000u, 1u) * 1'000'000ull,
                  initial_flow,
                  passive_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(passive_err));
            continue;
          }
        } else {
          initial_flow = dpu_state.Upsert(InitialFlowStateFromWirePacket(header, env, pool.data(), stride));
        }
        const std::uint64_t initial_publish_ns = samurai_pacing_monotonic_now_ns();
        if (dpu_state_publish) {
          std::string publish_err;
          samurai::wire::FlowStreamUpsertV1 ev = BuildFlowStreamUpsert(initial_flow, env, initial_publish_ns);
          ApplyDpuStreamPolicyToUpsert(dpu_state, initial_flow, env, ev);
          if (!PublishDpuFlowStreamUpsert(gpu_push, ev, header.correlation_id, job_id, publish_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(publish_err));
            continue;
          }
        }
        {
          std::string publish_err;
          const samurai::wire::FlowUpdateEventV1 ev = dpu_state.BuildUpdateEvent(initial_flow.flow_id, initial_publish_ns);
          if (!PublishDpuFlowUpdateOptionalRdma(dpu_contract_rdma, contract_writer, ev, publish_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(publish_err));
            continue;
          }
        }

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);
        const std::uint16_t established_tx_flags = EstablishedTxFlagsFromEnvelope(env);

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;

        std::vector<const uint8_t*> ptrs(static_cast<std::size_t>(batch_size), nullptr);
        std::vector<uint16_t> lens(static_cast<std::size_t>(batch_size), 0u);
        std::vector<int32_t> slots(static_cast<std::size_t>(batch_size), -1);
        DpuTcpRxScratch rx_scratch{};

        int offset = 0;
        while (offset < packet_count) {
          const int n_this = std::min(batch_size, packet_count - offset);
          for (int i = 0; i < n_this; ++i) {
            samurai_pacing_wait_next(&pace_state, &pace_cfg);
            const std::size_t off = static_cast<std::size_t>(offset + i) * stride;
            if (off + stride > pool.size()) {
              ptrs[static_cast<std::size_t>(i)] = nullptr;
              lens[static_cast<std::size_t>(i)] = 0u;
              continue;
            }
            ptrs[static_cast<std::size_t>(i)] = pool.data() + off;
            lens[static_cast<std::size_t>(i)] = static_cast<uint16_t>(std::min<std::size_t>(stride, 65535u));
          }

          int out_sent = 0;
          int out_errors = 0;
          err[0] = '\0';
          const int rc = doca.api.send_vector(
              txq.handle,
              ptrs.data(),
              lens.data(),
              slots.data(),
              n_this,
              &out_sent,
              &out_errors,
              err,
              sizeof(err));
          if (rc != 0) {
            const std::string msg = err[0] ? std::string(err) : "doca_send_vector_failed";
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(msg));
            packets_errors += static_cast<std::uint64_t>(n_this);
            break;
          }
          if (out_sent < 0) out_sent = 0;
          if (out_errors < 0) out_errors = 0;
          const std::uint64_t sent_before_batch = packets_sent;
          packets_sent += static_cast<std::uint64_t>(out_sent);
          packets_errors += static_cast<std::uint64_t>(out_errors);
          bytes_sent += static_cast<std::uint64_t>(out_sent) * static_cast<std::uint64_t>(stride);
          if (out_sent + out_errors < n_this) {
            packets_errors += static_cast<std::uint64_t>(n_this - (out_sent + out_errors));
          }

          const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
          if (out_sent > 0) {
            const std::uint32_t seq_advance = TcpSequenceAdvanceFromEnvelope(env);
            const std::uint32_t tx_payload_len =
                env.has_payload != 0u ? std::min<std::uint32_t>(env.pad_size, 1460u) : 0u;
            const std::uint32_t tx_seq = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(initial_flow.seq_num) + sent_before_batch * seq_advance) & 0xFFFFFFFFull);
            const std::uint16_t tx_flags = TcpFlagsFromEnvelope(env);
            (void)dpu_state.TrackTransmitBatch(
                initial_flow.flow_id,
                tx_seq,
                tx_payload_len,
                tx_flags,
                static_cast<std::uint32_t>(out_sent),
                seq_advance,
                now_ns);
            const samurai::dpu::FlowState* before_timer = dpu_state.Find(initial_flow.flow_id);
            const std::uint64_t before_timer_version = before_timer ? before_timer->version : 0u;
            const samurai::dpu::FlowState& timer_state = dpu_state.TickTcpTimers(initial_flow.flow_id, now_ns);
            if (timer_state.version != before_timer_version) {
              std::string timer_publish_err;
              const samurai::wire::FlowUpdateEventV1 timer_ev =
                  dpu_state.BuildUpdateEvent(timer_state.flow_id, now_ns);
              if (dpu_state_publish) {
                samurai::wire::FlowStreamUpsertV1 timer_upsert = BuildFlowStreamUpsert(timer_state, env, now_ns);
                ApplyDpuStreamPolicyToUpsert(dpu_state, timer_state, env, timer_upsert);
                if (!PublishDpuFlowStreamUpsert(
                        gpu_push, timer_upsert, header.correlation_id, job_id, timer_publish_err)) {
                  (void)SendFrame(push,
                                  static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                                  header.correlation_id,
                                  samurai::wire::WorkerKind::DOCA,
                                  job_id,
                                  JsonError(timer_publish_err));
                  packets_errors += static_cast<std::uint64_t>(n_this);
                  break;
                }
              }
              if (dpu_state_publish &&
                  !PublishDpuFlowUpdate(gpu_push, timer_ev, header.correlation_id, job_id, timer_publish_err)) {
                (void)SendFrame(push,
                                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                                header.correlation_id,
                                samurai::wire::WorkerKind::DOCA,
                                job_id,
                                JsonError(timer_publish_err));
                packets_errors += static_cast<std::uint64_t>(n_this);
                break;
              }
              if (!PublishDpuFlowUpdateOptionalRdma(dpu_contract_rdma, contract_writer, timer_ev, timer_publish_err)) {
                (void)SendFrame(push,
                                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                                header.correlation_id,
                                samurai::wire::WorkerKind::DOCA,
                                job_id,
                                JsonError(timer_publish_err));
                packets_errors += static_cast<std::uint64_t>(n_this);
                break;
              }
            }
          }
          if (rxq.handle > 0) {
            std::string rx_err;
            if (!PollDpuTcpRxFeedback(rxq,
                                      dpu_state,
                                      initial_flow.flow_id,
                                      gpu_push,
                                      dpu_state_publish,
                                      dpu_contract_rdma,
                                      contract_writer,
                                      established_tx_flags,
                                      env,
                                      rx_scratch,
                                      header.correlation_id,
                                      job_id,
                                      rx_err)) {
              (void)SendFrame(push,
                              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                              header.correlation_id,
                              samurai::wire::WorkerKind::DOCA,
                              job_id,
                              JsonError(rx_err));
              packets_errors += static_cast<std::uint64_t>(n_this);
              break;
            }
          }
          if (now_ns - last_hb_ns >= 1'000'000'000ull) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id);
            (void)PublishDpuHeartbeat(gpu_push, now_ns, header.correlation_id, job_id);
            last_hb_ns = now_ns;
          }
          if (now_ns - last_metric_ns >= 2'000'000'000ull) {
            const samurai::wire::MetricSnapshotV1 snap =
                BuildSnapshot(now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            SerializeSnapshot(snap));
            last_metric_ns = now_ns;
            last_hb_ns = now_ns;
          }
          offset += n_this;
        }

        DocaGpuNetioStats st{};
        err[0] = '\0';
        if (doca.api.get_stats && doca.api.get_stats(txq.handle, &st, err, sizeof(err)) == 0) {
          packets_sent = std::max<std::uint64_t>(packets_sent, st.tx_packets);
          bytes_sent = std::max<std::uint64_t>(bytes_sent, st.tx_bytes);
          packets_errors = std::max<std::uint64_t>(packets_errors, st.tx_errors + st.tx_drops);
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        if (rxq.handle > 0) {
          std::string rx_err;
          (void)PollDpuTcpRxFeedback(rxq,
                                     dpu_state,
                                     initial_flow.flow_id,
                                     gpu_push,
                                     dpu_state_publish,
                                     dpu_contract_rdma,
                                     contract_writer,
                                     established_tx_flags,
                                     env,
                                     rx_scratch,
                                     header.correlation_id,
                                     job_id,
                                     rx_err);
        }
        const samurai::dpu::FlowState* observed_flow = dpu_state.Find(initial_flow.flow_id);
        samurai::dpu::FlowState final_flow = observed_flow ? *observed_flow : initial_flow;
        if (rxq.handle <= 0) {
          const std::uint64_t seq_advance =
              static_cast<std::uint64_t>(TcpSequenceAdvanceFromEnvelope(env)) * packets_sent;
          final_flow.seq_num = static_cast<std::uint32_t>(
              (static_cast<std::uint64_t>(initial_flow.seq_num) + seq_advance) & 0xFFFFFFFFull);
        }
        final_flow.last_tx_ts = end_ns;
        if (packets_errors != 0u) {
          final_flow.tcp_state = samurai::dpu::kTcpStatePoisoned;
          final_flow.flags = static_cast<std::uint16_t>(final_flow.flags | samurai::dpu::kTcpFlagRst);
        } else if (rxq.handle <= 0 &&
                   final_flow.tcp_state != samurai::dpu::kTcpStatePoisoned &&
                   final_flow.tcp_state != samurai::dpu::kTcpStateCloseWait &&
                   final_flow.tcp_state != samurai::dpu::kTcpStateTimeWait) {
          final_flow.tcp_state = samurai::dpu::kTcpStateEstablished;
        }
        const samurai::dpu::FlowState& committed_final_flow = dpu_state.Transition(final_flow);
        if (dpu_state_publish) {
          std::string publish_err;
          samurai::wire::FlowStreamUpsertV1 ev = BuildFlowStreamUpsert(committed_final_flow, env, end_ns);
          ApplyDpuStreamPolicyToUpsert(dpu_state, committed_final_flow, env, ev);
          if (!PublishDpuFlowStreamUpsert(gpu_push, ev, header.correlation_id, job_id, publish_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(publish_err));
            continue;
          }
        }
        {
          std::string publish_err;
          const samurai::wire::FlowUpdateEventV1 ev =
              dpu_state.BuildUpdateEvent(committed_final_flow.flow_id, end_ns);
          if (!PublishDpuFlowUpdateOptionalRdma(dpu_contract_rdma, contract_writer, ev, publish_err)) {
            (void)SendFrame(push,
                            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                            header.correlation_id,
                            samurai::wire::WorkerKind::DOCA,
                            job_id,
                            JsonError(publish_err));
            continue;
          }
        }

        const samurai::wire::MetricSnapshotV1 snap =
            BuildSnapshot(end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(push,
                        static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                        header.correlation_id,
                        samurai::wire::WorkerKind::DOCA,
                        job_id,
                        SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonDone(header.correlation_id,
                                                        job_id,
                                                        packets_sent,
                                                        packets_errors,
                                                        bytes_sent,
                                                        snap.actual_rps,
                                                        snap.rate_accuracy_pct,
                                                        queue_id);
        (void)SendFrame(push,
                        static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                        header.correlation_id,
                        samurai::wire::WorkerKind::DOCA,
                        job_id,
                        done);
      } catch (const std::exception& exc) {
        (void)SendFrame(push,
                        static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                        header.correlation_id,
                        samurai::wire::WorkerKind::DOCA,
                        job_id,
                        JsonError(exc.what()));
      }
      continue;
    }

    zmq_msg_close(&msg);
    (void)SendFrame(push,
                    static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                    header.correlation_id,
                    samurai::wire::WorkerKind::DOCA,
                    job_id,
                    JsonError("unsupported_msg_type"));
  }

  if (doca.handle) {
    dlclose(doca.handle);
  }
  if (gpu_push) {
    zmq_close(gpu_push);
  }
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
