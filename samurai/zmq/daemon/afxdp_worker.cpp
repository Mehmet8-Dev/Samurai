#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <dirent.h>
#include <dlfcn.h>
#include <exception>
#include <iostream>
#include <optional>
#include <pthread.h>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <zmq.h>

#include "../../samurai/xdp/xdp_native_api.h"
#include "bridge.hpp"
#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"
// Paylaşılan userspace stateful TCP fast-path sürücüsü (DPDK ile ortak yol).
#include "stateful_fastpath.hpp"
// L7 profil/runner kurucusu (run_profile_json'u dpdk_direct transport ile sürer).
#include "stateful_l7_profile.hpp"

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;
using samurai::daemon::SerializeSnapshotV2;

using samurai::cpu_native::PacketConfig;
using samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_afxdp";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_afxdp";

using fn_xdp_get_native_api_v1_t = xdp_native_api_v1* (*)();

struct XdpNativeBridge {
  void* handle{nullptr};
  xdp_native_api_v1* api{nullptr};
  std::string lib_path;
};

// Çoklu veya tekli XDP bağlamlarının güvenli temizlenmesi
struct XdpMultiCtxGuard {
  XdpNativeBridge* bridge{nullptr};
  std::vector<int> handles;

  void add(int h) {
    if (h > 0) handles.push_back(h);
  }

  ~XdpMultiCtxGuard() {
    if (bridge && bridge->api && bridge->api->destroy_ctx) {
      char err[160];
      for (int h : handles) {
        if (h > 0) {
          err[0] = '\0';
          (void)bridge->api->destroy_ctx(h, err, sizeof(err));
        }
      }
    }
  }
};

// Ağ kartının donanımsal RX/TX kuyruk sayısını sysfs üzerinden dinamik tespit eder
int DetectInterfaceQueues(const std::string& iface) {
  if (iface.empty()) return 1;
  const std::string qpath = "/sys/class/net/" + iface + "/queues";
  DIR* d = opendir(qpath.c_str());
  if (!d) return 1;
  int count = 0;
  struct dirent* de = nullptr;
  while ((de = readdir(d)) != nullptr) {
    if (std::strncmp(de->d_name, "tx-", 3) == 0) {
      count++;
    }
  }
  closedir(d);
  return count > 0 ? count : 1;
}

// AF_XDP çoklu kuyruk taşıma shim'i:
// Tek veya çoklu kuyrukları (RSS demux) StatefulFastpathDriver üzerine oturtur.
// Send kuyruklar arasında round-robin dağıtım yapar; Recv ise tüm kuyruk soketlerini
// sırayla yoklayarak (fair polling) SYN-ACK'leri donanım RSS hangi kuyruğa atmışsa
// oradan toplar.
struct XdpMultiShim : samurai::daemon::FastpathTxRxShim {
  xdp_native_api_v1* api{nullptr};
  std::vector<int> handles;
  std::size_t send_rr{0};
  std::size_t recv_rr{0};

  XdpMultiShim(xdp_native_api_v1* a, const std::vector<int>& h)
      : api(a), handles(h) {}

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    if (!api || !api->send_buffer_strided || handles.empty()) {
      err = "xdp_send_buffer_strided_missing";
      return -1;
    }
    const int h = handles[send_rr % handles.size()];
    send_rr++;
    char xdp_err[160];
    xdp_err[0] = '\0';
    const int sent = api->send_buffer_strided(
        h, base, static_cast<int>(psize), static_cast<int>(stride),
        static_cast<int>(count), xdp_err, sizeof(xdp_err));
    if (sent < 0 && xdp_err[0]) err = xdp_err;
    return sent;
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    if (!api || !api->recv_frames || handles.empty()) return 0;
    int total_recvd = 0;
    const std::size_t n_handles = handles.size();
    for (std::size_t i = 0; i < n_handles && total_recvd < max; ++i) {
      const std::size_t idx = (recv_rr + i) % n_handles;
      const int h = handles[idx];
      const int remaining = max - total_recvd;
      std::uint8_t* curr_out = out + (static_cast<std::size_t>(total_recvd) * stride);
      std::uint16_t* curr_lens = lens + total_recvd;
      char xdp_err[160];
      xdp_err[0] = '\0';
      const int n = api->recv_frames(
          h, curr_out, static_cast<int>(stride), curr_lens, remaining,
          static_cast<int>(stride), xdp_err, sizeof(xdp_err));
      if (n > 0) {
        total_recvd += n;
      } else if (n < 0 && xdp_err[0] && err.empty()) {
        err = xdp_err;
      }
    }
    recv_rr = (recv_rr + 1) % n_handles;
    return total_recvd;
  }

  bool RxAvailable() const override {
    return api && api->recv_frames && !handles.empty();
  }
};

// Çoklu kuyruk stateless TX worker thread yapısı (DPDK ile eşdeğer çoklu çekirdek mimarisi)
struct alignas(64) XdpTxWorkerThread {
  std::thread th;
  int queue_id{0};
  int cpu_core{-1};
  int handle{-1};
  std::atomic<std::uint64_t> packets_sent{0};
  std::atomic<std::uint64_t> packets_errors{0};
  std::atomic<std::uint64_t> bytes_sent{0};
  std::atomic<std::uint64_t> sleep_calls{0};
  std::atomic<bool> done{false};
  std::atomic<bool>* stop_flag{nullptr};
};

void xdp_tx_thread_func(XdpTxWorkerThread* tw, xdp_native_api_v1* api,
                        const std::uint8_t* pool_data, std::size_t pool_len,
                        std::size_t stride, int start, int end,
                        int batch_size, samurai_pacing_config_t pace_cfg) {
  if (tw->cpu_core >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(tw->cpu_core, &set);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
  }

  samurai_pacing_state_t st{};
  samurai_pacing_init(&st, &pace_cfg);

  const int effective_batch = std::max(1, std::min(batch_size, 64));
  int i = start;
  char xdp_err[160];
  while (i < end) {
    if (tw->stop_flag && tw->stop_flag->load(std::memory_order_relaxed)) {
      break;
    }
    samurai_pacing_wait_next(&st, &pace_cfg);
    int batch = std::min(effective_batch, end - i);
    const std::size_t off = static_cast<std::size_t>(i) * stride;
    if (off + static_cast<std::size_t>(batch) * stride > pool_len) {
      const std::size_t avail = pool_len > off ? (pool_len - off) / stride : 0;
      batch = static_cast<int>(std::min<std::size_t>(batch, avail));
    }
    if (batch <= 0) break;

    const std::uint8_t* buf = pool_data + off;
    xdp_err[0] = '\0';
    int sent = 0;
    if (api->send_buffer_strided) {
      sent = api->send_buffer_strided(
          tw->handle, buf, static_cast<int>(stride), static_cast<int>(stride),
          batch, xdp_err, sizeof(xdp_err));
    } else {
      sent = api->send_buffer(
          tw->handle, buf, static_cast<int>(stride),
          batch, xdp_err, sizeof(xdp_err));
    }

    if (sent > 0) {
      tw->packets_sent.fetch_add(sent, std::memory_order_relaxed);
      tw->bytes_sent.fetch_add(sent * static_cast<std::uint64_t>(stride), std::memory_order_relaxed);
      i += sent;
    } else if (sent == 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(50));
    } else {
      tw->packets_errors.fetch_add(batch, std::memory_order_relaxed);
      i += batch;
    }
  }

  tw->sleep_calls.store(st.sleep_calls, std::memory_order_relaxed);
  tw->done.store(true, std::memory_order_release);
}



using samurai::daemon::ConfigFromEnvelope;


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
  // Primary location: the dedicated samurai/xdp/ source tree.
  out.emplace_back(repo_root + "/samurai/xdp/xdp_sender.so");
  out.emplace_back("samurai/xdp/xdp_sender.so");
  // Legacy in-package location (kept for backward compat).
  out.emplace_back(repo_root + "/samurai/xdp_sender.so");
  // cpython-tagged builds for 3.11 and 3.12
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-311/samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-312/samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/build/lib.linux-x86_64-cpython-310/samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back(repo_root + "/samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");

  // 3. Legacy relative-to-CWD paths (kept for backward compat).
  out.emplace_back("samurai/xdp_sender.so");
  out.emplace_back("xdp_sender.so");
  out.emplace_back("samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so");
  out.emplace_back("samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so");
  out.emplace_back("samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so");
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



std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct,
    int xdp_mode_effective,
    int xdp_queue_id,
    int xdp_num_queues = 1,
    std::uint64_t ipfix_exported_packets = 0,
    std::uint64_t ipfix_exported_records = 0) {
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
      ",\"xdp_num_queues\":" + std::to_string(xdp_num_queues) +
      ",\"ipfix_exported_packets\":" + std::to_string(ipfix_exported_packets) +
      ",\"ipfix_exported_records\":" + std::to_string(ipfix_exported_records) +
      ",\"note\":\"xdp_native_api+multi_queue+cpu_native+pacing_static\"}";
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
  int cli_num_queues = -1;
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
    } else if ((arg == "--xdp-queues" || arg == "--xdp-tx-queues" || arg == "--xdp-num-queues") && i + 1 < argc) {
      cli_num_queues = std::max(1, std::stoi(argv[++i]));
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
            push, samurai::wire::WorkerKind::AF_XDP, header, job_id,
            payload_ptr, payload_len, telemetry, running)) {
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      // V1 (blast) veya V2 (stateful/L7) kabul; env V1 tabanıdır (V2'de offset 0'da gömülü).
      const bool env_is_v1 =
          payload_len == sizeof(samurai::wire::JobEnvelopeV1) &&
          header.payload_len == sizeof(samurai::wire::JobEnvelopeV1);
      const bool env_is_v2 =
          payload_len == sizeof(samurai::wire::JobEnvelopeV2) &&
          header.payload_len == sizeof(samurai::wire::JobEnvelopeV2);
      if (!env_is_v1 && !env_is_v2) {
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
      // V2 tail'i (varsa) mesaj kapatılmadan önce yakala (payload_ptr sonra geçersiz olur).
      samurai::wire::JobEnvelopeV2 env2{};
      if (env_is_v2) {
        std::memcpy(&env2, payload_ptr, sizeof(env2));
      } else {
        env2.base = env;
      }
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

        const int iface_max_queues = DetectInterfaceQueues(iface);
        int requested_queues = 1;
        if (cli_num_queues > 0) {
          requested_queues = cli_num_queues;
        } else if (std::getenv("SAMURAI_XDP_QUEUES") != nullptr) {
          requested_queues = std::max(1, std::atoi(std::getenv("SAMURAI_XDP_QUEUES")));
        } else if (std::getenv("SAMURAI_XDP_TX_QUEUES") != nullptr) {
          requested_queues = std::max(1, std::atoi(std::getenv("SAMURAI_XDP_TX_QUEUES")));
        } else if (env_is_v2 && env2.concurrency > 1) {
          requested_queues = static_cast<int>(env2.concurrency);
        }

        const int queue_id = std::max(0, cli_queue_id >= 0 ? cli_queue_id : static_cast<int>(env.xdp_queue_id));
        const int mode = std::max(0, cli_mode >= 0 ? cli_mode : static_cast<int>(env.xdp_mode));
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));

        int num_queues = 1;
        if (requested_queues > 1) {
          num_queues = std::min<int>(requested_queues, iface_max_queues > 0 ? iface_max_queues : requested_queues);
          num_queues = std::min<int>(num_queues, packet_count);
          if (num_queues < 1) num_queues = 1;
        }
        const bool multi_queue = num_queues > 1;

        char xdp_err[160];
        xdp_err[0] = '\0';
        XdpMultiCtxGuard ctx_guard{};
        ctx_guard.bridge = &xdp;
        std::vector<int> handles;

        bool open_failed = false;
        for (int q = 0; q < num_queues; ++q) {
          const int qid = multi_queue ? q : queue_id;
          xdp_err[0] = '\0';
          int h = xdp.api->create_ctx(iface.c_str(), qid, mode, xdp_err, sizeof(xdp_err));
          if (h <= 0) {
            open_failed = true;
            break;
          }
          ctx_guard.add(h);
          handles.push_back(h);
        }

        if (open_failed || handles.empty()) {
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

        // Stateful userspace TCP fast-path (protocol=custom_tcp / attack_vector=
        // stateful|l7_custom_tcp): ortak sürücüyü çoklu kuyruk XDP shim'iyle koştur.
        // Donanımsal RSS trafiği hangi kuyruğa atarsa atsın XdpMultiShim tüm kuyrukları
        // tarayarak dönüş SYN-ACK'lerini yakalar.
        if (samurai::daemon::IsStatefulFastpathJob(env)) {
          telemetry.BeginJob();
          XdpMultiShim shim(xdp.api, handles);
          samurai::daemon::FastpathParams params =
              samurai::daemon::FastpathParamsFromEnvelope(env);
          params.backend = "af_xdp";

          std::atomic<bool> stop{false};
          samurai::daemon::ControlPollState ctrl{};
          samurai::daemon::StatefulFastpathDriver driver(shim);
          samurai::daemon::FastpathHooks hooks;
          hooks.emit_heartbeat = [&]() {
            samurai::daemon::PollControlNonBlocking(
                pull, push, samurai::wire::WorkerKind::AF_XDP, &telemetry, ctrl);
            if (ctrl.stop_job) {
              stop.store(true, std::memory_order_release);
            }
            if (ctrl.shutdown) {
              running = false;
            }
            (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                            header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id);
          };
          hooks.emit_metric = [&](const samurai::wire::MetricSnapshotV2& snap) {
            (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                            header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id,
                            SerializeSnapshotV2(snap));
          };

          const bool l7 = samurai::daemon::JobWantsL7Fastpath(env);
          samurai::daemon::L7RunnerBundle l7b;
          samurai::daemon::FastpathResult res;
          if (l7) {
            // Harici-wire modunda afxdp da dpdk_direct transport'u kullanır (aynı gate).
            l7b = samurai::daemon::MakeL7Runner(env2, "dpdk_direct");
            res = driver.Run(params, l7b.runner, stop, hooks);
          } else {
            std::string cfg_err;
            if (!driver.Configure(params, cfg_err)) {
              (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                              header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id,
                              JsonError(cfg_err));
              continue;
            }
            driver.SeedL4(params);
            res = driver.Run(params, {}, stop, hooks);
          }

          const std::uint64_t done_ns = samurai_pacing_monotonic_now_ns();
          samurai::daemon::RecordBatchToTelemetry(
              telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
              ReadFixed(env.protocol, sizeof(env.protocol)), res.tx_packets, env.packet_size, done_ns);
          telemetry.FlushEnd(done_ns);

          samurai::core::json::Value done = samurai::core::json::Value::Object();
          done.set("status", samurai::core::json::Value::Str("ok"));
          done.set("mode", samurai::core::json::Value::Str(l7 ? "stateful_fastpath_l7" : "stateful_fastpath"));
          if (l7 && l7b.result) done.set("l7", *l7b.result);
          done.set("job_id", samurai::core::json::Value::Str(job_id));
          done.set("tx_packets", samurai::core::json::Value::Int(static_cast<int64_t>(res.tx_packets)));
          done.set("rx_frames", samurai::core::json::Value::Int(static_cast<int64_t>(res.rx_frames)));
          done.set("connect_attempts", samurai::core::json::Value::Int(static_cast<int64_t>(res.connect_attempts)));
          done.set("connect_established", samurai::core::json::Value::Int(static_cast<int64_t>(res.connect_established)));
          done.set("retransmit_count", samurai::core::json::Value::Int(static_cast<int64_t>(res.retransmit_count)));
          done.set("retransmit_exhausted", samurai::core::json::Value::Int(static_cast<int64_t>(res.retransmit_exhausted)));
          done.set("connect_timeout", samurai::core::json::Value::Int(static_cast<int64_t>(res.connect_timeout)));
          done.set("rx_available", samurai::core::json::Value::Bool(res.rx_available));
          done.set("ipfix_exported_packets",
                   samurai::core::json::Value::Int(static_cast<int64_t>(telemetry.JobExportedPackets())));
          done.set("ipfix_exported_records",
                   samurai::core::json::Value::Int(static_cast<int64_t>(telemetry.JobExportedRecords())));
          const std::string done_str = done.dump();
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                          header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id,
                          std::vector<std::uint8_t>(done_str.begin(), done_str.end()));
          continue;
        }

        telemetry.BeginJob();

        PacketConfig cfg = ConfigFromEnvelope(env);
        const auto pool = samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
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

        if (multi_queue) {
          const int base_core = std::getenv("SAMURAI_XDP_BASE_CORE")
              ? std::atoi(std::getenv("SAMURAI_XDP_BASE_CORE")) : (env.pin_cpu >= 0 ? env.pin_cpu : -1);

          samurai_pacing_config_t thread_pace = pace_cfg;
          if (thread_pace.mode == SAMURAI_PACING_RPS) {
            thread_pace.target_rps = pace_cfg.target_rps / static_cast<double>(num_queues);
          } else if (thread_pace.mode == SAMURAI_PACING_IPG && thread_pace.ipg_ns > 0) {
            thread_pace.ipg_ns = pace_cfg.ipg_ns * static_cast<std::uint64_t>(num_queues);
          } else if (thread_pace.mode == SAMURAI_PACING_BURST && thread_pace.burst_size > 1) {
            thread_pace.burst_size =
                std::max<std::uint32_t>(1u, thread_pace.burst_size / static_cast<std::uint32_t>(num_queues));
          }

          std::atomic<bool> stop_threads{false};
          samurai::daemon::ControlPollState ctrl{};
          std::deque<XdpTxWorkerThread> workers;
          const int base_packets = packet_count / num_queues;
          const int remainder = packet_count % num_queues;
          int cursor = 0;
          for (int q = 0; q < num_queues; ++q) {
            workers.emplace_back();
            XdpTxWorkerThread& tw = workers.back();
            tw.queue_id = q;
            tw.cpu_core = base_core >= 0 ? base_core + q : -1;
            tw.handle = handles[q];
            tw.stop_flag = &stop_threads;
            const int cnt = base_packets + (q < remainder ? 1 : 0);
            const int seg_start = cursor;
            const int seg_end = cursor + cnt;
            cursor = seg_end;
            tw.th = std::thread(xdp_tx_thread_func, &tw, xdp.api, pool.data(), pool.size(),
                                stride, seg_start, seg_end, cli_batch_size, thread_pace);
          }

          while (true) {
            samurai::daemon::PollControlNonBlocking(
                pull, push, samurai::wire::WorkerKind::AF_XDP, &telemetry, ctrl);
            if (ctrl.stop_job) {
              stop_threads.store(true, std::memory_order_release);
            }
            if (ctrl.shutdown) {
              running = false;
            }
            bool all_done = true;
            for (const auto& w : workers) {
              if (!w.done.load(std::memory_order_acquire)) {
                all_done = false;
                break;
              }
            }
            if (all_done) break;

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
            if (now_ns - last_hb_ns >= 1'000'000'000ull) {
              (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                              header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id);
              last_hb_ns = now_ns;
            }
            if (now_ns - last_metric_ns >= 2'000'000'000ull) {
              std::uint64_t cur_sent = 0, cur_err = 0, cur_bytes = 0;
              for (const auto& w : workers) {
                cur_sent += w.packets_sent.load(std::memory_order_relaxed);
                cur_err += w.packets_errors.load(std::memory_order_relaxed);
                cur_bytes += w.bytes_sent.load(std::memory_order_relaxed);
              }
              const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
                  now_ns, start_ns, cur_sent, cur_err, cur_bytes, pace_cfg, pace_state);
              (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                              header.correlation_id, samurai::wire::WorkerKind::AF_XDP, job_id,
                              SerializeSnapshot(snap));
              last_metric_ns = now_ns;
              last_hb_ns = now_ns;
            }
          }

          for (auto& w : workers) {
            if (w.th.joinable()) w.th.join();
            packets_sent += w.packets_sent.load();
            packets_errors += w.packets_errors.load();
            bytes_sent += w.bytes_sent.load();
          }
        } else {
          // Tekil kuyruk yolu (handles[0])
          const int active_handle = handles[0];
          samurai::daemon::ControlPollState ctrl{};
          int offset = 0;
          while (offset < packet_count) {
            samurai::daemon::PollControlNonBlocking(
                pull, push, samurai::wire::WorkerKind::AF_XDP, &telemetry, ctrl);
            if (ctrl.shutdown) {
              running = false;
            }
            if (ctrl.stop_job) {
              break;
            }
            if (ctrl.reconfigure) {
              (void)samurai::daemon::ApplyReconfigureWindow(
                  reinterpret_cast<const std::uint8_t*>(&ctrl.reconf),
                  sizeof(ctrl.reconf), pace_cfg, pace_state);
              ctrl.reconfigure = false;
            }
            const int batch = std::min(cli_batch_size, packet_count - offset);
            for (int i = 0; i < batch; ++i) {
              samurai_pacing_wait_next(&pace_state, &pace_cfg);
            }
            int remaining = batch;
            int local_off = 0;
            int retry_zeros = 0;
            while (remaining > 0) {
              const std::uint8_t* raw_base = nullptr;
              std::uint32_t raw_count = 0;
              std::size_t raw_pkt_size = 0;
              std::size_t raw_stride = 0;
              if ((cfg.attack_vector == "l7_custom_tcp" || cfg.protocol == "custom_tcp") &&
                  samurai::l7_emu_native::peek_custom_tcp_tx_packets_raw(
                      static_cast<std::uint32_t>(remaining), &raw_base, &raw_count, &raw_pkt_size, &raw_stride) == 0 &&
                  raw_base != nullptr && raw_count > 0) {
                int sent = 0;
                xdp_err[0] = '\0';
                if (xdp.api->send_buffer_strided) {
                  sent = xdp.api->send_buffer_strided(
                      active_handle,
                      raw_base,
                      static_cast<int>(raw_pkt_size),
                      static_cast<int>(raw_stride),
                      static_cast<int>(raw_count),
                      xdp_err,
                      sizeof(xdp_err));
                }
                if (sent > 0) {
                  std::uint32_t consumed = 0;
                  samurai::l7_emu_native::consume_custom_tcp_tx_packets_raw(static_cast<std::uint32_t>(sent), &consumed);
                  packets_sent += static_cast<std::uint64_t>(sent);
                  bytes_sent += static_cast<std::uint64_t>(sent) * static_cast<std::uint64_t>(raw_stride);
                  local_off += sent;
                  remaining -= sent;
                  continue;
                }
              }

              const std::uint8_t* buf = pool.data() + (static_cast<std::size_t>(offset + local_off) * stride);
              xdp_err[0] = '\0';
              int sent = 0;
              if (xdp.api->send_buffer_strided) {
                sent = xdp.api->send_buffer_strided(
                    active_handle,
                    buf,
                    static_cast<int>(stride),
                    static_cast<int>(stride),
                    remaining,
                    xdp_err,
                    sizeof(xdp_err));
              } else {
                sent = xdp.api->send_buffer(
                    active_handle,
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
        }

        xdp_native_stats native_stats{};
        native_stats.mode = mode;
        native_stats.queue_id = queue_id;
        for (int h : handles) {
          xdp_native_stats cur_stats{};
          xdp_err[0] = '\0';
          if (xdp.api->get_stats(h, &cur_stats, xdp_err, sizeof(xdp_err)) == 0) {
            if (!multi_queue) {
              packets_sent = std::max<std::uint64_t>(packets_sent, cur_stats.tx_packets);
              bytes_sent = std::max<std::uint64_t>(bytes_sent, cur_stats.tx_bytes);
              packets_errors = std::max<std::uint64_t>(packets_errors, cur_stats.tx_errors);
            }
            native_stats.mode = cur_stats.mode;
            native_stats.queue_id = cur_stats.queue_id;
          }
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        samurai::daemon::RecordBatchToTelemetry(
            telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
            ReadFixed(env.protocol, sizeof(env.protocol)), packets_sent,
            static_cast<std::uint32_t>(stride), end_ns);
        telemetry.FlushEnd(end_ns);
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
            native_stats.queue_id,
            num_queues,
            telemetry.JobExportedPackets(),
            telemetry.JobExportedRecords());
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
