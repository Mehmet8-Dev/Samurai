#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <sched.h>
#include <dlfcn.h>
#include <memory>

#include <zmq.h>

#include "bridge.hpp"
#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

// Samurai'nin tek native DPDK çekirdeği. Başlık rte_*.h/Python.h içermez;
// gerçek DPDK mantığı dpdk_core.cpp içinde SAMURAI_WITH_DPDK ile koşullanmıştır.
#include "dpdk/dpdk_core.hpp"

// Paylaşılan userspace stateful TCP fast-path sürücüsü (DPDK/XDP ortak yolu).
#include "stateful_fastpath.hpp"
// L7 profil/runner kurucusu (run_profile_json'u dpdk_direct transport ile sürer).
#include "stateful_l7_profile.hpp"
// DPDK TX/RX shim'i (scenario_worker ile paylaşılan; yalnız SAMURAI_WITH_DPDK'da tanımlı).
#include "dpdk_fastpath_shim.hpp"

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

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_dpdk";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_dpdk";
constexpr const char* kDefaultGpuLib = "samurai/libgpu_packet_cuda.so";
constexpr std::uint64_t kDefaultGatewayMac = 0xFFFFFFFFFFFFull;

using fn_gpu_gen_packets_t = int (*)(std::int64_t, const char*, std::int64_t, const char*, int, const char*,
                                     std::int64_t, int, std::int64_t, std::uint64_t, std::uint64_t, const char*,
                                     std::uint8_t**, std::size_t*, int*);
using fn_gpu_gen_icmp_t = int (*)(std::int64_t, const char*, const char*, int, int, std::int64_t, std::int64_t,
                                  std::int64_t, std::uint64_t, std::uint64_t, const char*, std::uint8_t**,
                                  std::size_t*, int*);
using fn_gpu_p2p_arena_info_t = int (*)(std::uint64_t*, void**, void**, std::size_t*);
using fn_gpu_free_t = void (*)(void*);

struct DpdkGpuP2pPool {
  void* dl_handle{nullptr};
  fn_gpu_free_t free_fn{nullptr};
  std::uint8_t* data_ptr{nullptr};
  std::size_t byte_len{0};
  std::uint16_t packet_size{0};
  std::uint64_t bar1_iova{0};
  bool active{false};

  ~DpdkGpuP2pPool() {
    if (data_ptr && free_fn) {
      free_fn(data_ptr);
      data_ptr = nullptr;
    }
    if (dl_handle) {
      dlclose(dl_handle);
      dl_handle = nullptr;
    }
  }
};

inline bool TryGenerateGpuBar1Pool(
    const samurai::wire::JobEnvelopeV1& env,
    int packet_count,
    DpdkGpuP2pPool& out) {
  setenv("SAMURAI_GPU_PACKET_BAR1_P2P_OUTPUT", "1", 1);
  const char* lib_env = std::getenv("SAMURAI_GPU_NATIVE_LIB");
  const char* lib_path = (lib_env && *lib_env) ? lib_env : kDefaultGpuLib;
  out.dl_handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
  if (!out.dl_handle) {
    return false;
  }
  auto gen_pkts = reinterpret_cast<fn_gpu_gen_packets_t>(
      dlsym(out.dl_handle, "samurai_gpu_packet_generate_packets"));
  auto gen_icmp = reinterpret_cast<fn_gpu_gen_icmp_t>(
      dlsym(out.dl_handle, "samurai_gpu_packet_generate_icmp_packets"));
  auto arena_info = reinterpret_cast<fn_gpu_p2p_arena_info_t>(
      dlsym(out.dl_handle, "samurai_gpu_packet_p2p_get_arena_info"));
  out.free_fn = reinterpret_cast<fn_gpu_free_t>(
      dlsym(out.dl_handle, "samurai_gpu_packet_free"));
  if (!gen_pkts || !gen_icmp || !out.free_fn) {
    return false;
  }

  const std::string protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  const std::string spoof_subnet = ReadFixed(env.spoof_subnet, sizeof(env.spoof_subnet));
  const char* spoof_subnet_ptr = spoof_subnet.empty() ? "1.0.0.0/8" : spoof_subnet.c_str();
  const std::string target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  const std::string target_ip_norm = target_ip.empty() ? "127.0.0.1" : target_ip;
  const int pool_packets = std::min(std::max(1, packet_count), 65536);

  std::uint8_t* ptr = nullptr;
  std::size_t out_size = 0;
  int out_pkt_size = 0;
  int rc = -1;
  if (protocol == "icmp" || protocol == "ICMP") {
    rc = gen_icmp(
        pool_packets, target_ip_norm.c_str(), "192.168.1.100",
        env.spoof_enabled != 0u ? 1 : 0, 1, 8, 0,
        std::max<std::int64_t>(0, static_cast<std::int64_t>(env.packet_size) - 42),
        0ull, kDefaultGatewayMac, spoof_subnet_ptr, &ptr, &out_size, &out_pkt_size);
  } else {
    const std::string proto = protocol.empty() ? "udp" : protocol;
    rc = gen_pkts(
        pool_packets, target_ip_norm.c_str(), static_cast<std::int64_t>(env.target_port),
        proto.c_str(), env.spoof_enabled != 0u ? 1 : 0, "192.168.1.100",
        2, 1, env.window == 0ull ? -1 : static_cast<std::int64_t>(env.window),
        0ull, kDefaultGatewayMac, spoof_subnet_ptr, &ptr, &out_size, &out_pkt_size);
  }
  if (rc != 0 || !ptr || out_pkt_size <= 0 || out_size < static_cast<std::size_t>(out_pkt_size)) {
    return false;
  }
  out.data_ptr = ptr;
  out.byte_len = out_size;
  out.packet_size = static_cast<std::uint16_t>(out_pkt_size);
  if (arena_info) {
    void* host_bar1 = nullptr;
    void* cuda_dev = nullptr;
    std::uint64_t phys_base = 0;
    std::size_t arena_bytes = 0;
    if (arena_info(&phys_base, &host_bar1, &cuda_dev, &arena_bytes) == 0 &&
        static_cast<std::uint8_t*>(host_bar1) == ptr) {
      out.bar1_iova = phys_base;
    }
  }
  out.active = true;
  return true;
}





using samurai::daemon::ConfigFromEnvelope;
using samurai::daemon::JsonPayloadFromStats;

#ifdef SAMURAI_WITH_DPDK
// Portu iş süresince açık tutan RAII sarmalayıcı; scope çıkışında çekirdeğe
// close_port bildirir (portu teardown eder).
struct DpdkPortGuard {
  std::int64_t handle{-1};
  ~DpdkPortGuard() {
    if (handle >= 0) {
      samurai::dpdk::close_port(handle);
    }
  }
};

// DPDK taşıma shim'i (DpdkShim) artık dpdk_fastpath_shim.hpp'de tanımlı ve
// scenario_worker ile paylaşılır; burada using ile kısa adla kullanılır.
using samurai::daemon::DpdkMultiQueueGuard;
using samurai::daemon::DpdkShim;
using samurai::daemon::DpdkShimConfig;

// Stateful fast-path job'unu koşar: multi-queue+rte_flow veya tek-kuyruk portu
// açar, tcpdp'yi yapılandırır, L4 connect'leri seed eder, sürücü loop'unu
// (zero-copy rte_mbuf RX + strided bulk TX) çalıştırır ve METRIC_SNAPSHOT +
// JOB_DONE yayınlar. Blast (stateless) yolu değişmeden kalır.
inline void RunDpdkStatefulJob(
    void* pull,
    void* push,
    const samurai::wire::SamuraiWireHeaderV1& header,
    const std::string& job_id,
    const samurai::wire::JobEnvelopeV2& env2,
    int cli_port_id,
    int cli_queue_id,
    int cli_tx_queues,
    const std::string& cli_eal_args,
    samurai::daemon::TelemetrySink& telemetry,
    bool& running_out) {
  const samurai::wire::JobEnvelopeV1& env = env2.base;
  const std::uint16_t port_id = static_cast<std::uint16_t>(std::max(0,
      cli_port_id >= 0 ? cli_port_id
                       : (std::getenv("SAMURAI_DPDK_PORT_ID")
                              ? std::atoi(std::getenv("SAMURAI_DPDK_PORT_ID"))
                              : 0)));
  const std::uint16_t queue_id = static_cast<std::uint16_t>(std::max(0,
      cli_queue_id >= 0 ? cli_queue_id
                        : (std::getenv("SAMURAI_DPDK_QUEUE_ID")
                               ? std::atoi(std::getenv("SAMURAI_DPDK_QUEUE_ID"))
                               : static_cast<int>(env.xdp_queue_id))));
  std::string eal_args = cli_eal_args;
  if (eal_args.empty()) {
    const char* p = std::getenv("SAMURAI_DPDK_EAL_ARGS");
    if (p) eal_args = p;
  }

  std::string err;
  if (!samurai::dpdk::ensure_eal(eal_args, err)) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
    return;
  }

  samurai::daemon::FastpathParams params =
      samurai::daemon::FastpathParamsFromEnvelope(env);
  params.backend = "dpdk";

  const bool l7 = samurai::daemon::JobWantsL7Fastpath(env);

  // Kuyruk sayısını belirle: --dpdk-tx-queues veya SAMURAI_DPDK_TX_QUEUES varsa
  // onu kullan; belirtilmemişse ve açık --dpdk-queue-id verilmemişse donanım
  // eşzamanlılığına göre multi-queue başlat (rte_flow yoksa 1 kuyruğa düşer).
  std::uint16_t requested_queues = 1;
  if (!l7) {
    if (cli_tx_queues > 0) {
      requested_queues = static_cast<std::uint16_t>(cli_tx_queues);
    } else if (const char* tqe = std::getenv("SAMURAI_DPDK_TX_QUEUES")) {
      requested_queues = static_cast<std::uint16_t>(std::max(1, std::atoi(tqe)));
    } else if (cli_queue_id < 0 && env.xdp_queue_id == 0) {
      const unsigned hw = std::thread::hardware_concurrency();
      requested_queues =
          static_cast<std::uint16_t>(std::clamp<unsigned>(hw == 0 ? 1u : hw, 1u, 16u));
    }
  }

  std::atomic<bool> stop{false};
  samurai::daemon::ControlPollState ctrl{};
  samurai::daemon::FastpathHooks hooks;
  hooks.emit_heartbeat = [&]() {
    samurai::daemon::PollControlNonBlocking(
        pull, push, samurai::wire::WorkerKind::DPDK, &telemetry, ctrl);
    if (ctrl.stop_job) {
      stop.store(true, std::memory_order_release);
    }
    if (ctrl.shutdown) {
      running_out = false;
    }
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id);
  };
  hooks.emit_metric = [&](const samurai::wire::MetricSnapshotV2& snap) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                    SerializeSnapshotV2(snap));
  };

  samurai::daemon::L7RunnerBundle l7b;
  samurai::daemon::FastpathResult res;
  std::uint16_t active_queues = 1;

  if (!l7 && requested_queues > 1) {
    DpdkMultiQueueGuard mq_guard;
    if (!samurai::daemon::PrepareDpdkMultiQueueStateful(
            port_id, requested_queues, params.target_flows, eal_args, mq_guard, err)) {
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                      header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                      JsonError(err.empty() ? "dpdk_open_port_failed" : err));
      return;
    }
    active_queues = mq_guard.active_queues;
    if (active_queues > 1) {
      const int base_core = std::getenv("SAMURAI_DPDK_BASE_CORE")
          ? std::atoi(std::getenv("SAMURAI_DPDK_BASE_CORE"))
          : -1;
      samurai::daemon::ShardedFastpathConfig scfg;
      scfg.workers = active_queues;
      scfg.cpu_base = base_core;
      auto factory = [port_id, active_queues, &eal_args](std::uint32_t w)
          -> std::unique_ptr<samurai::daemon::FastpathTxRxShim> {
        DpdkShimConfig cfg;
        cfg.port_id = port_id;
        cfg.queue_id = static_cast<std::uint16_t>(w);
        cfg.num_tx_queues = active_queues;
        cfg.num_rx_queues = active_queues;
        cfg.enable_rss = true;
        cfg.burst_size = 64u;
        cfg.eal_args = eal_args;
        auto shim = std::make_unique<DpdkShim>(cfg);
        if (!shim->ok()) return nullptr;
        return shim;
      };
      samurai::daemon::ShardedFastpathDriver sharded_driver(std::move(factory), scfg);
      res = sharded_driver.Run(params, stop, hooks);
    }
  }

  if (l7 || active_queues <= 1) {
    DpdkShim shim(port_id, queue_id, eal_args);
    if (!shim.ok()) {
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                      header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                      JsonError(shim.open_err.empty() ? "dpdk_open_port_failed" : shim.open_err));
      return;
    }

    samurai::daemon::StatefulFastpathDriver driver(shim);
    if (l7) {
      // L7: run_profile_json (dpdk_direct) kendi connect'lerini açar; SeedL4 yok.
      // tcpdp yapılandırmasını da configure_custom_tcp_bridge yapar; driver.Configure yok.
      l7b = samurai::daemon::MakeL7Runner(env2, "dpdk_direct");
      res = driver.Run(params, l7b.runner, stop, hooks);
    } else {
      // Pure L4: driver tcpdp'yi yapılandırır ve connect'leri seed eder.
      if (!driver.Configure(params, err)) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                        header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
        return;
      }
      driver.SeedL4(params);
      res = driver.Run(params, {}, stop, hooks);
    }
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
  done.set("queues", samurai::core::json::Value::Int(static_cast<int64_t>(active_queues)));
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
                  header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                  std::vector<std::uint8_t>(done_str.begin(), done_str.end()));
}

// Tek bir TX kuyruğuna adanmış worker thread durumu (K4 multi-queue).
struct alignas(64) TxWorkerThread {
  std::thread th;
  std::uint16_t queue_id{0};
  int cpu_core{-1};  // -1 = pinleme yok
  std::atomic<std::uint64_t> packets_sent{0};
  std::atomic<std::uint64_t> packets_errors{0};
  std::atomic<std::uint64_t> bytes_sent{0};
  std::atomic<std::uint64_t> sleep_calls{0};
  std::atomic<bool> done{false};
  std::atomic<bool>* stop_flag{nullptr};
};

// Her TX thread kendi kuyruğuna, kendi paket alt-aralığına ve kendi pacing
// durumuna sahiptir; kuyruklar thread'e özel olduğundan kilit gerekmez.
void tx_thread_func(TxWorkerThread* tw, std::int64_t handle,
                    const std::uint8_t* pool_data, std::size_t pool_len,
                    std::uint64_t bar1_p2p_iova,
                    std::uint16_t stride, int start, int end,
                    samurai_pacing_config_t pace_cfg) {
  if (tw->cpu_core >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(tw->cpu_core, &set);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
  }
  // PMD/mempool güvenliği için thread'i EAL lcore olarak kaydet.
  const bool registered = samurai::dpdk::register_lcore_thread();

  samurai_pacing_state_t st{};
  samurai_pacing_init(&st, &pace_cfg);

  constexpr std::uint16_t kTxBurstMax = 64;
  int i = start;
  while (i < end) {
    if (tw->stop_flag && tw->stop_flag->load(std::memory_order_relaxed)) {
      break;
    }
    samurai_pacing_wait_next(&st, &pace_cfg);
    std::uint16_t batch = static_cast<std::uint16_t>(
        std::min<int>(end - i, static_cast<int>(kTxBurstMax)));

    const std::size_t off = (static_cast<std::size_t>(i) * stride) %
                            std::max<std::size_t>(stride, (pool_len / stride) * stride);
    if (off + static_cast<std::size_t>(batch) * stride > pool_len) {
      const std::size_t avail = pool_len > off ? (pool_len - off) / stride : 0;
      batch = static_cast<std::uint16_t>(std::min<std::size_t>(batch, avail));
    }
    if (batch == 0) {
      break;
    }

    const samurai::dpdk::TxResult r = (bar1_p2p_iova != 0u)
        ? samurai::dpdk::tx_burst_extbuf_zero_copy(
              handle, tw->queue_id, const_cast<std::uint8_t*>(pool_data), bar1_p2p_iova,
              pool_len, off, stride, batch)
        : samurai::dpdk::tx_burst(
              handle, tw->queue_id, pool_data + off, stride, batch);
    tw->packets_sent.fetch_add(r.sent, std::memory_order_relaxed);
    tw->packets_errors.fetch_add(r.errors, std::memory_order_relaxed);
    tw->bytes_sent.fetch_add(r.sent * static_cast<std::uint64_t>(stride),
                             std::memory_order_relaxed);
    i += batch;
  }

  tw->sleep_calls.store(st.sleep_calls, std::memory_order_relaxed);
  tw->done.store(true, std::memory_order_release);
  if (registered) {
    samurai::dpdk::unregister_lcore_thread();
  }
}
#endif

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_port_id = -1;
  int cli_queue_id = -1;
  int cli_tx_queues = -1;
  std::string cli_eal_args;

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
    } else if (arg == "--dpdk-port-id" && i + 1 < argc) {
      cli_port_id = std::stoi(argv[++i]);
    } else if (arg == "--dpdk-queue-id" && i + 1 < argc) {
      cli_queue_id = std::stoi(argv[++i]);
    } else if (arg == "--dpdk-tx-queues" && i + 1 < argc) {
      cli_tx_queues = std::stoi(argv[++i]);
    } else if (arg == "--dpdk-eal-args" && i + 1 < argc) {
      cli_eal_args = argv[++i];
    } else if (arg == "--gpu-p2p") {
      setenv("SAMURAI_DPDK_GPU_P2P", "1", 1);
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
            push, samurai::wire::WorkerKind::DPDK, header, job_id,
            payload_ptr, payload_len, telemetry, running)) {
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      // V1 (blast) veya V2 (stateful/L7 knob'ları) kabul edilir; env V1 tabanıdır ve
      // V2 payload'unda V1 offset 0'da gömülüdür, bu yüzden V1 prefix'i memcpy yeterli.
      const bool env_is_v1 =
          payload_len == sizeof(samurai::wire::JobEnvelopeV1) &&
          header.payload_len == sizeof(samurai::wire::JobEnvelopeV1);
      const bool env_is_v2 =
          payload_len == sizeof(samurai::wire::JobEnvelopeV2) &&
          header.payload_len == sizeof(samurai::wire::JobEnvelopeV2);
      if (!env_is_v1 && !env_is_v2) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                        samurai::wire::WorkerKind::DPDK, job_id, JsonError("job_envelope_size_mismatch"));
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
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id);
      zmq_msg_close(&msg);

#ifndef SAMURAI_WITH_DPDK
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id, JsonError("dpdk_not_built"));
      continue;
#else
      // Stateful userspace TCP fast-path (protocol=custom_tcp / attack_vector=stateful):
      // NIC'i sahiplenip TcpDataplaneCore'u koşar. Stateless blast yolu değişmez.
      if (samurai::daemon::IsStatefulFastpathJob(env)) {
        telemetry.BeginJob();
        RunDpdkStatefulJob(pull, push, header, job_id, env2, cli_port_id, cli_queue_id,
                           cli_tx_queues, cli_eal_args, telemetry, running);
        continue;
      }
      telemetry.BeginJob();
      try {
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const char* gpu_p2p_env = std::getenv("SAMURAI_DPDK_GPU_P2P");
        const bool want_gpu_p2p = (gpu_p2p_env && std::atoi(gpu_p2p_env) != 0);
        DpdkGpuP2pPool gpu_p2p_pool{};
        const bool using_gpu_p2p = want_gpu_p2p && TryGenerateGpuBar1Pool(env, packet_count, gpu_p2p_pool);
        samurai::cpu_native::PacketPoolView cpu_pool{};
        if (!using_gpu_p2p) {
          cpu_pool = samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
        }
        const std::uint8_t* active_pool_data = using_gpu_p2p ? gpu_p2p_pool.data_ptr : cpu_pool.data();
        const std::size_t active_pool_size = using_gpu_p2p ? gpu_p2p_pool.byte_len : cpu_pool.size();
        const std::size_t stride = using_gpu_p2p ? gpu_p2p_pool.packet_size : cpu_pool.packet_size;
        if (stride == 0 || active_pool_size < stride || !active_pool_data) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                          samurai::wire::WorkerKind::DPDK, job_id, JsonError("packet_pool_empty"));
          continue;
        }

        const std::uint16_t port_id = static_cast<std::uint16_t>(std::max(0,
            cli_port_id >= 0 ? cli_port_id
                             : (std::getenv("SAMURAI_DPDK_PORT_ID")
                                    ? std::atoi(std::getenv("SAMURAI_DPDK_PORT_ID"))
                                    : 0)));
        const std::uint16_t queue_id = static_cast<std::uint16_t>(std::max(0,
            cli_queue_id >= 0 ? cli_queue_id : static_cast<int>(env.xdp_queue_id)));
        std::string eal_args = cli_eal_args;
        if (eal_args.empty()) {
          const char* p = std::getenv("SAMURAI_DPDK_EAL_ARGS");
          if (p) eal_args = p;
        }

        std::string eal_args_effective = eal_args;
        std::string err;
        if (!samurai::dpdk::ensure_eal(eal_args_effective, err)) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                          samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
          continue;
        }

        // Kaç TX kuyruğu/thread? CLI/env ile istenir; NIC max_tx_queues ve
        // packet_count ile sınırlanır (K4 multi-queue).
        int requested_queues = cli_tx_queues > 0
            ? cli_tx_queues
            : (std::getenv("SAMURAI_DPDK_TX_QUEUES")
                   ? std::atoi(std::getenv("SAMURAI_DPDK_TX_QUEUES"))
                   : 1);
        if (requested_queues < 1) requested_queues = 1;
        samurai::dpdk::PortCapabilities caps{};
        if (samurai::dpdk::query_capabilities(port_id, caps, err) && caps.max_tx_queues > 0) {
          requested_queues = std::min<int>(requested_queues, static_cast<int>(caps.max_tx_queues));
        }
        requested_queues = std::min<int>(requested_queues, packet_count);
        const int num_queues = std::max(1, requested_queues);
        const bool multi_queue = num_queues > 1;

        // Port aç. Tek-queue'da eski queue_id davranışı korunur (queue_id+1 kuyruk);
        // multi-queue'da 0..N-1 kuyrukları kurulur.
        samurai::dpdk::OpenConfig open_cfg{};
        open_cfg.port_id = port_id;
        open_cfg.num_tx_queues = multi_queue
            ? static_cast<std::uint16_t>(num_queues)
            : static_cast<std::uint16_t>(queue_id + 1);
        open_cfg.num_rx_queues = 0;
        open_cfg.burst_size = 64;
        open_cfg.mempool_size = 8192u;
        open_cfg.eal_args = eal_args_effective;

        DpdkPortGuard dpdk{};
        dpdk.handle = samurai::dpdk::open_port(open_cfg, err);
        if (dpdk.handle < 0) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                          samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
          continue;
        }

        std::uint64_t active_bar1_iova = 0u;
        if (using_gpu_p2p) {
          if (gpu_p2p_pool.bar1_iova == 0u) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::DPDK,
                job_id,
                JsonError("dpdk_gpu_p2p_unverified_bar1_iova"));
            continue;
          }
          std::string extmem_err;
          if (!samurai::dpdk::register_extmem_region(
                  dpdk.handle, gpu_p2p_pool.data_ptr, gpu_p2p_pool.byte_len,
                  gpu_p2p_pool.bar1_iova, 4096u, extmem_err)) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::DPDK,
                job_id,
                JsonError("dpdk_gpu_p2p_dma_map_failed:" + extmem_err));
            continue;
          }
          active_bar1_iova = gpu_p2p_pool.bar1_iova;
        }

        // NUMA pinning guard (O1): CPU çekirdek tabanı env ile verilebilir.
        const int base_core = std::getenv("SAMURAI_DPDK_BASE_CORE")
            ? std::atoi(std::getenv("SAMURAI_DPDK_BASE_CORE")) : -1;
        const int nic_socket = samurai::dpdk::port_socket_id(dpdk.handle);
        if (base_core >= 0 && nic_socket >= 0) {
          samurai::daemon::WorkerLogInfo(
              "dpdk",
              "port " + std::to_string(port_id) + " NUMA node=" + std::to_string(nic_socket) +
                  "; pinning " + std::to_string(num_queues) + " TX thread(s) from core " +
                  std::to_string(base_core) + " (cross-NUMA hint: numactl --cpunodebind=" +
                  std::to_string(nic_socket) + ")");
        }

        // Pacing: snapshot için tam hedef; thread'ler için N'e bölünmüş hedef.
        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_config_t thread_pace = pace_cfg;
        if (multi_queue) {
          if (thread_pace.mode == SAMURAI_PACING_RPS) {
            thread_pace.target_rps = pace_cfg.target_rps / static_cast<double>(num_queues);
          } else if (thread_pace.mode == SAMURAI_PACING_IPG && thread_pace.ipg_ns > 0) {
            thread_pace.ipg_ns = pace_cfg.ipg_ns * static_cast<std::uint64_t>(num_queues);
          } else if (thread_pace.mode == SAMURAI_PACING_BURST && thread_pace.burst_size > 1) {
            thread_pace.burst_size =
                std::max<std::uint32_t>(1u, thread_pace.burst_size / static_cast<std::uint32_t>(num_queues));
          }
        }

        // TX thread'lerini başlat: her biri kendi kuyruğu + paket alt-aralığı.
        std::atomic<bool> stop_threads{false};
        std::deque<TxWorkerThread> workers;
        const int base_packets = packet_count / num_queues;
        const int remainder = packet_count % num_queues;
        int cursor = 0;
        for (int q = 0; q < num_queues; ++q) {
          workers.emplace_back();
          TxWorkerThread& tw = workers.back();
          tw.queue_id = multi_queue ? static_cast<std::uint16_t>(q) : queue_id;
          tw.cpu_core = base_core >= 0 ? base_core + q : -1;
          tw.stop_flag = &stop_threads;
          const int cnt = base_packets + (q < remainder ? 1 : 0);
          const int seg_start = cursor;
          const int seg_end = cursor + cnt;
          cursor = seg_end;
          tw.th = std::thread(tx_thread_func, &tw, dpdk.handle, active_pool_data, active_pool_size,
                              active_bar1_iova, static_cast<std::uint16_t>(stride), seg_start, seg_end, thread_pace);
        }

        auto aggregate = [&workers](std::uint64_t& ps, std::uint64_t& pe,
                                    std::uint64_t& bs, std::uint64_t& sc) {
          ps = pe = bs = sc = 0;
          for (auto& w : workers) {
            ps += w.packets_sent.load(std::memory_order_relaxed);
            pe += w.packets_errors.load(std::memory_order_relaxed);
            bs += w.bytes_sent.load(std::memory_order_relaxed);
            sc += w.sleep_calls.load(std::memory_order_relaxed);
          }
        };

        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        samurai::daemon::ControlPollState ctrl{};

        // Ana thread ilerlemeyi zamana göre yoklar; TX'i thread'ler yapar.
        bool all_done = false;
        while (!all_done) {
          struct timespec ts{0, 50'000'000L};  // 50 ms
          nanosleep(&ts, nullptr);
          samurai::daemon::PollControlNonBlocking(
              pull, push, samurai::wire::WorkerKind::DPDK, &telemetry, ctrl);
          if (ctrl.stop_job) {
            stop_threads.store(true, std::memory_order_release);
          }
          if (ctrl.shutdown) {
            running = false;
          }
          all_done = true;
          for (auto& w : workers) {
            if (!w.done.load(std::memory_order_acquire)) {
              all_done = false;
              break;
            }
          }

          const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
          std::uint64_t ps, pe, bs, sc;
          aggregate(ps, pe, bs, sc);
          if (now_ns - last_hb_ns >= 1'000'000'000ull) {
            (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                            header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id);
            last_hb_ns = now_ns;
          }
          if (now_ns - last_metric_ns >= 2'000'000'000ull) {
            samurai_pacing_state_t agg_state{};
            agg_state.sleep_calls = sc;
            const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
                now_ns, start_ns, ps, pe, bs, pace_cfg, agg_state);
            (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                            header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                            SerializeSnapshot(snap));
            last_metric_ns = now_ns;
            last_hb_ns = now_ns;
          }
        }

        for (auto& w : workers) {
          if (w.th.joinable()) {
            w.th.join();
          }
        }

        std::uint64_t packets_sent, packets_errors, bytes_sent, sleep_calls;
        aggregate(packets_sent, packets_errors, bytes_sent, sleep_calls);

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        samurai::daemon::RecordBatchToTelemetry(
            telemetry, ReadFixed(env.target_ip, sizeof(env.target_ip)), env.target_port,
            ReadFixed(env.protocol, sizeof(env.protocol)), packets_sent,
            static_cast<std::uint32_t>(stride), end_ns);
        telemetry.FlushEnd(end_ns);
        samurai_pacing_state_t final_state{};
        final_state.sleep_calls = sleep_calls;
        const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, final_state);
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                        header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                        SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id, job_id, packets_sent, packets_errors, bytes_sent,
            snap.actual_rps, snap.rate_accuracy_pct,
            ctrl.stop_job ? "aborted" : "done",
            telemetry.JobExportedPackets(), telemetry.JobExportedRecords());
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                        header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id, done);
      } catch (const std::exception& exc) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                        samurai::wire::WorkerKind::DPDK, job_id, JsonError(exc.what()));
      }
      continue;
#endif
    }

    zmq_msg_close(&msg);
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                    samurai::wire::WorkerKind::DPDK, job_id, JsonError("unsupported_msg_type"));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
