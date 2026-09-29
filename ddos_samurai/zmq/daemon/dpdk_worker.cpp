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

#include <zmq.h>

#include "bridge.hpp"
#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

// DDoSamurai'nin tek native DPDK çekirdeği. Başlık rte_*.h/Python.h içermez;
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

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_dpdk";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_dpdk";





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
using samurai::daemon::DpdkShim;

// Stateful fast-path job'unu koşar: portu açar, tcpdp'yi yapılandırır, L4 connect'leri
// seed eder, ortak sürücü loop'unu çalıştırır ve nihai METRIC_SNAPSHOT + JOB_DONE
// yayınlar. Blast (stateless) yolu değişmeden kalır — bu yalnız stateful branch'tir.
inline void RunDpdkStatefulJob(
    void* push,
    const samurai::wire::SamuraiWireHeaderV1& header,
    const std::string& job_id,
    const samurai::wire::JobEnvelopeV2& env2,
    int cli_port_id,
    int cli_queue_id,
    const std::string& cli_eal_args) {
  const samurai::wire::JobEnvelopeV1& env = env2.base;
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

  std::string err;
  if (!samurai::dpdk::ensure_eal(eal_args, err)) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
    return;
  }

  DpdkShim shim(port_id, queue_id, eal_args);
  if (!shim.ok()) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                    JsonError(shim.open_err.empty() ? "dpdk_open_port_failed" : shim.open_err));
    return;
  }

  samurai::daemon::FastpathParams params =
      samurai::daemon::FastpathParamsFromEnvelope(env);
  params.backend = "dpdk";

  samurai::daemon::StatefulFastpathDriver driver(shim);

  samurai::daemon::FastpathHooks hooks;
  hooks.emit_heartbeat = [&]() {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id);
  };
  hooks.emit_metric = [&](const samurai::wire::MetricSnapshotV2& snap) {
    (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                    header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                    SerializeSnapshotV2(snap));
  };

  std::atomic<bool> stop{false};
  const bool l7 = samurai::daemon::JobWantsL7Fastpath(env);
  samurai::daemon::L7RunnerBundle l7b;
  samurai::daemon::FastpathResult res;
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
};

// Her TX thread kendi kuyruğuna, kendi paket alt-aralığına ve kendi pacing
// durumuna sahiptir; kuyruklar thread'e özel olduğundan kilit gerekmez.
void tx_thread_func(TxWorkerThread* tw, std::int64_t handle,
                    const std::uint8_t* pool_data, std::size_t pool_len,
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
    samurai_pacing_wait_next(&st, &pace_cfg);
    std::uint16_t batch = static_cast<std::uint16_t>(
        std::min<int>(end - i, static_cast<int>(kTxBurstMax)));

    const std::size_t off = static_cast<std::size_t>(i) * stride;
    if (off + static_cast<std::size_t>(batch) * stride > pool_len) {
      const std::size_t avail = pool_len > off ? (pool_len - off) / stride : 0;
      batch = static_cast<std::uint16_t>(std::min<std::size_t>(batch, avail));
    }
    if (batch == 0) {
      break;
    }

    const samurai::dpdk::TxResult r = samurai::dpdk::tx_burst(
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
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id);
      running = false;
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
        RunDpdkStatefulJob(push, header, job_id, env2, cli_port_id, cli_queue_id, cli_eal_args);
        continue;
      }
      try {
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);
        const std::size_t stride = pool.packet_size;
        if (stride == 0 || pool.size() < stride) {
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

        // NUMA pinning guard (O1): CPU çekirdek tabanı env ile verilebilir.
        const int base_core = std::getenv("SAMURAI_DPDK_BASE_CORE")
            ? std::atoi(std::getenv("SAMURAI_DPDK_BASE_CORE")) : -1;
        const int nic_socket = samurai::dpdk::port_socket_id(dpdk.handle);
        if (base_core >= 0 && nic_socket >= 0) {
          std::fprintf(stderr,
              "[dpdk] port %u NUMA node=%d; %d TX thread core %d'den pinlenecek. "
              "Cross-NUMA ise: numactl --cpunodebind=%d\n",
              static_cast<unsigned>(port_id), nic_socket, num_queues, base_core, nic_socket);
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
        std::deque<TxWorkerThread> workers;
        const int base_packets = packet_count / num_queues;
        const int remainder = packet_count % num_queues;
        int cursor = 0;
        for (int q = 0; q < num_queues; ++q) {
          workers.emplace_back();
          TxWorkerThread& tw = workers.back();
          tw.queue_id = multi_queue ? static_cast<std::uint16_t>(q) : queue_id;
          tw.cpu_core = base_core >= 0 ? base_core + q : -1;
          const int cnt = base_packets + (q < remainder ? 1 : 0);
          const int seg_start = cursor;
          const int seg_end = cursor + cnt;
          cursor = seg_end;
          tw.th = std::thread(tx_thread_func, &tw, dpdk.handle, pool.data(), pool.size(),
                              static_cast<std::uint16_t>(stride), seg_start, seg_end, thread_pace);
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

        // Ana thread ilerlemeyi zamana göre yoklar; TX'i thread'ler yapar.
        bool all_done = false;
        while (!all_done) {
          struct timespec ts{0, 50'000'000L};  // 50 ms
          nanosleep(&ts, nullptr);
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
        samurai_pacing_state_t final_state{};
        final_state.sleep_calls = sleep_calls;
        const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, final_state);
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                        header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                        SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id, job_id, packets_sent, packets_errors, bytes_sent,
            snap.actual_rps, snap.rate_accuracy_pct);
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                        header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id, done);
      } catch (const std::exception& exc) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                        samurai::wire::WorkerKind::DPDK, job_id, JsonError(exc.what()));
      }
      continue;
#endif
    }

    if (msg_type == samurai::wire::MessageType::STOP_JOB) {
      zmq_msg_close(&msg);
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id);
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"dpdk\"}";
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id,
                      std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
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
