// samurai_afpacket_worker — kernel-socket data-plane worker.
//
// This backend targets commodity hosts: laptop NICs and any system without
// AF_XDP or DPDK support. It transmits over plain kernel sockets via the native
// af_packet engine (raw AF_INET/SOCK_RAW sendmmsg by default, with SO_TXTIME
// kernel pacing) and can optionally run the stateful RX handshake handler so
// SYN floods complete the TCP 3-way handshake against a live target.
//
// Two run modes, selected by environment (the control-plane sets them per job):
//   - stateless L3 (default): batched sendmmsg flood, reports sent/errors.
//   - stateful L4: SAMURAI_AFPACKET_STATEFUL=1 + SAMURAI_AFPACKET_IFACE=<if>
//     starts the RX_RING handshake handler and seeds the flow-state table.
//
// The RX pump (afpkt_start_rx_pump) is exposed by the af_packet engine for the
// future L7 path (l7_emu_native custom_tcp over a commodity NIC); that pump is
// wired once the engine's custom_tcp external transport lands.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <cmath>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

#include <sched.h>
#include <strings.h>
#include <zmq.h>

extern "C" {
#include "af_packet.h"
}

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

namespace {
using samurai::daemon::SendFrame;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ConfigFromEnvelope;
using samurai::daemon::JsonPayloadFromStats;

using ddos_samurai::cpu_native::PacketConfig;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_afpacket";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_afpacket";
constexpr samurai::wire::WorkerKind kKind = samurai::wire::WorkerKind::AF_PACKET;

void ApplyAffinity(std::int32_t pin_cpu) {
  if (pin_cpu < 0) return;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(static_cast<unsigned>(pin_cpu), &cpuset);
  (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

bool EnvTruthy(const char* name) {
  const char* v = std::getenv(name);
  if (!v || !v[0]) return false;
  return std::strcmp(v, "1") == 0 || ::strcasecmp(v, "true") == 0 ||
         ::strcasecmp(v, "yes") == 0 || ::strcasecmp(v, "on") == 0;
}

int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, kKind, job_id);
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;

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
      (void)SendAck(push, header.correlation_id, job_id);
      running = false;
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id, kKind, job_id, JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }

      samurai::wire::JobEnvelopeV1 env{};
      std::memcpy(&env, payload_ptr, sizeof(env));
      (void)SendAck(push, header.correlation_id, job_id);
      zmq_msg_close(&msg);

      try {
        ApplyAffinity(env.pin_cpu);
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);

        const int packet_size = static_cast<int>(pool.packet_size);
        const samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        // IPG pacing maps to the af_packet SO_TXTIME kernel-paced path; every
        // other mode uses batched sendmmsg for maximum throughput.
        const long long ipg_ns =
            (pace_cfg.mode == SAMURAI_PACING_IPG) ? static_cast<long long>(pace_cfg.ipg_ns) : 0;

        // Run mode.
        const char* iface_env = std::getenv("SAMURAI_AFPACKET_IFACE");
        const std::string iface = iface_env ? iface_env : "";
        const bool stateful = EnvTruthy("SAMURAI_AFPACKET_STATEFUL") && !iface.empty();

        if (stateful) {
          (void)afpkt_configure_state_engine(65536u, 256u, 60u);
          const std::uint16_t window = cfg.window.has_value()
              ? static_cast<std::uint16_t>(*cfg.window) : static_cast<std::uint16_t>(64240);
          const std::uint8_t ttl = cfg.ttl.has_value()
              ? static_cast<std::uint8_t>(*cfg.ttl) : static_cast<std::uint8_t>(64);
          afpkt_set_mimicry_settings(window, static_cast<std::uint16_t>(1460), ttl);
          (void)afpkt_start_rx_handler(iface.c_str());
        }

        char err_msg[128] = {0};
        afpkt_tx_metrics_t metrics{};
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        const int rc = afpkt_send_l3(
            cfg.target_ip.c_str(), cfg.target_port,
            pool.data(), pool.size(), packet_size, packet_count, ipg_ns,
            &metrics, err_msg, sizeof(err_msg));

        afpkt_state_stats_t st{};
        if (stateful) {
          // Seed the flow table from what we transmitted, then let inbound
          // SYN-ACKs complete handshakes before we snapshot and stop the RX.
          (void)afpkt_ingest_tx_packets(pool.data(), pool.size(), packet_size, packet_count);
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
          afpkt_get_state_engine_stats(&st);
          afpkt_stop_rx_handler();
        }
        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();

        const std::uint64_t packets_sent = static_cast<std::uint64_t>(std::max(0, metrics.sent));
        const std::uint64_t packets_errors = static_cast<std::uint64_t>(std::max(0, metrics.errors));
        const std::uint64_t bytes_sent = packets_sent * static_cast<std::uint64_t>(packet_size);
        const double duration_s = std::max(1e-9, static_cast<double>(end_ns - start_ns) / 1e9);
        const double actual_rps = static_cast<double>(packets_sent) / duration_s;
        double rate_accuracy_pct = 100.0;
        if (pace_cfg.mode == SAMURAI_PACING_RPS && pace_cfg.target_rps > 0.0) {
          const double e = std::abs(actual_rps - pace_cfg.target_rps);
          rate_accuracy_pct = std::max(0.0, 100.0 - ((e * 100.0) / pace_cfg.target_rps));
        }

        samurai::wire::MetricSnapshotV1 snap{};
        snap.timestamp_ns = end_ns;
        snap.packets_sent = packets_sent;
        snap.packets_errors = packets_errors;
        snap.bytes_sent = bytes_sent;
        snap.actual_rps = actual_rps;
        snap.jitter_p99_ns = 0.0;
        snap.rate_accuracy_pct = rate_accuracy_pct;
        snap.busywait_cycles = 0;
        snap.sleep_calls = 0;
        std::vector<std::uint8_t> snap_payload(sizeof(snap));
        std::memcpy(snap_payload.data(), &snap, sizeof(snap));
        (void)SendFrame(
            push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id, kKind, job_id, snap_payload);

        std::string note = stateful ? "afpacket:stateful" : "afpacket:l3";
        if (rc != 0 && err_msg[0]) {
          note += " tx_error=";
          note += err_msg;
        }
        if (stateful) {
          note += " state_active=" + std::to_string(st.active_entries) +
                  " state_evictions=" + std::to_string(st.timeout_evictions);
        }

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id, job_id, packets_sent, packets_errors,
            bytes_sent, actual_rps, rate_accuracy_pct, note);
        (void)SendFrame(
            push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id, kKind, job_id, done);
      } catch (const std::exception& exc) {
        afpkt_stop_rx_handler();
        (void)SendFrame(
            push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id, kKind, job_id, JsonError(exc.what()));
      }
      continue;
    }

    zmq_msg_close(&msg);
    (void)SendFrame(
        push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
        header.correlation_id, kKind, job_id, JsonError("unsupported_msg_type"));
  }

  afpkt_cleanup_ring();
  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
