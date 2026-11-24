#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <cmath>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include <atomic>
#include <mutex>

#include <arpa/inet.h>
#include <sched.h>
#include <zmq.h>

#include "engine.hpp"
#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"
#include "afpacket_tx.hpp"

namespace {
using samurai::daemon::OptionalIntFromWire;
using samurai::daemon::SendFrame;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;

using samurai::cpu_native::PacketConfig;
using samurai::cpu_native::SpoofOptions;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_cpu";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_cpu";



void ApplyAffinity(std::int32_t pin_cpu) {
  if (pin_cpu < 0) {
    return;
  }
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(static_cast<unsigned>(pin_cpu), &cpuset);
  (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

using samurai::daemon::ConfigFromEnvelope;
using samurai::daemon::JsonPayloadFromStats;


int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::CPU, job_id);
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
    samurai::wire::DecodedWireFrame frame{};
    if (!samurai::wire::DecodeWireFrame(zmq_msg_data(&msg), sz, frame)) {
      zmq_msg_close(&msg);
      continue;
    }

    const auto msg_type = static_cast<samurai::wire::MessageType>(frame.msg_type);
    const std::string& job_id = frame.job_id;
    const auto header = frame.as_v1_header;
    const std::size_t payload_len = frame.actual_payload_len;
    const std::uint8_t* payload_ptr = frame.payload_ptr;

    if (msg_type == samurai::wire::MessageType::PING) {
      (void)SendAck(push, frame.correlation_id, job_id);
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::SET_TELEMETRY) {
      const bool ok = samurai::daemon::HandleSetTelemetryFrame(
          payload_ptr, payload_len, telemetry, samurai_pacing_monotonic_now_ns());
      if (ok) {
        (void)SendAck(push, frame.correlation_id, job_id);
      } else {
        (void)SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                        frame.correlation_id, samurai::wire::WorkerKind::CPU, job_id,
                        JsonError("telemetry_config_size_mismatch"));
      }
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::SHUTDOWN) {
      (void)SendAck(push, frame.correlation_id, job_id);
      running = false;
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::STOP_JOB ||
        msg_type == samurai::wire::MessageType::ABORT ||
        msg_type == samurai::wire::MessageType::RECONFIGURE_JOB) {
      (void)SendAck(push, frame.correlation_id, job_id);
      zmq_msg_close(&msg);
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      telemetry.BeginJob();
      samurai::wire::JobEnvelopeV1 env{};
      if (!samurai::daemon::DecodeJobEnvelopeV1Frame(frame, env, &telemetry)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            frame.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            JsonError("job_envelope_size_mismatch"));
        zmq_msg_close(&msg);
        continue;
      }

      const std::uint64_t start_corr = frame.correlation_id;
      (void)SendAck(push, start_corr, job_id);
      zmq_msg_close(&msg);

      try {
        ApplyAffinity(env.pin_cpu);
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);
        const std::uint32_t dst_ip_be = samurai::daemon::TelemetrySink::ParseIpBe(cfg.target_ip);
        const std::uint32_t src_ip_be = htonl(0x0A000001u);
        const std::uint16_t dst_port_be = htons(env.target_port);
        const std::uint8_t flow_proto = samurai::daemon::TelemetrySink::ProtoFromName(cfg.protocol);
        const std::uint8_t flow_tcp_flags = (flow_proto == 6u) ? 0x02u : 0x00u;

        // TASK-WORKER-01: Asynchronous control channel decoupling.
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::atomic<bool> stop_flag{false};
        volatile int c_stop_flag = 0;
        std::atomic<bool> worker_done{false};
        std::mutex reconf_mu;
        std::atomic<bool> reconf_pending{false};
        samurai::wire::ReconfigureWindowV1 pending_reconf{};

        // Shared result state — written only by the worker thread, read after join.
        std::uint64_t packets_sent = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t packets_errors = 0;
        int tx_rc = 0;
        std::string tx_err_msg;
        std::string done_note = "done";

        std::thread packet_thread([&]() {
          const std::size_t stride = pool.packet_size;
          if (stride == 0 || pool.size() < stride) {
            packets_errors = static_cast<std::uint64_t>(packet_count);
            tx_rc = -1;
            tx_err_msg = "invalid_packet_pool_stride";
          } else if (samurai::daemon::AfPacketTxEnabled()) {
            // Real transmission over the af_packet kernel-socket backend.
            const long long ipg_ns =
                (pace_cfg.mode == SAMURAI_PACING_IPG) ? static_cast<long long>(pace_cfg.ipg_ns) : 0;
            const auto tx = samurai::daemon::AfPacketSendPool(
                cfg, pool.data(), pool.size(), static_cast<int>(stride),
                packet_count, ipg_ns, &c_stop_flag);
            packets_sent = tx.packets_sent;
            packets_errors = tx.packets_errors;
            bytes_sent = tx.bytes_sent;
            tx_rc = tx.rc;
            tx_err_msg = tx.error_msg;
            done_note = tx.note;
            if (telemetry.Enabled() && packets_sent > 0) {
              const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
              const std::uint64_t per_pkt = bytes_sent / packets_sent;
              const std::uint64_t limit = std::min<std::uint64_t>(packets_sent, 1024u);
              for (std::uint64_t k = 0; k < limit; ++k) {
                telemetry.RecordPacketNet(
                    src_ip_be, dst_ip_be, htons(static_cast<std::uint16_t>(1024u + (k & 0x3FFu))),
                    dst_port_be, flow_proto, static_cast<std::uint32_t>(per_pkt > 0 ? per_pkt : stride),
                    flow_tcp_flags, 0, now_ns);
              }
            }
          } else {
            packets_errors = static_cast<std::uint64_t>(packet_count);
            tx_rc = -1;
            tx_err_msg = "afpacket_tx_disabled_dry_run_removed";
            done_note = "error";
          }
          worker_done.store(true, std::memory_order_release);
        });

        // Main thread: poll ZMQ for ABORT/RECONFIGURE/SET_TELEMETRY/PING/SHUTDOWN while the worker runs.
        while (!worker_done.load(std::memory_order_acquire)) {
          samurai::daemon::ControlPollState cstate;
          samurai::daemon::PollControlNonBlocking(
              pull, push, samurai::wire::WorkerKind::CPU, &telemetry, cstate);
          if (cstate.stop_job) {
            c_stop_flag = 1;
            stop_flag.store(true, std::memory_order_release);
          }
          if (cstate.shutdown) {
            running = false;  // Exit outer loop after worker joins.
          }
          if (cstate.reconfigure) {
            std::lock_guard<std::mutex> lk(reconf_mu);
            pending_reconf = cstate.reconf;
            reconf_pending.store(true, std::memory_order_release);
          }
          // Brief sleep to avoid busy-spinning while still achieving <5ms latency.
          if (!worker_done.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        }

        // Wait for the packet thread to finish.
        packet_thread.join();

        if (tx_rc != 0) {
          telemetry.FlushEnd(samurai_pacing_monotonic_now_ns());
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::CPU,
              job_id,
              JsonError(tx_err_msg.empty() ? "afpacket_tx_failed" : tx_err_msg));
          continue;
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        telemetry.FlushEnd(end_ns);
        const samurai::wire::MetricSnapshotV1 snap = samurai::daemon::BuildSnapshot(
            end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        const double actual_rps = snap.actual_rps;
        const double rate_accuracy_pct = snap.rate_accuracy_pct;

        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            samurai::daemon::SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            actual_rps,
            rate_accuracy_pct,
            done_note,
            telemetry.JobExportedPackets(),
            telemetry.JobExportedRecords());
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
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
        samurai::wire::WorkerKind::CPU,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
