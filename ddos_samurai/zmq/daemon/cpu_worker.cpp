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

using ddos_samurai::cpu_native::PacketConfig;
using ddos_samurai::cpu_native::SpoofOptions;

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
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
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
        ApplyAffinity(env.pin_cpu);
        PacketConfig cfg = ConfigFromEnvelope(env);
        const int packet_count = std::max(1, static_cast<int>(env.packet_count));
        const auto pool = ddos_samurai::cpu_native::generate_packet_pool_view(cfg, packet_count, true, true);

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        // TASK-WORKER-01: Asynchronous control channel decoupling.
        //
        // Problem: The original synchronous loop starved the ZMQ pull socket,
        // causing ABORT/PAUSE/SHUTDOWN messages to queue up unprocessed until
        // the entire packet generation completed.
        //
        // Solution: Spawn packet generation on a dedicated worker thread while
        // the main thread continuously polls ZMQ for control commands. A shared
        // atomic stop_flag enables sub-5ms abort reaction latency.
        //
        // Relates to #4
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::atomic<bool> stop_flag{false};
        std::atomic<bool> worker_done{false};

        // Shared result state — written only by the worker thread, read after join.
        std::uint64_t packets_sent = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t packets_errors = 0;
        std::string done_note = "done";

        std::thread packet_thread([&]() {
          const std::size_t stride = pool.packet_size;
          if (stride == 0 || pool.size() < stride) {
            packets_errors = static_cast<std::uint64_t>(packet_count);
          } else if (samurai::daemon::AfPacketTxEnabled()) {
            // Real transmission over the af_packet kernel-socket backend.
            const long long ipg_ns =
                (pace_cfg.mode == SAMURAI_PACING_IPG) ? static_cast<long long>(pace_cfg.ipg_ns) : 0;
            const auto tx = samurai::daemon::AfPacketSendPool(
                cfg, pool.data(), pool.size(), static_cast<int>(stride), packet_count, ipg_ns);
            packets_sent = tx.packets_sent;
            packets_errors = tx.packets_errors;
            bytes_sent = tx.bytes_sent;
            done_note = tx.note;
          } else {
            for (int i = 0; i < packet_count; ++i) {
              // Check stop_flag every iteration for responsive abort handling.
              if (stop_flag.load(std::memory_order_relaxed)) {
                done_note = "aborted";
                break;
              }
              samurai_pacing_wait_next(&pace_state, &pace_cfg);
              const std::size_t off = static_cast<std::size_t>(i) * stride;
              if (off + stride > pool.size()) {
                packets_errors += 1u;
                continue;
              }
              packets_sent += 1u;
              bytes_sent += static_cast<std::uint64_t>(stride);
            }
          }
          worker_done.store(true, std::memory_order_release);
        });

        // Main thread: poll ZMQ for ABORT/PAUSE/SHUTDOWN while the worker runs.
        while (!worker_done.load(std::memory_order_acquire)) {
          zmq_msg_t ctrl_msg;
          zmq_msg_init(&ctrl_msg);
          const int ctrl_n = zmq_msg_recv(&ctrl_msg, pull, ZMQ_DONTWAIT);
          if (ctrl_n > 0) {
            const std::size_t ctrl_sz = static_cast<std::size_t>(zmq_msg_size(&ctrl_msg));
            if (ctrl_sz >= sizeof(samurai::wire::SamuraiWireHeaderV1)) {
              samurai::wire::SamuraiWireHeaderV1 ctrl_hdr{};
              std::memcpy(&ctrl_hdr, zmq_msg_data(&ctrl_msg), sizeof(ctrl_hdr));
              if (samurai::wire::IsHeaderV1Compatible(ctrl_hdr)) {
                const auto ctrl_type = static_cast<samurai::wire::MessageType>(ctrl_hdr.msg_type);
                const std::string ctrl_jid = samurai::daemon::ReadJobId(ctrl_hdr);
                if (ctrl_type == samurai::wire::MessageType::SHUTDOWN) {
                  stop_flag.store(true, std::memory_order_release);
                  (void)SendAck(push, ctrl_hdr.correlation_id, ctrl_jid);
                  running = false;  // Exit outer loop after worker joins.
                } else if (ctrl_type == samurai::wire::MessageType::ABORT ||
                           ctrl_type == samurai::wire::MessageType::STOP_JOB) {
                  stop_flag.store(true, std::memory_order_release);
                  (void)SendAck(push, ctrl_hdr.correlation_id, ctrl_jid);
                }
              }
            }
          }
          zmq_msg_close(&ctrl_msg);
          // Brief sleep to avoid busy-spinning while still achieving <5ms latency.
          if (!worker_done.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        }

        // Wait for the packet thread to finish.
        packet_thread.join();

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const double duration_s = std::max(1e-9, static_cast<double>(end_ns - start_ns) / 1e9);
        const double actual_rps = static_cast<double>(packets_sent) / duration_s;
        double rate_accuracy_pct = 100.0;
        if (pace_cfg.mode == SAMURAI_PACING_RPS && pace_cfg.target_rps > 0.0) {
          const double err = std::abs(actual_rps - pace_cfg.target_rps);
          rate_accuracy_pct = std::max(0.0, 100.0 - ((err * 100.0) / pace_cfg.target_rps));
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
        snap.sleep_calls = static_cast<std::uint32_t>(pace_state.sleep_calls & 0xFFFFFFFFu);

        std::vector<std::uint8_t> snap_payload(sizeof(snap));
        std::memcpy(snap_payload.data(), &snap, sizeof(snap));
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::CPU,
            job_id,
            snap_payload);

        const std::vector<std::uint8_t> done = JsonPayloadFromStats(
            header.correlation_id,
            job_id,
            packets_sent,
            packets_errors,
            bytes_sent,
            actual_rps,
            rate_accuracy_pct,
            done_note);
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
