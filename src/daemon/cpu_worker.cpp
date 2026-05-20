#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <zmq.h>

#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace {

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_cpu";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_cpu";

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
  if (zmq_msg_init_size(&msg, total) != 0) {
    return -1;
  }
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (!payload.empty()) {
    std::memcpy(p + sizeof(header), payload.data(), payload.size());
  }
  const int rc = zmq_msg_send(&msg, event_socket, 0);
  zmq_msg_close(&msg);
  return rc;
}

std::vector<std::uint8_t> MakeJobDoneJson(std::uint64_t correlation_id, const std::string& job_id) {
  const std::string json =
      "{\"status\":\"ok\",\"worker_kind\":\"cpu\",\"correlation_id\":" +
      std::to_string(correlation_id) +
      ",\"job_id\":\"" + job_id + "\",\"packets_sent\":0,\"packets_errors\":0,\"bytes_sent\":0}";
  return std::vector<std::uint8_t>(json.begin(), json.end());
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--job-endpoint" && i + 1 < argc) {
      jobs_ep = argv[++i];
    } else if (arg == "--event-endpoint" && i + 1 < argc) {
      events_ep = argv[++i];
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

  if (zmq_bind(pull, jobs_ep.c_str()) != 0) {
    std::cerr << "zmq_bind jobs failed: " << jobs_ep << "\n";
    zmq_close(pull);
    zmq_close(push);
    zmq_ctx_term(ctx);
    return 1;
  }
  if (zmq_connect(push, events_ep.c_str()) != 0) {
    std::cerr << "zmq_connect events failed: " << events_ep << "\n";
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

    samurai::wire::SamuraiWireHeaderV1 header{};
    std::memcpy(&header, zmq_msg_data(&msg), sizeof(header));
    zmq_msg_close(&msg);

    if (!samurai::wire::IsHeaderV1Compatible(header)) {
      continue;
    }

    const auto msg_type = static_cast<samurai::wire::MessageType>(header.msg_type);
    const std::string job_id = samurai::daemon::ReadJobId(header);

    if (msg_type == samurai::wire::MessageType::SHUTDOWN) {
      SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                samurai::wire::WorkerKind::CPU, job_id);
      running = false;
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), header.correlation_id,
                samurai::wire::WorkerKind::CPU, job_id);

      samurai::wire::MetricSnapshotV1 snap{};
      snap.timestamp_ns = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count());
      snap.packets_sent = 0;
      snap.packets_errors = 0;
      snap.bytes_sent = 0;
      snap.actual_rps = 0.0;
      snap.jitter_p99_ns = 0.0;
      snap.rate_accuracy_pct = 100.0;
      snap.busywait_cycles = 0;
      snap.sleep_calls = 0;

      std::vector<std::uint8_t> snap_payload(sizeof(snap));
      std::memcpy(snap_payload.data(), &snap, sizeof(snap));
      SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                header.correlation_id, samurai::wire::WorkerKind::CPU, job_id, snap_payload);

      const std::vector<std::uint8_t> done = MakeJobDoneJson(header.correlation_id, job_id);
      SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE), header.correlation_id,
                samurai::wire::WorkerKind::CPU, job_id, done);
      continue;
    }

    std::string err = "{\"status\":\"error\",\"error\":\"unsupported_msg_type\"}";
    SendFrame(
        push,
        static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
        header.correlation_id,
        samurai::wire::WorkerKind::CPU,
        job_id,
        std::vector<std::uint8_t>(err.begin(), err.end()));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
