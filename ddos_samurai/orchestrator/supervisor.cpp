#include "supervisor.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include <zmq.h>

#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace samurai::orchestrator {

namespace {

using samurai::wire::MessageType;

// Serializes a wire header + optional payload and pushes it on `sock`.
int SendWire(
    void* sock,
    MessageType type,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind kind,
    const std::string& job_id,
    const std::uint8_t* payload,
    std::size_t payload_len) {
  const auto header = samurai::daemon::MakeHeader(
      static_cast<std::uint8_t>(type),
      static_cast<std::uint32_t>(payload_len),
      correlation_id,
      kind,
      job_id);
  const std::size_t total = sizeof(header) + payload_len;
  zmq_msg_t msg;
  if (zmq_msg_init_size(&msg, total) != 0) {
    return -1;
  }
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (payload_len > 0 && payload != nullptr) {
    std::memcpy(p + sizeof(header), payload, payload_len);
  }
  const int rc = zmq_msg_send(&msg, sock, 0);
  zmq_msg_close(&msg);
  return rc;
}

// fork/exec the worker binary, wiring its jobs/events endpoints. The worker
// binds the jobs (PULL) endpoint and connects the events (PUSH) endpoint by
// default, which mirrors the supervisor's connect(jobs)/bind(events) below.
pid_t SpawnWorker(const SupervisorConfig& cfg) {
  const std::string path = cfg.worker_dir + "/" + cfg.worker.binary;
  const pid_t pid = fork();
  if (pid == 0) {
    execl(
        path.c_str(),
        cfg.worker.binary,
        "--job-endpoint", cfg.jobs_endpoint.c_str(),
        "--event-endpoint", cfg.events_endpoint.c_str(),
        static_cast<char*>(nullptr));
    std::fprintf(stderr, "orchestrator: exec failed for %s\n", path.c_str());
    _exit(127);
  }
  return pid;
}

void PrintSnapshot(const samurai::wire::MetricSnapshotV1& s) {
  std::printf(
      "{\"event\":\"metric_snapshot\",\"packets_sent\":%llu,\"packets_errors\":%llu,"
      "\"bytes_sent\":%llu,\"actual_rps\":%.2f,\"rate_accuracy_pct\":%.2f}\n",
      static_cast<unsigned long long>(s.packets_sent),
      static_cast<unsigned long long>(s.packets_errors),
      static_cast<unsigned long long>(s.bytes_sent),
      s.actual_rps,
      s.rate_accuracy_pct);
}

}  // namespace

int RunJob(const SupervisorConfig& cfg, const JobOptions& job) {
  void* ctx = zmq_ctx_new();
  if (ctx == nullptr) {
    std::fprintf(stderr, "orchestrator: zmq_ctx_new failed\n");
    return -1;
  }

  void* events = zmq_socket(ctx, ZMQ_PULL);
  void* jobs = zmq_socket(ctx, ZMQ_PUSH);
  if (events == nullptr || jobs == nullptr) {
    std::fprintf(stderr, "orchestrator: zmq_socket failed\n");
    if (events != nullptr) zmq_close(events);
    if (jobs != nullptr) zmq_close(jobs);
    zmq_ctx_term(ctx);
    return -1;
  }
  zmq_setsockopt(events, ZMQ_RCVTIMEO, &cfg.recv_timeout_ms, sizeof(cfg.recv_timeout_ms));

  if (zmq_bind(events, cfg.events_endpoint.c_str()) != 0) {
    std::fprintf(stderr, "orchestrator: bind(events) failed: %s\n", cfg.events_endpoint.c_str());
    zmq_close(events);
    zmq_close(jobs);
    zmq_ctx_term(ctx);
    return -1;
  }

  const pid_t pid = SpawnWorker(cfg);
  if (pid < 0) {
    std::fprintf(stderr, "orchestrator: fork failed\n");
    zmq_close(events);
    zmq_close(jobs);
    zmq_ctx_term(ctx);
    return -1;
  }

  if (zmq_connect(jobs, cfg.jobs_endpoint.c_str()) != 0) {
    std::fprintf(stderr, "orchestrator: connect(jobs) failed: %s\n", cfg.jobs_endpoint.c_str());
    zmq_close(events);
    zmq_close(jobs);
    zmq_ctx_term(ctx);
    return -1;
  }

  const std::string job_id = "cli-job";
  const std::uint64_t correlation_id = 1;
  const samurai::wire::JobEnvelopeV1 env = BuildJobEnvelope(job);

  (void)SendWire(
      jobs,
      MessageType::START_JOB,
      correlation_id,
      cfg.worker.kind,
      job_id,
      reinterpret_cast<const std::uint8_t*>(&env),
      sizeof(env));

  int idle = 0;
  bool done = false;
  int status_out = 0;
  while (!done && idle < cfg.max_idle_recvs) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    const int n = zmq_msg_recv(&msg, events, 0);
    if (n < 0) {
      zmq_msg_close(&msg);
      ++idle;
      continue;
    }
    idle = 0;

    const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
    if (sz >= sizeof(samurai::wire::SamuraiWireHeaderV1)) {
      samurai::wire::SamuraiWireHeaderV1 h{};
      std::memcpy(&h, zmq_msg_data(&msg), sizeof(h));
      const auto* pl = static_cast<const std::uint8_t*>(zmq_msg_data(&msg)) + sizeof(h);
      const std::size_t plen = sz - sizeof(h);
      if (samurai::wire::IsHeaderV1Compatible(h)) {
        switch (static_cast<MessageType>(h.msg_type)) {
          case MessageType::METRIC_SNAPSHOT:
            if (plen >= sizeof(samurai::wire::MetricSnapshotV1)) {
              samurai::wire::MetricSnapshotV1 s{};
              std::memcpy(&s, pl, sizeof(s));
              PrintSnapshot(s);
            }
            break;
          case MessageType::JOB_DONE:
            std::printf("{\"event\":\"job_done\"}\n");
            done = true;
            break;
          case MessageType::ERROR:
            std::printf("{\"event\":\"error\",\"detail\":\"%.*s\"}\n",
                        static_cast<int>(plen), reinterpret_cast<const char*>(pl));
            status_out = 1;
            done = true;
            break;
          default:
            break;
        }
      }
    }
    zmq_msg_close(&msg);
  }

  (void)SendWire(jobs, MessageType::SHUTDOWN, correlation_id, cfg.worker.kind, job_id, nullptr, 0);

  int wstatus = 0;
  waitpid(pid, &wstatus, 0);

  zmq_close(events);
  zmq_close(jobs);
  zmq_ctx_term(ctx);

  if (status_out != 0) {
    return status_out;
  }
  return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
}

}  // namespace samurai::orchestrator
