#include "supervisor.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include <zmq.h>

#include "json.hpp"
#include "run_summary.hpp"
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
    std::size_t payload_len,
    std::uint8_t version = samurai::wire::kVersionV1) {
  const auto header = samurai::daemon::MakeHeaderV(
      version,
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

// Fold the L7 defense-reaction signals out of the worker's JOB_DONE detail into
// the run stats. The HTTP status breakdown (429/403/503 = the SUT's WAF /
// rate-limiter / overload pushback) lives only in the emu engine_result JSON,
// not the binary metric snapshot, so without this the corpus would carry no
// defense signal. `detail` is the JOB_DONE payload: {..,"engine_result":{..}}.
void FoldEngineDefense(RunStats& acc, const char* detail, std::size_t len) {
  using samurai::core::json::Value;
  const auto parsed = samurai::core::json::Parse(std::string(detail, len));
  if (!parsed.ok || !parsed.value.is_object()) return;
  const Value* er = parsed.value.find("engine_result");
  if (er == nullptr || !er->is_object()) return;
  auto u64 = [&](const char* k, std::uint64_t& dst) {
    if (const Value* v = er->find(k)) dst = static_cast<std::uint64_t>(std::max<double>(0.0, v->as_double(0.0)));
  };
  auto gauge = [&](const char* k, double& dst) {
    if (const Value* v = er->find(k)) dst = v->as_double(0.0);
  };
  u64("responses_total", acc.responses_total);
  u64("status_2xx", acc.status_2xx);
  u64("status_3xx", acc.status_3xx);
  u64("status_4xx", acc.status_4xx);
  u64("status_5xx", acc.status_5xx);
  u64("l7_conn_attempted", acc.l7_conn_attempted);
  u64("l7_conn_established", acc.l7_conn_established);
  u64("l7_expectation_failures", acc.l7_expectation_failures);
  u64("l7_scheduler_backpressure_count", acc.l7_scheduler_backpressure_count);
  u64("h2_goaway_count", acc.h2_goaway_count);
  gauge("h2_stream_reset_ratio", acc.h2_stream_reset_ratio);
  gauge("l7_request_latency_p99_ms", acc.l7_request_latency_p99_ms);
  gauge("l7_tls_handshake_p99_ms", acc.l7_tls_handshake_p99_ms);
}

}  // namespace

int RunJob(const SupervisorConfig& cfg, const JobOptions& job, RunStats& out_stats) {
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

  std::uint8_t envelope_version = samurai::wire::kVersionV1;
  const std::uint8_t* envelope_ptr = nullptr;
  std::size_t envelope_size = 0;
  // Per-call locals: must not be static — each RunJob needs a fresh envelope.
  samurai::wire::JobEnvelopeV2 env_v2{};
  samurai::wire::JobEnvelopeV1 env_v1{};
  if (cfg.worker.kind == samurai::wire::WorkerKind::L7) {
    env_v2 = BuildJobEnvelopeV2(job);
    envelope_version = samurai::wire::kVersionV2;
    envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_v2);
    envelope_size = sizeof(env_v2);
  } else {
    env_v1 = BuildJobEnvelope(job);
    envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_v1);
    envelope_size = sizeof(env_v1);
  }

  (void)SendWire(
      jobs,
      MessageType::START_JOB,
      correlation_id,
      cfg.worker.kind,
      job_id,
      envelope_ptr,
      envelope_size,
      envelope_version);

  int idle = 0;
  bool done = false;
  int status_out = 0;
  RunStats& stats = out_stats;
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
            if (plen >= sizeof(samurai::wire::MetricSnapshotV2)) {
              samurai::wire::MetricSnapshotV2 s2{};
              std::memcpy(&s2, pl, sizeof(s2));
              AccumulateSnapshotV2(stats, s2);
              PrintSnapshot(s2.base);
            } else if (plen >= sizeof(samurai::wire::MetricSnapshotV1)) {
              samurai::wire::MetricSnapshotV1 s{};
              std::memcpy(&s, pl, sizeof(s));
              AccumulateSnapshot(stats, s);
              PrintSnapshot(s);
            }
            break;
          case MessageType::JOB_DONE:
            if (plen > 0) {
              // Worker'ın JOB_DONE payload'ı (ör. scenario_backend, scenario_sla_passed,
              // scenario_steps_est) artık yüzeye çıkarılıyor.
              std::printf("{\"event\":\"job_done\",\"detail\":%.*s}\n",
                          static_cast<int>(plen), reinterpret_cast<const char*>(pl));
              // Surface the L7 defense-reaction signals for the RL corpus.
              FoldEngineDefense(stats, reinterpret_cast<const char*>(pl), plen);
            } else {
              std::printf("{\"event\":\"job_done\"}\n");
            }
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

  RecomputeLoss(stats);
  std::printf("%s\n", SummaryJson(stats).c_str());

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
