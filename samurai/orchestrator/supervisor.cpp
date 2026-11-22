#include "supervisor.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <zmq.h>

#include "json.hpp"
#include "log.hpp"
#include "run_summary.hpp"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"

namespace samurai::orchestrator {

struct WarmWorkerPool::Slot {
  samurai::wire::WorkerKind kind{samurai::wire::WorkerKind::CPU};
  std::string worker_binary;
  std::string worker_dir;
  std::string jobs_endpoint;
  std::string events_endpoint;
  void* zmq_ctx = nullptr;
  void* jobs_sock = nullptr;
  void* events_sock = nullptr;
  pid_t pid = -1;
  bool busy = false;
  bool retire_on_release = false;
  bool telemetry_configured = false;
  bool last_ipfix_enabled = false;
  std::uint64_t next_corr_id = 1;
  std::string active_shard_id;
  std::mutex reconf_mu;
  std::vector<samurai::wire::ReconfigureWindowV1> pending_reconf;
};

namespace {

using samurai::wire::MessageType;

bool EnvWarmWorkersEnabled() {
  const char* raw = std::getenv("SAMURAI_WARM_WORKERS");
  if (raw == nullptr || raw[0] == '\0') return true;
  std::string s(raw);
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return !(s == "0" || s == "false" || s == "no" || s == "off");
}

void UnlinkIpcEndpoint(const std::string& endpoint) {
  static constexpr const char kPrefix[] = "ipc://";
  if (endpoint.rfind(kPrefix, 0) == 0 && endpoint.size() > sizeof(kPrefix) - 1) {
    ::unlink(endpoint.substr(sizeof(kPrefix) - 1).c_str());
  }
}

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

int SendWireV3(
    void* sock,
    MessageType type,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind kind,
    const std::string& job_id,
    const std::uint8_t* payload,
    std::size_t payload_len,
    std::uint8_t ext_count = 0) {
  const auto header = samurai::daemon::MakeHeaderV3(
      static_cast<std::uint8_t>(type),
      static_cast<std::uint32_t>(payload_len),
      correlation_id,
      kind,
      job_id,
      ext_count);
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

// Resolve a worker binary path. Checks the explicit `worker_dir` first, then
// (when using the default ".") probes next to the running executable
// (/proc/self/exe -> /usr/local/bin in containers, or build/cli -> ../zmq and
// build/control/daemon -> ../../zmq in source builds), then ./build/zmq.
// Returns an empty string if no direct path is executable, signalling the
// caller to fall back to PATH lookup via execvp().
std::string ResolveWorkerPath(const std::string& worker_dir, const std::string& binary) {
  auto is_exec = [](const std::string& p) -> bool {
    return !p.empty() && ::access(p.c_str(), X_OK) == 0;
  };

  if (!worker_dir.empty()) {
    const std::string direct = worker_dir + "/" + binary;
    if (is_exec(direct)) return direct;
  }

  if (worker_dir.empty() || worker_dir == ".") {
    char exe_buf[4096] = {0};
    const ssize_t len = ::readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if (len > 0) {
      std::string exe_path(exe_buf, static_cast<std::size_t>(len));
      const std::size_t slash = exe_path.find_last_of('/');
      if (slash != std::string::npos) {
        const std::string exe_dir = exe_path.substr(0, slash);
        const std::string candidates[] = {
            exe_dir + "/" + binary,
            exe_dir + "/../zmq/" + binary,
            exe_dir + "/../../zmq/" + binary,
        };
        for (const auto& c : candidates) {
          if (is_exec(c)) return c;
        }
      }
    }
    const std::string build_cand = "build/zmq/" + binary;
    if (is_exec(build_cand)) return build_cand;
  }

  return "";
}

// fork/exec the worker binary, wiring its jobs/events endpoints. The worker
// binds the jobs (PULL) endpoint and connects the events (PUSH) endpoint by
// default, which mirrors the supervisor's connect(jobs)/bind(events) below.
pid_t SpawnWorker(
    const std::string& worker_dir,
    const std::string& binary,
    const std::string& jobs_endpoint,
    const std::string& events_endpoint) {
  const std::string resolved = ResolveWorkerPath(worker_dir, binary);
  const pid_t pid = fork();
  if (pid == 0) {
    if (!resolved.empty()) {
      execl(
          resolved.c_str(),
          binary.c_str(),
          "--job-endpoint", jobs_endpoint.c_str(),
          "--event-endpoint", events_endpoint.c_str(),
          static_cast<char*>(nullptr));
      std::fprintf(stderr, "orchestrator: exec failed for %s\n", resolved.c_str());
    } else if (worker_dir.empty() || worker_dir == ".") {
      execlp(
          binary.c_str(),
          binary.c_str(),
          "--job-endpoint", jobs_endpoint.c_str(),
          "--event-endpoint", events_endpoint.c_str(),
          static_cast<char*>(nullptr));
      std::fprintf(
          stderr,
          "orchestrator: exec failed for %s (not found in %s, exe dir, build/zmq, or PATH)\n",
          binary.c_str(),
          worker_dir.c_str());
    } else {
      const std::string path = worker_dir + "/" + binary;
      execl(
          path.c_str(),
          binary.c_str(),
          "--job-endpoint", jobs_endpoint.c_str(),
          "--event-endpoint", events_endpoint.c_str(),
          static_cast<char*>(nullptr));
      std::fprintf(stderr, "orchestrator: exec failed for %s\n", path.c_str());
    }
    _exit(127);
  }
  return pid;
}

void DrainEvents(void* events_sock) {
  if (!events_sock) return;
  zmq_msg_t msg;
  zmq_msg_init(&msg);
  while (zmq_msg_recv(&msg, events_sock, ZMQ_DONTWAIT) >= 0) {
    zmq_msg_close(&msg);
    zmq_msg_init(&msg);
  }
  zmq_msg_close(&msg);
}

bool PingWarmWorker(
    void* jobs_sock,
    void* events_sock,
    samurai::wire::WorkerKind kind,
    const std::string& job_id,
    std::uint64_t corr_id,
    int timeout_ms) {
  if (!jobs_sock || !events_sock) return false;
  DrainEvents(events_sock);
  if (SendWire(jobs_sock, MessageType::PING, corr_id, kind, job_id, nullptr, 0) < 0) {
    return false;
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    const auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now())
                            .count();
    zmq_pollitem_t item{events_sock, 0, ZMQ_POLLIN, 0};
    const int prc = zmq_poll(&item, 1, static_cast<long>(std::max<long long>(1, rem_ms)));
    if (prc <= 0) {
      if (prc < 0 && errno == EINTR) continue;
      return false;
    }
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    if (zmq_msg_recv(&msg, events_sock, ZMQ_DONTWAIT) >= 0) {
      const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
      samurai::wire::DecodedWireFrame frm{};
      if (samurai::wire::DecodeWireFrame(zmq_msg_data(&msg), sz, frm) &&
          static_cast<MessageType>(frm.msg_type) == MessageType::ACK &&
          frm.correlation_id == corr_id) {
        zmq_msg_close(&msg);
        return true;
      }
      zmq_msg_close(&msg);
    } else {
      zmq_msg_close(&msg);
    }
  }
  return false;
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

OutputMode ResolveOutputMode(OutputMode requested) {
  if (requested != OutputMode::kAuto) return requested;
  if (const char* env = std::getenv("SAMURAI_OUTPUT_FORMAT"); env && env[0] != '\0') {
    std::string s(env);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s == "pretty") return OutputMode::kPretty;
    if (s == "ndjson" || s == "json") return OutputMode::kNdjson;
    if (s == "quiet") return OutputMode::kQuiet;
  }
  return (::isatty(STDOUT_FILENO) == 1) ? OutputMode::kPretty : OutputMode::kNdjson;
}

std::string FormatBytes(std::uint64_t bytes) {
  char buf[64];
  if (bytes < 1024ULL) {
    std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
  } else if (bytes < 1024ULL * 1024ULL) {
    std::snprintf(buf, sizeof(buf), "%.2f KiB", static_cast<double>(bytes) / 1024.0);
  } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
    std::snprintf(buf, sizeof(buf), "%.2f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
  } else {
    std::snprintf(buf, sizeof(buf), "%.2f GiB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
  }
  return std::string(buf);
}

void PrintPrettySnapshot(const samurai::wire::MetricSnapshotV1& s) {
  const std::string tx = FormatBytes(s.bytes_sent);
  std::printf("[samurai] progress  | sent=%llu  err=%llu  rps=%.2f  acc=%.2f%%  tx=%s\n",
              static_cast<unsigned long long>(s.packets_sent),
              static_cast<unsigned long long>(s.packets_errors),
              s.actual_rps,
              s.rate_accuracy_pct,
              tx.c_str());
}

void PrintPrettySummary(const SupervisorConfig& cfg,
                        const JobOptions& job,
                        const RunStats& s,
                        int status_out) {
  const std::string tx = FormatBytes(s.bytes_sent);
  std::printf(
      "\nSamurai Run Summary (%s)\n"
      "--------------------------------------------------\n"
      "  Target            : %s:%u (%s / %s)\n"
      "  Status            : %s\n"
      "  Packets           : attempted=%llu  sent=%llu  errors=%llu\n"
      "  Throughput        : %.2f RPS (accuracy %.2f%%)  |  TX=%s\n"
      "  Wire Loss Est     : %llu pkt (%.4f%%)\n",
      cfg.worker.name,
      job.target_ip.c_str(),
      static_cast<unsigned>(job.target_port),
      job.protocol.c_str(),
      job.attack_vector.c_str(),
      status_out == 0 ? "OK" : "ERROR",
      static_cast<unsigned long long>(s.attempted),
      static_cast<unsigned long long>(s.sent),
      static_cast<unsigned long long>(s.errors),
      s.actual_rps,
      s.rate_accuracy_pct,
      tx.c_str(),
      static_cast<unsigned long long>(s.wire_loss_est_packets),
      s.wire_loss_est_pct);

  if (s.ipfix_exported_packets > 0 || s.ipfix_exported_records > 0) {
    std::printf("  IPFIX Telemetry   : exported_packets=%llu  exported_records=%llu\n",
                static_cast<unsigned long long>(s.ipfix_exported_packets),
                static_cast<unsigned long long>(s.ipfix_exported_records));
  }
  if (s.telco_active_sessions > 0 || s.telco_established_sessions > 0 || s.telco_failed_sessions > 0) {
    std::printf("  Telco Telemetry   : active=%llu  established=%llu  failed=%llu  cps=%u  p99=%u us\n",
                static_cast<unsigned long long>(s.telco_active_sessions),
                static_cast<unsigned long long>(s.telco_established_sessions),
                static_cast<unsigned long long>(s.telco_failed_sessions),
                s.telco_current_cps,
                s.telco_p99_setup_latency_us);
  }
  if (cfg.worker.kind != samurai::wire::WorkerKind::TELCO &&
      (s.tls_handshakes_completed > 0 || s.dns_queries_sent > 0 || s.l7_conn_attempted > 0 || s.responses_total > 0)) {
    std::printf("  L7 Telemetry      : conn=%llu/%llu  responses=%llu (2xx=%llu 4xx=%llu 5xx=%llu)  tls=%llu  dns=%llu\n",
                static_cast<unsigned long long>(s.l7_conn_established),
                static_cast<unsigned long long>(s.l7_conn_attempted),
                static_cast<unsigned long long>(s.responses_total),
                static_cast<unsigned long long>(s.status_2xx),
                static_cast<unsigned long long>(s.status_4xx),
                static_cast<unsigned long long>(s.status_5xx),
                static_cast<unsigned long long>(s.tls_handshakes_completed),
                static_cast<unsigned long long>(s.dns_queries_sent));
  }
  std::printf("--------------------------------------------------\n");
}

// Folds L7 defense-reaction signals, IPFIX export totals, and Telco
// control/user-plane telemetry out of the worker's JOB_DONE JSON payload into
// RunStats. `detail` is `{..,"engine_result":{..},"ipfix_exported_packets":..}`.
void FoldJobDonePayload(RunStats& acc, const char* detail, std::size_t len) {
  using samurai::core::json::Value;
  const auto parsed = samurai::core::json::Parse(std::string(detail, len));
  if (!parsed.ok || !parsed.value.is_object()) return;

  const Value& root = parsed.value;
  const Value* er = root.find("engine_result");
  const Value* telco_obj = root.find("telco_telemetry");

  auto read_u64_any = [&](const char* k, std::uint64_t& dst) {
    if (const Value* v = root.find(k)) {
      dst = static_cast<std::uint64_t>(std::max<double>(0.0, v->as_double(0.0)));
      return;
    }
    if (telco_obj && telco_obj->is_object()) {
      if (const Value* v = telco_obj->find(k)) {
        dst = static_cast<std::uint64_t>(std::max<double>(0.0, v->as_double(0.0)));
        return;
      }
    }
    if (er && er->is_object()) {
      if (const Value* v = er->find(k)) {
        dst = static_cast<std::uint64_t>(std::max<double>(0.0, v->as_double(0.0)));
      }
    }
  };
  auto read_u32_any = [&](const char* k, std::uint32_t& dst) {
    std::uint64_t tmp = dst;
    read_u64_any(k, tmp);
    dst = static_cast<std::uint32_t>(tmp);
  };

  // IPFIX / NetFlow export totals (top-level or nested)
  read_u64_any("ipfix_exported_packets", acc.ipfix_exported_packets);
  read_u64_any("ipfix_exported_records", acc.ipfix_exported_records);

  // Telco control & user plane telemetry
  read_u64_any("telco_active_sessions", acc.telco_active_sessions);
  read_u64_any("telco_established_sessions", acc.telco_established_sessions);
  read_u64_any("telco_failed_sessions", acc.telco_failed_sessions);
  read_u32_any("telco_current_cps", acc.telco_current_cps);
  read_u32_any("telco_avg_setup_latency_us", acc.telco_avg_setup_latency_us);
  read_u32_any("telco_p99_setup_latency_us", acc.telco_p99_setup_latency_us);
  read_u64_any("telco_retransmit_count", acc.telco_retransmit_count);

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
  // Flow / connection-level defense signals (userspace TCP stack only).
  u64("tcp_peer_rst_count", acc.tcp_peer_rst_count);
  u64("tcp_connect_timeout_count", acc.tcp_connect_timeout_count);
  u64("tcp_retransmit_count", acc.tcp_retransmit_count);
  u64("tcp_timeout_close_count", acc.tcp_timeout_close_count);
}

void WaitOrKillPid(pid_t pid, bool had_clean_shutdown, bool force_kill) {
  if (pid <= 0) return;
  int wstatus = 0;
  if (had_clean_shutdown && !force_kill) {
    for (int i = 0; i < 20; ++i) {
      const pid_t w = waitpid(pid, &wstatus, WNOHANG);
      if (w == pid || w < 0) return;
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
  }
  ::kill(pid, SIGTERM);
  for (int i = 0; i < 16; ++i) {
    const pid_t w = waitpid(pid, &wstatus, WNOHANG);
    if (w == pid || w < 0) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  ::kill(pid, SIGKILL);
  waitpid(pid, &wstatus, 0);
}

}  // namespace

WarmWorkerPool::WarmWorkerPool() {
  enabled_.store(EnvWarmWorkersEnabled());
}

WarmWorkerPool::~WarmWorkerPool() {
  ShutdownAll();
}

void WarmWorkerPool::DestroySlot(const std::shared_ptr<Slot>& slot, bool send_shutdown, bool force_kill) {
  if (!slot) return;
  bool sent_shutdown = false;
  if (send_shutdown && slot->jobs_sock && slot->pid > 0) {
    sent_shutdown =
        (SendWire(slot->jobs_sock,
                  MessageType::SHUTDOWN,
                  slot->next_corr_id++,
                  slot->kind,
                  slot->active_shard_id.empty() ? std::string("warm-shutdown") : slot->active_shard_id,
                  nullptr,
                  0) >= 0);
  }
  if (slot->pid > 0) {
    WaitOrKillPid(slot->pid, sent_shutdown, force_kill);
    slot->pid = -1;
  }
  if (slot->events_sock) {
    zmq_close(slot->events_sock);
    slot->events_sock = nullptr;
  }
  if (slot->jobs_sock) {
    zmq_close(slot->jobs_sock);
    slot->jobs_sock = nullptr;
  }
  if (slot->zmq_ctx) {
    zmq_ctx_term(slot->zmq_ctx);
    slot->zmq_ctx = nullptr;
  }
  UnlinkIpcEndpoint(slot->jobs_endpoint);
  UnlinkIpcEndpoint(slot->events_endpoint);
}

void WarmWorkerPool::ShutdownAll() {
  shutting_down_.store(true);
  std::vector<std::shared_ptr<Slot>> to_destroy;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = slots_.begin(); it != slots_.end();) {
      if ((*it)->busy) {
        (*it)->retire_on_release = true;
        ++it;
      } else {
        to_destroy.push_back(*it);
        it = slots_.erase(it);
      }
    }
  }
  for (auto& s : to_destroy) {
    DestroySlot(s, /*send_shutdown=*/true, /*force_kill=*/false);
  }
}

std::shared_ptr<WarmWorkerPool::Slot> WarmWorkerPool::AcquireSlot(
    const SupervisorConfig& cfg,
    const std::string& shard_id,
    bool& out_reused) {
  out_reused = false;
  if (shutting_down_.load()) return nullptr;

  while (!shutting_down_.load()) {
    std::shared_ptr<Slot> candidate;
    {
      std::lock_guard<std::mutex> lk(mu_);
      for (const auto& s : slots_) {
        if (!s->busy && !s->retire_on_release &&
            s->kind == cfg.worker.kind && s->worker_dir == cfg.worker_dir) {
          s->busy = true;
          s->active_shard_id = shard_id;
          {
            std::lock_guard<std::mutex> rlk(s->reconf_mu);
            s->pending_reconf.clear();
          }
          candidate = s;
          break;
        }
      }
    }

    if (!candidate) {
      break;
    }

    int wst = 0;
    const pid_t wp = (candidate->pid > 0) ? waitpid(candidate->pid, &wst, WNOHANG) : -1;
    if (wp == 0 && PingWarmWorker(candidate->jobs_sock,
                                  candidate->events_sock,
                                  cfg.worker.kind,
                                  shard_id.empty() ? std::string("ping") : shard_id,
                                  candidate->next_corr_id++,
                                  1000)) {
      reuse_count_.fetch_add(1);
      out_reused = true;
      return candidate;
    }

    // Candidate exited unexpectedly or did not respond to PING -> evict & retry.
    if (wp != 0) candidate->pid = -1;
    {
      std::lock_guard<std::mutex> lk(mu_);
      slots_.erase(std::remove(slots_.begin(), slots_.end(), candidate), slots_.end());
    }
    DestroySlot(candidate, /*send_shutdown=*/false, /*force_kill=*/true);
  }

  if (shutting_down_.load()) return nullptr;

  auto slot = std::make_shared<Slot>();
  slot->kind = cfg.worker.kind;
  slot->worker_binary = cfg.worker.binary;
  slot->worker_dir = cfg.worker_dir;
  slot->busy = true;
  slot->active_shard_id = shard_id;
  const std::uint64_t seq = next_slot_seq_.fetch_add(1);
  const std::string ep_tag = std::to_string(static_cast<long>(::getpid())) + "_" + std::to_string(seq);
  slot->jobs_endpoint = "ipc:///tmp/samurai_warm_" + ep_tag + "_jobs";
  slot->events_endpoint = "ipc:///tmp/samurai_warm_" + ep_tag + "_events";
  UnlinkIpcEndpoint(slot->jobs_endpoint);
  UnlinkIpcEndpoint(slot->events_endpoint);

  slot->zmq_ctx = zmq_ctx_new();
  if (!slot->zmq_ctx) {
    return nullptr;
  }
  slot->events_sock = zmq_socket(slot->zmq_ctx, ZMQ_PULL);
  slot->jobs_sock = zmq_socket(slot->zmq_ctx, ZMQ_PUSH);
  if (!slot->events_sock || !slot->jobs_sock) {
    DestroySlot(slot, false, false);
    return nullptr;
  }
  int linger = 200;
  zmq_setsockopt(slot->jobs_sock, ZMQ_LINGER, &linger, sizeof(linger));
  zmq_setsockopt(slot->events_sock, ZMQ_LINGER, &linger, sizeof(linger));
  zmq_setsockopt(slot->events_sock, ZMQ_RCVTIMEO, &cfg.recv_timeout_ms, sizeof(cfg.recv_timeout_ms));

  if (zmq_bind(slot->events_sock, slot->events_endpoint.c_str()) != 0) {
    std::fprintf(stderr, "orchestrator: warm bind(events) failed: %s\n", slot->events_endpoint.c_str());
    DestroySlot(slot, false, false);
    return nullptr;
  }

  slot->pid = SpawnWorker(slot->worker_dir, slot->worker_binary, slot->jobs_endpoint, slot->events_endpoint);
  if (slot->pid < 0) {
    std::fprintf(stderr, "orchestrator: fork failed\n");
    DestroySlot(slot, false, false);
    return nullptr;
  }

  if (zmq_connect(slot->jobs_sock, slot->jobs_endpoint.c_str()) != 0) {
    std::fprintf(stderr, "orchestrator: warm connect(jobs) failed: %s\n", slot->jobs_endpoint.c_str());
    DestroySlot(slot, false, true);
    return nullptr;
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    if (shutting_down_.load()) {
      DestroySlot(slot, true, false);
      return nullptr;
    }
    slots_.push_back(slot);
  }
  spawn_count_.fetch_add(1);
  out_reused = false;
  return slot;
}

void WarmWorkerPool::ReleaseSlot(const std::shared_ptr<Slot>& slot, bool keep_warm) {
  if (!slot) return;
  bool retire = !keep_warm || shutting_down_.load() || slot->retire_on_release || slot->pid <= 0;
  if (!retire) {
    int wst = 0;
    const pid_t w = waitpid(slot->pid, &wst, WNOHANG);
    if (w != 0) {
      slot->pid = -1;
      retire = true;
    }
  }

  if (retire) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      slots_.erase(std::remove(slots_.begin(), slots_.end(), slot), slots_.end());
    }
    DestroySlot(slot, /*send_shutdown=*/keep_warm, /*force_kill=*/!keep_warm);
    return;
  }

  DrainEvents(slot->events_sock);
  bool destroy_after = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    slot->active_shard_id.clear();
    slot->busy = false;
    {
      std::lock_guard<std::mutex> rlk(slot->reconf_mu);
      slot->pending_reconf.clear();
    }
    if (shutting_down_.load() || slot->retire_on_release) {
      slots_.erase(std::remove(slots_.begin(), slots_.end(), slot), slots_.end());
      destroy_after = true;
    }
  }
  if (destroy_after) {
    DestroySlot(slot, /*send_shutdown=*/true, /*force_kill=*/false);
  }
}

bool WarmWorkerPool::ReconfigureActiveShard(
    const std::string& shard_id,
    const samurai::wire::ReconfigureWindowV1& window) {
  if (shard_id.empty()) return false;
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& s : slots_) {
    if (s->busy && s->active_shard_id == shard_id) {
      std::lock_guard<std::mutex> rlk(s->reconf_mu);
      s->pending_reconf.push_back(window);
      return true;
    }
  }
  return false;
}

std::size_t WarmWorkerPool::WarmSlotCount() const {
  std::lock_guard<std::mutex> lk(mu_);
  return slots_.size();
}

std::size_t WarmWorkerPool::ActiveSlotCount() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::size_t n = 0;
  for (const auto& s : slots_) {
    if (s->busy) ++n;
  }
  return n;
}

long WarmWorkerPool::LastWorkerPid(samurai::wire::WorkerKind kind) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (auto it = slots_.rbegin(); it != slots_.rend(); ++it) {
    if ((*it)->kind == kind && (*it)->pid > 0) {
      return static_cast<long>((*it)->pid);
    }
  }
  return -1;
}

int RunJob(const SupervisorConfig& cfg,
           const JobOptions& job,
           RunStats& out_stats,
           WarmWorkerPool* pool,
           std::atomic<bool>* cancel_requested,
           const std::string& shard_id) {
  const bool use_pool =
      (pool != nullptr) &&
      pool->Enabled() &&
      (cfg.worker.kind != samurai::wire::WorkerKind::DEFENSE);

  void* oneshot_ctx = nullptr;
  void* oneshot_events = nullptr;
  void* oneshot_jobs = nullptr;
  pid_t oneshot_pid = -1;

  std::shared_ptr<WarmWorkerPool::Slot> slot;
  bool reused = false;
  if (use_pool) {
    slot = pool->AcquireSlot(cfg, shard_id, reused);
    if (!slot) {
      std::fprintf(stderr, "orchestrator: unable to acquire warm worker slot\n");
      return -1;
    }
  } else {
    oneshot_ctx = zmq_ctx_new();
    if (oneshot_ctx == nullptr) {
      std::fprintf(stderr, "orchestrator: zmq_ctx_new failed\n");
      return -1;
    }
    oneshot_events = zmq_socket(oneshot_ctx, ZMQ_PULL);
    oneshot_jobs = zmq_socket(oneshot_ctx, ZMQ_PUSH);
    if (oneshot_events == nullptr || oneshot_jobs == nullptr) {
      std::fprintf(stderr, "orchestrator: zmq_socket failed\n");
      if (oneshot_events != nullptr) zmq_close(oneshot_events);
      if (oneshot_jobs != nullptr) zmq_close(oneshot_jobs);
      zmq_ctx_term(oneshot_ctx);
      return -1;
    }
    int linger = 200;
    zmq_setsockopt(oneshot_jobs, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_setsockopt(oneshot_events, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_setsockopt(oneshot_events, ZMQ_RCVTIMEO, &cfg.recv_timeout_ms, sizeof(cfg.recv_timeout_ms));

    if (zmq_bind(oneshot_events, cfg.events_endpoint.c_str()) != 0) {
      std::fprintf(stderr, "orchestrator: bind(events) failed: %s\n", cfg.events_endpoint.c_str());
      zmq_close(oneshot_events);
      zmq_close(oneshot_jobs);
      zmq_ctx_term(oneshot_ctx);
      return -1;
    }

    oneshot_pid = SpawnWorker(cfg.worker_dir, cfg.worker.binary, cfg.jobs_endpoint, cfg.events_endpoint);
    if (oneshot_pid < 0) {
      std::fprintf(stderr, "orchestrator: fork failed\n");
      zmq_close(oneshot_events);
      zmq_close(oneshot_jobs);
      zmq_ctx_term(oneshot_ctx);
      return -1;
    }

    if (zmq_connect(oneshot_jobs, cfg.jobs_endpoint.c_str()) != 0) {
      std::fprintf(stderr, "orchestrator: connect(jobs) failed: %s\n", cfg.jobs_endpoint.c_str());
      WaitOrKillPid(oneshot_pid, false, true);
      zmq_close(oneshot_events);
      zmq_close(oneshot_jobs);
      zmq_ctx_term(oneshot_ctx);
      return -1;
    }
  }

  void* events = use_pool ? slot->events_sock : oneshot_events;
  void* jobs = use_pool ? slot->jobs_sock : oneshot_jobs;
  const std::string job_id = shard_id.empty() ? std::string("cli-job") : shard_id;
  std::uint64_t next_corr = use_pool ? slot->next_corr_id : 1;
  const bool send_v3 =
      cfg.use_wire_v3 && cfg.worker.kind != samurai::wire::WorkerKind::DEFENSE;

  auto send_msg = [&](MessageType mtype,
                      const std::uint8_t* payload,
                      std::size_t plen,
                      std::uint8_t legacy_ver = samurai::wire::kVersionV1) {
    if (send_v3) {
      return SendWireV3(jobs, mtype, next_corr++, cfg.worker.kind, job_id, payload, plen, 0);
    }
    return SendWire(jobs, mtype, next_corr++, cfg.worker.kind, job_id, payload, plen, legacy_ver);
  };

  // Propagate telemetry config before START_JOB whenever enabled, or when a
  // warm slot previously had IPFIX enabled and now switches it off.
  if (cfg.worker.kind != samurai::wire::WorkerKind::DEFENSE &&
      (job.ipfix_enabled || (slot && slot->telemetry_configured && slot->last_ipfix_enabled))) {
    const samurai::wire::TelemetryConfigV1 tcfg = BuildTelemetryConfig(job);
    (void)send_msg(
        MessageType::SET_TELEMETRY,
        reinterpret_cast<const std::uint8_t*>(&tcfg),
        sizeof(tcfg));
    if (slot) {
      slot->telemetry_configured = true;
      slot->last_ipfix_enabled = job.ipfix_enabled;
    }
  }

  if (send_v3) {
    samurai::wire::JobV3Payload v3{};
    if (cfg.worker.kind == samurai::wire::WorkerKind::L7) {
      samurai::wire::FromJobEnvelopeV2(BuildJobEnvelopeV2(job), v3.base, v3.l7);
      v3.has_l7 = true;
    } else if (cfg.worker.kind == samurai::wire::WorkerKind::TELCO) {
      samurai::wire::FromTelcoJobEnvelopeV1(BuildTelcoJobEnvelope(job), v3.base, v3.telco);
      v3.has_telco = true;
    } else if (cfg.worker.kind == samurai::wire::WorkerKind::GPU &&
               IsTelcoGtpuProtocol(job.protocol)) {
      samurai::wire::FromTelcoGpuJobEnvelopeV1(BuildTelcoGpuJobEnvelope(job), v3.base, v3.telco);
      v3.has_telco = true;
    } else {
      v3.base = samurai::wire::FromJobEnvelopeV1(BuildJobEnvelope(job));
    }
    if (job.ipfix_enabled) {
      const samurai::wire::TelemetryConfigV1 tcfg = BuildTelemetryConfig(job);
      v3.has_telemetry = true;
      v3.telemetry.enabled = tcfg.enabled;
      v3.telemetry.netflow_v9 = tcfg.netflow_v9;
      v3.telemetry.collector_port = tcfg.collector_port;
      v3.telemetry.sample_rate = tcfg.sample_rate;
      v3.telemetry.domain_id = tcfg.domain_id;
      v3.telemetry.export_interval_ms = tcfg.export_interval_ms;
      std::memcpy(v3.telemetry.collector_ip, tcfg.collector_ip, sizeof(v3.telemetry.collector_ip));
    }
    std::uint8_t ext_count = 0;
    const std::vector<std::uint8_t> v3_bytes = samurai::wire::SerializeJobV3Payload(v3, &ext_count);
    (void)SendWireV3(
        jobs,
        MessageType::START_JOB,
        next_corr++,
        cfg.worker.kind,
        job_id,
        v3_bytes.data(),
        v3_bytes.size(),
        ext_count);
  } else {
    std::uint8_t envelope_version = samurai::wire::kVersionV1;
    const std::uint8_t* envelope_ptr = nullptr;
    std::size_t envelope_size = 0;
    // Per-call locals: must not be static — each RunJob needs a fresh envelope.
    samurai::wire::JobEnvelopeV2 env_v2{};
    samurai::wire::JobEnvelopeV1 env_v1{};
    samurai::wire::TelcoGpuJobEnvelopeV1 env_telco_gpu{};
    samurai::wire::TelcoJobEnvelopeV1 env_telco{};
    if (cfg.worker.kind == samurai::wire::WorkerKind::L7) {
      env_v2 = BuildJobEnvelopeV2(job);
      envelope_version = samurai::wire::kVersionV2;
      envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_v2);
      envelope_size = sizeof(env_v2);
    } else if (cfg.worker.kind == samurai::wire::WorkerKind::TELCO) {
      env_telco = BuildTelcoJobEnvelope(job);
      envelope_version = samurai::wire::kVersionV1;
      envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_telco);
      envelope_size = sizeof(env_telco);
    } else if (cfg.worker.kind == samurai::wire::WorkerKind::GPU &&
               IsTelcoGtpuProtocol(job.protocol)) {
      env_telco_gpu = BuildTelcoGpuJobEnvelope(job);
      envelope_version = samurai::wire::kVersionV1;
      envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_telco_gpu);
      envelope_size = sizeof(env_telco_gpu);
    } else {
      env_v1 = BuildJobEnvelope(job);
      envelope_ptr = reinterpret_cast<const std::uint8_t*>(&env_v1);
      envelope_size = sizeof(env_v1);
    }

    (void)SendWire(
        jobs,
        MessageType::START_JOB,
        next_corr++,
        cfg.worker.kind,
        job_id,
        envelope_ptr,
        envelope_size,
        envelope_version);
  }

  const std::int64_t total_budget_ms =
      static_cast<std::int64_t>(std::max(100, cfg.recv_timeout_ms)) *
      static_cast<std::int64_t>(std::max(1, cfg.max_idle_recvs));
  const int poll_slice_ms = std::min(50, std::max(10, cfg.recv_timeout_ms));

  const OutputMode out_mode = ResolveOutputMode(cfg.output_mode);
  if (out_mode == OutputMode::kPretty) {
    std::printf("[samurai] job start | worker=%s  target=%s:%u  proto=%s  count=%u  rps=%.0f\n",
                cfg.worker.name,
                job.target_ip.c_str(),
                static_cast<unsigned>(job.target_port),
                job.protocol.c_str(),
                job.packet_count,
                job.target_rps);
  }

  bool done = false;
  bool timed_out = false;
  bool cancel_sent = false;
  bool keep_warm = true;
  int status_out = 0;
  std::chrono::steady_clock::time_point cancel_deadline{};
  auto last_activity = std::chrono::steady_clock::now();
  RunStats& stats = out_stats;

  while (!done) {
    if (cancel_requested && cancel_requested->load()) {
      if (!cancel_sent) {
        (void)send_msg(MessageType::STOP_JOB, nullptr, 0);
        cancel_sent = true;
        cancel_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
      } else if (std::chrono::steady_clock::now() >= cancel_deadline) {
        (void)send_msg(MessageType::ABORT, nullptr, 0);
        keep_warm = false;
        status_out = -15;
        break;
      }
    }

    if (slot) {
      std::vector<samurai::wire::ReconfigureWindowV1> queued;
      {
        std::lock_guard<std::mutex> rlk(slot->reconf_mu);
        if (!slot->pending_reconf.empty()) {
          queued.swap(slot->pending_reconf);
        }
      }
      for (const auto& rw : queued) {
        (void)send_msg(
            MessageType::RECONFIGURE_JOB,
            reinterpret_cast<const std::uint8_t*>(&rw),
            sizeof(rw));
      }
    }

    zmq_pollitem_t pitem{events, 0, ZMQ_POLLIN, 0};
    const int prc = zmq_poll(&pitem, 1, poll_slice_ms);
    if (prc < 0) {
      if (errno == EINTR) continue;
      keep_warm = false;
      status_out = -1;
      break;
    }

    if (prc == 0) {
      const auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - last_activity)
                               .count();
      if (idle_ms >= total_budget_ms) {
        timed_out = true;
        keep_warm = false;
        if (use_pool) status_out = -2;
        break;
      }
      continue;
    }

    while (!done) {
      zmq_msg_t msg;
      zmq_msg_init(&msg);
      const int n = zmq_msg_recv(&msg, events, ZMQ_DONTWAIT);
      if (n < 0) {
        zmq_msg_close(&msg);
        break;
      }
      last_activity = std::chrono::steady_clock::now();

      const std::size_t sz = static_cast<std::size_t>(zmq_msg_size(&msg));
      samurai::wire::DecodedWireFrame frm{};
      if (samurai::wire::DecodeWireFrame(zmq_msg_data(&msg), sz, frm)) {
        const auto* pl = frm.payload_ptr;
        const std::size_t plen = frm.actual_payload_len;
        switch (static_cast<MessageType>(frm.msg_type)) {
          case MessageType::METRIC_SNAPSHOT:
            if (plen >= sizeof(samurai::wire::MetricSnapshotV2)) {
              samurai::wire::MetricSnapshotV2 s2{};
              std::memcpy(&s2, pl, sizeof(s2));
              AccumulateSnapshotV2(stats, s2);
              if (out_mode == OutputMode::kNdjson) {
                PrintSnapshot(s2.base);
              } else if (out_mode == OutputMode::kPretty) {
                PrintPrettySnapshot(s2.base);
              }
            } else if (plen >= sizeof(samurai::wire::MetricSnapshotV1)) {
              samurai::wire::MetricSnapshotV1 s{};
              std::memcpy(&s, pl, sizeof(s));
              AccumulateSnapshot(stats, s);
              if (out_mode == OutputMode::kNdjson) {
                PrintSnapshot(s);
              } else if (out_mode == OutputMode::kPretty) {
                PrintPrettySnapshot(s);
              }
            }
            break;
          case MessageType::JOB_DONE:
            if (plen > 0) {
              if (out_mode == OutputMode::kNdjson) {
                std::printf("{\"event\":\"job_done\",\"detail\":%.*s}\n",
                            static_cast<int>(plen), reinterpret_cast<const char*>(pl));
              }
              FoldJobDonePayload(stats, reinterpret_cast<const char*>(pl), plen);
            } else if (out_mode == OutputMode::kNdjson) {
              std::printf("{\"event\":\"job_done\"}\n");
            }
            done = true;
            break;
          case MessageType::ERROR:
            if (out_mode == OutputMode::kNdjson) {
              std::printf("{\"event\":\"error\",\"detail\":\"%.*s\"}\n",
                          static_cast<int>(plen), reinterpret_cast<const char*>(pl));
            } else {
              samurai::core::LogTagged(
                  "orchestrator",
                  samurai::core::LogLevel::kError,
                  std::string(reinterpret_cast<const char*>(pl), plen));
            }
            status_out = 1;
            done = true;
            break;
          default:
            break;
        }
      }
      zmq_msg_close(&msg);
    }
  }

  RecomputeLoss(stats);
  if (out_mode == OutputMode::kNdjson) {
    std::printf("%s\n", SummaryJson(stats).c_str());
  } else if (out_mode == OutputMode::kPretty) {
    PrintPrettySummary(cfg, job, stats, status_out);
  }

  if (cancel_sent && status_out == 0) {
    status_out = -15;
  }

  if (use_pool) {
    slot->next_corr_id = next_corr;
    pool->ReleaseSlot(slot, keep_warm && !timed_out);
    return status_out;
  }

  const bool clean_shutdown =
      !timed_out && !cancel_sent &&
      (send_msg(MessageType::SHUTDOWN, nullptr, 0) >= 0);

  int wstatus = 0;
  if (clean_shutdown) {
    waitpid(oneshot_pid, &wstatus, 0);
  } else {
    WaitOrKillPid(oneshot_pid, false, cancel_sent || timed_out);
  }

  zmq_close(events);
  zmq_close(jobs);
  zmq_ctx_term(oneshot_ctx);

  if (status_out != 0) {
    return status_out;
  }
  return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
}

}  // namespace samurai::orchestrator
