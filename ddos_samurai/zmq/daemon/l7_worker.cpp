#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zmq.h>

#include "pacing_engine.h"
#include "wire_protocol.h"
#include "zmq_worker_base.hpp"
#include "worker_common.hpp"

#include "bridge.hpp"
#include "json.hpp"

namespace {
using samurai::daemon::SendFrame;
using samurai::daemon::BuildSnapshot;
using samurai::daemon::JsonError;
using samurai::daemon::PacingFromEnvelope;
using samurai::daemon::ReadFixed;
using samurai::daemon::SerializeSnapshot;

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_l7";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_l7";


std::string ToLower(std::string v) {
  for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return v;
}



int SendAck(void* push, std::uint64_t cid, const std::string& job_id) {
  return SendFrame(push, static_cast<std::uint8_t>(samurai::wire::MessageType::ACK), cid, samurai::wire::WorkerKind::L7, job_id);
}




std::vector<std::uint8_t> JsonDone(
    std::uint64_t correlation_id,
    const std::string& job_id,
    const std::string& protocol,
    std::uint64_t packets_sent,
    std::uint64_t packets_errors,
    std::uint64_t bytes_sent,
    std::uint64_t bytes_recv,
    std::uint64_t scenario_payload_bytes,
    double actual_rps,
    double rate_accuracy_pct) {
  std::ostringstream oss;
  oss
      << "{\"status\":\"ok\",\"worker_kind\":\"l7\""
      << ",\"correlation_id\":" << correlation_id
      << ",\"job_id\":\"" << job_id << "\""
      << ",\"l7_protocol\":\"" << protocol << "\""
      << ",\"packets_sent\":" << packets_sent
      << ",\"packets_errors\":" << packets_errors
      << ",\"bytes_sent\":" << bytes_sent
      << ",\"bytes_recv\":" << bytes_recv
      << ",\"scenario_payload_bytes\":" << scenario_payload_bytes
      << ",\"actual_rps\":" << actual_rps
      << ",\"rate_accuracy_pct\":" << rate_accuracy_pct
      << ",\"note\":\"l7_tcp_native+pacing_static\"}";
  const std::string s = oss.str();
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> JsonDoneEmu(
    std::uint64_t correlation_id,
    const std::string& job_id,
    const std::string& protocol,
    const std::string& result_json) {
  std::ostringstream oss;
  oss << "{\"status\":\"ok\",\"worker_kind\":\"l7\""
      << ",\"correlation_id\":" << correlation_id
      << ",\"job_id\":\"" << job_id << "\""
      << ",\"l7_protocol\":\"" << protocol << "\""
      << ",\"engine\":\"l7_emu_native_bridge\""
      << ",\"engine_result\":" << result_json << "}";
  const std::string s = oss.str();
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

bool ReadFileBytes(const std::string& path, std::vector<std::uint8_t>& out, std::string& err) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    err = "payload_ref_read_failed";
    return false;
  }
  f.seekg(0, std::ios::end);
  const std::streamoff sz = f.tellg();
  if (sz < 0) {
    err = "payload_ref_stat_failed";
    return false;
  }
  f.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(sz));
  if (!out.empty() && !f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()))) {
    err = "payload_ref_read_failed";
    return false;
  }
  return true;
}

std::vector<std::uint8_t> BuildDefaultRequest(const samurai::wire::JobEnvelopeV1& env, const std::string& protocol_lc) {
  const std::string host = ReadFixed(env.target_ip, sizeof(env.target_ip));
  if (protocol_lc == "http2" || protocol_lc == "h2") {
    static constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    return std::vector<std::uint8_t>(kH2Preface, kH2Preface + sizeof(kH2Preface) - 1);
  }
  if (protocol_lc == "http1" || protocol_lc == "http" || protocol_lc == "https") {
    std::string req = "GET / HTTP/1.1\r\nHost: " + (host.empty() ? std::string("localhost") : host) +
                      "\r\nUser-Agent: samurai-l7-worker\r\nConnection: close\r\n\r\n";
    return std::vector<std::uint8_t>(req.begin(), req.end());
  }
  static constexpr char kCustomMsg[] = "samurai-l7\n";
  return std::vector<std::uint8_t>(kCustomMsg, kCustomMsg + sizeof(kCustomMsg) - 1);
}

bool SetSocketTimeoutMs(int fd, int timeout_ms) {
  const timeval tv{
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
         setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

bool ConnectWithTimeout(const std::string& target, int port, int timeout_ms, int& out_fd, std::string& err) {
  out_fd = -1;
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_ADDRCONFIG;

  addrinfo* res = nullptr;
  const std::string port_s = std::to_string(port);
  const int gai_rc = getaddrinfo(target.c_str(), port_s.c_str(), &hints, &res);
  if (gai_rc != 0 || !res) {
    err = "l7_resolve_failed";
    return false;
  }

  bool ok = false;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    const int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;

    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
      close(fd);
      continue;
    }

    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
      (void)fcntl(fd, F_SETFL, flags);
      out_fd = fd;
      ok = true;
      break;
    }

    if (errno == EINPROGRESS) {
      pollfd pfd{};
      pfd.fd = fd;
      pfd.events = POLLOUT;
      const int prc = poll(&pfd, 1, timeout_ms);
      if (prc > 0) {
        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) == 0 && so_err == 0) {
          (void)fcntl(fd, F_SETFL, flags);
          out_fd = fd;
          ok = true;
          break;
        }
      }
    }

    close(fd);
  }
  freeaddrinfo(res);
  if (!ok) {
    err = "l7_connect_failed";
    return false;
  }
  if (!SetSocketTimeoutMs(out_fd, timeout_ms)) {
    close(out_fd);
    out_fd = -1;
    err = "l7_set_socket_timeout_failed";
    return false;
  }
  return true;
}

bool SendAll(int fd, const std::uint8_t* data, std::size_t len) {
  std::size_t off = 0;
  while (off < len) {
    const ssize_t n = send(fd, data + off, len - off, 0);
    if (n <= 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

std::uint64_t RecvSome(int fd) {
  std::array<std::uint8_t, 4096> buf{};
  const ssize_t n = recv(fd, buf.data(), buf.size(), 0);
  return n > 0 ? static_cast<std::uint64_t>(n) : 0u;
}

}  // namespace

int main(int argc, char** argv) {
  std::string jobs_ep = kDefaultJobs;
  std::string events_ep = kDefaultEvents;
  bool bind_jobs = true;
  bool bind_events = false;
  int connect_timeout_ms = 2000;

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
    } else if (arg == "--connect-timeout-ms" && i + 1 < argc) {
      connect_timeout_ms = std::max(50, std::stoi(argv[++i]));
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

    if (msg_type == samurai::wire::MessageType::STOP_JOB) {
      zmq_msg_close(&msg);
      (void)SendAck(push, header.correlation_id, job_id);
      const std::string stopped = "{\"status\":\"stopped\",\"worker_kind\":\"l7\"}";
      (void)SendFrame(
          push,
          static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
          header.correlation_id,
          samurai::wire::WorkerKind::L7,
          job_id,
          std::vector<std::uint8_t>(stopped.begin(), stopped.end()));
      continue;
    }

    if (msg_type == samurai::wire::MessageType::START_JOB) {
      if (payload_len != sizeof(samurai::wire::JobEnvelopeV1) || header.payload_len != sizeof(samurai::wire::JobEnvelopeV1)) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::L7,
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
        const std::string target = ReadFixed(env.target_ip, sizeof(env.target_ip));
        const int port = static_cast<int>(env.target_port);
        if (target.empty()) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::L7,
              job_id,
              JsonError("target_required"));
          continue;
        }
        if (port <= 0 || port > 65535) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::L7,
              job_id,
              JsonError("target_port_invalid"));
          continue;
        }

        const std::string protocol = ReadFixed(env.protocol, sizeof(env.protocol));
        const std::string protocol_lc = ToLower(protocol.empty() ? std::string("http1") : protocol);
        const std::string scenario_ref = ReadFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref));
        const bool use_l7_emu =
            protocol_lc == "quic" || protocol_lc == "h3" || protocol_lc == "http3" || !scenario_ref.empty();

        std::vector<std::uint8_t> request_payload;
        const std::string payload_ref = ReadFixed(env.payload_ref, sizeof(env.payload_ref));
        if (env.has_payload != 0u && !payload_ref.empty()) {
          std::string payload_err;
          if (!ReadFileBytes(payload_ref, request_payload, payload_err)) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                JsonError(payload_err));
            continue;
          }
        } else {
          request_payload = BuildDefaultRequest(env, protocol_lc);
        }
        if (request_payload.empty()) {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::L7,
              job_id,
              JsonError("l7_payload_empty"));
          continue;
        }

        std::uint64_t scenario_payload_bytes = 0;
        std::vector<std::uint8_t> scenario_content;
        if (!scenario_ref.empty()) {
          std::string scenario_read_err;
          if (!ReadFileBytes(scenario_ref, scenario_content, scenario_read_err)) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                JsonError(scenario_read_err));
            continue;
          }
          scenario_payload_bytes = static_cast<std::uint64_t>(scenario_content.size());
        }

        if (use_l7_emu) {
          try {
            using samurai::core::json::Parse;
            using samurai::core::json::ParseResult;
            using samurai::core::json::Value;
            Value profile = Value::Object();
            if (!scenario_content.empty()) {
              const std::string scenario_text(
                  reinterpret_cast<const char*>(scenario_content.data()), scenario_content.size());
              const ParseResult pr = Parse(scenario_text);
              if (pr.ok && pr.value.is_object()) profile = pr.value;
            }
            if (profile.find("target_ip") == nullptr || profile.find("protocol") == nullptr) {
              Value p = Value::Object();
              p.set("protocol", Value::Str(protocol_lc == "h3" ? "quic" : protocol_lc));
              p.set("target_ip", Value::Str(target));
              p.set("target_port", Value::Int(port));
              p.set("scheme", Value::Str(
                  (protocol_lc == "https" || protocol_lc == "quic" || protocol_lc == "h3" || protocol_lc == "http3")
                      ? "https" : "http"));
              p.set("host_header", Value::Str(target));
              p.set("verify", Value::Int(0));
              p.set("keepalive", Value::Int(0));
              p.set("timeout_ms", Value::Int(5000));
              p.set("max_connections", Value::Int(1));
              p.set("max_streams_per_connection", Value::Int(1));
              p.set("session_repeats", Value::Int(std::max(1, static_cast<int>(env.packet_count))));
              for (const auto& kv : profile.members()) p.set(kv.first, kv.second);
              profile = p;
            }
            if (profile.find("ops") == nullptr && !request_payload.empty()) {
              Value op = Value::Object();
              op.set("opcode", Value::Str("http_request"));
              op.set("method", Value::Str("GET"));
              op.set("path", Value::Str("/"));
              Value body = Value::Object();
              body.set("kind", Value::Str("raw"));
              Value body_bytes = Value::Array();
              for (const std::uint8_t b : request_payload) body_bytes.push_back(Value::Int(static_cast<std::int64_t>(b)));
              body.set("bytes", body_bytes);
              op.set("body", body);
              Value ops = Value::Array();
              ops.push_back(op);
              profile.set("ops", ops);
            }
            Value cfg = Value::Object();
            cfg.set("concurrency", Value::Int(1));
            cfg.set("profile_l7", Value::Int(1));
            cfg.set("profile_sample_limit", Value::Int(0));
            const Value emu_result = ddos_samurai::l7_emu_native::run_profile_json(profile, cfg);
            const std::vector<std::uint8_t> emu_done = JsonDoneEmu(
                header.correlation_id, job_id, protocol_lc, emu_result.dump());
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                emu_done);
            continue;
          } catch (const std::exception& exc) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                JsonError(std::string("l7_emu_profile_failed:") + exc.what()));
            continue;
          }
        }

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(env);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const int request_count = std::max(1, static_cast<int>(env.packet_count));
        const std::uint64_t start_ns = samurai_pacing_monotonic_now_ns();
        std::uint64_t last_hb_ns = start_ns;
        std::uint64_t last_metric_ns = start_ns;
        std::uint64_t packets_sent = 0;
        std::uint64_t packets_errors = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_recv = 0;

        for (int i = 0; i < request_count; ++i) {
          samurai_pacing_wait_next(&pace_state, &pace_cfg);

          int fd = -1;
          std::string conn_err;
          if (!ConnectWithTimeout(target, port, connect_timeout_ms, fd, conn_err)) {
            packets_errors += 1u;
          } else {
            if (!SendAll(fd, request_payload.data(), request_payload.size())) {
              packets_errors += 1u;
            } else {
              packets_sent += 1u;
              bytes_sent += static_cast<std::uint64_t>(request_payload.size());
              bytes_recv += RecvSome(fd);
            }
            close(fd);
          }

          const std::uint64_t now_ns = samurai_pacing_monotonic_now_ns();
          if (now_ns - last_hb_ns >= 1'000'000'000ull) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::HEARTBEAT),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id);
            last_hb_ns = now_ns;
          }
          if (now_ns - last_metric_ns >= 2'000'000'000ull) {
            const samurai::wire::MetricSnapshotV1 snap =
                BuildSnapshot(now_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                SerializeSnapshot(snap));
            last_metric_ns = now_ns;
            last_hb_ns = now_ns;
          }
        }

        const std::uint64_t end_ns = samurai_pacing_monotonic_now_ns();
        const samurai::wire::MetricSnapshotV1 snap =
            BuildSnapshot(end_ns, start_ns, packets_sent, packets_errors, bytes_sent, pace_cfg, pace_state);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
            header.correlation_id,
            samurai::wire::WorkerKind::L7,
            job_id,
            SerializeSnapshot(snap));

        const std::vector<std::uint8_t> done = JsonDone(
            header.correlation_id,
            job_id,
            protocol_lc,
            packets_sent,
            packets_errors,
            bytes_sent,
            bytes_recv,
            scenario_payload_bytes,
            snap.actual_rps,
            snap.rate_accuracy_pct);
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
            header.correlation_id,
            samurai::wire::WorkerKind::L7,
            job_id,
            done);
      } catch (const std::exception& exc) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::L7,
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
        samurai::wire::WorkerKind::L7,
        job_id,
        JsonError("unsupported_msg_type"));
  }

  zmq_close(pull);
  zmq_close(push);
  zmq_ctx_term(ctx);
  return 0;
}
