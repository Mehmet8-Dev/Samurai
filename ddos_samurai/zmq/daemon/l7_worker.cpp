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

namespace {
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
  if (zmq_msg_init_size(&msg, total) != 0) return -1;
  auto* p = static_cast<std::uint8_t*>(zmq_msg_data(&msg));
  std::memcpy(p, &header, sizeof(header));
  if (!payload.empty()) std::memcpy(p + sizeof(header), payload.data(), payload.size());
  const int rc = zmq_msg_send(&msg, event_socket, 0);
  zmq_msg_close(&msg);
  return rc;
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
        if (protocol_lc == "quic" || protocol_lc == "h3" || protocol_lc == "http3") {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::L7,
              job_id,
              JsonError("l7_protocol_requires_udp_or_quic_worker"));
          continue;
        }

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
        const std::string scenario_ref = ReadFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref));
        if (!scenario_ref.empty()) {
          std::ifstream sf(scenario_ref, std::ios::binary | std::ios::ate);
          if (!sf) {
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                JsonError("scenario_payload_ref_missing"));
            continue;
          }
          const std::streamoff ssz = sf.tellg();
          scenario_payload_bytes = ssz > 0 ? static_cast<std::uint64_t>(ssz) : 0u;
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
