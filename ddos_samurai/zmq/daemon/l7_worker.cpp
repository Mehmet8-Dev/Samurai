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

std::vector<std::uint8_t> BuildDefaultRequest(const std::string& target_ip, const std::string& protocol_lc) {
  const std::string host = target_ip.empty() ? std::string("localhost") : target_ip;
  if (protocol_lc == "http2" || protocol_lc == "h2") {
    static constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    return std::vector<std::uint8_t>(kH2Preface, kH2Preface + sizeof(kH2Preface) - 1);
  }
  if (protocol_lc == "http1" || protocol_lc == "http" || protocol_lc == "https") {
    std::string req = "GET / HTTP/1.1\r\nHost: " + host +
                      "\r\nUser-Agent: samurai-l7-worker\r\nConnection: close\r\n\r\n";
    return std::vector<std::uint8_t>(req.begin(), req.end());
  }
  static constexpr char kCustomMsg[] = "samurai-l7\n";
  return std::vector<std::uint8_t>(kCustomMsg, kCustomMsg + sizeof(kCustomMsg) - 1);
}

// L7 job parameters. Carries the V1 fields plus the V2 stateful-runtime knobs;
// populated from either envelope version so the worker stays backward compatible.
struct L7JobParams {
  std::string target_ip;
  int target_port{0};
  std::string protocol;
  std::string attack_vector;
  std::string scenario_ref;
  std::string payload_ref;
  bool has_payload{false};
  std::uint32_t packet_count{1};
  std::uint32_t concurrency{1};
  std::uint32_t max_connections{1};
  std::uint32_t max_streams_per_connection{1};
  bool verify_tls{false};
  bool keepalive{false};
  std::string scheme;
  std::string host_header;
  std::uint32_t l7_timeout_ms{5000};
};

L7JobParams ParseL7Job(
    const samurai::wire::SamuraiWireHeaderV1& header,
    const std::uint8_t* payload,
    std::size_t payload_len,
    std::string& err) {
  L7JobParams p;
  if (header.version == samurai::wire::kVersionV2) {
    if (payload_len < sizeof(samurai::wire::JobEnvelopeV2)) {
      err = "l7_envelope_v2_size_mismatch";
      return p;
    }
    samurai::wire::JobEnvelopeV2 env{};
    std::memcpy(&env, payload, sizeof(env));
    p.target_ip = ReadFixed(env.base.target_ip, sizeof(env.base.target_ip));
    p.target_port = static_cast<int>(env.base.target_port);
    p.protocol = ReadFixed(env.base.protocol, sizeof(env.base.protocol));
    p.attack_vector = ReadFixed(env.base.attack_vector, sizeof(env.base.attack_vector));
    p.scenario_ref = ReadFixed(env.base.scenario_payload_ref, sizeof(env.base.scenario_payload_ref));
    p.payload_ref = ReadFixed(env.base.payload_ref, sizeof(env.base.payload_ref));
    p.has_payload = env.base.has_payload != 0u;
    p.packet_count = env.base.packet_count;
    p.concurrency = env.concurrency > 0u ? env.concurrency : 1u;
    p.max_connections = env.max_connections > 0u ? env.max_connections : 1u;
    p.max_streams_per_connection = env.max_streams_per_connection > 0u ? env.max_streams_per_connection : 1u;
    p.verify_tls = env.verify_tls != 0u;
    p.keepalive = env.keepalive != 0u;
    p.scheme = ReadFixed(env.scheme, sizeof(env.scheme));
    p.host_header = ReadFixed(env.host_header, sizeof(env.host_header));
    p.l7_timeout_ms = env.l7_timeout_ms > 0u ? env.l7_timeout_ms : 5000u;
    return p;
  }
  if (payload_len < sizeof(samurai::wire::JobEnvelopeV1)) {
    err = "l7_envelope_v1_size_mismatch";
    return p;
  }
  samurai::wire::JobEnvelopeV1 env{};
  std::memcpy(&env, payload, sizeof(env));
  p.target_ip = ReadFixed(env.target_ip, sizeof(env.target_ip));
  p.target_port = static_cast<int>(env.target_port);
  p.protocol = ReadFixed(env.protocol, sizeof(env.protocol));
  p.attack_vector = ReadFixed(env.attack_vector, sizeof(env.attack_vector));
  p.scenario_ref = ReadFixed(env.scenario_payload_ref, sizeof(env.scenario_payload_ref));
  p.payload_ref = ReadFixed(env.payload_ref, sizeof(env.payload_ref));
  p.has_payload = env.has_payload != 0u;
  p.packet_count = env.packet_count;
  return p;
}

// Maps the raw protocol label onto the emu-engine dispatch set. Plain "tcp"
// plus an http* attack vector (e.g. the web-stress profile) is normalized to
// http1 so profiles drive the real stateful engine instead of raw byte blobs.
std::string NormalizeL7Protocol(const std::string& protocol_lc, const std::string& attack_vector_lc) {
  if (protocol_lc == "http" || protocol_lc == "http1" || protocol_lc == "https") {
    return "http1";
  }
  if (protocol_lc == "h2" || protocol_lc == "http2") {
    return "http2";
  }
  if (protocol_lc == "quic" || protocol_lc == "h3" || protocol_lc == "http3") {
    return "quic";
  }
  if (protocol_lc == "dns") {
    return "dns";
  }
  if (protocol_lc == "tcp" && attack_vector_lc.compare(0, 4, "http") == 0) {
    return "http1";
  }
  return protocol_lc;
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
      std::string envelope_err;
      const L7JobParams params = ParseL7Job(header, payload_ptr, payload_len, envelope_err);
      if (!envelope_err.empty()) {
        (void)SendFrame(
            push,
            static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
            header.correlation_id,
            samurai::wire::WorkerKind::L7,
            job_id,
            JsonError(envelope_err));
        zmq_msg_close(&msg);
        continue;
      }
      (void)SendAck(push, header.correlation_id, job_id);
      zmq_msg_close(&msg);

      try {
        const std::string target = params.target_ip;
        const int port = params.target_port;
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

        const std::string protocol = params.protocol;
        const std::string raw_protocol_lc = ToLower(protocol.empty() ? std::string("http1") : protocol);
        const std::string attack_vector_lc = ToLower(params.attack_vector);
        const std::string dispatch_protocol = NormalizeL7Protocol(raw_protocol_lc, attack_vector_lc);
        const std::string& scenario_ref = params.scenario_ref;
        const bool use_l7_emu =
            dispatch_protocol == "http1" || dispatch_protocol == "http2" || dispatch_protocol == "quic" ||
            !scenario_ref.empty();

        if (dispatch_protocol == "dns") {
          (void)SendFrame(
              push,
              static_cast<std::uint8_t>(samurai::wire::MessageType::ERROR),
              header.correlation_id,
              samurai::wire::WorkerKind::L7,
              job_id,
              JsonError("l7_dns_engine_not_yet_implemented"));
          continue;
        }

        std::vector<std::uint8_t> request_payload;
        if (params.has_payload && !params.payload_ref.empty()) {
          std::string payload_err;
          if (!ReadFileBytes(params.payload_ref, request_payload, payload_err)) {
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
          request_payload = BuildDefaultRequest(target, raw_protocol_lc);
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
            Value conn = Value::Object();
            if (const Value* existing_conn = profile.find("connection_template");
                existing_conn != nullptr && existing_conn->is_object()) {
              conn = *existing_conn;
            }
            if (conn.find("transport_backend") == nullptr) {
              const char* transport_env = std::getenv("SAMURAI_L7_TRANSPORT");
              const std::string transport_lc =
                  transport_env != nullptr ? ToLower(std::string(transport_env)) : std::string("");
              const char* transport_name = "kernel_socket";
              if (dispatch_protocol == "quic") {
                transport_name = "custom_quic";
              } else if (transport_lc == "custom_tcp") {
                transport_name = "custom_tcp";
              } else if (transport_lc == "custom_quic") {
                transport_name = "custom_quic";
              }
              conn.set("transport_backend", Value::Str(transport_name));
            }
            if (conn.find("target_ip") == nullptr) conn.set("target_ip", Value::Str(target));
            if (conn.find("target_port") == nullptr) conn.set("target_port", Value::Int(port));
            const bool use_tls_scheme =
                !params.scheme.empty() ? (params.scheme == "https")
                                       : (raw_protocol_lc == "https" || dispatch_protocol == "quic");
            if (conn.find("scheme") == nullptr) conn.set("scheme", Value::Str(use_tls_scheme ? "https" : "http"));
            if (conn.find("host_header") == nullptr)
              conn.set("host_header", Value::Str(params.host_header.empty() ? target : params.host_header));
            if (conn.find("verify") == nullptr) conn.set("verify", Value::Int(params.verify_tls ? 1 : 0));
            if (conn.find("keepalive") == nullptr) conn.set("keepalive", Value::Int(params.keepalive ? 1 : 0));
            if (conn.find("timeout_ms") == nullptr)
              conn.set("timeout_ms", Value::Int(static_cast<std::int64_t>(params.l7_timeout_ms)));
            if (conn.find("max_connections") == nullptr)
              conn.set("max_connections", Value::Int(static_cast<std::int64_t>(params.max_connections)));
            if (conn.find("max_streams_per_connection") == nullptr)
              conn.set("max_streams_per_connection",
                       Value::Int(static_cast<std::int64_t>(params.max_streams_per_connection)));
            if (conn.find("session_repeats") == nullptr)
              conn.set("session_repeats", Value::Int(std::max(1, static_cast<int>(params.packet_count))));
            profile.set("connection_template", conn);
            if (profile.find("flow_attempted") == nullptr) {
              profile.set("flow_attempted", Value::Int(std::max(1, static_cast<int>(params.packet_count))));
            }
            if (profile.find("protocol") == nullptr) {
              const char* emu_protocol = "http1";
              if (dispatch_protocol == "http2") emu_protocol = "http2";
              else if (dispatch_protocol == "quic") emu_protocol = "quic";
              profile.set("protocol", Value::Str(emu_protocol));
            }
            if (profile.find("flow_program") == nullptr && !request_payload.empty()) {
              Value op = Value::Object();
              op.set("opcode", Value::Str("SEND_HEADERS"));
              op.set("method", Value::Str("GET"));
              op.set("path", Value::Str("/"));
              Value body = Value::Object();
              body.set("kind", Value::Str("raw"));
              Value body_bytes = Value::Array();
              for (const std::uint8_t b : request_payload) body_bytes.push_back(Value::Int(static_cast<std::int64_t>(b)));
              body.set("bytes", body_bytes);
              op.set("body", body);
              Value ops = Value::Array();
              const int repeat_count = std::max(1, static_cast<int>(params.packet_count));
              for (int r = 0; r < repeat_count; ++r) ops.push_back(op);
              Value flow_program = Value::Object();
              flow_program.set("ops", ops);
              profile.set("flow_program", flow_program);
            }
            Value cfg = Value::Object();
            cfg.set("concurrency", Value::Int(static_cast<std::int64_t>(params.concurrency)));
            cfg.set("profile_l7", Value::Int(1));
            cfg.set("profile_sample_limit", Value::Int(0));
            const Value emu_result = ddos_samurai::l7_emu_native::run_profile_json(profile, cfg);

            auto read_u64 = [&emu_result](const char* key) -> std::uint64_t {
              const Value* v = emu_result.find(key);
              if (v == nullptr || !v->is_number()) return 0u;
              return static_cast<std::uint64_t>(std::max<double>(0.0, v->as_double()));
            };
            auto read_double = [&emu_result](const char* key) -> double {
              const Value* v = emu_result.find(key);
              if (v == nullptr || !v->is_number()) return 0.0;
              return v->as_double();
            };
            const std::uint64_t emu_attempted = read_u64("attempted");
            const std::uint64_t emu_sent = read_u64("sent");
            const std::uint64_t emu_errors = read_u64("errors");
            const std::uint64_t emu_tx_bytes = read_u64("l7_tx_bytes");
            const std::uint64_t emu_end_ns = samurai_pacing_monotonic_now_ns();
            samurai::wire::MetricSnapshotV2 emu_snap{};
            emu_snap.base.timestamp_ns = emu_end_ns;
            emu_snap.base.packets_sent = emu_sent;
            emu_snap.base.packets_errors = emu_errors;
            emu_snap.base.bytes_sent = emu_tx_bytes;
            emu_snap.base.actual_rps = read_double("l7_rps");
            emu_snap.base.rate_accuracy_pct = emu_attempted > 0
                                             ? std::min(100.0, (static_cast<double>(emu_sent) * 100.0) / static_cast<double>(emu_attempted))
                                             : 0.0;
            
            // Extract Phase 6 L7 metrics
            emu_snap.tcp_active_tcb_count = static_cast<std::uint32_t>(read_u64("tcp_active_tcb_count"));
            emu_snap.tcp_timer_wheel_overflows = static_cast<std::uint32_t>(read_u64("tcp_timer_wheel_overflows"));
            emu_snap.tls_handshakes_completed = static_cast<std::uint32_t>(read_u64("tls_handshakes_completed"));
            emu_snap.tls_session_reuse_hits = static_cast<std::uint32_t>(read_u64("tls_session_reuse_hits"));
            emu_snap.dns_queries_sent = static_cast<std::uint32_t>(read_u64("dns_queries_sent"));
            emu_snap.dns_responses_parsed = static_cast<std::uint32_t>(read_u64("dns_responses_parsed"));
            emu_snap.dns_ecs_injected = static_cast<std::uint32_t>(read_u64("dns_ecs_injected"));
            emu_snap.dhcp_leases_active = static_cast<std::uint32_t>(read_u64("dhcp_leases_active"));
            emu_snap.arp_resolved_entries = static_cast<std::uint32_t>(read_u64("arp_resolved_entries"));
            emu_snap.igmp_active_groups = static_cast<std::uint32_t>(read_u64("igmp_active_groups"));
            emu_snap.hot_path_zero_copy_tx_bytes = read_u64("hot_path_zero_copy_tx_bytes");
            emu_snap.hot_path_zero_copy_rx_bytes = read_u64("hot_path_zero_copy_rx_bytes");

            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::METRIC_SNAPSHOT),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                samurai::daemon::SerializeSnapshotV2(emu_snap));
            (void)SendFrame(
                push,
                static_cast<std::uint8_t>(samurai::wire::MessageType::JOB_DONE),
                header.correlation_id,
                samurai::wire::WorkerKind::L7,
                job_id,
                JsonDoneEmu(header.correlation_id, job_id, dispatch_protocol, emu_result.dump()));
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

        samurai_pacing_config_t pace_cfg = PacingFromEnvelope(header, payload_ptr);
        samurai_pacing_state_t pace_state{};
        samurai_pacing_init(&pace_state, &pace_cfg);

        const int request_count = std::max(1, static_cast<int>(params.packet_count));
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
            raw_protocol_lc,
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
