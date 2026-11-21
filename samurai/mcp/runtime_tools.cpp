#include "runtime_tools.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

namespace samurai::mcp {

namespace {

using samurai::core::json::Value;

constexpr std::size_t kMaxCaptureBytes = 512 * 1024;  // 512 KiB cap per pipe

bool IsExecutableFile(const std::string& path) {
  return !path.empty() && ::access(path.c_str(), X_OK) == 0;
}

std::string SelfExeDir() {
  char buf[4096] = {0};
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return "";
  std::string p(buf, static_cast<std::size_t>(n));
  const auto slash = p.find_last_of('/');
  return slash == std::string::npos ? "" : p.substr(0, slash);
}

std::string LowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string ReadWholeFile(const std::string& path) {
  std::ifstream in(path);
  if (!in.is_open()) return "";
  std::ostringstream oss;
  oss << in.rdbuf();
  return oss.str();
}

// Pure POSIX TCP HTTP/1.1 GET helper for loopback/private samurai_master API.
Value HttpGetJsonOrText(const std::string& host_ip,
                        int port,
                        const std::string& path,
                        const std::string& bearer_token) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    Value err = Value::Object();
    err.set("error", Value::Str("socket() failed"));
    return err;
  }

  timeval tv{};
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  if (::inet_pton(AF_INET, host_ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    Value err = Value::Object();
    err.set("error", Value::Str("Invalid IPv4 host: " + host_ip));
    return err;
  }

  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    const std::string msg = std::string("connect failed: ") + std::strerror(errno);
    ::close(fd);
    Value err = Value::Object();
    err.set("error", Value::Str(msg));
    return err;
  }

  std::ostringstream req;
  req << "GET " << path << " HTTP/1.1\r\n"
      << "Host: " << host_ip << ":" << port << "\r\n"
      << "Accept: application/json\r\n"
      << "Connection: close\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  req << "\r\n";
  const std::string req_str = req.str();

  std::size_t sent = 0;
  while (sent < req_str.size()) {
    const ssize_t n = ::send(fd, req_str.data() + sent, req_str.size() - sent, MSG_NOSIGNAL);
    if (n <= 0) {
      ::close(fd);
      Value err = Value::Object();
      err.set("error", Value::Str("send failed"));
      return err;
    }
    sent += static_cast<std::size_t>(n);
  }

  std::string raw;
  char buf[4096];
  while (raw.size() < 256 * 1024) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    raw.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);

  const auto sep = raw.find("\r\n\r\n");
  if (sep == std::string::npos) {
    Value err = Value::Object();
    err.set("error", Value::Str("Malformed HTTP response"));
    return err;
  }

  int status_code = 0;
  const auto sp1 = raw.find(' ');
  if (sp1 != std::string::npos && sp1 + 4 <= raw.size()) {
    status_code = std::atoi(raw.c_str() + sp1 + 1);
  }
  const std::string body = raw.substr(sep + 4);
  const auto parsed = samurai::core::json::Parse(body);

  Value out = Value::Object();
  out.set("http_status", Value::Int(status_code));
  if (parsed.ok) {
    out.set("body", parsed.value);
  } else {
    out.set("body", Value::Str(body));
  }
  return out;
}

}  // namespace

std::string FindNativeBinary(const std::vector<std::string>& candidates) {
  std::vector<std::string> dirs;
  if (const char* env_dir = std::getenv("SAMURAI_BIN_DIR")) {
    if (env_dir[0] != '\0') dirs.emplace_back(env_dir);
  }

  const std::string exe_dir = SelfExeDir();
  if (!exe_dir.empty()) {
    dirs.push_back(exe_dir);
    dirs.push_back(exe_dir + "/../cli");
    dirs.push_back(exe_dir + "/../zmq");
    dirs.push_back(exe_dir + "/../l4");
    dirs.push_back(exe_dir + "/../control/daemon");
  }

  dirs.push_back("build/cli");
  dirs.push_back("build/zmq");
  dirs.push_back("build/l4");
  dirs.push_back("build/control/daemon");
  dirs.push_back("/usr/local/bin");

  if (const char* path_env = std::getenv("PATH")) {
    std::stringstream ss(path_env);
    std::string seg;
    while (std::getline(ss, seg, ':')) {
      if (!seg.empty()) dirs.push_back(seg);
    }
  }

  for (const auto& name : candidates) {
    for (const auto& d : dirs) {
      const std::string full = d + "/" + name;
      if (IsExecutableFile(full)) return full;
    }
  }
  return "";
}

SubprocessResult RunSubprocess(const std::vector<std::string>& argv, int timeout_s) {
  SubprocessResult res;
  if (argv.empty()) {
    res.error = "Empty command";
    return res;
  }

  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
    if (out_pipe[0] >= 0) { ::close(out_pipe[0]); ::close(out_pipe[1]); }
    if (err_pipe[0] >= 0) { ::close(err_pipe[0]); ::close(err_pipe[1]); }
    res.error = "pipe() failed";
    return res;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(err_pipe[0]); ::close(err_pipe[1]);
    res.error = "fork() failed";
    return res;
  }

  if (pid == 0) {
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(err_pipe[0]); ::close(err_pipe[1]);

    std::vector<char*> c_argv;
    c_argv.reserve(argv.size() + 1);
    for (const auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
    c_argv.push_back(nullptr);

    ::execv(c_argv[0], c_argv.data());
    _exit(127);
  }

  ::close(out_pipe[1]);
  ::close(err_pipe[1]);
  ::fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
  ::fcntl(err_pipe[0], F_SETFL, O_NONBLOCK);

  bool out_open = true;
  bool err_open = true;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(std::max(1, timeout_s));

  char buf[4096];
  while (out_open || err_open) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      res.timed_out = true;
      res.error = "Command timed out after " + std::to_string(timeout_s) + "s";
      ::kill(pid, SIGTERM);
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      ::kill(pid, SIGKILL);
      break;
    }

    const int rem_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());

    pollfd fds[2];
    nfds_t nfds = 0;
    int out_idx = -1;
    int err_idx = -1;
    if (out_open) {
      out_idx = static_cast<int>(nfds);
      fds[nfds++] = pollfd{out_pipe[0], POLLIN, 0};
    }
    if (err_open) {
      err_idx = static_cast<int>(nfds);
      fds[nfds++] = pollfd{err_pipe[0], POLLIN, 0};
    }

    const int prc = ::poll(fds, nfds, std::min(rem_ms, 200));
    if (prc < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (prc == 0) continue;

    auto drain_fd = [&](int fd, std::string& dst, bool& open_flag) {
      for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
          if (dst.size() < kMaxCaptureBytes) {
            const std::size_t take = std::min(
                static_cast<std::size_t>(n), kMaxCaptureBytes - dst.size());
            dst.append(buf, take);
          }
        } else if (n == 0) {
          open_flag = false;
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          open_flag = false;
          break;
        }
      }
    };

    if (out_idx >= 0 && (fds[out_idx].revents & (POLLIN | POLLHUP | POLLERR))) {
      drain_fd(out_pipe[0], res.stdout_text, out_open);
    }
    if (err_idx >= 0 && (fds[err_idx].revents & (POLLIN | POLLHUP | POLLERR))) {
      drain_fd(err_pipe[0], res.stderr_text, err_open);
    }
  }

  ::close(out_pipe[0]);
  ::close(err_pipe[0]);

  int wstatus = 0;
  ::waitpid(pid, &wstatus, 0);
  if (WIFEXITED(wstatus)) {
    res.exit_code = WEXITSTATUS(wstatus);
  } else if (WIFSIGNALED(wstatus)) {
    res.exit_code = 128 + WTERMSIG(wstatus);
  }
  return res;
}

Value HostMetadataJson() {
  Value h = Value::Object();
  utsname u{};
  if (::uname(&u) == 0) {
    h.set("os", Value::Str(u.sysname));
    h.set("kernel", Value::Str(u.release));
    h.set("arch", Value::Str(u.machine));
  }
  h.set("cpu_count", Value::Int(static_cast<std::int64_t>(std::thread::hardware_concurrency())));
  h.set("runtime", Value::Str("native-cpp17"));
  return h;
}

ToolResult HandleListWorkers(const Value&) {
  Value workers = Value::Object();
  for (const auto& w : AllowedWorkers()) {
    const std::string bin_name = "samurai_" + w + "_worker";
    const std::string path = FindNativeBinary({bin_name});
    Value entry = Value::Object();
    entry.set("binary", Value::Str(bin_name));
    entry.set("available", Value::Bool(!path.empty()));
    entry.set("path", path.empty() ? Value::Null() : Value::Str(path));
    workers.set(w, std::move(entry));
  }

  Value benches = Value::Object();
  auto set_opt_path = [&](Value& obj, const char* key, const std::vector<std::string>& cands) {
    const std::string p = FindNativeBinary(cands);
    obj.set(key, p.empty() ? Value::Null() : Value::Str(p));
  };
  set_opt_path(benches, "tcp_100k", {"samurai_bench_100k_tcp", "test_100k_tcp_flows"});
  set_opt_path(benches, "tcp_1m", {"samurai_bench_1m_tcp", "test_1m_tcp_flows"});
  set_opt_path(benches, "l7_userspace", {"samurai_bench_l7", "bench_l7_stateful_userspace"});

  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  set_opt_path(out, "cli_binary", {"samurai"});
  set_opt_path(out, "master_binary", {"samurai_master"});
  set_opt_path(out, "slave_binary", {"samurai_slave"});
  out.set("benchmarks", std::move(benches));
  out.set("workers", std::move(workers));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleListProfiles(const Value&) {
  const std::string bin = FindNativeBinary({"samurai"});
  if (bin.empty()) {
    return MakeToolError("samurai CLI binary not found. Build via CMake first.");
  }
  const auto res = RunSubprocess({bin, "--list-profiles"}, 15);
  Value out = Value::Object();
  out.set("binary", Value::Str(bin));
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("profiles_output", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleRunBenchmark(const Value& args, const SafetyConfig& safety) {
  const std::string bin = FindNativeBinary({"samurai"});
  if (bin.empty()) {
    return MakeToolError("samurai CLI binary not found. Build via CMake first.");
  }

  const std::string worker = LowerCopy(args.find("worker") ? args.find("worker")->as_string("cpu") : "cpu");
  if (!IsAllowedWorker(worker)) {
    return MakeToolError("Unsupported worker: " + worker);
  }

  const std::string target = args.find("target") ? args.find("target")->as_string("127.0.0.1") : "127.0.0.1";
  const auto target_check = ValidateMcpTarget(target, safety);
  if (!target_check.ok) {
    return MakeToolError("Target blocked by fail-closed MCP safety gate: " + target_check.reason);
  }

  const std::int64_t port = args.find("port") ? args.find("port")->as_int(80) : 80;
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  const std::int64_t count = args.find("count") ? args.find("count")->as_int(1000) : 1000;
  if (count < 1 || static_cast<std::uint64_t>(count) > safety.max_packet_count) {
    return MakeToolError("count must be between 1 and " + std::to_string(safety.max_packet_count));
  }

  const std::int64_t size = args.find("size") ? args.find("size")->as_int(64) : 64;
  if (size < 1 || size > 65535) {
    return MakeToolError("size must be between 1 and 65535");
  }

  const std::string protocol = LowerCopy(args.find("protocol") ? args.find("protocol")->as_string("udp") : "udp");
  if (!IsAllowedProtocol(protocol)) {
    return MakeToolError("Unsupported protocol: " + protocol);
  }

  const double rps = args.find("rps") ? args.find("rps")->as_double(0.0) : 0.0;
  if (rps < 0.0) {
    return MakeToolError("rps must be >= 0");
  }

  const int timeout_s = std::clamp(
      static_cast<int>(args.find("timeout_s") ? args.find("timeout_s")->as_int(30) : 30),
      5, safety.max_timeout_s);

  char tmpl[] = "/tmp/samurai_mcp_report_XXXXXX";
  const int tmp_fd = ::mkstemp(tmpl);
  if (tmp_fd < 0) {
    return MakeToolError("Failed to create temporary report file");
  }
  ::close(tmp_fd);
  const std::string report_path(tmpl);

  std::vector<std::string> cmd = {bin, "--worker", worker};
  if (const Value* prof = args.find("profile"); prof && prof->is_string() && !prof->as_string().empty()) {
    cmd.push_back("--profile");
    cmd.push_back(prof->as_string());
  }
  cmd.push_back("--target");      cmd.push_back(target);
  cmd.push_back("--port");        cmd.push_back(std::to_string(port));
  cmd.push_back("--count");       cmd.push_back(std::to_string(count));
  cmd.push_back("--size");        cmd.push_back(std::to_string(size));
  cmd.push_back("--protocol");    cmd.push_back(protocol);
  cmd.push_back("--report-json"); cmd.push_back(report_path);
  cmd.push_back("--confirm");

  if (rps > 0.0) {
    cmd.push_back("--rps");
    cmd.push_back(std::to_string(rps));
  }
  if (const Value* l7p = args.find("l7_protocol"); l7p && l7p->is_string() && !l7p->as_string().empty()) {
    cmd.push_back("--l7-protocol");
    cmd.push_back(l7p->as_string());
  }
  if (const Value* pf = args.find("l7_profile_file"); pf && pf->is_string() && !pf->as_string().empty()) {
    cmd.push_back("--l7-profile-file");
    cmd.push_back(pf->as_string());
  }
  if (const Value* conc = args.find("concurrency"); conc && conc->is_number() && conc->as_int(0) > 0) {
    cmd.push_back("--concurrency");
    cmd.push_back(std::to_string(conc->as_int(1)));
  }
  if (const Value* ka = args.find("keepalive"); ka && ka->as_bool(false)) {
    cmd.push_back("--keepalive");
  }
  if (const Value* kerr = args.find("kpi_max_errors"); kerr && kerr->is_number()) {
    cmd.push_back("--kpi-max-errors");
    cmd.push_back(std::to_string(kerr->as_int(0)));
  }
  if (const Value* kloss = args.find("kpi_max_loss_pct"); kloss && kloss->is_number()) {
    cmd.push_back("--kpi-max-loss-pct");
    cmd.push_back(std::to_string(kloss->as_double(0.0)));
  }

  const auto res = RunSubprocess(cmd, timeout_s);
  const std::string report_raw = ReadWholeFile(report_path);
  ::unlink(report_path.c_str());

  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("timed_out", Value::Bool(res.timed_out));
  if (!report_raw.empty()) {
    const auto parsed = samurai::core::json::Parse(report_raw);
    out.set("report", parsed.ok ? parsed.value : Value::Str(report_raw));
  } else {
    out.set("report", Value::Null());
  }
  out.set("stdout", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleRunRfcSuite(const Value& args, const SafetyConfig& safety) {
  const std::string bin = FindNativeBinary({"samurai"});
  if (bin.empty()) {
    return MakeToolError("samurai CLI binary not found.");
  }

  const std::string suite = LowerCopy(args.find("suite") ? args.find("suite")->as_string("all") : "all");
  if (suite != "all" && suite != "rfc2544" && suite != "rfc3511" && suite != "rfc8219") {
    return MakeToolError("suite must be one of: all, rfc2544, rfc3511, rfc8219");
  }

  std::vector<std::string> cmd = {bin, "--run-rfc-suite", suite};
  if (const Value* tgt = args.find("target"); tgt && tgt->is_string() && !tgt->as_string().empty()) {
    const auto chk = ValidateMcpTarget(tgt->as_string(), safety);
    if (!chk.ok) {
      return MakeToolError("Target blocked by fail-closed MCP safety gate: " + chk.reason);
    }
    cmd.push_back("--target");
    cmd.push_back(tgt->as_string());
    if (const Value* live = args.find("live_dataplane"); live && live->as_bool(false)) {
      cmd.push_back("--confirm");
    }
  }

  const auto res = RunSubprocess(cmd, 60);
  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("suite", Value::Str(suite));
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("markdown_report", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleBenchTcpFlows(const Value& args) {
  const std::string scale = LowerCopy(args.find("scale") ? args.find("scale")->as_string("100k") : "100k");
  std::string bin;
  int timeout_s = 30;
  if (scale == "100k") {
    bin = FindNativeBinary({"samurai_bench_100k_tcp", "test_100k_tcp_flows"});
  } else if (scale == "1m") {
    bin = FindNativeBinary({"samurai_bench_1m_tcp", "test_1m_tcp_flows"});
    timeout_s = 120;
  } else {
    return MakeToolError("scale must be '100k' or '1m'");
  }
  if (bin.empty()) {
    return MakeToolError("TCP flow benchmark binary for scale='" + scale + "' not found.");
  }

  const auto res = RunSubprocess({bin}, timeout_s);
  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("scale", Value::Str(scale));
  out.set("binary", Value::Str(bin));
  out.set("methodology_note",
          Value::Str("In-memory userspace TcpDataplaneCore benchmark (64-shard lock-striped flow table, RFC 1071 checksums)."));
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("output", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleBenchL7Userspace(const Value& args) {
  const std::string bin = FindNativeBinary({"samurai_bench_l7", "bench_l7_stateful_userspace"});
  if (bin.empty()) {
    return MakeToolError("bench_l7_stateful_userspace binary not found.");
  }

  const std::string proto = LowerCopy(args.find("proto") ? args.find("proto")->as_string("h1") : "h1");
  if (proto != "h1" && proto != "h2") {
    return MakeToolError("proto must be 'h1' or 'h2' (h3 requires an active QUIC server port)");
  }

  const std::int64_t flows = args.find("flows") ? args.find("flows")->as_int(5000) : 5000;
  if (flows < 100 || flows > 200000) {
    return MakeToolError("flows must be between 100 and 200000");
  }

  const auto res = RunSubprocess({bin, "--proto", proto, "--flows", std::to_string(flows)}, 90);
  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("proto", Value::Str(proto));
  out.set("flows", Value::Int(flows));
  out.set("methodology_note",
          Value::Str("Shared-nothing userspace L7 benchmark (TcpDataplaneCore + InMemoryShardPeer + dynamic RFC 7230 / nghttp2)."));
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("output", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleClusterStatus(const Value& args, const SafetyConfig& safety) {
  const std::string host = args.find("host") ? args.find("host")->as_string("127.0.0.1") : "127.0.0.1";
  const auto chk = ValidateMcpTarget(host, safety);
  if (!chk.ok) {
    return MakeToolError("Cluster host blocked by fail-closed MCP safety gate: " + chk.reason);
  }
  const std::int64_t port = args.find("port") ? args.find("port")->as_int(8089) : 8089;
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  std::string token;
  if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_VIEWER_TOKEN")) {
    token = t;
  }

  Value out = Value::Object();
  out.set("endpoint", Value::Str("http://" + host + ":" + std::to_string(port)));
  out.set("healthz", HttpGetJsonOrText(host, static_cast<int>(port), "/healthz", token));
  out.set("state", HttpGetJsonOrText(host, static_cast<int>(port), "/v1/state", token));
  return MakeToolSuccess(std::move(out));
}

}  // namespace samurai::mcp
