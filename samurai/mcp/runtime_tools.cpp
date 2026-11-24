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
#if defined(__linux__)
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#endif

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

std::string EnvOrEmpty(const char* name) {
  const char* val = std::getenv(name);
  return (val != nullptr && val[0] != '\0') ? std::string(val) : std::string();
}

std::string ArgStr(const Value& args, const char* key) {
  const Value* v = args.find(key);
  return (v && v->is_string()) ? v->as_string() : std::string();
}

std::string FormatMacBytes(const unsigned char mac[6]) {
  char buf[24];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

bool IsZeroMac(const std::string& mac) {
  return mac.empty() || mac == "00:00:00:00:00:00";
}

bool IsLoopbackIpv4(const std::string& ip) {
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
  return (ntohl(addr.s_addr) >> 24) == 127U;
}

std::string ResolveRouteSourceIp(const std::string& target_ip, int target_port) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return "";
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(static_cast<std::uint16_t>(std::clamp(target_port, 1, 65535)));
  if (::inet_pton(AF_INET, target_ip.c_str(), &dst.sin_addr) != 1) {
    ::close(fd);
    return "";
  }
  std::string out;
  if (::connect(fd, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == 0) {
    sockaddr_in src{};
    socklen_t len = sizeof(src);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&src), &len) == 0) {
      char buf[INET_ADDRSTRLEN] = {0};
      if (::inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf)) != nullptr) {
        out = buf;
      }
    }
  }
  ::close(fd);
  return out;
}

void ResolveInterfaceForSourceIp(const std::string& src_ip,
                                 std::string& out_iface,
                                 std::string& out_src_mac) {
#if defined(__linux__)
  if (src_ip.empty()) return;
  struct ifaddrs* ifaddr = nullptr;
  if (::getifaddrs(&ifaddr) != 0 || ifaddr == nullptr) return;

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || !ifa->ifa_name || ifa->ifa_addr->sa_family != AF_INET) continue;
    const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
    char buf[INET_ADDRSTRLEN] = {0};
    if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr && src_ip == buf) {
      out_iface = ifa->ifa_name;
      break;
    }
  }

  if (!out_iface.empty()) {
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr || !ifa->ifa_name || ifa->ifa_addr->sa_family != AF_PACKET) continue;
      if (out_iface != ifa->ifa_name) continue;
      const auto* sll = reinterpret_cast<const sockaddr_ll*>(ifa->ifa_addr);
      if (sll->sll_halen == 6) {
        out_src_mac = FormatMacBytes(sll->sll_addr);
        break;
      }
    }
  }
  ::freeifaddrs(ifaddr);
#else
  (void)src_ip;
  (void)out_iface;
  (void)out_src_mac;
#endif
}

std::string LookupProcArpMac(const std::string& target_ip, const std::string& iface) {
  std::ifstream in("/proc/net/arp");
  if (!in.is_open()) return "";
  std::string line;
  std::getline(in, line);  // skip header
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string ip, hw_type, flags, hw_addr, mask, dev;
    if (!(iss >> ip >> hw_type >> flags >> hw_addr >> mask >> dev)) continue;
    if (ip != target_ip) continue;
    if (!iface.empty() && dev != iface) continue;
    if (flags == "0x0" || IsZeroMac(hw_addr)) continue;
    return LowerCopy(hw_addr);
  }
  return "";
}

std::string ResolveDstMacForTarget(const std::string& target_ip, const std::string& iface) {
  if (iface == "lo" || IsLoopbackIpv4(target_ip)) {
    return "00:00:00:00:00:00";
  }
  std::string mac = LookupProcArpMac(target_ip, iface);
  if (!mac.empty()) return mac;

#if defined(__linux__)
  // Trigger neighbor resolution via a single UDP probe to discard port 9 so /proc/net/arp populates.
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd >= 0) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);
    if (::inet_pton(AF_INET, target_ip.c_str(), &dst.sin_addr) == 1) {
      const char byte = 0;
      (void)::sendto(fd, &byte, 1, MSG_DONTWAIT, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
      std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
    if (!iface.empty()) {
      arpreq req{};
      std::memcpy(&req.arp_pa, &dst, sizeof(dst));
      std::snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", iface.c_str());
      if (::ioctl(fd, SIOCGARP, &req) == 0 && (req.arp_flags & ATF_COM) != 0) {
        const auto* hw = reinterpret_cast<const unsigned char*>(req.arp_ha.sa_data);
        const std::string resolved = FormatMacBytes(hw);
        if (!IsZeroMac(resolved)) {
          ::close(fd);
          return resolved;
        }
      }
    }
    ::close(fd);
  }
#endif
  return LookupProcArpMac(target_ip, iface);
}

bool HasExplicitCustomTcpArgs(const Value& args) {
  static const char* kKeys[] = {
      "custom_tcp_wire",
      "xdp_mode",
      "custom_tcp_iface",
      "custom_tcp_src_ip",
      "custom_tcp_dst_mac",
      "custom_tcp_src_mac",
      "xdp_queue_id",
  };
  for (const char* k : kKeys) {
    if (args.find(k) != nullptr) return true;
  }
  return false;
}

bool NormalizeCustomTcpWire(const std::string& raw, std::string& out_wire) {
  const std::string w = LowerCopy(raw);
  if (w == "af_xdp" || w == "afxdp") {
    out_wire = "af_xdp";
    return true;
  }
  if (w == "af_packet" || w == "afpacket") {
    out_wire = "af_packet";
    return true;
  }
  if (w == "dpdk") {
    out_wire = "dpdk";
    return true;
  }
  if (w == "in_memory" || w == "inmem") {
    out_wire = "in_memory";
    return true;
  }
  return false;
}

bool NormalizeXdpMode(const std::string& raw, std::string& out_mode) {
  const std::string m = LowerCopy(raw);
  if (m == "0" || m == "skb" || m == "copy" || m == "skb_copy") {
    out_mode = "0";
    return true;
  }
  if (m == "1" || m == "native" || m == "zerocopy" || m == "zero_copy") {
    out_mode = "1";
    return true;
  }
  if (m == "2" || m == "offload") {
    out_mode = "2";
    return true;
  }
  return false;
}

bool ProfileFileUsesCustomTcp(const std::string& path) {
  if (path.empty()) return false;
  const std::string raw = ReadWholeFile(path);
  if (raw.empty()) return false;
  const auto parsed = samurai::core::json::Parse(raw);
  if (!parsed.ok || !parsed.value.is_object()) return false;
  if (const Value* ct = parsed.value.find("connection_template"); ct && ct->is_object()) {
    if (const Value* tb = ct->find("transport_backend"); tb && tb->is_string()) {
      const std::string tr = LowerCopy(tb->as_string());
      return tr == "custom_tcp" || tr == "dpdk" || tr == "dpdk_direct";
    }
  }
  return false;
}

}  // namespace

CustomTcpEnvResolution ResolveCustomTcpEnv(const Value& args,
                                           const std::string& target_ip,
                                           int target_port,
                                           bool requested_custom_tcp) {
  CustomTcpEnvResolution res;
  if (!requested_custom_tcp && !HasExplicitCustomTcpArgs(args)) {
    return res;
  }

  res.active = true;
  const bool auto_env = args.find("auto_custom_tcp_env") ? args.find("auto_custom_tcp_env")->as_bool(true) : true;

  std::string raw_wire = ArgStr(args, "custom_tcp_wire");
  if (raw_wire.empty()) raw_wire = EnvOrEmpty("SAMURAI_CUSTOM_TCP_WIRE");
  if (raw_wire.empty()) raw_wire = "af_xdp";
  if (!NormalizeCustomTcpWire(raw_wire, res.wire)) {
    res.error = "Invalid custom_tcp_wire '" + raw_wire + "'. Expected: af_xdp, af_packet, dpdk, or in_memory.";
    return res;
  }

  std::string raw_xdp_mode = ArgStr(args, "xdp_mode");
  if (raw_xdp_mode.empty()) raw_xdp_mode = EnvOrEmpty("SAMURAI_XDP_MODE");
  if (raw_xdp_mode.empty()) raw_xdp_mode = "0";  // Default to AF_XDP SKB/Copy mode
  if (!NormalizeXdpMode(raw_xdp_mode, res.xdp_mode)) {
    res.error = "Invalid xdp_mode '" + raw_xdp_mode + "'. Expected: skb/copy (0), native/zerocopy (1), or offload (2).";
    return res;
  }

  res.iface = ArgStr(args, "custom_tcp_iface");
  if (res.iface.empty()) res.iface = EnvOrEmpty("SAMURAI_CUSTOM_TCP_RX_IFACE");
  if (res.iface.empty()) res.iface = EnvOrEmpty("SAMURAI_XDP_INTERFACE");

  res.src_ip = ArgStr(args, "custom_tcp_src_ip");
  if (res.src_ip.empty()) res.src_ip = EnvOrEmpty("SAMURAI_CUSTOM_TCP_SRC_IP");

  res.src_mac = LowerCopy(ArgStr(args, "custom_tcp_src_mac"));
  if (res.src_mac.empty()) res.src_mac = LowerCopy(EnvOrEmpty("SAMURAI_CUSTOM_TCP_SRC_MAC"));

  res.dst_mac = LowerCopy(ArgStr(args, "custom_tcp_dst_mac"));
  if (res.dst_mac.empty()) res.dst_mac = LowerCopy(EnvOrEmpty("SAMURAI_CUSTOM_TCP_DST_MAC"));

  if (const Value* qv = args.find("xdp_queue_id"); qv && qv->is_number() && qv->as_int(-1) >= 0) {
    res.queue_id = std::to_string(qv->as_int(0));
  } else {
    res.queue_id = EnvOrEmpty("SAMURAI_XDP_QUEUE_ID");
    if (res.queue_id.empty()) res.queue_id = "0";
  }

  if (auto_env && res.wire != "in_memory") {
    if (res.src_ip.empty()) {
      const std::string detected_ip = ResolveRouteSourceIp(target_ip, target_port);
      if (!detected_ip.empty()) {
        res.src_ip = detected_ip;
        res.auto_detected = true;
      }
    }
    if (res.iface.empty() || res.src_mac.empty()) {
      std::string detected_iface;
      std::string detected_mac;
      ResolveInterfaceForSourceIp(res.src_ip, detected_iface, detected_mac);
      if (res.iface.empty() && !detected_iface.empty()) {
        res.iface = detected_iface;
        res.auto_detected = true;
      }
      if (res.src_mac.empty() && !detected_mac.empty()) {
        res.src_mac = detected_mac;
        res.auto_detected = true;
      }
    }
    if (res.dst_mac.empty()) {
      const std::string detected_dst = ResolveDstMacForTarget(target_ip, res.iface);
      if (!detected_dst.empty()) {
        res.dst_mac = detected_dst;
        res.auto_detected = true;
      }
    }
  }

  auto push_env = [&](const char* k, const std::string& v) {
    if (!v.empty()) res.env_overrides.emplace_back(k, v);
  };
  push_env("SAMURAI_CUSTOM_TCP_WIRE", res.wire);
  push_env("SAMURAI_CUSTOM_TCP_BACKEND",
           res.wire == "af_packet" ? "af_packet" : (res.wire == "dpdk" ? "dpdk" : "af_xdp"));
  if (EnvOrEmpty("SAMURAI_CUSTOM_TCP_MODE").empty()) {
    push_env("SAMURAI_CUSTOM_TCP_MODE", "required");
  }
  push_env("SAMURAI_XDP_MODE", res.xdp_mode);
  push_env("SAMURAI_XDP_QUEUE_ID", res.queue_id);
  push_env("SAMURAI_CUSTOM_TCP_RX_IFACE", res.iface);
  if (res.wire == "af_xdp") {
    push_env("SAMURAI_XDP_INTERFACE", res.iface);
  }
  push_env("SAMURAI_CUSTOM_TCP_SRC_IP", res.src_ip);
  push_env("SAMURAI_CUSTOM_TCP_SRC_MAC", res.src_mac);
  push_env("SAMURAI_CUSTOM_TCP_DST_MAC", res.dst_mac);

  Value summary = Value::Object();
  summary.set("wire", Value::Str(res.wire));
  summary.set("xdp_mode", Value::Str(res.xdp_mode == "0" ? "skb_copy(0)" : (res.xdp_mode == "1" ? "native_zerocopy(1)" : "offload(2)")));
  summary.set("iface", Value::Str(res.iface));
  summary.set("src_ip", Value::Str(res.src_ip));
  summary.set("src_mac", Value::Str(res.src_mac));
  summary.set("dst_mac", Value::Str(res.dst_mac));
  summary.set("queue_id", Value::Str(res.queue_id));
  summary.set("auto_detected", Value::Bool(res.auto_detected));
  Value env_obj = Value::Object();
  for (const auto& kv : res.env_overrides) {
    env_obj.set(kv.first, Value::Str(kv.second));
  }
  summary.set("env", std::move(env_obj));
  res.summary_json = std::move(summary);
  return res;
}

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

SubprocessResult RunSubprocess(const std::vector<std::string>& argv,
                               int timeout_s,
                               const EnvVarList& env_overrides) {
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

    for (const auto& kv : env_overrides) {
      if (!kv.first.empty()) {
        ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
      }
    }

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

  const std::string raw_target = args.find("target") ? args.find("target")->as_string("127.0.0.1") : "127.0.0.1";
  std::string target;
  const auto target_check = ResolveMcpTarget(raw_target, safety, target);
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
  for (const auto& allow_ip : safety.allow_targets) {
    cmd.push_back("--allow-target");
    cmd.push_back(allow_ip);
  }
  for (const auto& deny_ip : safety.deny_targets) {
    cmd.push_back("--deny-target");
    cmd.push_back(deny_ip);
  }
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

  auto push_str = [&](const char* key, const char* flag) {
    if (const Value* v = args.find(key); v && v->is_string() && !v->as_string().empty()) {
      cmd.push_back(flag);
      cmd.push_back(v->as_string());
    }
  };
  auto push_pos_int = [&](const char* key, const char* flag) {
    if (const Value* v = args.find(key); v && v->is_number() && v->as_int(0) > 0) {
      cmd.push_back(flag);
      cmd.push_back(std::to_string(v->as_int(0)));
    }
  };
  auto push_nonneg_int = [&](const char* key, const char* flag) {
    if (const Value* v = args.find(key); v && v->is_number() && v->as_int(-1) >= 0) {
      cmd.push_back(flag);
      cmd.push_back(std::to_string(v->as_int(0)));
    }
  };
  auto push_num = [&](const char* key, const char* flag) {
    if (const Value* v = args.find(key); v && v->is_number()) {
      cmd.push_back(flag);
      cmd.push_back(std::to_string(v->as_double(0.0)));
    }
  };
  auto push_bool_flag = [&](const char* key, const char* flag) {
    if (const Value* v = args.find(key); v && v->as_bool(false)) {
      cmd.push_back(flag);
    }
  };

  if (rps > 0.0) {
    cmd.push_back("--rps");
    cmd.push_back(std::to_string(rps));
  }

  // Core / vector / CPU pinning / dataplane transport & config
  push_str("vector", "--vector");
  push_nonneg_int("pin_cpu", "--pin-cpu");
  push_str("config", "--config");
  push_str("iface", "--iface");
  push_str("transport", "--transport");
  push_nonneg_int("dpdk_port", "--dpdk-port");
  push_nonneg_int("dpdk_queue", "--dpdk-queue");
  push_str("log_level", "--log-level");

  // L7 / TLS / HTTP2 / QUIC controls
  push_str("l7_protocol", "--l7-protocol");
  push_str("l7_profile_file", "--l7-profile-file");
  push_str("l7_payload_file", "--l7-payload-file");
  push_str("scheme", "--scheme");
  push_str("host_header", "--host-header");
  push_pos_int("concurrency", "--concurrency");
  push_pos_int("max_connections", "--max-connections");
  push_pos_int("max_streams", "--max-streams");
  push_pos_int("l7_timeout_ms", "--l7-timeout-ms");
  push_bool_flag("verify_tls", "--verify-tls");
  push_bool_flag("keepalive", "--keepalive");

  // Carrier 4G/5G Telecom controls (GTP-U, PFCP, SCTP, Diameter, SIP/RTP/SRTP, QinQ)
  push_pos_int("telco_subscribers", "--telco-subscribers");
  push_nonneg_int("telco_subscriber_start", "--telco-subscriber-start");
  push_pos_int("telco_cps", "--telco-cps");
  push_pos_int("telco_duration_ms", "--telco-duration-ms");
  push_pos_int("vlan_s", "--vlan-s");
  push_pos_int("vlan_c", "--vlan-c");
  push_pos_int("sctp_rate", "--sctp-rate");
  push_pos_int("diameter_rate", "--diameter-rate");
  push_pos_int("sip_rate", "--sip-rate");
  push_bool_flag("enable_srtp", "--enable-srtp");
  push_nonneg_int("teid_start", "--teid-start");
  push_pos_int("teid_count", "--teid-count");
  push_nonneg_int("qfi", "--qfi");
  push_str("ue_subnet", "--ue-subnet");
  push_str("gtpu_vlan", "--gtpu-vlan");
  push_str("gtpu_inner_proto", "--gtpu-inner-proto");
  push_str("telco_base_ip", "--telco-base-ip");
  push_str("telco_gateway_ip", "--telco-gateway-ip");

  // GPU CUDA / GeForce BAR1 P2P controls
  push_bool_flag("gpu_bar1_p2p", "--gpu-bar1-p2p");
  push_bool_flag("gpu_persistent", "--gpu-persistent");

  // Live IPFIX / NetFlow v9/v10 telemetry export (collector validated fail-closed)
  if (const Value* ipfix = args.find("ipfix_enabled"); ipfix && ipfix->as_bool(false)) {
    const std::string raw_collector =
        args.find("ipfix_collector") ? args.find("ipfix_collector")->as_string("127.0.0.1") : "127.0.0.1";
    std::string collector;
    const auto cchk = ResolveMcpTarget(raw_collector, safety, collector);
    if (!cchk.ok) {
      ::unlink(report_path.c_str());
      return MakeToolError("ipfix_collector blocked by fail-closed MCP safety gate: " + cchk.reason);
    }
    cmd.push_back("--ipfix-enabled");
    cmd.push_back("--ipfix-collector");
    cmd.push_back(collector);
    push_pos_int("ipfix_port", "--ipfix-port");
    push_pos_int("ipfix_sample_rate", "--ipfix-sample-rate");
    push_bool_flag("ipfix_netflow_v9", "--ipfix-netflow-v9");
    push_pos_int("ipfix_domain_id", "--ipfix-domain-id");
  }

  // KPI pass/fail gates
  push_num("kpi_min_rate_accuracy", "--kpi-min-rate-accuracy");
  push_num("kpi_max_loss_pct", "--kpi-max-loss-pct");
  push_nonneg_int("kpi_max_errors", "--kpi-max-errors");
  push_pos_int("kpi_min_sent", "--kpi-min-sent");
  push_pos_int("kpi_min_tls_handshakes", "--kpi-min-tls-handshakes");
  push_pos_int("kpi_min_dns_queries", "--kpi-min-dns-queries");
  push_pos_int("kpi_min_dhcp_leases", "--kpi-min-dhcp-leases");
  push_nonneg_int("kpi_max_tcp_overflows", "--kpi-max-tcp-overflows");

  const std::string l7_profile_path = ArgStr(args, "l7_profile_file");
  const bool wants_custom_tcp =
      (worker == "afxdp") || ProfileFileUsesCustomTcp(l7_profile_path);
  const CustomTcpEnvResolution tcp_env =
      ResolveCustomTcpEnv(args, target, static_cast<int>(port), wants_custom_tcp);
  if (!tcp_env.error.empty()) {
    ::unlink(report_path.c_str());
    return MakeToolError(tcp_env.error);
  }

  const auto res = RunSubprocess(cmd, timeout_s, tcp_env.env_overrides);
  const std::string report_raw = ReadWholeFile(report_path);
  ::unlink(report_path.c_str());

  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  if (tcp_env.active) {
    out.set("custom_tcp_env", tcp_env.summary_json);
  }
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
    std::string resolved_tgt;
    const auto chk = ResolveMcpTarget(tgt->as_string(), safety, resolved_tgt);
    if (!chk.ok) {
      return MakeToolError("Target blocked by fail-closed MCP safety gate: " + chk.reason);
    }
    cmd.push_back("--target");
    cmd.push_back(resolved_tgt);
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
  const std::string raw_host = args.find("host") ? args.find("host")->as_string("127.0.0.1") : "127.0.0.1";
  std::string host;
  const auto chk = ResolveMcpTarget(raw_host, safety, host);
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
