#include "cluster_tools.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <thread>

#include "autoscale.hpp"
#include "runtime_tools.hpp"
#include "shard.hpp"

namespace samurai::mcp {

namespace {

using samurai::core::json::Parse;
using samurai::core::json::Value;

std::string LowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string OptStr(const Value& obj, const char* key, const std::string& def = "") {
  if (const Value* v = obj.find(key); v && v->is_string()) return v->as_string(def);
  return def;
}

std::int64_t OptInt(const Value& obj, const char* key, std::int64_t def) {
  if (const Value* v = obj.find(key); v && v->is_number()) return v->as_int(def);
  return def;
}

bool OptBool(const Value& obj, const char* key, bool def) {
  if (const Value* v = obj.find(key); v && v->is_bool()) return v->as_bool(def);
  return def;
}

std::string ResolveToken(const Value& args, bool write_op) {
  const std::string explicit_tok = OptStr(args, "auth_token", "");
  if (!explicit_tok.empty()) return explicit_tok;
  if (write_op) {
    if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_ADMIN_TOKEN"); t && t[0]) return t;
    if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN"); t && t[0]) return t;
  } else {
    if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_VIEWER_TOKEN"); t && t[0]) return t;
    if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN"); t && t[0]) return t;
    if (const char* t = std::getenv("SAMURAI_MANAGEMENT_API_ADMIN_TOKEN"); t && t[0]) return t;
  }
  return "";
}

// Pure POSIX HTTP/1.1 GET/POST helper (zero curl/Python dependencies).
Value HttpCallLocal(const std::string& method,
                    const std::string& host_ip,
                    int port,
                    const std::string& path,
                    const std::string& bearer_token,
                    const std::string& body = "") {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    Value err = Value::Object();
    err.set("error", Value::Str("socket() failed"));
    return err;
  }

  timeval tv{};
  tv.tv_sec = 5;
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
  req << method << " " << path << " HTTP/1.1\r\n"
      << "Host: " << host_ip << ":" << port << "\r\n"
      << "Accept: application/json, text/plain\r\n"
      << "Connection: close\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  if (!body.empty() || method == "POST") {
    req << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n";
  }
  req << "\r\n" << body;

  const std::string wire = req.str();
  std::size_t sent = 0;
  while (sent < wire.size()) {
    const ssize_t n = ::send(fd, wire.data() + sent, wire.size() - sent, MSG_NOSIGNAL);
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
  while (raw.size() < 512 * 1024) {
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
  const std::string resp_body = raw.substr(sep + 4);
  const auto parsed = Parse(resp_body);

  Value out = Value::Object();
  out.set("http_status", Value::Int(status_code));
  if (parsed.ok) {
    out.set("body", parsed.value);
  } else {
    out.set("body", Value::Str(resp_body));
  }
  return out;
}

std::vector<std::string> SplitCsv(const std::string& s) {
  std::vector<std::string> out;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, ',')) {
    std::size_t a = 0;
    while (a < item.size() && std::isspace(static_cast<unsigned char>(item[a]))) ++a;
    std::size_t b = item.size();
    while (b > a && std::isspace(static_cast<unsigned char>(item[b - 1]))) --b;
    if (b > a) out.push_back(item.substr(a, b - a));
  }
  return out;
}

void TerminatePid(pid_t pid) {
  if (pid <= 0) return;
  ::kill(pid, SIGTERM);
  int wstatus = 0;
  for (int i = 0; i < 15; ++i) {
    const pid_t w = ::waitpid(pid, &wstatus, WNOHANG);
    if (w == pid || w < 0) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ::kill(pid, SIGKILL);
  ::waitpid(pid, &wstatus, 0);
}

bool IsPidAlive(pid_t pid) {
  if (pid <= 0) return false;
  int wstatus = 0;
  const pid_t w = ::waitpid(pid, &wstatus, WNOHANG);
  return w == 0;
}

pid_t SpawnDetachedQuiet(const std::vector<std::string>& argv,
                         const std::vector<std::pair<std::string, std::string>>& extra_env) {
  const pid_t pid = ::fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    for (const auto& kv : extra_env) {
      ::setenv(kv.first.c_str(), kv.second.c_str(), 1);
    }
    // Redirect stdout/stderr to /dev/null so child logs never corrupt MCP JSON-RPC stdout.
    if (FILE* f = std::fopen("/dev/null", "w")) {
      ::dup2(fileno(f), STDOUT_FILENO);
      ::dup2(fileno(f), STDERR_FILENO);
      std::fclose(f);
    }
    std::vector<char*> c_argv;
    c_argv.reserve(argv.size() + 1);
    for (const auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
    c_argv.push_back(nullptr);
    ::execv(c_argv[0], c_argv.data());
    _exit(127);
  }
  return pid;
}

}  // namespace

ClusterManager::~ClusterManager() {
  std::lock_guard<std::mutex> lock(mu_);
  StopLocalMeshLocked();
}

ToolResult ClusterManager::HandleDiscover(const Value& args, const SafetyConfig& safety) const {
  const std::string host = OptStr(args, "host", "127.0.0.1");
  const auto chk = ValidateMcpTarget(host, safety);
  if (!chk.ok) {
    return MakeToolError("Cluster host blocked by fail-closed MCP safety gate: " + chk.reason);
  }
  const int port = static_cast<int>(OptInt(args, "port", 8089));
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  const std::string token = ResolveToken(args, /*write_op=*/false);
  const bool include_metrics = OptBool(args, "include_metrics", false);
  const bool include_events = OptBool(args, "include_events", false);

  Value out = Value::Object();
  out.set("endpoint", Value::Str("http://" + host + ":" + std::to_string(port)));
  out.set("healthz", HttpCallLocal("GET", host, port, "/healthz", token));
  out.set("summary", HttpCallLocal("GET", host, port, "/v1/cluster/summary", token));
  out.set("workers", HttpCallLocal("GET", host, port, "/v1/cluster/workers", token));
  out.set("shards", HttpCallLocal("GET", host, port, "/v1/cluster/shards", token));
  if (include_events) {
    out.set("events", HttpCallLocal("GET", host, port, "/v1/cluster/events", token));
  }
  if (include_metrics) {
    out.set("metrics", HttpCallLocal("GET", host, port, "/metrics", token));
  }
  return MakeToolSuccess(std::move(out));
}

ToolResult ClusterManager::HandleProvisionNode(const Value& args, const SafetyConfig& safety) const {
  const std::string master_host = OptStr(args, "host", "127.0.0.1");
  const auto mchk = ValidateMcpTarget(master_host, safety);
  if (!mchk.ok) {
    return MakeToolError("Master host blocked by fail-closed MCP safety gate: " + mchk.reason);
  }
  const int port = static_cast<int>(OptInt(args, "port", 8089));
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  const std::string hosts_csv = OptStr(args, "node_hosts", OptStr(args, "hosts", ""));
  if (hosts_csv.empty()) {
    return MakeToolError("node_hosts (CSV of private/loopback IPv4 node addresses) is required.");
  }

  // Validate EVERY provisioned node IP through the fail-closed target-safety gate.
  const auto nodes = SplitCsv(hosts_csv);
  if (nodes.empty()) return MakeToolError("node_hosts cannot be empty.");
  for (const auto& ip : nodes) {
    const auto nchk = ValidateMcpTarget(ip, safety);
    if (!nchk.ok) {
      return MakeToolError("Node host '" + ip + "' blocked by fail-closed MCP safety gate: " + nchk.reason);
    }
  }

  const std::string worker_kind = LowerCopy(OptStr(args, "worker_kind", "bundle"));
  if (worker_kind != "bundle" && !IsAllowedWorker(worker_kind)) {
    return MakeToolError("Unsupported worker_kind '" + worker_kind + "'. Use 'bundle' or an allowed worker.");
  }

  Value req = Value::Object();
  req.set("hosts", Value::Str(hosts_csv));
  req.set("ssh_user", Value::Str(OptStr(args, "ssh_user", "root")));
  const std::string ssh_key = OptStr(args, "ssh_key_path", "");
  if (!ssh_key.empty()) req.set("ssh_key_path", Value::Str(ssh_key));
  req.set("worker_kind", Value::Str(worker_kind));
  const std::string region = OptStr(args, "worker_region", "");
  if (!region.empty()) req.set("worker_region", Value::Str(region));
  req.set("timeout_s", Value::Int(std::clamp<std::int64_t>(OptInt(args, "timeout_s", 10), 2, 60)));

  const std::string token = ResolveToken(args, /*write_op=*/true);
  Value out = Value::Object();
  out.set("endpoint", Value::Str("http://" + master_host + ":" + std::to_string(port) + "/v1/cluster/provision"));
  out.set("requested_nodes", Value::Str(hosts_csv));
  out.set("worker_kind", Value::Str(worker_kind));
  out.set("response", HttpCallLocal("POST", master_host, port, "/v1/cluster/provision", token, req.dump()));
  return MakeToolSuccess(std::move(out));
}

ToolResult ClusterManager::HandleReconfigure(const Value& args, const SafetyConfig& safety) const {
  const std::string host = OptStr(args, "host", "127.0.0.1");
  const auto chk = ValidateMcpTarget(host, safety);
  if (!chk.ok) {
    return MakeToolError("Master host blocked by fail-closed MCP safety gate: " + chk.reason);
  }
  const int port = static_cast<int>(OptInt(args, "port", 8089));
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  Value body = Value::Object();
  if (const std::string sid = OptStr(args, "shard_id", ""); !sid.empty()) {
    body.set("shard_id", Value::Str(sid));
  }
  if (const std::string wid = OptStr(args, "worker_id", ""); !wid.empty()) {
    body.set("worker_id", Value::Str(wid));
  }
  if (const Value* params = args.find("params"); params && params->is_object()) {
    body.set("params", *params);
  } else {
    Value p = Value::Object();
    for (const char* k : {"target_rps", "concurrency", "request_mix", "source_rotation", "pacing_mode"}) {
      if (const Value* v = args.find(k)) p.set(k, *v);
    }
    body.set("params", std::move(p));
  }

  const std::string token = ResolveToken(args, /*write_op=*/true);
  Value out = Value::Object();
  out.set("endpoint", Value::Str("http://" + host + ":" + std::to_string(port) + "/v1/shards/reconfigure"));
  out.set("response", HttpCallLocal("POST", host, port, "/v1/shards/reconfigure", token, body.dump()));
  return MakeToolSuccess(std::move(out));
}

ToolResult ClusterManager::HandleAbort(const Value& args, const SafetyConfig& safety) const {
  const std::string host = OptStr(args, "host", "127.0.0.1");
  const auto chk = ValidateMcpTarget(host, safety);
  if (!chk.ok) {
    return MakeToolError("Master host blocked by fail-closed MCP safety gate: " + chk.reason);
  }
  const int port = static_cast<int>(OptInt(args, "port", 8089));
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  const std::string token = ResolveToken(args, /*write_op=*/true);
  Value out = Value::Object();
  out.set("endpoint", Value::Str("http://" + host + ":" + std::to_string(port) + "/v1/jobs/abort"));
  out.set("response", HttpCallLocal("POST", host, port, "/v1/jobs/abort", token, "{}"));
  return MakeToolSuccess(std::move(out));
}

ToolResult ClusterManager::HandlePlanShards(const Value& args) const {
  const std::string mode = LowerCopy(OptStr(args, "mode", "packets"));
  const std::string strategy = LowerCopy(OptStr(args, "strategy", "capability"));
  const std::string target_region = OptStr(args, "target_region", "");

  std::vector<std::string> worker_ids;
  std::map<std::string, samurai::control::WorkerCapabilities> caps;
  if (const Value* warr = args.find("workers"); warr && warr->is_array()) {
    for (const auto& item : warr->elements()) {
      if (item.is_string()) {
        worker_ids.push_back(item.as_string());
      } else if (item.is_object()) {
        const std::string wid = OptStr(item, "worker_id", "");
        if (wid.empty()) continue;
        worker_ids.push_back(wid);
        samurai::control::WorkerCapabilities c;
        c.gpu_available = OptBool(item, "gpu_available", false);
        c.xdp_available = OptBool(item, "xdp_available", false);
        c.capacity_score = static_cast<int>(OptInt(item, "capacity_score", 0));
        c.region = OptStr(item, "region", "");
        caps[wid] = std::move(c);
      }
    }
  }
  if (worker_ids.empty()) {
    return MakeToolError("workers array is required (strings or objects with worker_id/region/capacity_score/gpu_available/xdp_available).");
  }

  Value out = Value::Object();
  out.set("mode", Value::Str(mode));
  out.set("strategy", Value::Str(strategy));
  out.set("worker_count", Value::Int(static_cast<std::int64_t>(worker_ids.size())));

  int total_shards = 0;
  if (mode == "telco") {
    const std::uint32_t total_subs =
        static_cast<std::uint32_t>(std::max<std::int64_t>(1, OptInt(args, "total_subscribers", 1000)));
    const std::string proto = LowerCopy(OptStr(args, "protocol", "gtpu"));
    const std::uint32_t target_cps =
        static_cast<std::uint32_t>(std::max<std::int64_t>(1, OptInt(args, "target_cps", 5000)));
    const std::string pool_name = OptStr(args, "pool_profile", "linear");
    const auto pool = samurai::control::TelcoLabSizingProfile::Preset(pool_name);

    const auto telco_shards = samurai::control::SplitTelcoSubscribers(
        total_subs, worker_ids, caps, target_region, strategy, proto, target_cps,
        100, 10, nullptr, 0x0A000001u, 0x0A0000FEu, &pool, nullptr);

    Value arr = Value::Array();
    for (const auto& s : telco_shards) arr.push_back(s.ToJson());
    total_shards = static_cast<int>(telco_shards.size());
    out.set("pool_profile", pool.ToJson());
    out.set("shards", std::move(arr));
  } else {
    const std::uint64_t total_count =
        static_cast<std::uint64_t>(std::max<std::int64_t>(1, OptInt(args, "total_count", 100000)));
    const auto shards = samurai::control::SplitJobToShards(
        total_count, worker_ids, strategy, caps, target_region, nullptr);
    Value arr = Value::Array();
    for (const auto& s : shards) {
      Value o = Value::Object();
      o.set("shard_id", Value::Str(s.shard_id));
      o.set("worker_id", Value::Str(s.worker_id));
      o.set("packet_count", Value::Int(static_cast<std::int64_t>(s.packet_count)));
      arr.push_back(std::move(o));
    }
    total_shards = static_cast<int>(shards.size());
    out.set("total_count", Value::Int(static_cast<std::int64_t>(total_count)));
    out.set("shards", std::move(arr));
  }

  // Optional native AutoscaleController recommendation.
  samurai::control::AutoscaleConfig acfg;
  acfg.enabled = true;
  acfg.min_replicas = static_cast<int>(std::max<std::int64_t>(1, OptInt(args, "min_replicas", 1)));
  acfg.max_replicas = static_cast<int>(std::max<std::int64_t>(acfg.min_replicas, OptInt(args, "max_replicas", 32)));
  acfg.shards_per_worker = static_cast<int>(std::max<std::int64_t>(1, OptInt(args, "shards_per_worker", 2)));
  acfg.step = static_cast<int>(std::max<std::int64_t>(1, OptInt(args, "scale_step", 4)));
  acfg.cooldown_s = 0.0;
  samurai::control::AutoscaleController asc(acfg);
  const int pending = static_cast<int>(OptInt(args, "pending_shards", total_shards));
  const int inflight = static_cast<int>(OptInt(args, "inflight_shards", 0));
  const auto dec = asc.MaybeScale(pending, inflight, static_cast<int>(worker_ids.size()));

  Value as_json = Value::Object();
  as_json.set("current_workers", Value::Int(static_cast<std::int64_t>(worker_ids.size())));
  as_json.set("desired_replicas", Value::Int(dec.desired));
  as_json.set("recommended_next_step", Value::Int(dec.applied));
  as_json.set("changed", Value::Bool(dec.changed));
  as_json.set("reason", Value::Str(dec.reason));
  out.set("autoscale_recommendation", std::move(as_json));

  return MakeToolSuccess(std::move(out));
}

void ClusterManager::ReapExitedLocked() {
  if (master_pid_ > 0 && !IsPidAlive(master_pid_)) {
    master_pid_ = -1;
  }
  slaves_.erase(
      std::remove_if(slaves_.begin(), slaves_.end(),
                     [](const LocalSlave& s) { return !IsPidAlive(s.pid); }),
      slaves_.end());
}

void ClusterManager::StopLocalMeshLocked() {
  for (const auto& s : slaves_) {
    TerminatePid(s.pid);
  }
  slaves_.clear();
  if (master_pid_ > 0) {
    TerminatePid(master_pid_);
    master_pid_ = -1;
  }
}

pid_t ClusterManager::SpawnLocalSlaveLocked(const std::string& slave_bin,
                                            const std::string& worker_id,
                                            const std::string& worker_kind,
                                            const std::string& region) {
  std::vector<std::string> cmd = {
      slave_bin,
      "--control-endpoints", "127.0.0.1:" + std::to_string(control_port_),
      "--dispatch-mode", "reverse",
      "--worker", worker_kind,
      "--worker-id", worker_id,
      "--worker-region", region,
      "--heartbeat-interval-ms", "1000",
      "--master-timeout-s", "60",
  };
  std::vector<std::pair<std::string, std::string>> env;
  if (!cluster_secret_.empty()) {
    env.emplace_back("SAMURAI_CLUSTER_SECRET", cluster_secret_);
  }
  return SpawnDetachedQuiet(cmd, env);
}

Value ClusterManager::LocalMeshSummaryLocked() const {
  Value out = Value::Object();
  out.set("running", Value::Bool(master_pid_ > 0));
  out.set("master_pid", Value::Int(master_pid_));
  out.set("control_endpoint", Value::Str("tcp://127.0.0.1:" + std::to_string(control_port_)));
  out.set("management_endpoint", Value::Str("http://127.0.0.1:" + std::to_string(mgmt_port_)));
  out.set("slave_count", Value::Int(static_cast<std::int64_t>(slaves_.size())));

  Value arr = Value::Array();
  for (const auto& s : slaves_) {
    Value o = Value::Object();
    o.set("worker_id", Value::Str(s.worker_id));
    o.set("worker_kind", Value::Str(s.worker_kind));
    o.set("region", Value::Str(s.region));
    o.set("pid", Value::Int(s.pid));
    arr.push_back(std::move(o));
  }
  out.set("slaves", std::move(arr));
  return out;
}

ToolResult ClusterManager::HandleLocalMesh(const Value& args) {
  const std::string action = LowerCopy(OptStr(args, "action", "status"));
  std::lock_guard<std::mutex> lock(mu_);
  ReapExitedLocked();

  if (action == "status") {
    return MakeToolSuccess(LocalMeshSummaryLocked());
  }

  if (action == "stop") {
    StopLocalMeshLocked();
    Value out = LocalMeshSummaryLocked();
    out.set("stopped", Value::Bool(true));
    return MakeToolSuccess(std::move(out));
  }

  const std::string master_bin = FindNativeBinary({"samurai_master"});
  const std::string slave_bin = FindNativeBinary({"samurai_slave"});
  if (master_bin.empty() || slave_bin.empty()) {
    return MakeToolError("samurai_master / samurai_slave binaries not found. Build via CMake first.");
  }

  if (action == "start") {
    if (master_pid_ > 0) {
      StopLocalMeshLocked();
    }
    control_port_ = static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "control_port", 5099), 1024, 65535));
    mgmt_port_ = static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "management_port", 8089), 1024, 65535));
    cluster_secret_ = OptStr(args, "cluster_secret", "samurai-mcp-local-secret");
    admin_token_ = OptStr(args, "admin_token", "samurai-mcp-local-admin");
    const int desired_slaves = static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "slaves", 2), 0, 16));
    const std::string worker_kind = LowerCopy(OptStr(args, "worker_kind", "bundle"));
    const std::string region = OptStr(args, "worker_region", "local-lab");
    if (worker_kind != "bundle" && !IsAllowedWorker(worker_kind)) {
      return MakeToolError("Unsupported worker_kind: " + worker_kind);
    }

    // Bind strictly on 127.0.0.1 (fail-closed loopback-only lab mesh).
    std::vector<std::string> mcmd = {
        master_bin,
        "--control-listen", "tcp://127.0.0.1:" + std::to_string(control_port_),
        "--management-listen", "127.0.0.1:" + std::to_string(mgmt_port_),
        "--count", "0",
        "--worker", worker_kind == "bundle" ? "cpu" : worker_kind,
        "--target", "127.0.0.1",
        "--port", "80",
    };
    std::vector<std::pair<std::string, std::string>> menv = {
        {"SAMURAI_CLUSTER_SECRET", cluster_secret_},
        {"SAMURAI_MANAGEMENT_API_ADMIN_TOKEN", admin_token_},
        {"SAMURAI_MANAGEMENT_API_VIEWER_TOKEN", admin_token_},
    };
    master_pid_ = SpawnDetachedQuiet(mcmd, menv);
    if (master_pid_ <= 0) {
      return MakeToolError("Failed to fork/exec samurai_master");
    }

    // Wait briefly for management API /healthz to become reachable (up to 1.5s).
    bool healthy = false;
    for (int i = 0; i < 15; ++i) {
      const Value hz = HttpCallLocal("GET", "127.0.0.1", mgmt_port_, "/healthz", admin_token_);
      if (const Value* st = hz.find("http_status"); st && st->as_int(0) == 200) {
        healthy = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (int i = 0; i < desired_slaves; ++i) {
      const std::string wid = "mcp-slave-" + std::to_string(next_slave_seq_++);
      const pid_t spid = SpawnLocalSlaveLocked(slave_bin, wid, worker_kind, region);
      if (spid > 0) {
        slaves_.push_back(LocalSlave{wid, worker_kind, region, spid});
      }
    }

    Value out = LocalMeshSummaryLocked();
    out.set("master_healthy", Value::Bool(healthy));
    out.set("auth_token", Value::Str(admin_token_));
    return MakeToolSuccess(std::move(out));
  }

  if (action == "scale") {
    if (master_pid_ <= 0) {
      return MakeToolError("Local mesh is not running. Call with action='start' first.");
    }
    const int desired = static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "slaves", 2), 0, 16));
    const std::string worker_kind = LowerCopy(OptStr(args, "worker_kind", "bundle"));
    const std::string region = OptStr(args, "worker_region", "local-lab");
    if (worker_kind != "bundle" && !IsAllowedWorker(worker_kind)) {
      return MakeToolError("Unsupported worker_kind: " + worker_kind);
    }

    while (static_cast<int>(slaves_.size()) < desired) {
      const std::string wid = "mcp-slave-" + std::to_string(next_slave_seq_++);
      const pid_t spid = SpawnLocalSlaveLocked(slave_bin, wid, worker_kind, region);
      if (spid <= 0) break;
      slaves_.push_back(LocalSlave{wid, worker_kind, region, spid});
    }
    while (static_cast<int>(slaves_.size()) > desired) {
      TerminatePid(slaves_.back().pid);
      slaves_.pop_back();
    }

    Value out = LocalMeshSummaryLocked();
    out.set("scaled_to", Value::Int(static_cast<std::int64_t>(slaves_.size())));
    return MakeToolSuccess(std::move(out));
  }

  return MakeToolError("Invalid action '" + action + "'. Expected: start, scale, status, or stop.");
}

}  // namespace samurai::mcp
