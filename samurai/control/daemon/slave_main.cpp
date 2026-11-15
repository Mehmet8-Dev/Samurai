// samurai_slave — distributed slave daemon.
//
// Native replacement for the run_distributed_slave entrypoint: serve a worker
// control server (so the master can drive shards), register with the master and
// heartbeat, and execute dispatched shards via the ZMQ worker supervisor.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <map>
#include <memory>
#include <string>

#include <unistd.h>

#include "control_client.hpp"
#include "control_server.hpp"
#include "control_auth.hpp"
#include "curve.hpp"
#include "daemon_args.hpp"
#include "slave_node.hpp"
#include "supervisor_shard_runner.hpp"
#include "worker_registry.hpp"
#include "worker_shard_service.hpp"

namespace {
std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

std::string Hostname() {
  char buf[256] = {0};
  if (::gethostname(buf, sizeof(buf) - 1) == 0 && buf[0]) return std::string(buf);
  return "localhost";
}

class MockShardRun : public samurai::control::ShardRun {
 public:
  MockShardRun(std::int64_t count, int delay_ms)
      : count_(count), delay_ms_(delay_ms) {
    thread_ = std::thread([this]() {
      if (delay_ms_ > 0) {
        int slept = 0;
        while (slept < delay_ms_ && !term_.load()) {
          int step = std::min(10, delay_ms_ - slept);
          std::this_thread::sleep_for(std::chrono::milliseconds(step));
          slept += step;
          sent_.store(count_ * slept / delay_ms_);
        }
      }
      if (!term_.load()) {
        sent_.store(count_);
        done_.store(true);
      }
      alive_.store(false);
    });
  }

  ~MockShardRun() override {
    if (thread_.joinable()) thread_.join();
  }

  bool IsAlive() override { return alive_.load(); }
  std::int64_t Progress() const override { return sent_.load(); }
  std::int64_t Sent() const override { return sent_.load(); }
  std::int64_t Errors() const override { return 0; }
  int ExitCode() const override { return term_.load() ? -15 : 0; }
  void Terminate() override {
    term_.store(true);
    alive_.store(false);
  }
  void Join() override {
    if (thread_.joinable()) thread_.join();
  }

 private:
  std::int64_t count_ = 0;
  int delay_ms_ = 0;
  std::atomic<bool> alive_{true};
  std::atomic<bool> done_{false};
  std::atomic<bool> term_{false};
  std::atomic<std::int64_t> sent_{0};
  std::thread thread_;
};

class MockShardRunner : public samurai::control::ShardRunner {
 public:
  explicit MockShardRunner(int default_delay_ms = 100) : default_delay_ms_(default_delay_ms) {}
  std::shared_ptr<samurai::control::ShardRun> Start(
      const std::string&, const samurai::core::json::Value& args) override {
    const auto* c = args.find("count");
    std::int64_t count = c ? c->as_int(1000) : 1000;
    const auto* d = args.find("_mock_delay_ms");
    int delay = d ? static_cast<int>(d->as_int(default_delay_ms_)) : default_delay_ms_;
    return std::make_shared<MockShardRun>(count, delay);
  }

 private:
  int default_delay_ms_ = 100;
};

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --control-endpoints host:port[,host:port] [options]\n"
      "  --control-endpoints EPS   master control endpoints (required)\n"
      "  --control-listen EP       this worker's control bind (default tcp://0.0.0.0:0)\n"
      "  --advertise EP            control endpoint advertised to the master\n"
      "                            (default: resolved from --control-listen)\n"
      "  --dispatch-mode MODE      direct | reverse | auto (default direct)\n"
      "                            reverse = pull shards over the heartbeat channel\n"
      "                            (no inbound server); auto = inbound server +\n"
      "                            reverse fallback if the master can't reach it\n"
      "  --reverse                 alias for --dispatch-mode reverse\n"
      "  --cluster-secret S        cluster secret (or env SAMURAI_CLUSTER_SECRET)\n"
      "  --tenant-namespace T      tenant namespace\n"
      "  --curve-server-public K   master CURVE public key (Z85) — encrypts the\n"
      "                            outbound channel; required if master uses CURVE\n"
      "  --gen-control-curve       generate a CURVE keypair for this worker's\n"
      "                            inbound control server (direct/auto) and\n"
      "                            advertise its public key so the master encrypts\n"
      "                            direct StartShard/StopShard/Probe RPCs\n"
      "  --worker-id ID            worker id (default: hostname)\n"
      "  --worker-region R         worker region capability\n"
      "  --worker NAME             dataplane worker kind, or 'bundle' to hold all\n"
      "                            binaries and pick per shard (default: cpu)\n"
      "  --worker-dir DIR          directory with the worker binaries (default: .)\n"
      "  --heartbeat-interval-ms N (default 2000)\n"
      "  --register-timeout-s N    (default 10)\n"
      "  --master-timeout-s N      exit if master unreachable this long (default 30)\n"
      "  --mock                    run in simulated/mock shard execution mode (for HA chaos tests)\n"
      "  --mock-delay-ms N         simulated execution delay per shard in ms (default 100)\n"
      "  -h, --help\n",
      argv0);
}
}  // namespace

int main(int argc, char** argv) {
  using namespace samurai::control;
  using namespace samurai::control::daemon;

  if (Flag(argc, argv, "-h") || Flag(argc, argv, "--help")) {
    Usage(argv[0]);
    return 0;
  }
  const std::string endpoints = Opt(argc, argv, "--control-endpoints", "");
  if (endpoints.empty()) {
    std::fprintf(stderr, "samurai_slave: --control-endpoints is required\n");
    return 2;
  }
  const std::string worker_kind = Opt(argc, argv, "--worker", "cpu");
  const bool is_mock = Flag(argc, argv, "--mock") || (worker_kind == "mock");
  // Bundle: the node holds every worker binary and resolves the flavor per shard
  // from the job's `worker` field; a fixed kind runs that one flavor for all shards.
  const bool bundle = samurai::orchestrator::IsBundleWorkerName(worker_kind);
  const auto entry = is_mock ? std::nullopt : samurai::orchestrator::LookupWorker(bundle ? "cpu" : worker_kind);
  if (!is_mock && !entry) {
    std::fprintf(stderr, "samurai_slave: unknown worker kind: %s\n", worker_kind.c_str());
    return 2;
  }
  const std::string worker_dir = Opt(argc, argv, "--worker-dir", ".");
  const std::string listen = Opt(argc, argv, "--control-listen", "tcp://0.0.0.0:0");
  const std::string cluster_secret =
      OptOrEnv(argc, argv, "--cluster-secret", "SAMURAI_CLUSTER_SECRET");
  const std::string tenant = Opt(argc, argv, "--tenant-namespace", "");
  const std::string worker_id = Opt(argc, argv, "--worker-id", Hostname());
  const std::string region = Opt(argc, argv, "--worker-region", "");

  // Dispatch mode: direct (inbound server), reverse (pull-only), or auto
  // (inbound server + reverse-capable, so the master can fall back to pull if
  // direct is unreachable). --reverse is kept as an alias for backward compat.
  std::string mode = Opt(argc, argv, "--dispatch-mode", "");
  if (mode.empty()) mode = Flag(argc, argv, "--reverse") ? "reverse" : "direct";
  if (mode != "direct" && mode != "reverse" && mode != "auto") {
    std::fprintf(stderr, "samurai_slave: invalid --dispatch-mode '%s' (direct|reverse|auto)\n",
                 mode.c_str());
    return 2;
  }
  const bool wants_server = (mode != "reverse");  // direct + auto bind an inbound server
  const bool wants_pull = (mode != "direct");     // reverse + auto wire the pull path

  // Register/heartbeat client (outbound) + a dedicated client for reverse
  // completion reports. `reporter` is declared before `service` so it outlives
  // the service destructor, which joins monitor threads that may report.
  SlaveControlClient client(endpoints, cluster_secret, tenant);
  SlaveControlClient reporter(endpoints, cluster_secret, tenant);
  const std::string curve_pub = Opt(argc, argv, "--curve-server-public", "");
  if (!curve_pub.empty()) {
    if (!client.set_curve_client(curve_pub) || !reporter.set_curve_client(curve_pub)) {
      std::fprintf(stderr, "samurai_slave: CURVE not supported by this libzmq build\n");
      return 1;
    }
    std::printf("samurai_slave: CURVE encryption enabled toward the master\n");
  }

  // Worker-side control service (+ inbound control server only in direct mode).
  // Bundle resolves the worker binary per shard (fallback = cpu); fixed runs one.
  std::unique_ptr<ShardRunner> custom_runner;
  std::unique_ptr<SupervisorShardRunner> sup_runner;
  ShardRunner* active_runner = nullptr;
  if (is_mock) {
    const int mock_delay = static_cast<int>(OptInt(argc, argv, "--mock-delay-ms", 100));
    custom_runner = std::make_unique<MockShardRunner>(mock_delay);
    active_runner = custom_runner.get();
  } else {
    sup_runner = std::make_unique<SupervisorShardRunner>(
        bundle ? SupervisorShardRunner(worker_dir, *entry)
               : SupervisorShardRunner(*entry, worker_dir));
    active_runner = sup_runner.get();
  }
  WorkerShardService service(worker_id, active_runner);
  AuthConfig auth;
  auth.expected_secret = cluster_secret;  // require the secret if set

  std::unique_ptr<ControlServer> server;
  std::string advertise;
  std::string control_curve_public;  // advertised so the master encrypts direct RPCs
  const bool gen_control_curve = Flag(argc, argv, "--gen-control-curve");
  if (wants_server) {
    server = std::make_unique<ControlServer>(listen, &service, auth);
    if (gen_control_curve) {
      const CurveKeypair kp = GenerateCurveKeypair();
      if (!kp.ok) {
        std::fprintf(stderr, "samurai_slave: CURVE not supported by this libzmq build\n");
        return 1;
      }
      server->set_curve_server(kp.secret_key);
      control_curve_public = kp.public_key;
    }
    if (!server->Start()) {
      std::fprintf(stderr, "samurai_slave: failed to bind control server on %s\n", listen.c_str());
      return 1;
    }
    advertise = Opt(argc, argv, "--advertise", server->endpoint());
    if (gen_control_curve) {
      std::printf("samurai_slave: inbound control CURVE enabled (public=%s)\n",
                  control_curve_public.c_str());
    }
  }

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  SlaveConfig cfg;
  cfg.worker_id = worker_id;
  cfg.hostname = worker_id;
  if (mode == "reverse") {
    cfg.capabilities["dispatch_mode"] = "reverse";  // no control_endpoint advertised
  } else if (mode == "auto") {
    cfg.capabilities["dispatch_mode"] = "auto";     // reverse-capable + endpoint below
    cfg.capabilities["control_endpoint"] = advertise;
  } else {
    cfg.capabilities["control_endpoint"] = advertise;
  }
  // Advertise the inbound control server's CURVE public key so the master can
  // encrypt direct StartShard/StopShard/Probe RPCs toward this worker.
  if (!control_curve_public.empty()) {
    cfg.capabilities["control_curve_public"] = control_curve_public;
  }
  if (!region.empty()) cfg.capabilities["region"] = region;
  if (!tenant.empty()) cfg.capabilities["tenant_namespace"] = tenant;
  // Advertise which worker flavors this node can run so the master only dispatches
  // matching shards. Bundle nodes list the whole catalog; fixed nodes list one.
  if (bundle) {
    std::string kinds;
    for (const auto& e : samurai::orchestrator::kWorkerTable) {
      if (!kinds.empty()) kinds += ",";
      kinds += e.name;
    }
    cfg.capabilities["worker_kinds"] = kinds;
  } else if (is_mock) {
    cfg.capabilities["worker_kinds"] = (worker_kind == "mock") ? "mock,cpu" : (worker_kind + ",cpu");
  } else {
    cfg.capabilities["worker_kinds"] = worker_kind;
  }
  cfg.register_timeout_s = static_cast<int>(OptInt(argc, argv, "--register-timeout-s", 10));
  // Auto-tune: reverse/auto workers pull work on the heartbeat, so default to a
  // tighter interval for low dispatch latency (still overridable).
  const long hb_default = wants_pull ? 500 : 2000;
  cfg.heartbeat_interval_ms =
      static_cast<int>(OptInt(argc, argv, "--heartbeat-interval-ms", hb_default));
  cfg.master_timeout_s = static_cast<int>(OptInt(argc, argv, "--master-timeout-s", 30));
  SlaveNode node(&client, cfg);

  if (wants_pull) {
    // Pull shards from the heartbeat body and run them through the same
    // WorkerShardService::StartShard the master would drive over RPC in direct
    // mode; report completion back over the outbound channel.
    node.set_on_start([&service](const samurai::core::json::Value& shard) {
      service.StartShard(shard, RpcContext{});
    });
    node.set_on_stop([&service](const std::string& sid, std::int64_t leader_epoch) {
      samurai::core::json::Value b = samurai::core::json::Value::Object();
      b.set("shard_id", samurai::core::json::Value::Str(sid));
      b.set("_leader_epoch", samurai::core::json::Value::Int(leader_epoch));
      service.StopShard(b, RpcContext{});
    });
    node.set_on_reconfigure([&service](const samurai::core::json::Value& reconf) {
      service.ReconfigureShard(reconf, RpcContext{});
    });
    node.set_active_shard_provider([&service]() { return service.ActiveShardId(); });
    service.set_on_finalize([&reporter, worker_id](const std::string& sid, const std::string& stats) {
      const long long now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
      reporter.ReportStats(worker_id, sid, stats, now_ms);
    });
  }

  if (!node.Register()) {
    std::fprintf(stderr, "samurai_slave: registration with master failed (endpoints=%s)\n",
                 endpoints.c_str());
    if (server) server->Stop();
    return 1;
  }
  if (mode == "reverse") {
    std::printf("samurai_slave: registered worker_id=%s mode=reverse\n", worker_id.c_str());
  } else {
    std::printf("samurai_slave: registered worker_id=%s mode=%s control_endpoint=%s\n",
                worker_id.c_str(), mode.c_str(), advertise.c_str());
  }
  std::fflush(stdout);

  node.RunHeartbeatLoop([]() { return !g_stop.load(); });

  if (server) server->Stop();
  std::printf("samurai_slave: shutdown\n");
  return 0;
}
