// samurai_slave — distributed slave daemon.
//
// Native replacement for the run_distributed_slave entrypoint: serve a worker
// control server (so the master can drive shards), register with the master and
// heartbeat, and execute dispatched shards via the ZMQ worker supervisor.

#include <atomic>
#include <csignal>
#include <cstdio>
#include <map>
#include <string>

#include <unistd.h>

#include "control_client.hpp"
#include "control_server.hpp"
#include "control_auth.hpp"
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

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --control-endpoints host:port[,host:port] [options]\n"
      "  --control-endpoints EPS   master control endpoints (required)\n"
      "  --control-listen EP       this worker's control bind (default tcp://0.0.0.0:0)\n"
      "  --advertise EP            control endpoint advertised to the master\n"
      "                            (default: resolved from --control-listen)\n"
      "  --cluster-secret S        cluster secret\n"
      "  --tenant-namespace T      tenant namespace\n"
      "  --worker-id ID            worker id (default: hostname)\n"
      "  --worker-region R         worker region capability\n"
      "  --worker NAME             dataplane worker kind (default: cpu)\n"
      "  --worker-dir DIR          directory with the worker binaries (default: .)\n"
      "  --heartbeat-interval-ms N (default 2000)\n"
      "  --register-timeout-s N    (default 10)\n"
      "  --master-timeout-s N      exit if master unreachable this long (default 30)\n"
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
  const auto entry = samurai::orchestrator::LookupWorker(worker_kind);
  if (!entry) {
    std::fprintf(stderr, "samurai_slave: unknown worker kind: %s\n", worker_kind.c_str());
    return 2;
  }
  const std::string worker_dir = Opt(argc, argv, "--worker-dir", ".");
  const std::string listen = Opt(argc, argv, "--control-listen", "tcp://0.0.0.0:0");
  const std::string cluster_secret = Opt(argc, argv, "--cluster-secret", "");
  const std::string tenant = Opt(argc, argv, "--tenant-namespace", "");
  const std::string worker_id = Opt(argc, argv, "--worker-id", Hostname());
  const std::string region = Opt(argc, argv, "--worker-region", "");

  // Worker-side control service + server.
  SupervisorShardRunner runner(*entry, worker_dir);
  WorkerShardService service(worker_id, &runner);
  AuthConfig auth;
  auth.expected_secret = cluster_secret;  // require the secret if set
  ControlServer server(listen, &service, auth);
  if (!server.Start()) {
    std::fprintf(stderr, "samurai_slave: failed to bind control server on %s\n", listen.c_str());
    return 1;
  }
  std::string advertise = Opt(argc, argv, "--advertise", server.endpoint());

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  // Register + heartbeat with the master.
  SlaveControlClient client(endpoints, cluster_secret, tenant);
  SlaveConfig cfg;
  cfg.worker_id = worker_id;
  cfg.hostname = worker_id;
  cfg.capabilities["control_endpoint"] = advertise;
  if (!region.empty()) cfg.capabilities["region"] = region;
  if (!tenant.empty()) cfg.capabilities["tenant_namespace"] = tenant;
  cfg.register_timeout_s = static_cast<int>(OptInt(argc, argv, "--register-timeout-s", 10));
  cfg.heartbeat_interval_ms = static_cast<int>(OptInt(argc, argv, "--heartbeat-interval-ms", 2000));
  cfg.master_timeout_s = static_cast<int>(OptInt(argc, argv, "--master-timeout-s", 30));
  SlaveNode node(&client, cfg);

  if (!node.Register()) {
    std::fprintf(stderr, "samurai_slave: registration with master failed (endpoints=%s)\n",
                 endpoints.c_str());
    server.Stop();
    return 1;
  }
  std::printf("samurai_slave: registered worker_id=%s control_endpoint=%s\n", worker_id.c_str(),
              advertise.c_str());
  std::fflush(stdout);

  node.RunHeartbeatLoop([]() { return !g_stop.load(); });

  server.Stop();
  std::printf("samurai_slave: shutdown\n");
  return 0;
}
