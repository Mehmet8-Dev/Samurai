// samurai_master — distributed master daemon.
//
// Native replacement for the run_distributed_master entrypoint: optionally win
// HA leadership, serve the control server (workers register/heartbeat/report),
// optionally expose the HTTP management API, wait for workers, then split and
// dispatch one job across the cluster and print the aggregated snapshot.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

#include "control_auth.hpp"
#include "control_server.hpp"
#include "daemon_args.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "management_api.hpp"
#include "master_adapters.hpp"
#include "master_coordinator.hpp"
#include "servicer.hpp"

namespace {
std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

using samurai::core::json::Value;

Value BuildState(samurai::control::Servicer* svc) {
  Value st = Value::Object();
  Value workers = Value::Array();
  for (const auto& w : svc->SnapshotWorkers()) {
    Value o = Value::Object();
    o.set("worker_id", Value::Str(w.worker_id));
    o.set("last_heartbeat_ms", Value::Int(w.last_heartbeat_ms));
    auto rit = w.capabilities.find("region");
    if (rit != w.capabilities.end()) o.set("region", Value::Str(rit->second));
    auto tit = w.capabilities.find("tenant_namespace");
    if (tit != w.capabilities.end()) o.set("tenant_namespace", Value::Str(tit->second));
    workers.push_back(std::move(o));
  }
  st.set("workers", std::move(workers));
  return st;
}

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --count N [options]\n"
      "  --control-listen EP       control server bind (default tcp://0.0.0.0:5099)\n"
      "  --cluster-secret S        cluster secret\n"
      "  --tenant-namespace T      tenant namespace\n"
      "  --count N                 total packets for the job (required, > 0)\n"
      "  --target IP               target ipv4 (default 127.0.0.1)\n"
      "  --port N                  target port (default 80)\n"
      "  --protocol P              l4 protocol (default udp)\n"
      "  --size N                  packet size (default 64)\n"
      "  --shard-unit-count N      packets per shard (0 = auto)\n"
      "  --job-timeout-s N         wait cap for the job (default 120)\n"
      "  --poll-interval-ms N      master dispatch poll (default 250)\n"
      "  --expect-workers N        wait for this many workers first (default 1)\n"
      "  --wait-workers-s N        how long to wait for workers (default 30)\n"
      "  --management-listen EP    also serve the HTTP management API (host:port)\n"
      "  --ha-mode MODE            static | file-lock (default off)\n"
      "  --ha-node-id ID           this node's id\n"
      "  --ha-peers CSV            peer node ids (static mode)\n"
      "  --ha-lease-path PATH      lease file (file-lock mode)\n"
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
  const long count = OptInt(argc, argv, "--count", 0);
  if (count <= 0) {
    std::fprintf(stderr, "samurai_master: --count must be > 0\n");
    return 2;
  }

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  // HA leadership (optional).
  std::unique_ptr<LeaderElector> elector;
  std::int64_t leader_epoch = 0;
  const std::string ha_mode = Opt(argc, argv, "--ha-mode", "off");
  if (ha_mode == "static") {
    elector = std::make_unique<StaticLeaderElector>(Opt(argc, argv, "--ha-node-id", ""),
                                                    Opt(argc, argv, "--ha-peers", ""));
  } else if (ha_mode == "file-lock") {
    elector = std::make_unique<FileLeaseLeaderElector>(
        Opt(argc, argv, "--ha-node-id", ""),
        Opt(argc, argv, "--ha-lease-path", "/tmp/ddos_samurai_master_lease.json"), 15.0);
  }
  if (elector) {
    if (!elector->TryAcquire() || !elector->IsLeader()) {
      std::printf("samurai_master: not leader (%s); skipping master run\n",
                  elector->Snapshot().dump().c_str());
      return 0;
    }
    elector->StartRenewLoop(5.0);
    leader_epoch = elector->LeaderEpoch();
  }

  // Control server.
  const std::string cluster_secret = Opt(argc, argv, "--cluster-secret", "");
  const std::string tenant = Opt(argc, argv, "--tenant-namespace", "");
  ServicerConfig scfg;
  scfg.tenant_namespace = tenant;
  Servicer servicer(scfg);
  AuthConfig auth;
  auth.expected_secret = cluster_secret;
  ControlServer server(Opt(argc, argv, "--control-listen", "tcp://0.0.0.0:5099"), &servicer, auth);
  if (!server.Start()) {
    std::fprintf(stderr, "samurai_master: failed to bind control server\n");
    return 1;
  }
  std::printf("samurai_master: control server on %s\n", server.endpoint().c_str());

  // Management API (optional).
  std::unique_ptr<ManagementApiServer> mgmt;
  const std::string mgmt_listen = Opt(argc, argv, "--management-listen", "");
  if (!mgmt_listen.empty()) {
    ManagementConfig mcfg;
    mcfg.tenant_namespace = tenant;
    ManagementProviders providers;
    providers.state_provider = [&servicer]() { return BuildState(&servicer); };
    providers.abort_callback = []() {
      Value r = Value::Object();
      r.set("aborted", Value::Bool(true));
      return r;
    };
    mgmt = std::make_unique<ManagementApiServer>(mgmt_listen, mcfg, providers);
    if (mgmt->Start()) {
      std::printf("samurai_master: management api on %s\n", mgmt->endpoint().c_str());
    }
  }

  // Wait for workers.
  const long expect = OptInt(argc, argv, "--expect-workers", 1);
  const double wait_deadline =
      std::chrono::duration_cast<std::chrono::duration<double>>(
          std::chrono::system_clock::now().time_since_epoch())
          .count() +
      static_cast<double>(OptInt(argc, argv, "--wait-workers-s", 30));
  while (!g_stop.load() && static_cast<long>(servicer.worker_count()) < expect) {
    const double now = std::chrono::duration_cast<std::chrono::duration<double>>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    if (now >= wait_deadline) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (static_cast<long>(servicer.worker_count()) < expect) {
    std::fprintf(stderr, "samurai_master: only %zu/%ld workers registered; proceeding\n",
                 servicer.worker_count(), expect);
  }

  // Build + dispatch the job.
  ServicerMasterView view(&servicer);
  ClientWorkerCommander commander(cluster_secret, tenant);
  MasterCoordinator coord(&view, &commander);

  JobConfig job;
  job.count = count;
  job.job_timeout_s = OptInt(argc, argv, "--job-timeout-s", 0);
  job.shard_unit_count = OptInt(argc, argv, "--shard-unit-count", 0);
  job.master_poll_interval_ms = static_cast<int>(OptInt(argc, argv, "--poll-interval-ms", 250));
  job.tenant_namespace = tenant;
  job.leader_epoch = leader_epoch;
  job.base_args = Value::Object();
  job.base_args.set("target", Value::Str(Opt(argc, argv, "--target", "127.0.0.1")));
  job.base_args.set("port", Value::Int(OptInt(argc, argv, "--port", 80)));
  job.base_args.set("protocol", Value::Str(Opt(argc, argv, "--protocol", "udp")));
  job.base_args.set("size", Value::Int(OptInt(argc, argv, "--size", 64)));

  const JobResult res = coord.RunSingleJob(job, "job-1", [&elector]() {
    return !elector || elector->IsLeader();
  });
  std::printf("%s\n", res.snapshot.dump().c_str());

  if (mgmt) mgmt->Stop();
  server.Stop();
  if (elector) elector->Stop();
  return res.rc;
}
