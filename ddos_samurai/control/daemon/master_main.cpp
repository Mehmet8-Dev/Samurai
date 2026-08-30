// samurai_master — distributed master daemon.
//
// Native replacement for the run_distributed_master entrypoint: optionally win
// HA leadership, serve the control server (workers register/heartbeat/report),
// optionally expose the HTTP management API, wait for workers, then split and
// dispatch one job across the cluster and print the aggregated snapshot.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "autoscale.hpp"
#include "control_auth.hpp"
#include "control_server.hpp"
#include "curve.hpp"
#include "daemon_args.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "management_api.hpp"
#include "master_adapters.hpp"
#include "master_coordinator.hpp"
#include "multimaster.hpp"
#include "redis_kvstore.hpp"
#include "servicer.hpp"

namespace {
std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

using samurai::core::json::Value;

std::string LowerCopy(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

// `mm` (nullable) surfaces the federated region snapshots for the management API
// `multi_master_regions` field; nullptr / inactive => the field is omitted.
// `autoscale_json` (nullable) is the latest autoscale decision object; when set
// it is attached as the `autoscale` field.
Value BuildState(samurai::control::Servicer* svc,
                 samurai::control::RedisMultiMasterCoordinator* mm = nullptr,
                 const Value* autoscale_json = nullptr) {
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
  if (mm && mm->active()) {
    Value regions = Value::Array();
    for (auto& snap : mm->LatestRegionSnapshots()) regions.push_back(std::move(snap));
    st.set("multi_master_regions", std::move(regions));
  }
  if (autoscale_json && autoscale_json->is_object()) {
    st.set("autoscale", *autoscale_json);
  }
  return st;
}

// Serialize an autoscale decision (+ its static target identity) into the JSON
// object surfaced by the management API.
Value AutoscaleStateJson(const samurai::control::AutoscaleDecision& d,
                         const std::string& target_name, const std::string& target_kind) {
  Value o = Value::Object();
  o.set("enabled", Value::Bool(d.enabled));
  o.set("changed", Value::Bool(d.changed));
  o.set("reason", Value::Str(d.reason));
  o.set("has_values", Value::Bool(d.has_values));
  o.set("current", Value::Int(d.current));
  o.set("desired", Value::Int(d.desired));
  o.set("applied", Value::Int(d.applied));
  o.set("target_name", Value::Str(target_name));
  o.set("target_kind", Value::Str(target_kind));
  // The live K8s read/patch backend is deferred; `current`/`applied` are the
  // controller's in-memory replica model, not an observed cluster value.
  o.set("backend", Value::Str("in-memory"));
  return o;
}

// Collect the job parameters (CLI or delegated) into a single JSON spec so both
// the local and cross-region delegated paths build a JobConfig the same way.
Value JobSpecFromArgs(int argc, char** argv) {
  using namespace samurai::control::daemon;
  Value s = Value::Object();
  s.set("count", Value::Int(OptInt(argc, argv, "--count", 0)));
  s.set("target", Value::Str(Opt(argc, argv, "--target", "127.0.0.1")));
  s.set("port", Value::Int(OptInt(argc, argv, "--port", 80)));
  s.set("protocol", Value::Str(Opt(argc, argv, "--protocol", "udp")));
  s.set("size", Value::Int(OptInt(argc, argv, "--size", 64)));
  s.set("worker", Value::Str(Opt(argc, argv, "--worker", "cpu")));
  s.set("target_region", Value::Str(Opt(argc, argv, "--target-region", "")));
  s.set("job_timeout_s", Value::Int(OptInt(argc, argv, "--job-timeout-s", 0)));
  s.set("shard_unit_count", Value::Int(OptInt(argc, argv, "--shard-unit-count", 0)));
  s.set("poll_interval_ms", Value::Int(OptInt(argc, argv, "--poll-interval-ms", 250)));
  return s;
}

samurai::control::JobConfig BuildJobConfig(const Value& spec, std::int64_t leader_epoch,
                                           const std::string& tenant,
                                           const std::string& master_region) {
  auto geti = [&](const char* k, std::int64_t d) {
    const Value* v = spec.find(k);
    return v ? v->as_int(d) : d;
  };
  auto gets = [&](const char* k, const char* d) {
    const Value* v = spec.find(k);
    return v ? v->as_string(d) : std::string(d);
  };
  samurai::control::JobConfig job;
  job.count = geti("count", 0);
  job.job_timeout_s = geti("job_timeout_s", 0);
  job.shard_unit_count = geti("shard_unit_count", 0);
  job.master_poll_interval_ms = static_cast<int>(geti("poll_interval_ms", 250));
  job.tenant_namespace = tenant;
  job.leader_epoch = leader_epoch;
  const std::string tr = LowerCopy(gets("target_region", ""));
  job.target_region = tr;
  job.worker_region = master_region;
  job.region_aware_routing = !tr.empty();
  if (!tr.empty()) job.shard_strategy = "region";
  job.base_args = Value::Object();
  job.base_args.set("target", Value::Str(gets("target", "127.0.0.1")));
  job.base_args.set("port", Value::Int(geti("port", 80)));
  job.base_args.set("protocol", Value::Str(gets("protocol", "udp")));
  job.base_args.set("size", Value::Int(geti("size", 64)));
  job.base_args.set("worker", Value::Str(gets("worker", "cpu")));
  return job;
}

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --count N [options]\n"
      "  --control-listen EP       control server bind (default tcp://0.0.0.0:5099)\n"
      "  --cluster-secret S        cluster secret\n"
      "  --tenant-namespace T      tenant namespace\n"
      "  --curve-server-secret K   enable CURVE encryption (Z85 server secret key)\n"
      "  --gen-curve-keys          print a fresh CURVE keypair and exit\n"
      "  --insecure-control        allow a non-loopback control bind without CURVE\n"
      "                            (cluster secret sent in cleartext — unsafe)\n"
      "  --count N                 total packets for the job (required, > 0)\n"
      "  --target IP               target ipv4 (default 127.0.0.1)\n"
      "  --port N                  target port (default 80)\n"
      "  --protocol P              l4 protocol (default udp)\n"
      "  --size N                  packet size (default 64)\n"
      "  --worker NAME             worker flavor this job needs (default cpu); only\n"
      "                            dispatched to workers advertising that kind\n"
      "  --shard-unit-count N      packets per shard (0 = auto)\n"
      "  --job-timeout-s N         wait cap for the job (default 120)\n"
      "  --poll-interval-ms N      master dispatch poll (default 250)\n"
      "  --expect-workers N        wait for this many workers first (default 1)\n"
      "  --wait-workers-s N        how long to wait for workers (default 30)\n"
      "  --management-listen EP    also serve the HTTP management API (host:port)\n"
      "  --mgmt-tls                serve the management API over TLS (https)\n"
      "  --mgmt-tls-cert PATH      PEM cert chain (self-signed if cert/key omitted)\n"
      "  --mgmt-tls-key PATH       PEM private key\n"
      "  --agent-join-token T      enable zero-install agent join on the mgmt API\n"
      "                            (curl .../v1/agent/install?token=T | sh); the\n"
      "                            token is also the manifest HMAC key\n"
      "  --agent-artifact-dir DIR  dir with samurai_slave + worker binaries to serve\n"
      "  --agent-advertise EP      public control endpoint agents connect to\n"
      "                            (default: --control-listen value)\n"
      "  --agent-worker NAME       worker kind agents run, or 'bundle' to ship all\n"
      "                            worker binaries and pick per shard (default cpu)\n"
      "  --agent-dispatch-mode M   reverse | auto for agents (default reverse)\n"
      "  --agent-insecure-http     allow agent bootstrap on a non-loopback mgmt\n"
      "                            bind (join token + secret sent in cleartext)\n"
      "  --target-region R         route/delegate this job to region R (region-\n"
      "                            aware shard routing; cross-region delegation)\n"
      "  --ha-mode MODE            static | file-lock | redis (default off)\n"
      "  --ha-node-id ID           this node's id\n"
      "  --ha-peers CSV            peer node ids (static mode)\n"
      "  --ha-lease-path PATH      lease file (file-lock mode)\n"
      "  --ha-lease-key KEY        Redis lease key (redis mode;\n"
      "                            default samurai:ha:<tenant|default>:lease)\n"
      "  Multi-master (region federation):\n"
      "  --multi-master-enable     coordinate with peer-region masters over Redis;\n"
      "                            delegate/serve cross-region jobs. With this set,\n"
      "                            --count 0 means serve-only (no local job)\n"
      "  --multi-master-region-id R  this master's region (default: --target-region\n"
      "                            unset -> required when enabled)\n"
      "  --multi-master-redis-url U  default redis://127.0.0.1:6379/0\n"
      "  --multi-master-namespace N  key-prefix isolation (default 'default')\n"
      "  --multi-master-heartbeat-ttl-s N  region heartbeat TTL (default 15)\n"
      "  --multi-master-dequeue-max N  delegated jobs pulled per poll (default 3)\n"
      "  Autoscale (worker replica controller; decision-only, k8s patch deferred):\n"
      "  --autoscale-enable        evaluate desired worker replicas from live load\n"
      "                            and surface it (log + management API). Keeps the\n"
      "                            master running as a persistent controller\n"
      "  --autoscale-target-name N  scale target name (required to activate)\n"
      "  --autoscale-target-kind K  deployment | statefulset (default deployment)\n"
      "  --autoscale-namespace N   target namespace (default 'default')\n"
      "  --autoscale-min N         min replicas (default 1)\n"
      "  --autoscale-max N         max replicas (default 100)\n"
      "  --autoscale-step N        max replica delta per step (default 1)\n"
      "  --autoscale-cooldown-s N  min seconds between scale steps (default 15)\n"
      "  --autoscale-shards-per-worker N  target shards per worker (default 4)\n"
      "  --autoscale-idle-scale-down-s N  idle secs before scaling to min (default 60)\n"
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
  if (Flag(argc, argv, "--gen-curve-keys")) {
    const CurveKeypair kp = GenerateCurveKeypair();
    if (!kp.ok) {
      std::fprintf(stderr, "samurai_master: CURVE not supported by this libzmq build\n");
      return 1;
    }
    std::printf("curve_public=%s\ncurve_secret=%s\n", kp.public_key.c_str(), kp.secret_key.c_str());
    return 0;
  }
  const long count = OptInt(argc, argv, "--count", 0);
  const bool mm_enabled = Flag(argc, argv, "--multi-master-enable");
  // Multi-master masters may be serve-only (they run delegated jobs pulled from
  // peer regions), so --count 0 is allowed then; otherwise a job needs a count.
  if (count <= 0 && !mm_enabled) {
    std::fprintf(stderr, "samurai_master: --count must be > 0\n");
    return 2;
  }

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  const std::string ha_mode = Opt(argc, argv, "--ha-mode", "off");

  // Shared Redis KvStore, backing both cross-region multi-master coordination
  // and (optionally) the Redis-lease HA elector. Unreachable/absent Redis is not
  // fatal: the master degrades to a single, standalone region.
  std::unique_ptr<KvStore> kv;
  if (mm_enabled || ha_mode == "redis") {
    const std::string url = Opt(argc, argv, "--multi-master-redis-url", "redis://127.0.0.1:6379/0");
    std::string kverr;
    kv = MakeKvStore(url, kverr);
    if (!kv) {
      std::fprintf(stderr,
          "samurai_master: Redis backend unavailable (%s); multi-master / redis-HA\n"
          "  disabled — running as a single standalone region.\n",
          kverr.c_str());
    } else {
      std::printf("samurai_master: Redis backend connected (%s)\n", url.c_str());
    }
  }

  // HA leadership (optional).
  std::unique_ptr<LeaderElector> elector;
  std::int64_t leader_epoch = 0;
  if (ha_mode == "static") {
    elector = std::make_unique<StaticLeaderElector>(Opt(argc, argv, "--ha-node-id", ""),
                                                    Opt(argc, argv, "--ha-peers", ""));
  } else if (ha_mode == "file-lock") {
    elector = std::make_unique<FileLeaseLeaderElector>(
        Opt(argc, argv, "--ha-node-id", ""),
        Opt(argc, argv, "--ha-lease-path", "/tmp/ddos_samurai_master_lease.json"), 15.0);
  } else if (ha_mode == "redis") {
    if (kv) {
      const std::string tenant0 = Opt(argc, argv, "--tenant-namespace", "");
      const std::string lease_key = Opt(argc, argv, "--ha-lease-key",
          "samurai:ha:" + (tenant0.empty() ? std::string("default") : tenant0) + ":lease");
      elector = std::make_unique<RedisLeaseLeaderElector>(
          Opt(argc, argv, "--ha-node-id", ""), lease_key, kv.get(), 15.0);
    } else {
      std::fprintf(stderr,
          "samurai_master: --ha-mode redis requires a reachable Redis; skipping HA\n");
    }
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

  // Cross-region multi-master coordinator (region federation). Active only with
  // a reachable Redis backend; otherwise a harmless no-op (single region).
  std::unique_ptr<RedisMultiMasterCoordinator> mm;
  std::string master_region;
  if (mm_enabled) {
    MultiMasterConfig mmcfg;
    mmcfg.enabled = true;
    mmcfg.namespace_ = Opt(argc, argv, "--multi-master-namespace", "default");
    mmcfg.region_id =
        Opt(argc, argv, "--multi-master-region-id", Opt(argc, argv, "--target-region", ""));
    mmcfg.node_id = Opt(argc, argv, "--ha-node-id", "master");
    mmcfg.heartbeat_ttl_s =
        static_cast<int>(OptInt(argc, argv, "--multi-master-heartbeat-ttl-s", 15));
    master_region = LowerCopy(mmcfg.region_id);
    mm = std::make_unique<RedisMultiMasterCoordinator>(mmcfg, kv.get());
    if (mm->active()) {
      std::printf("samurai_master: multi-master active (region=%s namespace=%s)\n",
                  master_region.c_str(), mmcfg.namespace_.c_str());
      if (master_region.empty()) {
        std::fprintf(stderr,
            "samurai_master: WARNING: multi-master enabled with an empty region id;\n"
            "  heartbeat/dequeue are disabled. Set --multi-master-region-id.\n");
      }
    } else {
      std::fprintf(stderr,
          "samurai_master: multi-master enabled but coordinator inactive (no Redis);\n"
          "  running as a single standalone region.\n");
    }
  }

  // Autoscale controller (optional). The scaling *decision* state machine is
  // native and driven by live cluster load; the K8s read/patch backend is
  // deferred, so it runs in in-memory mode — it computes and surfaces desired
  // worker replica counts (log + management API) but does not patch a cluster.
  AutoscaleConfig ascfg;
  ascfg.enabled = Flag(argc, argv, "--autoscale-enable");
  ascfg.namespace_ = Opt(argc, argv, "--autoscale-namespace", "default");
  ascfg.target_kind = Opt(argc, argv, "--autoscale-target-kind", "deployment");
  ascfg.target_name = Opt(argc, argv, "--autoscale-target-name", "");
  ascfg.min_replicas = static_cast<int>(OptInt(argc, argv, "--autoscale-min", 1));
  ascfg.max_replicas = static_cast<int>(OptInt(argc, argv, "--autoscale-max", 100));
  ascfg.step = static_cast<int>(OptInt(argc, argv, "--autoscale-step", 1));
  ascfg.cooldown_s = static_cast<double>(OptInt(argc, argv, "--autoscale-cooldown-s", 15));
  ascfg.shards_per_worker = static_cast<int>(OptInt(argc, argv, "--autoscale-shards-per-worker", 4));
  ascfg.idle_scale_down_s =
      static_cast<double>(OptInt(argc, argv, "--autoscale-idle-scale-down-s", 60));
  const bool autoscale_on = ascfg.enabled && !ascfg.target_name.empty();
  std::unique_ptr<AutoscaleController> autoscaler;
  if (ascfg.enabled) {
    if (ascfg.target_name.empty()) {
      std::fprintf(stderr,
          "samurai_master: WARNING: --autoscale-enable without --autoscale-target-name;\n"
          "  the controller stays disabled (no target to scale).\n");
    } else {
      autoscaler = std::make_unique<AutoscaleController>(ascfg);
      std::printf("samurai_master: autoscale enabled (target=%s/%s ns=%s min=%d max=%d spw=%d)\n",
                  ascfg.target_kind.c_str(), ascfg.target_name.c_str(), ascfg.namespace_.c_str(),
                  ascfg.min_replicas, ascfg.max_replicas, ascfg.shards_per_worker);
    }
  }
  // Live load signals fed by the coordinator's progress_cb; the autoscale thread
  // reads them and publishes its latest decision under as_mu.
  std::atomic<int> as_pending{0};
  std::atomic<int> as_inflight{0};
  std::mutex as_mu;
  Value as_json = Value::Object();

  // Control server.
  const std::string cluster_secret = Opt(argc, argv, "--cluster-secret", "");
  const std::string tenant = Opt(argc, argv, "--tenant-namespace", "");
  ServicerConfig scfg;
  scfg.tenant_namespace = tenant;
  Servicer servicer(scfg);
  AuthConfig auth;
  auth.expected_secret = cluster_secret;
  const std::string control_listen = Opt(argc, argv, "--control-listen", "tcp://0.0.0.0:5099");
  ControlServer server(control_listen, &servicer, auth);
  const std::string curve_secret = Opt(argc, argv, "--curve-server-secret", "");
  std::string curve_public;
  if (!curve_secret.empty()) {
    server.set_curve_server(curve_secret);
    curve_public = CurvePublicFromSecret(curve_secret);
    std::printf("samurai_master: CURVE encryption enabled on the control server\n");
  }
  // Public-exposure safety: on a non-loopback bind the cluster secret travels
  // the control channel app-layer, so refuse plaintext unless explicitly forced.
  if (!IsLoopbackEndpoint(control_listen) && curve_secret.empty()) {
    if (!Flag(argc, argv, "--insecure-control")) {
      std::fprintf(stderr,
          "samurai_master: refusing to bind the control server to a non-loopback\n"
          "  address (%s) without CURVE — the cluster secret would travel in\n"
          "  cleartext. Enable --curve-server-secret, bind to loopback behind a\n"
          "  tunnel, or pass --insecure-control to override.\n",
          control_listen.c_str());
      return 2;
    }
    std::fprintf(stderr,
        "samurai_master: WARNING: control server on %s is plaintext "
        "(--insecure-control); the cluster secret is exposed.\n",
        control_listen.c_str());
  }
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

    // TLS for the management HTTP API. Enabled by --mgmt-tls; uses the given
    // cert/key files or an ephemeral self-signed cert when none are provided.
    ManagementTlsConfig tls;
    tls.enabled = Flag(argc, argv, "--mgmt-tls");
    tls.cert_path = Opt(argc, argv, "--mgmt-tls-cert", "");
    tls.key_path = Opt(argc, argv, "--mgmt-tls-key", "");
    mcfg.agent_public_scheme = tls.enabled ? "https" : "http";
    // Self-signed TLS (no cert files): the agent can't verify the cert, so its
    // install-script curls must use -k (the manifest HMAC still authenticates).
    mcfg.agent_tls_skip_verify = tls.enabled && tls.cert_path.empty();

    // Self-bootstrapping agent join (zero-install slave). Opt-in via a join token;
    // agents pull the slave + worker binaries and register in reverse mode.
    mcfg.agent_join_token = Opt(argc, argv, "--agent-join-token", "");
    if (!mcfg.agent_join_token.empty()) {
      // On a non-loopback bind the join token + cluster secret leave the host, so
      // require a secured channel: TLS on the API, or an explicit plaintext opt-in.
      if (!IsLoopbackEndpoint(mgmt_listen) && !tls.enabled &&
          !Flag(argc, argv, "--agent-insecure-http")) {
        std::fprintf(stderr,
            "samurai_master: refusing to enable agent bootstrap on a non-loopback\n"
            "  mgmt address (%s) without TLS: the join token and cluster secret\n"
            "  would travel in cleartext. Enable --mgmt-tls, bind --management-listen\n"
            "  to loopback behind a TLS proxy / tunnel, or pass --agent-insecure-http.\n",
            mgmt_listen.c_str());
        return 2;
      }
      if (!IsLoopbackEndpoint(mgmt_listen) && !tls.enabled) {
        std::fprintf(stderr,
            "samurai_master: WARNING: agent bootstrap served plaintext on %s "
            "(--agent-insecure-http); join token + secret are exposed.\n",
            mgmt_listen.c_str());
      }
      mcfg.agent_artifact_dir = Opt(argc, argv, "--agent-artifact-dir", ".");
      mcfg.agent_advertise_endpoint = Opt(argc, argv, "--agent-advertise", control_listen);
      mcfg.agent_dispatch_mode = Opt(argc, argv, "--agent-dispatch-mode", "reverse");
      mcfg.agent_worker = Opt(argc, argv, "--agent-worker", "cpu");
      mcfg.agent_cluster_secret = cluster_secret;  // agent presents this for app-layer auth
      mcfg.agent_curve_public = curve_public;  // empty unless --curve-server-secret set
      std::printf("samurai_master: agent bootstrap enabled (worker=%s advertise=%s curve=%s tls=%s)\n",
                  mcfg.agent_worker.c_str(), mcfg.agent_advertise_endpoint.c_str(),
                  curve_public.empty() ? "off" : "on", tls.enabled ? "on" : "off");
    }
    ManagementProviders providers;
    providers.state_provider = [&servicer, &mm, &as_mu, &as_json, autoscale_on]() {
      Value asj;
      bool has_as = false;
      if (autoscale_on) {
        std::lock_guard<std::mutex> lk(as_mu);
        asj = as_json;
        has_as = asj.find("enabled") != nullptr;  // populated once the thread ran
      }
      return BuildState(&servicer, mm.get(), has_as ? &asj : nullptr);
    };
    providers.abort_callback = []() {
      Value r = Value::Object();
      r.set("aborted", Value::Bool(true));
      return r;
    };
    mgmt = std::make_unique<ManagementApiServer>(mgmt_listen, mcfg, providers, tls);
    if (mgmt->Start()) {
      std::printf("samurai_master: management api on %s (%s)\n", mgmt->endpoint().c_str(),
                  tls.enabled ? "https" : "http");
    } else {
      std::fprintf(stderr, "samurai_master: failed to start management api%s\n",
                   tls.enabled ? " (TLS cert/key load or self-signed generation failed)" : "");
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

  // Build + dispatch the job. The base_args `worker` field declares the flavor
  // the job needs; bundle slaves resolve their binary per shard from it, and the
  // coordinator only dispatches to workers advertising it (WorkerDispatchScore).
  ServicerMasterView view(&servicer);
  ClientWorkerCommander commander(cluster_secret, tenant, 5000, &servicer);
  MasterCoordinator coord(&view, &commander);
  auto guard = [&elector]() { return !elector || elector->IsLeader(); };

  // Feed the autoscale controller live shard backlog/in-flight counts from the
  // coordinator (no-op when autoscale is off).
  auto attach_progress = [&](JobConfig& job) {
    if (!autoscaler) return;
    job.progress_cb = [&as_pending, &as_inflight](int p, int i) {
      as_pending.store(p);
      as_inflight.store(i);
    };
  };

  int rc = 0;

  // Background region heartbeat + snapshot publisher (leader only). Runs
  // alongside the primary job and the serve loop; the store is thread-safe.
  std::thread hb_thread;
  if (mm && mm->active() && !master_region.empty()) {
    const int hb_interval_ms = std::max(
        1000,
        static_cast<int>(OptInt(argc, argv, "--multi-master-heartbeat-ttl-s", 15) * 1000 / 3));
    hb_thread = std::thread([&]() {
      while (!g_stop.load()) {
        if (!elector || elector->IsLeader()) {
          Value hb = Value::Object();
          hb.set("workers", Value::Int(static_cast<std::int64_t>(servicer.worker_count())));
          mm->Heartbeat(hb);
          mm->PublishSnapshot(BuildState(&servicer, nullptr));
        }
        for (int slept = 0; slept < hb_interval_ms && !g_stop.load(); slept += 100) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
  }

  // Background autoscale evaluator (leader only). Reads the live load signals the
  // coordinator publishes via progress_cb, evaluates one scaling step (the
  // controller enforces its own cooldown), publishes the decision for the
  // management API, and logs actual changes. In-memory backend: no K8s patch.
  std::thread as_thread;
  if (autoscaler) {
    const int tick_ms = std::max(1000, static_cast<int>(ascfg.cooldown_s * 1000.0 / 3.0));
    as_thread = std::thread([&]() {
      while (!g_stop.load()) {
        if (!elector || elector->IsLeader()) {
          const int p = as_pending.load();
          const int i = as_inflight.load();
          const AutoscaleDecision d =
              autoscaler->MaybeScale(p, i, static_cast<int>(servicer.worker_count()));
          {
            std::lock_guard<std::mutex> lk(as_mu);
            as_json = AutoscaleStateJson(d, ascfg.target_name, ascfg.target_kind);
          }
          if (d.changed) {
            std::printf(
                "samurai_master: autoscale scaled current=%d desired=%d applied=%d "
                "(pending=%d inflight=%d workers=%zu) [in-memory; k8s patch deferred]\n",
                d.current, d.desired, d.applied, p, i, servicer.worker_count());
          }
        }
        for (int slept = 0; slept < tick_ms && !g_stop.load(); slept += 100) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
  }

  // Primary job: run it on this region's workers, or delegate the whole job to a
  // peer region when --target-region names a different region.
  if (count > 0) {
    const Value spec = JobSpecFromArgs(argc, argv);
    const std::string tr = LowerCopy(Opt(argc, argv, "--target-region", ""));
    if (mm && mm->active() && !tr.empty() && tr != master_region) {
      if (mm->EnqueueJob(tr, spec)) {
        std::printf("samurai_master: delegated job (count=%ld) to region %s\n", count, tr.c_str());
      } else {
        std::fprintf(stderr, "samurai_master: delegation to region %s failed\n", tr.c_str());
        rc = 1;
      }
    } else {
      JobConfig job = BuildJobConfig(spec, leader_epoch, tenant, master_region);
      attach_progress(job);
      const JobResult res = coord.RunSingleJob(job, "job-1", guard);
      std::printf("%s\n", res.snapshot.dump().c_str());
      rc = res.rc;
    }
  }

  // Serve loop: pull delegated jobs from peer regions and run them locally until
  // signalled. This is what makes a region a live participant in the federation.
  if (mm && mm->active() && !master_region.empty()) {
    const int dequeue_max =
        static_cast<int>(OptInt(argc, argv, "--multi-master-dequeue-max", 3));
    std::printf("samurai_master: serving delegated jobs for region %s (Ctrl-C to stop)\n",
                master_region.c_str());
    long deleg_seq = 0;
    while (!g_stop.load()) {
      if (!elector || elector->IsLeader()) {
        for (auto& j : mm->DequeueJobs(dequeue_max)) {
          JobConfig job = BuildJobConfig(j, leader_epoch, tenant, master_region);
          attach_progress(job);
          const Value* from = j.find("_mmr_delegated_from");
          const std::string from_region = from ? from->as_string("") : "";
          std::printf("samurai_master: running delegated job from '%s' (count=%lld)\n",
                      from_region.c_str(), static_cast<long long>(job.count));
          const JobResult res =
              coord.RunSingleJob(job, "deleg-" + std::to_string(++deleg_seq), guard);
          Value ev = Value::Object();
          ev.set("type", Value::Str("delegated_job_done"));
          ev.set("rc", Value::Int(res.rc));
          ev.set("from_region", Value::Str(from_region));
          mm->PublishEvent(ev);
          std::printf("%s\n", res.snapshot.dump().c_str());
        }
      }
      for (int slept = 0; slept < 500 && !g_stop.load(); slept += 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  }

  if (hb_thread.joinable()) hb_thread.join();
  if (as_thread.joinable()) as_thread.join();
  if (mgmt) mgmt->Stop();
  server.Stop();
  if (elector) elector->Stop();
  return rc;
}
