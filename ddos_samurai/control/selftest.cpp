// Self-test for the native control-plane logic (increment 1). Asserts the
// ported behaviour matches the Python ddos_samurai/control contract. Exits 0 on
// success, 1 on the first failed check.

#include <cstdint>
#include <cstdio>
#include <map>
#include <numeric>
#include <string>
#include <vector>

#include <ctime>

#include "auth.hpp"
#include "autoscale.hpp"
#include "discovery.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "jwt.hpp"
#include "master_coordinator.hpp"
#include "multimaster.hpp"
#include "shard.hpp"
#include "shard_runner.hpp"
#include "telemetry.hpp"
#include "worker_shard_service.hpp"

#ifdef SAMURAI_CONTROL_HAVE_ZMQ
#include "control_client.hpp"
#include "control_server.hpp"
#endif

namespace {

int g_failures = 0;

void Check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

std::uint64_t Sum(const std::vector<samurai::control::Shard>& shards) {
  std::uint64_t t = 0;
  for (const auto& s : shards) t += s.packet_count;
  return t;
}

}  // namespace

int main() {
  using namespace samurai::control;

  // --- shard: equal split conserves total and front-loads the remainder ---
  {
    auto shards = SplitJobToShards(1000, {"w1", "w2", "w3"});
    Check(shards.size() == 3, "equal: 3 shards");
    Check(Sum(shards) == 1000, "equal: total conserved");
    Check(shards[0].packet_count == 334 && shards[1].packet_count == 333 &&
              shards[2].packet_count == 333,
          "equal: 334/333/333 split");
    Check(shards[0].shard_id == "shard-1" && shards[0].worker_id == "w1",
          "equal: shard id/worker mapping");
  }
  // blank workers dropped; empty -> no shards
  Check(SplitJobToShards(100, {"  ", ""}).empty(), "equal: blank workers dropped");

  // --- shard: capability weighting (gpu=+2, xdp=+1) conserves total ---
  {
    std::map<std::string, WorkerCapabilities> caps;
    caps["w1"].gpu_available = true;   // weight 3
    caps["w2"].xdp_available = true;   // weight 2
    // w3 -> weight 1
    auto shards = SplitJobToShards(600, {"w1", "w2", "w3"}, "capability", caps);
    Check(Sum(shards) == 600, "capability: total conserved");
    Check(shards[0].packet_count >= shards[2].packet_count,
          "capability: gpu worker gets the largest shard");
  }

  // --- shard: region strategy boosts matching region ---
  {
    std::map<std::string, WorkerCapabilities> caps;
    caps["w1"].region = "eu";
    caps["w2"].region = "us";
    auto shards = SplitJobToShards(500, {"w1", "w2"}, "region", caps, "eu");
    Check(Sum(shards) == 500, "region: total conserved");
    Check(shards[0].packet_count > shards[1].packet_count,
          "region: matching-region worker gets more");
  }

  // --- auth: endpoint parsing ---
  {
    auto eps = SplitEndpoints("a:1, b:2 ,, c:3");
    Check(eps.size() == 3 && eps[0] == "a:1" && eps[1] == "b:2" && eps[2] == "c:3",
          "auth: split_endpoints trims + drops blanks");
  }

  // --- auth: cluster secret validation ---
  Check(ValidateClusterSecret("", "anything"), "auth: blank expected -> allow");
  Check(ValidateClusterSecret("s3cr3t", "s3cr3t"), "auth: matching secret -> allow");
  Check(!ValidateClusterSecret("s3cr3t", "nope"), "auth: mismatched secret -> deny");

  // --- auth: RBAC resolution prefers strongest role ---
  {
    auto rs = NormalizeRoleSecrets("A", "O", "V", "W");
    Check(ResolveRoleFromSecret("A", rs) == "admin", "auth: admin secret");
    Check(ResolveRoleFromSecret("W", rs) == "worker", "auth: worker secret");
    Check(ResolveRoleFromSecret("nope", rs).empty(), "auth: unknown secret -> no role");
    // overlap: same secret for admin+viewer resolves to admin (strongest)
    auto overlap = NormalizeRoleSecrets("SHARED", "", "SHARED", "");
    Check(ResolveRoleFromSecret("SHARED", overlap) == "admin",
          "auth: overlapping secret -> strongest role");
  }

  // --- discovery: manual endpoints win ---
  {
    EndpointDiscovery d("h1:5099, h2:5099");
    Check(d.Resolve().size() == 2, "discovery: manual resolve");
    Check(d.ResolveWithFallback().size() == 2, "discovery: fallback returns manual");
    EndpointDiscovery empty("");
    Check(empty.ResolveWithFallback().empty(), "discovery: no manual -> empty");
  }

  // --- autoscale: disabled controller reports disabled ---
  {
    AutoscaleConfig cfg;  // enabled=false
    AutoscaleController ctl(cfg);
    auto d = ctl.MaybeScale(10, 0, 1);
    Check(!d.enabled && d.reason == "disabled", "autoscale: disabled");
  }

  // --- autoscale: enabled controller scales up under load (step-limited) ---
  {
    double clock = 1000.0;
    AutoscaleConfig cfg;
    cfg.enabled = true;
    cfg.target_name = "samurai-workers";
    cfg.min_replicas = 1;
    cfg.max_replicas = 10;
    cfg.step = 2;
    cfg.cooldown_s = 5.0;
    cfg.shards_per_worker = 4;
    AutoscaleController ctl(cfg, [&clock]() { return clock; });
    // 16 pending shards / 4 per worker => desired 4 workers; step=2 => applied 3.
    auto d = ctl.MaybeScale(16, 0, 1);
    Check(d.enabled && d.changed && d.desired == 4 && d.applied == 3,
          "autoscale: scale-up step-limited (desired 4, applied 3)");
    // within cooldown -> no change
    auto d2 = ctl.MaybeScale(16, 0, 1);
    Check(!d2.changed && d2.reason == "cooldown", "autoscale: cooldown blocks");
    // past cooldown -> next step toward desired
    clock += 6.0;
    auto d3 = ctl.MaybeScale(16, 0, 1);
    Check(d3.changed && d3.applied == 4, "autoscale: reaches desired after cooldown");
  }

  // --- json: parse / access / round-trip ---
  {
    namespace json = samurai::core::json;
    auto r = json::Parse(R"({"a":1,"b":"two","c":[true,null,3.5],"n":{"x":-7}})");
    Check(r.ok && r.value.is_object(), "json: parse object");
    Check(r.value.find("a") && r.value.find("a")->as_int() == 1, "json: int field");
    Check(r.value.find("b") && r.value.find("b")->as_string() == "two", "json: string field");
    const auto* c = r.value.find("c");
    Check(c && c->is_array() && c->elements().size() == 3, "json: array field");
    Check(c && c->elements()[2].as_double() == 3.5, "json: nested double");
    const auto* n = r.value.find("n");
    Check(n && n->find("x") && n->find("x")->as_int() == -7, "json: nested object");
    // round-trip: dump then re-parse yields the same int
    auto r2 = json::Parse(r.value.dump());
    Check(r2.ok && r2.value.find("a")->as_int() == 1, "json: dump/parse round-trip");
    // trailing garbage is an error
    Check(!json::Parse("{}x").ok, "json: trailing garbage rejected");
    // escaping round-trips through dump/parse
    auto esc = json::Parse(R"({"s":"a\"b\\c\n"})");
    Check(esc.ok && esc.value.find("s")->as_string() == "a\"b\\c\n", "json: escapes decoded");
  }

  // --- jwt: HS256 encode/decode round-trip + verification ---
  {
    namespace json = samurai::core::json;
    const std::string secret = "top-secret-key";
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));

    json::Value claims = json::Value::Object();
    claims.set("sub", json::Value::Str("admin"));
    claims.set("role", json::Value::Str("operator"));
    claims.set("exp", json::Value::Int(now + 3600));
    claims.set("nbf", json::Value::Int(now - 10));

    const std::string token = EncodeJwtHs256(claims, secret);
    auto ok = DecodeJwtHs256(token, secret);
    Check(ok.ok, "jwt: valid token decodes");
    Check(ok.ok && ok.payload.find("sub") && ok.payload.find("sub")->as_string() == "admin",
          "jwt: claims recovered");

    // wrong secret -> signature mismatch
    auto bad_secret = DecodeJwtHs256(token, "not-the-secret");
    Check(!bad_secret.ok && bad_secret.error == "jwt signature mismatch",
          "jwt: wrong secret rejected");

    // tampered signature -> mismatch. Flip the FIRST signature char (all real
    // bits); the last char only carries discarded padding bits.
    std::string tampered = token;
    const auto sig_dot = tampered.rfind('.');
    tampered[sig_dot + 1] = (tampered[sig_dot + 1] == 'A') ? 'B' : 'A';
    auto bad_sig = DecodeJwtHs256(tampered, secret);
    Check(!bad_sig.ok && bad_sig.error == "jwt signature mismatch", "jwt: tampered signature rejected");

    // expired token
    json::Value expired = json::Value::Object();
    expired.set("exp", json::Value::Int(now - 100));
    auto exp_tok = EncodeJwtHs256(expired, secret);
    Check(DecodeJwtHs256(exp_tok, secret).error == "jwt expired", "jwt: expired rejected");
    // ...but accepted when verify_exp = false
    Check(DecodeJwtHs256(exp_tok, secret, /*verify_exp=*/false).ok, "jwt: exp skipped when disabled");

    // not-yet-valid token
    json::Value future = json::Value::Object();
    future.set("nbf", json::Value::Int(now + 1000));
    auto nbf_tok = EncodeJwtHs256(future, secret);
    Check(DecodeJwtHs256(nbf_tok, secret).error == "jwt not yet valid", "jwt: nbf rejected");

    // malformed token
    Check(DecodeJwtHs256("not.a.jwt.token", secret).error == "invalid jwt format",
          "jwt: malformed rejected");
    Check(DecodeJwtHs256("", secret).error == "empty token", "jwt: empty rejected");
  }

  // --- telemetry: DistributedAggregator rollups ---
  {
    namespace json = samurai::core::json;
    DistributedAggregator agg;
    auto mk = [](const std::string& wid, const std::string& sid, int sent, int errors,
                 const std::string& region) {
      json::Value v = json::Value::Object();
      v.set("worker_id", json::Value::Str(wid));
      v.set("shard_id", json::Value::Str(sid));
      v.set("sent", json::Value::Int(sent));
      v.set("errors", json::Value::Int(errors));
      v.set("region", json::Value::Str(region));
      return v;
    };
    // Two updates for shard-1 (max semantics), one for shard-2 with more errors.
    agg.Add(mk("w1", "shard-1", 100, 0, "eu"));
    agg.Add(mk("w1", "shard-1", 250, 1, "eu"));
    agg.Add(mk("w2", "shard-2", 40, 9, "us"));
    auto snap = agg.Snapshot();
    Check(snap.find("sent")->as_int() == 390, "telemetry: sent summed (100+250+40)");
    Check(snap.find("errors")->as_int() == 10, "telemetry: errors summed");
    Check(snap.find("workers")->as_int() == 2, "telemetry: distinct workers");
    Check(snap.find("shards")->as_int() == 2, "telemetry: distinct shards");
    // per_shard uses max, not sum, for shard-1
    const auto* per_shard = snap.find("per_shard");
    Check(per_shard && per_shard->elements().size() == 2, "telemetry: per_shard size");
    // top_error_shards ordered by errors desc -> shard-2 first
    const auto* top = snap.find("top_error_shards");
    Check(top && !top->elements().empty() &&
              top->elements()[0].find("shard_id")->as_string() == "shard-2",
          "telemetry: top error shard first");
    // numeric_totals accumulates sent across all items
    const auto* nt = snap.find("numeric_totals");
    Check(nt && nt->find("sent") && nt->find("sent")->as_double() == 390.0,
          "telemetry: numeric_totals sent");
    // region rollup: two regions
    const auto* rr = snap.find("region_rollup");
    Check(rr && rr->elements().size() == 2, "telemetry: two regions");
  }

  // --- multimaster: cross-region enqueue/dequeue + heartbeat scan ---
  {
    namespace json = samurai::core::json;
    InMemoryKvStore store;
    std::int64_t clock_ms = 1000;
    auto now = [&clock_ms]() { return clock_ms; };

    MultiMasterConfig eu_cfg;
    eu_cfg.enabled = true;
    eu_cfg.region_id = "eu";
    eu_cfg.node_id = "eu-master";
    RedisMultiMasterCoordinator eu(eu_cfg, &store, now);

    MultiMasterConfig us_cfg;
    us_cfg.enabled = true;
    us_cfg.region_id = "us";
    us_cfg.node_id = "us-master";
    RedisMultiMasterCoordinator us(us_cfg, &store, now);

    Check(eu.active() && us.active(), "multimaster: active with store");

    // eu enqueues a job destined for us; us dequeues it with delegated_from.
    json::Value job = json::Value::Object();
    job.set("target", json::Value::Str("10.0.0.1"));
    job.set("count", json::Value::Int(500));
    Check(eu.EnqueueJob("us", job), "multimaster: enqueue to us");
    auto jobs = us.DequeueJobs(5);
    Check(jobs.size() == 1, "multimaster: us dequeues one job");
    Check(!jobs.empty() && jobs[0].find("target") &&
              jobs[0].find("target")->as_string() == "10.0.0.1",
          "multimaster: job payload preserved");
    Check(!jobs.empty() && jobs[0].find("_mmr_delegated_from") &&
              jobs[0].find("_mmr_delegated_from")->as_string() == "eu",
          "multimaster: delegated_from stamped");
    // queue now empty
    Check(us.DequeueJobs(5).empty(), "multimaster: queue drained");

    // heartbeats from both regions -> regions_state returns both, sorted.
    Check(eu.Heartbeat() && us.Heartbeat(), "multimaster: heartbeats");
    auto regions = us.RegionsState();
    Check(regions.size() == 2, "multimaster: two regions in state");
    Check(regions.size() == 2 && regions[0].find("region_id")->as_string() == "eu" &&
              regions[1].find("region_id")->as_string() == "us",
          "multimaster: regions sorted by id");

    // offline coordinator (no store) is inert.
    RedisMultiMasterCoordinator offline(eu_cfg, nullptr, now);
    Check(!offline.active(), "multimaster: null store -> inactive");
    Check(!offline.Heartbeat(), "multimaster: offline heartbeat no-op");
    Check(!offline.Snapshot().find("enabled")->as_bool(), "multimaster: offline snapshot enabled=false");
  }

  // --- ha: static + file-lease leader election ---
  {
    // Static: lexical-min node id wins.
    StaticLeaderElector a("node-a", "node-b,node-c");
    StaticLeaderElector b("node-b", "node-a,node-c");
    Check(a.IsLeader(), "ha: static lexical-min is leader");
    Check(!b.IsLeader(), "ha: static non-min is follower");
    Check(a.Snapshot().find("leader_id")->as_string() == "node-a", "ha: static leader_id");

    // File-lease: first acquirer holds; second is blocked until release.
    const std::string lease =
        "/tmp/claude-0/-home-user-Samurai/e22cf02a-7f79-5de1-b1eb-8cd527ed8d7d/scratchpad/ha_lease.json";
    std::remove(lease.c_str());
    FileLeaseLeaderElector e1("n1", lease, 30.0);
    FileLeaseLeaderElector e2("n2", lease, 30.0);
    Check(e1.TryAcquire() && e1.IsLeader(), "ha: file-lease first acquires");
    Check(!e2.TryAcquire() && !e2.IsLeader(), "ha: file-lease second blocked");
    Check(e1.RenewOnce(), "ha: file-lease owner renews");
    Check(e1.Snapshot().find("leader_id")->as_string() == "n1", "ha: file-lease leader_id");
    e1.Release();
    Check(e2.TryAcquire() && e2.IsLeader(), "ha: file-lease acquirable after release");
    e2.Release();
    std::remove(lease.c_str());
  }

  // --- slave: worker shard service lifecycle ---
  {
    namespace json = samurai::core::json;
    InMemoryShardRunner runner;
    WorkerShardService svc("worker-A", &runner);
    RpcContext ctx;  // no meta/role needed for the worker service

    json::Value args = json::Value::Object();
    args.set("_leader_epoch", json::Value::Int(5));
    args.set("count", json::Value::Int(300));
    args.set("_test_sent", json::Value::Int(300));
    json::Value start = json::Value::Object();
    start.set("shard_id", json::Value::Str("shard-1"));
    start.set("job_id", json::Value::Str("job-1"));
    start.set("args_json", json::Value::Str(args.dump()));
    auto sr = svc.StartShard(start, ctx);
    Check(sr.find("started") && sr.find("started")->as_bool(), "wss: StartShard started");
    svc.WaitForShardIdle("shard-1");

    json::Value gbody = json::Value::Object();
    gbody.set("worker_id", json::Value::Str("worker-A"));
    auto status = svc.GetWorkerStatus(gbody, ctx);
    Check(status.find("state") && status.find("state")->as_string() == "done",
          "wss: completed shard -> state done");
    auto stats = json::Parse(status.find("stats_json")->as_string());
    Check(stats.ok && stats.value.find("sent") && stats.value.find("sent")->as_int() == 300,
          "wss: finalized stats carry sent");
    Check(stats.value.find("exitcode") && stats.value.find("exitcode")->as_int() == 0,
          "wss: exitcode 0");

    // Stale leader epoch is fenced off.
    json::Value stale_args = json::Value::Object();
    stale_args.set("_leader_epoch", json::Value::Int(3));
    json::Value stale = json::Value::Object();
    stale.set("shard_id", json::Value::Str("shard-2"));
    stale.set("args_json", json::Value::Str(stale_args.dump()));
    auto srr = svc.StartShard(stale, ctx);
    Check(!srr.find("started")->as_bool() &&
              srr.find("error")->as_string().find("stale leader epoch") != std::string::npos,
          "wss: stale leader epoch rejected");

    // Unknown worker id -> disconnected.
    json::Value other = json::Value::Object();
    other.set("worker_id", json::Value::Str("worker-Z"));
    auto st2 = svc.GetWorkerStatus(other, ctx);
    Check(st2.find("state")->as_string() == "disconnected", "wss: unknown worker disconnected");
  }

  // --- master: dispatch coordinator drives a job to completion ---
  {
    namespace json = samurai::core::json;

    struct FakeView : MasterView {
      std::map<std::string, WorkerInfo> workers;
      std::map<std::string, std::string> stats;
      std::vector<WorkerInfo> Workers() override {
        std::vector<WorkerInfo> out;
        for (auto& kv : workers) out.push_back(kv.second);
        return out;
      }
      bool ShardReported(const std::string& sid) override { return stats.count(sid) > 0; }
      std::string GetShardStats(const std::string& sid) override {
        auto it = stats.find(sid);
        return it == stats.end() ? std::string("{}") : it->second;
      }
      void SetShardStats(const std::string& sid, const std::string& js) override { stats[sid] = js; }
    };
    struct FakeCmd : WorkerCommander {
      FakeView* view = nullptr;
      DispatchOutcome Dispatch(const std::string&, const std::string& sid, const std::string&,
                               const std::string&, std::int64_t count, std::int64_t) override {
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());  // simulate the worker finishing + reporting
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override {
        return {"done", "", "{}"};
      }
      bool StopShard(const std::string&, const std::string&) override { return true; }
    };

    FakeView view;
    std::int64_t clk = 1000000;
    for (const char* wid : {"w1", "w2"}) {
      WorkerInfo w;
      w.worker_id = wid;
      w.capabilities["control_endpoint"] = std::string("tcp://") + wid + ":5099";
      w.last_heartbeat_ms = clk;
      view.workers[wid] = w;
    }
    FakeCmd cmd;
    cmd.view = &view;

    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 1000;
    job.shard_unit_count = 250;  // -> 4 shards
    job.master_poll_interval_ms = 1;
    auto res = coord.RunSingleJob(job, "job-1");
    Check(res.rc == 0, "master: job completes rc=0");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 1000,
          "master: aggregated sent=1000");
    Check(res.snapshot.find("shards_reported") &&
              res.snapshot.find("shards_reported")->as_int() == 4,
          "master: 4 shards reported");
    Check(res.snapshot.find("inflight_shards_left")->as_int() == 0 &&
              res.snapshot.find("pending_shards_left")->as_int() == 0,
          "master: nothing left pending/inflight");
  }

#ifdef SAMURAI_CONTROL_HAVE_ZMQ
  // --- control transport: ZMQ server<->client round trip (RPCs + auth) ---
  {
    namespace json = samurai::core::json;

    // Cluster-secret auth, no RBAC.
    ServicerConfig scfg;
    scfg.cluster_id = "cluster-test";
    Servicer servicer(scfg);
    AuthConfig auth;
    auth.expected_secret = "s3cr3t";
    ControlServer server("tcp://127.0.0.1:*", &servicer, auth);
    Check(server.Start(), "control: server starts");
    const std::string ep = server.endpoint();
    Check(!ep.empty(), "control: endpoint resolved");

    SlaveControlClient slave(ep, "s3cr3t");
    auto reg = slave.RegisterWorker("w1", "host1", {{"gpu_available", "1"}});
    Check(reg.ok && reg.body.find("accepted") && reg.body.find("accepted")->as_bool(),
          "control: RegisterWorker accepted");
    Check(reg.body.find("cluster_id") && reg.body.find("cluster_id")->as_string() == "cluster-test",
          "control: cluster_id echoed");

    auto hb = slave.Heartbeat("w1", 1000);
    Check(hb.ok && hb.body.find("acknowledged")->as_bool() &&
              hb.body.find("command")->as_string() == "continue",
          "control: Heartbeat ack for known worker");
    auto hb2 = slave.Heartbeat("ghost", 1000);
    Check(hb2.ok && !hb2.body.find("acknowledged")->as_bool() &&
              hb2.body.find("command")->as_string() == "register",
          "control: unknown worker told to register");

    auto rs = slave.ReportStats("w1", "shard-1", "{\"sent\":42}", 123);
    Check(rs.ok && rs.body.find("received")->as_bool(), "control: ReportStats received");

    WorkerControlClient master(ep, "s3cr3t");
    auto st = master.GetWorkerStatus("w1");
    Check(st.ok && st.body.find("state")->as_string() == "idle", "control: GetWorkerStatus state");
    Check(st.body.find("stats_json")->as_string() == "{\"sent\":42}",
          "control: reported stats propagated to status");

    // Wrong secret -> UNAUTHENTICATED.
    SlaveControlClient bad(ep, "wrong-secret");
    auto badreg = bad.RegisterWorker("w2", "host2", {});
    Check(!badreg.ok && badreg.status == "UNAUTHENTICATED", "control: wrong secret rejected");

    server.Stop();
    Check(!server.running(), "control: server stops");
  }

  // --- control transport: RBAC per-RPC enforcement ---
  {
    Servicer servicer;  // no tenant, no jwt
    AuthConfig auth;
    auth.rbac_enabled = true;
    auth.role_secrets = NormalizeRoleSecrets("ADMINSEC", "", "", "WORKERSEC");
    ControlServer server("tcp://127.0.0.1:*", &servicer, auth);
    Check(server.Start(), "rbac: server starts");
    const std::string ep = server.endpoint();

    // worker-role secret: may Register, may not AbortJob.
    SlaveControlClient worker(ep, "WORKERSEC");
    auto wr = worker.RegisterWorker("w1", "h", {});
    Check(wr.ok && wr.body.find("accepted")->as_bool(), "rbac: worker may RegisterWorker");
    WorkerControlClient worker_cmd(ep, "WORKERSEC");
    auto forbidden = worker_cmd.AbortJob("job-1", "test");
    Check(!forbidden.ok && forbidden.status == "PERMISSION_DENIED",
          "rbac: worker forbidden from AbortJob");

    // admin-role secret: may AbortJob.
    WorkerControlClient admin(ep, "ADMINSEC");
    auto aborted = admin.AbortJob("job-1", "test");
    Check(aborted.ok && aborted.body.find("aborted")->as_bool(), "rbac: admin may AbortJob");

    server.Stop();
  }
#endif  // SAMURAI_CONTROL_HAVE_ZMQ

  if (g_failures == 0) {
    std::printf("control selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "control selftest: %d failure(s)\n", g_failures);
  return 1;
}
