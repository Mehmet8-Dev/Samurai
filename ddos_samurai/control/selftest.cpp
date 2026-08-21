// Self-test for the native control-plane logic (increment 1). Asserts the
// ported behaviour matches the Python ddos_samurai/control contract. Exits 0 on
// success, 1 on the first failed check.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

#include <ctime>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audit_log.hpp"
#include "auth.hpp"
#include "autoscale.hpp"
#include "discovery.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "jwt.hpp"
#include "management_api.hpp"
#include "master_coordinator.hpp"
#include "multimaster.hpp"
#include "shard.hpp"
#include "shard_runner.hpp"
#include "telemetry.hpp"
#include "worker_shard_service.hpp"

#ifdef SAMURAI_CONTROL_HAVE_ZMQ
#include "control_client.hpp"
#include "control_server.hpp"
#include "curve.hpp"
#include "master_adapters.hpp"
#include "slave_node.hpp"
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

// Minimal HTTP round trip to 127.0.0.1:<port>; returns the raw response ("" on
// failure).
std::string HttpRequestRaw(int port, const std::string& raw_request) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return "";
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  timeval tv{3, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  std::string resp;
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
      ::send(fd, raw_request.data(), raw_request.size(), 0) >= 0) {
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return resp;
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

  // --- management api: router auth + endpoints + one socket round trip ---
  {
    namespace json = samurai::core::json;

    // state_provider: two workers (one tenantless, one under "t1").
    auto state = []() {
      json::Value st = json::Value::Object();
      json::Value workers = json::Value::Array();
      json::Value w1 = json::Value::Object();
      w1.set("worker_id", json::Value::Str("w1"));
      w1.set("tenant_namespace", json::Value::Str(""));
      json::Value w2 = json::Value::Object();
      w2.set("worker_id", json::Value::Str("w2"));
      w2.set("tenant_namespace", json::Value::Str("t1"));
      workers.push_back(w1);
      workers.push_back(w2);
      st.set("workers", std::move(workers));
      return st;
    };
    ManagementConfig cfg;
    cfg.role_tokens["admin"] = "ADM";
    cfg.role_tokens["viewer"] = "VIEW";
    ManagementProviders providers;
    providers.state_provider = state;
    providers.abort_callback = []() {
      json::Value r = json::Value::Object();
      r.set("aborted", json::Value::Bool(true));
      r.set("workers_notified", json::Value::Int(3));
      return r;
    };
    providers.metrics_provider = []() { return std::string("samurai_up 1\n"); };
    ManagementApi api(cfg, providers);

    auto req = [](const std::string& method, const std::string& path, const std::string& authz) {
      HttpRequest r;
      r.method = method;
      r.path = path;
      if (!authz.empty()) r.headers["authorization"] = authz;
      return r;
    };

    Check(api.Handle(req("GET", "/healthz", "")).status == 200, "mgmt: healthz open");
    // viewer token can read summary
    auto sum = api.Handle(req("GET", "/v1/cluster/summary", "Bearer VIEW"));
    Check(sum.status == 200, "mgmt: viewer reads summary");
    auto sumj = json::Parse(sum.body);
    Check(sumj.ok && sumj.value.find("workers_count")->as_int() == 2,
          "mgmt: summary counts both workers (no tenant filter)");
    // no auth -> 401
    Check(api.Handle(req("GET", "/v1/cluster/summary", "")).status == 401,
          "mgmt: missing token unauthorized");
    // viewer cannot abort -> 403
    Check(api.Handle(req("POST", "/v1/jobs/abort", "Bearer VIEW")).status == 403,
          "mgmt: viewer forbidden from abort");
    // admin can abort -> 200
    auto ab = api.Handle(req("POST", "/v1/jobs/abort", "Bearer ADM"));
    Check(ab.status == 200 && json::Parse(ab.body).value.find("aborted")->as_bool(),
          "mgmt: admin aborts");
    // workers endpoint lists workers
    auto wk = api.Handle(req("GET", "/v1/cluster/workers", "Bearer ADM"));
    Check(wk.status == 200 && json::Parse(wk.body).value.find("workers")->elements().size() == 2,
          "mgmt: workers endpoint lists both");
    // metrics (viewer+)
    auto mx = api.Handle(req("GET", "/metrics", "Bearer VIEW"));
    Check(mx.status == 200 && mx.body == "samurai_up 1\n", "mgmt: metrics text");
    Check(api.Handle(req("GET", "/nope", "Bearer ADM")).status == 404, "mgmt: unknown path 404");

    // ParseHttpRequest sanity (query + headers).
    HttpRequest parsed;
    Check(ParseHttpRequest("GET /v1/cluster/summary?tenant_namespace=t1 HTTP/1.1\r\n"
                           "Authorization: Bearer X\r\n\r\n",
                           parsed) &&
              parsed.path == "/v1/cluster/summary" && parsed.query["tenant_namespace"] == "t1" &&
              parsed.headers["authorization"] == "Bearer X",
          "mgmt: request parser");

    // End-to-end over a real socket.
    ManagementApiServer server("127.0.0.1:0", cfg, providers);
    Check(server.Start(), "mgmt: server starts");
    const std::string ep = server.endpoint();
    const int port = std::atoi(ep.substr(ep.rfind(':') + 1).c_str());
    const std::string resp =
        HttpRequestRaw(port, "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    Check(resp.find("200 OK") != std::string::npos && resp.find("\"status\":\"ok\"") != std::string::npos,
          "mgmt: socket round trip healthz 200");
    server.Stop();
    Check(!server.running(), "mgmt: server stops");
  }

  // --- audit: RBAC tamper-evident hash chain ---
  {
    namespace json = samurai::core::json;
    const std::string path = "/tmp/samurai_rbac_audit_test.log";
    std::remove(path.c_str());
    auto mk = [](const char* rpc, int allowed, const char* role) {
      json::Value v = json::Value::Object();
      v.set("rpc", json::Value::Str(rpc));
      v.set("allowed", json::Value::Int(allowed));
      v.set("role", json::Value::Str(role));
      return v;
    };
    {
      RbacAuditLog log(path);
      Check(log.Append(mk("AbortJob", 0, "worker")), "audit: append 1");
      Check(log.Append(mk("RegisterWorker", 1, "worker")), "audit: append 2");
      Check(log.Append(mk("StartShard", 1, "operator")), "audit: append 3");
    }
    Check(RbacAuditLog::Verify(path).ok, "audit: chain verifies");

    // Reopen: continues the chain from the last hash.
    std::string last_hash;
    {
      std::ifstream f(path);
      std::string line, l;
      while (std::getline(f, line)) {
        if (!line.empty()) l = line;
      }
      auto p = json::Parse(l);
      last_hash = p.value.find("entry_hash")->as_string("");
    }
    {
      RbacAuditLog log2(path);
      Check(log2.prev_hash() == last_hash, "audit: reopen loads last hash");
      Check(log2.Append(mk("Heartbeat", 1, "worker")), "audit: append after reopen");
    }
    Check(RbacAuditLog::Verify(path).ok, "audit: verifies after reopen append");

    // Tamper: edit a field without recomputing the hash -> verification breaks.
    {
      std::ifstream in(path);
      std::stringstream ss;
      ss << in.rdbuf();
      std::string content = ss.str();
      const auto pos = content.find("AbortJob");
      if (pos != std::string::npos) content.replace(pos, 8, "HackedJb");  // same length
      std::ofstream out(path, std::ios::trunc);
      out << content;
    }
    auto tampered = RbacAuditLog::Verify(path);
    Check(!tampered.ok && tampered.error.find("entry_hash mismatch") != std::string::npos,
          "audit: tampered entry detected");
    std::remove(path.c_str());
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
    const std::string lease = "/tmp/samurai_ha_lease_test.json";
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

    // Redis-lease elector over the in-memory KvStore (fencing epoch increments).
    InMemoryKvStore store;
    RedisLeaseLeaderElector r1("n1", "samurai:ha:master", &store, 30.0);
    RedisLeaseLeaderElector r2("n2", "samurai:ha:master", &store, 30.0);
    Check(r1.TryAcquire() && r1.IsLeader() && r1.LeaderEpoch() == 1,
          "ha: redis first acquires, epoch 1");
    Check(!r2.TryAcquire() && !r2.IsLeader(), "ha: redis second blocked");
    Check(r1.RenewOnce() && r1.IsLeader(), "ha: redis owner renews");
    Check(r1.Snapshot().find("leader_id")->as_string() == "n1", "ha: redis leader_id");
    r1.Release();
    Check(r2.TryAcquire() && r2.IsLeader() && r2.LeaderEpoch() == 2,
          "ha: redis re-acquire bumps fencing epoch to 2");
    r2.Release();
    // Null store -> inert.
    RedisLeaseLeaderElector offline("n3", "k", nullptr, 30.0);
    Check(!offline.TryAcquire() && !offline.IsLeader(), "ha: redis null store inert");
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

  // --- master: reverse-mode dispatch (NAT'd worker, no control_endpoint) ---
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
      int direct_calls = 0;
      int reverse_calls = 0;
      DispatchOutcome Dispatch(const std::string&, const std::string&, const std::string&,
                               const std::string&, std::int64_t, std::int64_t) override {
        ++direct_calls;
        return {false, "direct path must not be used for a reverse worker"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {}; }
      bool StopShard(const std::string&, const std::string&) override { return true; }
      DispatchOutcome DispatchReverse(const std::string&, const std::string& sid, const std::string&,
                                      const std::string&, std::int64_t count,
                                      std::int64_t) override {
        ++reverse_calls;
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());  // simulate the worker pulling + reporting
        return {true, "enqueued"};
      }
    };

    FakeView view;
    std::int64_t clk = 1000000;
    WorkerInfo w;
    w.worker_id = "rev1";
    w.capabilities["dispatch_mode"] = "reverse";  // deliberately no control_endpoint
    w.last_heartbeat_ms = clk;
    view.workers["rev1"] = w;
    FakeCmd cmd;
    cmd.view = &view;

    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 500;
    job.shard_unit_count = 250;  // -> 2 shards
    job.master_poll_interval_ms = 1;
    auto res = coord.RunSingleJob(job, "rjob");
    Check(res.rc == 0, "master(reverse): job completes rc=0");
    Check(cmd.reverse_calls == 2 && cmd.direct_calls == 0,
          "master(reverse): dispatched via the reverse path only");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 500,
          "master(reverse): aggregated sent=500");
  }

  // --- master: reverse pickup verification — a lost enqueue is rebalanced ---
  {
    namespace json = samurai::core::json;

    struct FakeView : MasterView {
      std::map<std::string, WorkerInfo> workers;
      std::map<std::string, std::string> stats;
      std::int64_t* clk = nullptr;
      std::vector<WorkerInfo> Workers() override {
        std::vector<WorkerInfo> out;
        for (auto& kv : workers) {
          WorkerInfo w = kv.second;
          w.last_heartbeat_ms = *clk;  // keep the worker "alive" (not lost)
          out.push_back(w);
        }
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
      int reverse_calls = 0;
      bool drop_first = true;
      DispatchOutcome Dispatch(const std::string&, const std::string&, const std::string&,
                               const std::string&, std::int64_t, std::int64_t) override {
        return {false, "no"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {}; }
      bool StopShard(const std::string&, const std::string&) override { return true; }
      DispatchOutcome DispatchReverse(const std::string&, const std::string& sid, const std::string&,
                                      const std::string&, std::int64_t count,
                                      std::int64_t) override {
        ++reverse_calls;
        if (drop_first) {
          drop_first = false;  // simulate a lost enqueue: worker never picks it up
          return {true, "enqueued-but-lost"};
        }
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());  // second attempt completes
        return {true, "enqueued"};
      }
    };

    FakeView view;
    std::int64_t clk = 1000000;
    view.clk = &clk;
    WorkerInfo w;
    w.worker_id = "rev1";
    w.capabilities["dispatch_mode"] = "reverse";
    w.active_shard_id = "";  // never echoes the shard -> pickup deemed lost
    view.workers["rev1"] = w;
    FakeCmd cmd;
    cmd.view = &view;

    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [&clk](int ms) { clk += ms; });
    JobConfig job;
    job.count = 100;
    job.shard_unit_count = 100;  // 1 shard
    job.master_poll_interval_ms = 1000;
    job.heartbeat_timeout_ms = 100000;  // keep the worker alive across the grace window
    job.reverse_pickup_grace_ms = 3000;
    auto res = coord.RunSingleJob(job, "pjob");
    Check(res.rc == 0, "master(reverse): stuck pickup rebalanced to completion");
    Check(cmd.reverse_calls == 2, "master(reverse): re-dispatched after pickup grace");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 100,
          "master(reverse): rebalanced shard aggregated sent=100");
  }

  // --- master: auto-fallback — direct unreachable, delivered via reverse pull ---
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
      int direct_calls = 0;
      int reverse_calls = 0;
      DispatchOutcome Dispatch(const std::string&, const std::string&, const std::string&,
                               const std::string&, std::int64_t, std::int64_t) override {
        ++direct_calls;
        return {false, "E_RPC endpoint unreachable (simulated NAT)"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {}; }
      bool StopShard(const std::string&, const std::string&) override { return true; }
      DispatchOutcome DispatchReverse(const std::string&, const std::string& sid, const std::string&,
                                      const std::string&, std::int64_t count,
                                      std::int64_t) override {
        ++reverse_calls;
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());  // worker pulled it + reported
        return {true, "enqueued"};
      }
    };

    FakeView view;
    std::int64_t clk = 1000000;
    WorkerInfo w;
    w.worker_id = "auto1";
    w.capabilities["dispatch_mode"] = "auto";
    w.capabilities["control_endpoint"] = "tcp://10.0.0.9:5099";  // advertised but unreachable
    w.last_heartbeat_ms = clk;
    view.workers["auto1"] = w;
    FakeCmd cmd;
    cmd.view = &view;

    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 300;
    job.shard_unit_count = 300;  // 1 shard
    job.master_poll_interval_ms = 1;
    auto res = coord.RunSingleJob(job, "ajob");
    Check(res.rc == 0, "master(auto): job completes via reverse fallback rc=0");
    Check(cmd.direct_calls >= 1 && cmd.reverse_calls >= 1,
          "master(auto): tried direct first, then fell back to reverse");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 300,
          "master(auto): aggregated sent=300");
  }

  // --- wss: StopShard reports completion via on_finalize (reverse straggler) ---
  {
    namespace json = samurai::core::json;

    struct BlockingRun : ShardRun {
      std::atomic<bool> alive{true};
      std::atomic<bool> term{false};
      bool IsAlive() override { return alive.load(); }
      std::int64_t Progress() const override { return 5; }
      std::int64_t Sent() const override { return 5; }
      std::int64_t Errors() const override { return 0; }
      int ExitCode() const override { return term.load() ? -15 : 0; }
      void Terminate() override {
        term.store(true);
        alive.store(false);
      }
      void Join() override {
        while (!term.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        alive.store(false);
      }
    };
    struct BlockingRunner : ShardRunner {
      std::shared_ptr<ShardRun> Start(const std::string&, const json::Value&) override {
        return std::make_shared<BlockingRun>();
      }
    };

    BlockingRunner runner;
    WorkerShardService svc("wb1", &runner);
    std::string got_sid, got_stats;
    int fin = 0;
    svc.set_on_finalize([&](const std::string& sid, const std::string& st) {
      got_sid = sid;
      got_stats = st;
      ++fin;
    });
    RpcContext ctx;
    json::Value start = json::Value::Object();
    start.set("shard_id", json::Value::Str("sB"));
    start.set("job_id", json::Value::Str("jB"));
    {
      json::Value a = json::Value::Object();
      a.set("count", json::Value::Int(5));
      start.set("args_json", json::Value::Str(a.dump()));
    }
    auto sres = svc.StartShard(start, ctx);
    Check(sres.find("started") && sres.find("started")->as_bool(), "wss(stop): shard started");

    json::Value stop = json::Value::Object();
    stop.set("shard_id", json::Value::Str("sB"));
    auto pres = svc.StopShard(stop, ctx);
    Check(pres.find("stopped") && pres.find("stopped")->as_bool(), "wss(stop): shard stopped");
    Check(fin == 1 && got_sid == "sB", "wss(stop): on_finalize fired once on stop");
    const auto p = json::Parse(got_stats);
    Check(p.ok && p.value.is_object() && p.value.find("status") &&
              p.value.find("status")->as_string() == "stopped",
          "wss(stop): finalized status=stopped");
    svc.WaitForShardIdle("sB");  // let the bailing monitor thread exit cleanly
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

  // --- full distributed round trip: slave register/heartbeat + master
  //     coordinator dispatch over the real ZMQ transport ---
  {
    namespace json = samurai::core::json;
    AuthConfig no_auth;  // inactive (no secret, no rbac)

    // Master: servicer + control server.
    ServicerConfig scfg;
    scfg.cluster_id = "cluster-int";
    Servicer master_svc(scfg);
    ControlServer master_server("tcp://127.0.0.1:*", &master_svc, no_auth);
    Check(master_server.Start(), "int: master server up");
    const std::string em = master_server.endpoint();

    // Worker: shard service + control server.
    InMemoryShardRunner runner;
    WorkerShardService worker_svc("w1", &runner);
    ControlServer worker_server("tcp://127.0.0.1:*", &worker_svc, no_auth);
    Check(worker_server.Start(), "int: worker server up");
    const std::string ew = worker_server.endpoint();

    // Slave registers with the master, advertising its control endpoint.
    SlaveControlClient slave_client(em);
    SlaveConfig slcfg;
    slcfg.worker_id = "w1";
    slcfg.capabilities["control_endpoint"] = ew;
    SlaveNode slave(&slave_client, slcfg);
    Check(slave.Register(), "int: slave registers with master");
    auto hb = slave.HeartbeatOnce();
    Check(hb.ok && hb.acknowledged, "int: slave heartbeat acknowledged");
    Check(master_svc.worker_count() == 1, "int: master registry has the worker");

    // Master dispatches a job; the worker runs the shards; master aggregates.
    ServicerMasterView view(&master_svc);
    ClientWorkerCommander cmd;
    MasterCoordinator coord(&view, &cmd);
    JobConfig job;
    job.count = 1000;
    job.shard_unit_count = 250;  // -> 4 shards, all to the single worker
    job.master_poll_interval_ms = 10;
    auto res = coord.RunSingleJob(job, "jobI");
    Check(res.rc == 0, "int: distributed job completes rc=0");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 1000,
          "int: aggregated sent=1000 across the cluster");
    Check(res.snapshot.find("shards_reported")->as_int() == 4, "int: 4 shards reported");

    worker_server.Stop();
    master_server.Stop();
  }

  // --- reverse-mode round trip over ZMQ: master enqueues -> worker pulls it on
  //     its heartbeat -> executes -> reports stats outbound -> master sees it ---
  {
    namespace json = samurai::core::json;
    AuthConfig no_auth;

    ServicerConfig scfg;
    scfg.cluster_id = "cluster-rev";
    Servicer master_svc(scfg);
    ControlServer master_server("tcp://127.0.0.1:*", &master_svc, no_auth);
    Check(master_server.Start(), "rev: master server up");
    const std::string em = master_server.endpoint();

    // Reverse worker: shard service + runner, but NO inbound control server.
    InMemoryShardRunner runner;
    WorkerShardService worker_svc("wr1", &runner);

    SlaveControlClient slave_client(em);
    SlaveControlClient reporter(em);
    SlaveConfig slcfg;
    slcfg.worker_id = "wr1";
    slcfg.capabilities["dispatch_mode"] = "reverse";  // no control_endpoint
    SlaveNode slave(&slave_client, slcfg);
    slave.set_on_start(
        [&worker_svc](const json::Value& shard) { worker_svc.StartShard(shard, RpcContext{}); });
    worker_svc.set_on_finalize([&reporter](const std::string& sid, const std::string& stats) {
      reporter.ReportStats("wr1", sid, stats, 0);
    });
    Check(slave.Register(), "rev: reverse slave registers");

    // Master queues a start command; the worker only learns of it via heartbeat.
    PendingCommand pc;
    pc.type = "start";
    pc.shard_id = "rshard-1";
    pc.job_id = "rjobZ";
    {
      json::Value a = json::Value::Object();
      a.set("count", json::Value::Int(321));
      pc.args_json = a.dump();
    }
    pc.packet_count = 321;
    master_svc.EnqueueCommand("wr1", pc);
    Check(!master_svc.HasShardStats("rshard-1"), "rev: no stats before the worker runs");

    auto hb = slave.HeartbeatOnce();
    Check(hb.ok && hb.acknowledged, "rev: heartbeat pulls the shard");
    worker_svc.WaitForShardIdle("rshard-1");  // wait for finalize + outbound report

    Check(master_svc.HasShardStats("rshard-1"), "rev: master received the reported stats");
    const auto parsed = json::Parse(master_svc.GetShardStatsRaw("rshard-1"));
    Check(parsed.ok && parsed.value.is_object() && parsed.value.find("sent") &&
              parsed.value.find("sent")->as_int() == 321,
          "rev: reported sent=321 round-tripped to the master");

    master_server.Stop();
  }

  // --- CURVE transport encryption: encrypted round trip + key enforcement ---
  {
    const CurveKeypair kp = GenerateCurveKeypair();
    Check(kp.ok, "curve: keypair generated");

    ServicerConfig scfg;
    scfg.cluster_id = "cluster-curve";
    Servicer servicer(scfg);
    AuthConfig no_auth;
    ControlServer server("tcp://127.0.0.1:*", &servicer, no_auth);
    server.set_curve_server(kp.secret_key);
    Check(server.Start(), "curve: encrypted server starts");
    const std::string ep = server.endpoint();

    // Client with the correct server public key: encrypted round trip works.
    SlaveControlClient good(ep, "", "", 1500);
    Check(good.set_curve_client(kp.public_key), "curve: client keys set");
    auto reg = good.RegisterWorker("cw1", "h", {});
    Check(reg.ok && reg.body.find("accepted") && reg.body.find("accepted")->as_bool(),
          "curve: encrypted RegisterWorker accepted");

    // Plaintext client against a CURVE server: handshake fails (no reply).
    SlaveControlClient plain(ep, "", "", 800);
    auto reg2 = plain.RegisterWorker("cw2", "h", {});
    Check(!reg2.ok, "curve: plaintext client rejected by encrypted server");

    server.Stop();
  }

  // --- direct-channel CURVE: the master encrypts StartShard/Probe toward a
  //     worker that advertised its inbound control server's CURVE public key ---
  {
    namespace json = samurai::core::json;
    const CurveKeypair kp = GenerateCurveKeypair();
    Check(kp.ok, "curve-direct: worker keypair generated");
    AuthConfig no_auth;

    ServicerConfig scfg;
    scfg.cluster_id = "cluster-curve-direct";
    Servicer master_svc(scfg);
    ControlServer master_server("tcp://127.0.0.1:*", &master_svc, no_auth);
    Check(master_server.Start(), "curve-direct: master server up");
    const std::string em = master_server.endpoint();

    // Worker inbound control server protected with CURVE.
    InMemoryShardRunner runner;
    WorkerShardService worker_svc("wc1", &runner);
    ControlServer worker_server("tcp://127.0.0.1:*", &worker_svc, no_auth);
    worker_server.set_curve_server(kp.secret_key);
    Check(worker_server.Start(), "curve-direct: encrypted worker server up");
    const std::string ew = worker_server.endpoint();

    // A plaintext master client is rejected by the CURVE-protected worker.
    {
      WorkerControlClient plain(ew, "", "", 800);
      auto rr = plain.StartShard("cshard-x", "cjob", "{}", 1, 1000);
      Check(!rr.ok, "curve-direct: plaintext StartShard rejected by encrypted worker");
    }

    // Slave registers advertising its endpoint AND its control CURVE public key.
    SlaveControlClient slave_client(em);
    SlaveConfig slcfg;
    slcfg.worker_id = "wc1";
    slcfg.capabilities["control_endpoint"] = ew;
    slcfg.capabilities["control_curve_public"] = kp.public_key;
    SlaveNode slave(&slave_client, slcfg);
    Check(slave.Register(), "curve-direct: slave registers with curve public");
    slave.HeartbeatOnce();

    // The commander (with the servicer) looks up the worker key and encrypts the
    // direct dispatch; the whole job completes over the encrypted channel.
    ServicerMasterView view(&master_svc);
    ClientWorkerCommander cmd("", "", 5000, &master_svc);
    MasterCoordinator coord(&view, &cmd);
    JobConfig job;
    job.count = 500;
    job.shard_unit_count = 500;  // single shard -> one direct StartShard + Probe
    job.master_poll_interval_ms = 10;
    auto res = coord.RunSingleJob(job, "jobCD");
    Check(res.rc == 0, "curve-direct: encrypted dispatch completes rc=0");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 500,
          "curve-direct: encrypted shard reported sent=500");

    worker_server.Stop();
    master_server.Stop();
  }

  // --- pickup echo daemon-e2e: over real ZMQ, the worker echoes active_shard_id
  //     on its heartbeat so the master confirms a reverse pickup via the echo
  //     (independently of the later ReportStats completion) ---
  {
    namespace json = samurai::core::json;
    AuthConfig no_auth;

    struct BlockingRun : ShardRun {
      std::atomic<bool> alive{true};
      std::atomic<bool> term{false};
      bool IsAlive() override { return alive.load(); }
      std::int64_t Progress() const override { return 7; }
      std::int64_t Sent() const override { return 7; }
      std::int64_t Errors() const override { return 0; }
      int ExitCode() const override { return term.load() ? -15 : 0; }
      void Terminate() override { term.store(true); alive.store(false); }
      void Join() override {
        while (!term.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        alive.store(false);
      }
    };
    struct BlockingRunner : ShardRunner {
      std::shared_ptr<ShardRun> Start(const std::string&, const json::Value&) override {
        return std::make_shared<BlockingRun>();
      }
    };

    ServicerConfig scfg;
    scfg.cluster_id = "cluster-pickup";
    Servicer master_svc(scfg);
    ControlServer master_server("tcp://127.0.0.1:*", &master_svc, no_auth);
    Check(master_server.Start(), "pickup-e2e: master server up");
    const std::string em = master_server.endpoint();

    BlockingRunner runner;
    WorkerShardService worker_svc("wp1", &runner);

    SlaveControlClient slave_client(em);
    SlaveConfig slcfg;
    slcfg.worker_id = "wp1";
    slcfg.capabilities["dispatch_mode"] = "reverse";
    SlaveNode slave(&slave_client, slcfg);
    slave.set_on_start(
        [&worker_svc](const json::Value& s) { worker_svc.StartShard(s, RpcContext{}); });
    slave.set_on_stop([&worker_svc](const std::string& sid) {
      json::Value stop = json::Value::Object();
      stop.set("shard_id", json::Value::Str(sid));
      worker_svc.StopShard(stop, RpcContext{});
    });
    slave.set_active_shard_provider([&worker_svc]() { return worker_svc.ActiveShardId(); });
    Check(slave.Register(), "pickup-e2e: reverse slave registers");

    PendingCommand pc;
    pc.type = "start";
    pc.shard_id = "pe1";
    pc.job_id = "jP";
    {
      json::Value a = json::Value::Object();
      a.set("count", json::Value::Int(7));
      pc.args_json = a.dump();
    }
    pc.packet_count = 7;
    master_svc.EnqueueCommand("wp1", pc);

    // HB1 pulls + starts the shard (the master optimistically marks the pickup).
    auto hb1 = slave.HeartbeatOnce();
    Check(hb1.ok, "pickup-e2e: first heartbeat pulls the shard");

    // HB2: with no command in flight, the worker's own echo of the running shard
    // is what keeps active_shard_id set -> the master confirms the pickup.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto hb2 = slave.HeartbeatOnce();
    Check(hb2.ok, "pickup-e2e: second heartbeat echoes active shard");
    {
      auto ws = master_svc.SnapshotWorkers();
      Check(ws.size() == 1 && ws[0].active_shard_id == "pe1",
            "pickup-e2e: master confirms pickup via active_shard_id echo");
    }

    // Reverse stop over the heartbeat releases the blocking shard.
    PendingCommand stop_cmd;
    stop_cmd.type = "stop";
    stop_cmd.shard_id = "pe1";
    master_svc.EnqueueCommand("wp1", stop_cmd);
    slave.HeartbeatOnce();
    worker_svc.WaitForShardIdle("pe1");

    // A further heartbeat carries no command, so the idle echo alone must clear
    // the master's view -> proves the echo (not a stale optimistic value) drives
    // active_shard_id end-to-end over ZMQ.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    slave.HeartbeatOnce();
    {
      auto ws = master_svc.SnapshotWorkers();
      Check(ws.size() == 1 && ws[0].active_shard_id.empty(),
            "pickup-e2e: master clears active via idle echo after stop");
    }

    master_server.Stop();
  }
#endif  // SAMURAI_CONTROL_HAVE_ZMQ

  if (g_failures == 0) {
    std::printf("control selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "control selftest: %d failure(s)\n", g_failures);
  return 1;
}
