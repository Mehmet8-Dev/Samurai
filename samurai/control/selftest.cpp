// Self-test for the native control-plane logic (increment 1). Asserts the
// ported behaviour matches the Python samurai/control contract. Exits 0 on
// success, 1 on the first failed check.

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <numeric>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audit_log.hpp"
#include "auth.hpp"
#include "daemon/daemon_args.hpp"
#include "autoscale.hpp"
#include "closed_loop.hpp"
#include "lever_shield.hpp"
#include "variant_memory.hpp"
#include "ban_memory.hpp"
#include "online_adapter.hpp"
#include "novelty_detector.hpp"
#include "rl_explore.hpp"
#include "rl_policy.hpp"
#include "discovery.hpp"
#include "sut_probe.hpp"
#include "http_client.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "jwt.hpp"
#include "k8s_client.hpp"
#include "management_api.hpp"
#include "provisioner.hpp"
#include "master_coordinator.hpp"
#include "multimaster.hpp"
#include "redis_kvstore.hpp"
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

  // --- autoscale signal path: coordinator progress_cb reports live backlog ---
  // Proves the wiring the daemon relies on: RunSingleJob feeds (pending,inflight)
  // shard counts to JobConfig.progress_cb, which the master feeds to MaybeScale.
  {
    namespace json = samurai::core::json;
    struct PView : MasterView {
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
    struct PCmd : WorkerCommander {
      PView* view = nullptr;
      DispatchOutcome Dispatch(const std::string&, const std::string& sid, const std::string&,
                               const std::string&, std::int64_t count, std::int64_t) override {
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override {
        return {"done", "", "{}"};
      }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
    };
    PView view;
    std::int64_t clk = 1000000;
    WorkerInfo w;
    w.worker_id = "w1";
    w.capabilities["control_endpoint"] = "tcp://w1:5099";
    w.last_heartbeat_ms = clk;
    view.workers["w1"] = w;
    PCmd cmd;
    cmd.view = &view;
    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 1000;
    job.shard_unit_count = 250;  // 4 shards, 1 worker => a backlog must be observed
    job.master_poll_interval_ms = 1;
    int max_pending = 0;
    bool called = false;
    job.progress_cb = [&](int p, int i) {
      called = true;
      if (p > max_pending) max_pending = p;
      (void)i;
    };
    auto res = coord.RunSingleJob(job, "pcbjob");
    Check(res.rc == 0, "autoscale-signal: job completes rc=0");
    Check(called && max_pending > 0, "autoscale-signal: progress_cb saw pending backlog");
  }

  // --- k8s_client: scale path + config resolution ---
  {
    Check(ScalePath("deployment", "default", "slave") ==
              "/apis/apps/v1/namespaces/default/deployments/slave/scale",
          "k8s: deployment scale path");
    Check(ScalePath("StatefulSet", "ns1", "s") ==
              "/apis/apps/v1/namespaces/ns1/statefulsets/s/scale",
          "k8s: statefulset scale path (case-insensitive)");
    auto over = ResolveK8sConfig("http://127.0.0.1:8001", false);
    Check(over.active && over.source == "api-override" && over.api_base == "http://127.0.0.1:8001",
          "k8s: api-override config active");
    // Reader must recognise a complete response (Content-Length) so it stops
    // instead of blocking until a keep-alive connection closes.
    Check(ResponseCompleteForTest("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"),
          "k8s: response complete at content-length");
    Check(!ResponseCompleteForTest("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab"),
          "k8s: response incomplete under content-length");
    Check(ResponseCompleteForTest("HTTP/1.1 204 No Content\r\nX: y\r\n\r\n"),
          "k8s: bodyless response complete on headers");
    Check(!ResponseCompleteForTest("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"),
          "k8s: headers-only with content-length not complete");
    // No override + no in-cluster service account => inactive (in-memory fallback).
    ::unsetenv("KUBERNETES_SERVICE_HOST");
    auto none = ResolveK8sConfig("", false);
    Check(!none.active, "k8s: no config => inactive");
    // Live scale round-trip only when a proxy is provided (e.g. `kubectl proxy`).
    if (const char* api = std::getenv("SAMURAI_TEST_K8S_API")) {
      const char* kind = std::getenv("SAMURAI_TEST_K8S_KIND");
      const char* ns = std::getenv("SAMURAI_TEST_K8S_NS");
      const char* name = std::getenv("SAMURAI_TEST_K8S_NAME");
      auto cfg = ResolveK8sConfig(api, true);
      auto g = GetScale(cfg, kind ? kind : "deployment", ns ? ns : "default",
                        name ? name : "samurai-slave");
      Check(g.ok, "k8s(live): GET scale ok");
      auto p = PatchScale(cfg, kind ? kind : "deployment", ns ? ns : "default",
                          name ? name : "samurai-slave", g.replicas);
      Check(p.ok && p.replicas == g.replicas, "k8s(live): PATCH scale round-trip");
    }
  }

  // --- autoscale real backend: reads + patches through the injected backend ---
  {
    double clock = 1000.0;
    AutoscaleConfig cfg;
    cfg.enabled = true;
    cfg.target_name = "slave";
    cfg.min_replicas = 1;
    cfg.max_replicas = 10;
    cfg.step = 10;         // no step limiting so we reach desired in one move
    cfg.cooldown_s = 5.0;
    cfg.shards_per_worker = 4;
    AutoscaleController ctl(cfg, [&clock]() { return clock; });
    int cluster_replicas = 2;  // the "live" replica count the backend owns
    int reads = 0, patches = 0;
    AutoscaleBackend b;
    b.read_replicas = [&](int& out) { ++reads; out = cluster_replicas; return true; };
    b.patch_replicas = [&](int desired, int& applied) {
      ++patches;
      cluster_replicas = desired;  // the cluster adopts the desired count
      applied = desired;
      return true;
    };
    ctl.set_backend(std::move(b));
    Check(ctl.has_backend() && ctl.backend_mode() == "kubernetes", "autoscale-k8s: backend active");
    // 16 pending / 4 per worker => desired 4; backend read sees 2, patch -> 4.
    auto d = ctl.MaybeScale(16, 0, 1);
    Check(d.changed && d.ok && d.current == 2 && d.desired == 4 && d.applied == 4,
          "autoscale-k8s: read=2 patch->4 applied");
    Check(reads == 1 && patches == 1 && cluster_replicas == 4,
          "autoscale-k8s: backend read+patch invoked, cluster updated");
    // Backend patch failure => no change, retry (no cooldown consumed).
    clock += 6.0;
    AutoscaleBackend bf;
    bf.read_replicas = [&](int& out) { out = cluster_replicas; return true; };
    bf.patch_replicas = [&](int, int&) { return false; };
    ctl.set_backend(std::move(bf));
    auto d2 = ctl.MaybeScale(40, 0, 1);  // desired 10 > 4 => wants a patch
    Check(!d2.changed && !d2.ok && d2.reason == "backend-patch-failed",
          "autoscale-k8s: patch failure reported, no change");
  }

  // --- closed-loop: disabled short-circuits ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;  // enabled=false
    ClosedLoopController cl(cfg);
    LoadSample s;
    s.valid = true;
    auto d = cl.Step(s);
    Check(!d.enabled && d.done && d.phase == "disabled", "closed-loop: disabled short-circuits");
  }

  // --- closed-loop: SLO health verdict (unknown inputs are skipped) ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.slo_max_error_pct = 1.0;
    cfg.slo_max_latency_ms = 200.0;  // latency unknown on the sample => rule skipped
    ClosedLoopController cl(cfg);

    LoadSample green;
    green.attempted = 1000;
    green.errors = 5;  // 0.5% <= 1%
    Check(cl.IsHealthy(green), "closed-loop: 0.5% error is green");

    LoadSample red;
    red.attempted = 1000;
    red.errors = 20;  // 2% > 1%
    Check(!cl.IsHealthy(red), "closed-loop: 2% error is red");

    LoadSample derived;  // error_pct left at -1 => derived from errors/attempted
    derived.attempted = 100;
    derived.errors = 2;  // 2%
    Check(!cl.IsHealthy(derived), "closed-loop: derived error_pct honored");
  }

  // --- closed-loop pushback SLO: a rate-limited window is red even with 0 errors ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.slo_max_pushback_pct = 20.0;  // >20% (4xx+5xx) share is a breach
    ClosedLoopController cl(cfg);

    LoadSample low;  // 10% pushback, no errors => green
    low.attempted = 1000;
    low.errors = 0;
    low.pushback_pct = 10.0;
    Check(cl.IsHealthy(low), "closed-loop: 10% pushback under cap is green");

    LoadSample high;  // 60% of requests 429'd, still 0 errors => must be red
    high.attempted = 1000;
    high.errors = 0;
    high.pushback_pct = 60.0;
    Check(!cl.IsHealthy(high), "closed-loop: 60% pushback (429 wall) is red despite 0 errors");

    LoadSample unknown;  // pushback unknown (-1) => rule skipped, not failed
    unknown.attempted = 1000;
    unknown.errors = 0;
    Check(cl.IsHealthy(unknown), "closed-loop: unknown pushback skips the rule");
  }

  // --- closed-loop AIMD: increase while green, backoff on violation ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.strategy = ClosedLoopStrategy::kAimd;
    cfg.min_rps = 100;
    cfg.max_rps = 10000;
    cfg.initial_rps = 1000;
    cfg.aimd_increase_rps = 500;
    cfg.aimd_backoff = 0.5;
    cfg.slo_max_error_pct = 1.0;
    ClosedLoopController cl(cfg);
    Check(cl.initial_setpoint() == 1000, "closed-loop aimd: initial setpoint");

    LoadSample green;
    green.attempted = 1000;
    green.errors = 0;
    auto d1 = cl.Step(green);  // ran 1000 green -> best=1000, next=1500
    Check(d1.last_healthy && d1.setpoint_rps == 1500 && d1.best_good_rps == 1000,
          "closed-loop aimd: additive increase");

    LoadSample red;
    red.attempted = 1000;
    red.errors = 50;           // 5% > 1%
    auto d2 = cl.Step(red);    // ran 1500 red -> next = 1500*0.5 = 750
    Check(!d2.last_healthy && d2.setpoint_rps == 750 && d2.phase == "backoff",
          "closed-loop aimd: multiplicative backoff");
    Check(d2.best_good_rps == 1000, "closed-loop aimd: best-good retained across backoff");
  }

  // --- closed-loop AIMD: window budget ends the run at best-good ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.strategy = ClosedLoopStrategy::kAimd;
    cfg.min_rps = 100;
    cfg.max_rps = 10000;
    cfg.initial_rps = 1000;
    cfg.aimd_increase_rps = 500;
    cfg.aimd_max_windows = 2;
    cfg.slo_max_error_pct = 1.0;
    ClosedLoopController cl(cfg);
    LoadSample green;
    green.attempted = 1000;
    green.errors = 0;
    cl.Step(green);            // window 1
    auto d = cl.Step(green);   // window 2 -> budget exhausted
    Check(d.done && d.phase == "done" && d.setpoint_rps == d.best_good_rps,
          "closed-loop aimd: window budget stops at best-good");
  }

  // --- closed-loop binary-search: brackets up then bisects to the ceiling ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.strategy = ClosedLoopStrategy::kBinSearch;
    cfg.min_rps = 1000;
    cfg.max_rps = 100000;
    cfg.initial_rps = 1000;
    cfg.binsearch_tolerance_rps = 300;
    cfg.binsearch_max_windows = 40;
    cfg.slo_max_error_pct = 1.0;
    ClosedLoopController cl(cfg);

    // The SUT sustains up to ~8000 rps; above that it starts erroring.
    const double ceiling = 8000.0;
    int guard = 0;
    ClosedLoopDecision d;
    double ran = cl.current_setpoint();
    do {
      LoadSample s;
      s.attempted = 1000;
      s.errors = ran <= ceiling ? 0 : 50;  // green under the ceiling, red above
      d = cl.Step(s);
      ran = d.setpoint_rps;
    } while (!d.done && ++guard < 60);

    Check(d.done, "closed-loop binsearch: converges");
    Check(d.best_good_rps <= ceiling && d.best_good_rps >= ceiling - 1500,
          "closed-loop binsearch: best-good sits just under the true ceiling");
  }

  // --- closed-loop kRl: the safety shield bounds the policy proposal ---
  {
    using namespace samurai::control;
    ClosedLoopConfig cfg;
    cfg.enabled = true;
    cfg.strategy = ClosedLoopStrategy::kRl;
    cfg.min_rps = 100;
    cfg.max_rps = 100000;
    cfg.initial_rps = 1000;
    cfg.aimd_increase_rps = 500;
    cfg.aimd_backoff = 0.5;
    cfg.rl_max_jump_factor = 2.0;
    cfg.slo_max_error_pct = 1.0;
    ClosedLoopController cl(cfg);  // setpoint starts at 1000

    // Green, proposal within the 2x jump cap -> taken verbatim.
    LoadSample g1;
    g1.attempted = 1000;
    g1.errors = 0;
    g1.rl_action_rps = 1800;  // <= 1000*2
    auto d1 = cl.Step(g1);
    Check(d1.phase == "rl" && d1.setpoint_rps == 1800, "kRl shield: in-range proposal honored");

    // Green, proposal exceeds the jump cap (1800*2=3600) -> clamped to the cap.
    LoadSample g2;
    g2.attempted = 1000;
    g2.errors = 0;
    g2.rl_action_rps = 999999;
    auto d2 = cl.Step(g2);
    Check(d2.setpoint_rps == 3600, "kRl shield: over-jump proposal clamped to factor*setpoint");

    // Red window -> forced multiplicative backoff, proposal ignored.
    LoadSample r;
    r.attempted = 1000;
    r.errors = 50;             // 5% > 1%
    r.rl_action_rps = 999999;  // policy still says "go higher"
    auto d3 = cl.Step(r);
    Check(!d3.last_healthy && d3.phase == "backoff" && d3.setpoint_rps == 1800,
          "kRl shield: SLO-red forces backoff, ignores proposal");

    // No proposal (-1) on a green window -> AIMD additive fallback.
    LoadSample g4;
    g4.attempted = 1000;
    g4.errors = 0;
    g4.rl_action_rps = -1.0;
    auto d4 = cl.Step(g4);
    Check(d4.setpoint_rps == 1800 + 500, "kRl shield: missing proposal falls back to AIMD");
  }

  // --- RL policy: SRLP load + forward + feature layout (golden) ---
  {
    using namespace samurai::control;
    // Build a tiny SRLP file by hand (must match export.py's byte layout):
    // in_dim=2, one linear layer out_dim=1, W=[[1,0]], b=[0], identity norm,
    // action in [0,100]. So output = clamp(x0,0,1)*100.
    auto put_u32 = [](std::string& s, std::uint32_t v) {
      s.append(reinterpret_cast<const char*>(&v), 4);
    };
    auto put_f32 = [](std::string& s, float v) {
      s.append(reinterpret_cast<const char*>(&v), 4);
    };
    std::string blob = "SRLP";
    put_u32(blob, 2);   // version
    put_u32(blob, 2);   // in_dim
    put_u32(blob, 1);   // n_layers
    put_u32(blob, 1);   // out_dims[0] (== action_dim)
    put_f32(blob, 1.0f); put_f32(blob, 0.0f);  // W row
    put_f32(blob, 0.0f);                        // b
    put_f32(blob, 0.0f); put_f32(blob, 0.0f);  // norm_mean
    put_f32(blob, 1.0f); put_f32(blob, 1.0f);  // norm_std
    put_u32(blob, 1);                           // action_dim
    put_f32(blob, 0.0f);                        // action_lo[0]
    put_f32(blob, 100.0f);                      // action_hi[0]

    const std::string path = "/tmp/samurai_selftest_policy.srlp";
    { std::ofstream o(path, std::ios::binary); o.write(blob.data(), blob.size()); }

    RlPolicy p;
    std::string err;
    Check(p.Load(path, &err), "rl policy: SRLP loads");
    Check(p.input_dim() == 2 && p.action_dim() == 1, "rl policy: in/action dims read");
    Check(std::abs(p.Propose({0.3f, 9.0f})[0] - 30.0) < 1e-3, "rl policy: forward matches (0.3*100)");
    Check(std::abs(p.Propose({5.0f, 0.0f})[0] - 100.0) < 1e-3, "rl policy: output clamped to action_hi");

    // Feature layout: 20-vector, correct positions + mask bits.
    RlStateInputs in;
    in.rps = 500; in.max_rps = 1000; in.win = 8; in.step_horizon = 32.0;
    in.error_pct = 2.0;            // known
    in.p99_ms = -1.0;              // unknown -> imputed 0, mask 0
    in.rate_limited_ratio = 0.4;   // known
    auto f = RlPolicy::BuildFeatures(in);
    Check(f.size() == 20, "rl policy: feature vector width");
    Check(f[0] == 0.5f, "rl policy: rps_norm");
    Check(f[1] == 2.0f, "rl policy: error_pct");
    Check(f[4] == 0.0f, "rl policy: unknown p99 imputed to 0");
    Check(f[5] == 0.25f, "rl policy: step_norm = win/horizon");
    Check(f[6] == 0.4f, "rl policy: rate_limited_ratio");
    Check(f[11] == 1.0f, "rl policy: error_pct mask set");
    Check(f[14] == 0.0f, "rl policy: p99 mask clear (unknown)");
    Check(f[15] == 1.0f, "rl policy: rate_limited mask set");
    std::remove(path.c_str());

    // Path-aware block features: appended after the 20 base dims as [ratios..., known...].
    // best_success = {-1, 0.9, -1, 0.05, -1} => variant1 honored (ratio .1), variant3
    // blocked (ratio .95), the rest unobserved (ratio imputed 0, known 0). Must match
    // the Python dataset layout (build_dataset._encode_block).
    RlStateInputs bin;
    bin.rps = 500; bin.max_rps = 1000; bin.win = 8; bin.step_horizon = 32.0;
    bin.variant_block_success = {-1.0, 0.9, -1.0, 0.05, -1.0};
    auto bf = RlPolicy::BuildFeatures(bin);
    Check(bf.size() == 30, "rl policy: block features widen state to 30");
    Check(std::abs(bf[20] - 0.0f) < 1e-6 && bf[25] == 0.0f, "rl policy: unobserved variant0 -> ratio 0, known 0");
    Check(std::abs(bf[21] - 0.1f) < 1e-6 && bf[26] == 1.0f, "rl policy: honored variant1 -> ratio .1, known 1");
    Check(std::abs(bf[23] - 0.95f) < 1e-6 && bf[28] == 1.0f, "rl policy: blocked variant3 -> ratio .95, known 1");
    // Empty memory => legacy 20-dim state (old policies keep loading).
    RlStateInputs lin; lin.rps = 1; lin.max_rps = 1;
    Check(RlPolicy::BuildFeatures(lin).size() == 20, "rl policy: empty block memory -> legacy 20-dim");

    // Persistent-ban features: appended AFTER the block features as [ban_pressure,
    // ban_known]. Must match the Python dataset layout (build_dataset._encode_ban).
    RlStateInputs nin;  // ban only, no block -> width 22
    nin.rps = 500; nin.max_rps = 1000; nin.ban_features = true; nin.ban_pressure = 0.7;
    auto nf = RlPolicy::BuildFeatures(nin);
    Check(nf.size() == 22, "rl policy: ban features widen state to 22");
    Check(std::abs(nf[20] - 0.7f) < 1e-6 && nf[21] == 1.0f, "rl policy: ban_pressure .7, known 1");
    RlStateInputs uin;  // ban enabled but never observed -> pressure 0, known 0
    uin.rps = 1; uin.max_rps = 1; uin.ban_features = true;  // ban_pressure default -1
    auto uf = RlPolicy::BuildFeatures(uin);
    Check(uf.size() == 22 && uf[20] == 0.0f && uf[21] == 0.0f,
          "rl policy: unobserved ban -> pressure 0, known 0");
    // Block + ban together: ban trails the block bits (width 20 + 2V + 2 = 32).
    RlStateInputs cin;
    cin.rps = 500; cin.max_rps = 1000;
    cin.variant_block_success = {-1.0, 0.9, -1.0, 0.05, -1.0};
    cin.ban_features = true; cin.ban_pressure = 0.4;
    auto cf = RlPolicy::BuildFeatures(cin);
    Check(cf.size() == 32, "rl policy: block+ban widen state to 32");
    Check(std::abs(cf[30] - 0.4f) < 1e-6 && cf[31] == 1.0f, "rl policy: ban trails block bits");

    // Flow-level IPS features: appended AFTER the ban features as four flow rates
    // then ONE shared flow_known bit. Must match the Python dataset layout
    // (build_dataset._encode_flow): rates imputed 0 when < 0; known bit 1 only on a
    // flow-capable transport with a measurable rate. flow-only => width 20 + 5 = 25.
    RlStateInputs fin;
    fin.rps = 500; fin.max_rps = 1000; fin.flow_features = true; fin.flow_capable = true;
    fin.rst_rate = 0.0875; fin.connect_timeout_rate = 0.0;  // retransmit/timeout_close left -1
    auto ff = RlPolicy::BuildFeatures(fin);
    Check(ff.size() == 25, "rl policy: flow features widen state to 25");
    Check(std::abs(ff[20] - 0.0875f) < 1e-6 && ff[21] == 0.0f, "rl policy: rst_rate .0875, connect_timeout 0");
    Check(ff[22] == 0.0f && ff[23] == 0.0f, "rl policy: unknown flow rates imputed 0");
    Check(ff[24] == 1.0f, "rl policy: flow_known 1 on flow-capable transport with a rate");
    // Not flow-capable (kernel_socket serve) => whole group masked (known bit 0).
    RlStateInputs fkin;
    fkin.rps = 500; fkin.max_rps = 1000; fkin.flow_features = true; fkin.flow_capable = false;
    fkin.rst_rate = 0.5;
    auto fkf = RlPolicy::BuildFeatures(fkin);
    Check(fkf.size() == 25 && fkf[24] == 0.0f && fkf[20] == 0.0f,
          "rl policy: kernel-socket serve masks flow (value + known 0)");
    // Block + ban + flow compose: width 20 + 2V + 2 + 5 = 37, flow trails everything.
    RlStateInputs ain;
    ain.rps = 500; ain.max_rps = 1000;
    ain.variant_block_success = {-1.0, 0.9, -1.0, 0.05, -1.0};
    ain.ban_features = true; ain.ban_pressure = 0.4;
    ain.flow_features = true; ain.flow_capable = true; ain.rst_rate = 0.1;
    auto af = RlPolicy::BuildFeatures(ain);
    Check(af.size() == 37, "rl policy: block+ban+flow widen state to 37");
    Check(std::abs(af[32] - 0.1f) < 1e-6 && af[36] == 1.0f, "rl policy: flow trails block+ban bits");

    // Multi-dim (Mahoraga) action: 2-in -> 2-out identity, per-dim bounds
    // rps in [100,1100], concurrency in [1,65]. input [0.5,0.25] -> [600,17].
    std::string m = "SRLP";
    put_u32(m, 2); put_u32(m, 2); put_u32(m, 1); put_u32(m, 2);  // ver,in,nlayers,out=2
    put_f32(m, 1.0f); put_f32(m, 0.0f);   // W row 0
    put_f32(m, 0.0f); put_f32(m, 1.0f);   // W row 1
    put_f32(m, 0.0f); put_f32(m, 0.0f);   // b
    put_f32(m, 0.0f); put_f32(m, 0.0f);   // norm_mean
    put_f32(m, 1.0f); put_f32(m, 1.0f);   // norm_std
    put_u32(m, 2);                         // action_dim
    put_f32(m, 100.0f); put_f32(m, 1.0f);  // action_lo[rps, concurrency]
    put_f32(m, 1100.0f); put_f32(m, 65.0f);// action_hi
    const std::string mpath = "/tmp/samurai_selftest_policy_md.srlp";
    { std::ofstream o(mpath, std::ios::binary); o.write(m.data(), m.size()); }
    RlPolicy pm;
    Check(pm.Load(mpath, &err) && pm.action_dim() == 2, "rl policy: multi-dim SRLP loads");
    auto av = pm.Propose({0.5f, 0.25f});
    Check(av.size() == 2 && std::abs(av[0] - 600.0) < 1e-3 && std::abs(av[1] - 17.0) < 1e-3,
          "rl policy: multi-dim forward (rps=600, concurrency=17)");
    std::remove(mpath.c_str());

    // v3 categorical head: dim0 rps continuous (1 output), dim1 request_mix
    // categorical over {0,3,4} (3 logits). W=0 so output == bias:
    // b = [0.5, -1, 2, 0] -> rps frac 0.5 -> 600; argmax logit at idx1 -> cat 3.
    std::string c = "SRLP";
    put_u32(c, 3);            // version 3
    put_u32(c, 1);            // in_dim
    put_u32(c, 1);            // n_layers
    put_u32(c, 4);            // out_dims[0] == total output width
    for (int i = 0; i < 4; ++i) put_f32(c, 0.0f);  // W (4x1) zeros
    put_f32(c, 0.5f); put_f32(c, -1.0f); put_f32(c, 2.0f); put_f32(c, 0.0f);  // b
    put_f32(c, 0.0f);        // norm_mean
    put_f32(c, 1.0f);        // norm_std
    put_u32(c, 2);           // action_dim (dimensions, not output width)
    put_u32(c, 0);           // dim0 kind = continuous
    put_f32(c, 100.0f); put_f32(c, 1100.0f);       // dim0 lo, hi
    put_u32(c, 1);           // dim1 kind = categorical
    put_u32(c, 3);           // dim1 n_cat
    put_f32(c, 0.0f); put_f32(c, 3.0f); put_f32(c, 4.0f);  // dim1 cats
    const std::string cpath = "/tmp/samurai_selftest_policy_v3.srlp";
    { std::ofstream o(cpath, std::ios::binary); o.write(c.data(), c.size()); }
    RlPolicy pc;
    Check(pc.Load(cpath, &err) && pc.action_dim() == 2, "rl policy: v3 categorical SRLP loads");
    auto cv = pc.Propose({0.0f});
    Check(cv.size() == 2 && std::abs(cv[0] - 600.0) < 1e-3 && cv[1] == 3.0,
          "rl policy: v3 categorical forward (rps=600, request_mix=argmax->3)");
    std::remove(cpath.c_str());

    // v4 RL² recurrent: GRU context carried across windows (the wheel turns).
    // state_dim=20 (matches BuildFeatures), hidden=1, action_dim=1 (continuous [0,1]).
    // Identity normalizer. The MLP is one linear layer over [state(20), hidden(1)]
    // with W picking rps_norm (state[0], weight 1) + hidden (weight 1), b=0, so
    //   output = clamp(rps_norm + hidden).
    // GRU: only the new-gate (n) input weight on token[0] (rps_norm) is 10; every
    // other weight/bias is 0, w_hh=0. So with h=0, token=[s_std, a_norm]:
    //   r=z=0.5, n=tanh(10*rps_norm), h' = (1-0.5)*n + 0.5*0 = 0.5*tanh(10*rps_norm).
    //   window1: rps_norm 0.3, hidden 0 -> out 0.3; token folds -> h = 0.5*tanh(3.0)
    //            = 0.497527
    //   window2: rps_norm 0.3, hidden 0.497527 -> out = clamp(0.3+0.497527) = 0.797527
    std::string g = "SRLP";
    put_u32(g, 4);    // version
    put_u32(g, 20);   // state_dim
    put_u32(g, 1);    // hidden
    put_u32(g, 1);    // action_dim
    // gru_w_ih (3H x T = 3 x 21), gate order r,z,n. r,z rows all 0; n row = [10, 0..0].
    for (int i = 0; i < 21; ++i) put_f32(g, 0.0f);  // r row
    for (int i = 0; i < 21; ++i) put_f32(g, 0.0f);  // z row
    put_f32(g, 10.0f);
    for (int i = 1; i < 21; ++i) put_f32(g, 0.0f);  // n row: token[0]=rps_norm only
    for (int i = 0; i < 3; ++i) put_f32(g, 0.0f);   // gru_w_hh (3x1)
    for (int i = 0; i < 3; ++i) put_f32(g, 0.0f);   // gru_b_ih
    for (int i = 0; i < 3; ++i) put_f32(g, 0.0f);   // gru_b_hh
    put_u32(g, 1);    // n_layers
    put_u32(g, 1);    // out_dims[0]
    put_f32(g, 1.0f);                                 // W[0][0] rps_norm
    for (int i = 1; i < 20; ++i) put_f32(g, 0.0f);    // W[0][1..19]
    put_f32(g, 1.0f);                                 // W[0][20] hidden
    put_f32(g, 0.0f);                                 // b
    for (int i = 0; i < 20; ++i) put_f32(g, 0.0f);    // norm_mean
    for (int i = 0; i < 20; ++i) put_f32(g, 1.0f);    // norm_std
    put_u32(g, 0);                                    // dim0 kind = continuous
    put_f32(g, 0.0f); put_f32(g, 1.0f);               // dim0 lo, hi
    const std::string gpath = "/tmp/samurai_selftest_policy_v4.srlp";
    { std::ofstream o(gpath, std::ios::binary); o.write(g.data(), g.size()); }
    RlPolicy pg;
    Check(pg.Load(gpath, &err), "rl policy: v4 recurrent SRLP loads");
    Check(pg.recurrent() && pg.state_dim() == 20 && pg.hidden_dim() == 1 &&
              pg.action_dim() == 1 && pg.input_dim() == 21,
          "rl policy: v4 dims (state=20 hidden=1 action=1, mlp_in=21)");

    RlStateInputs w;
    w.rps = 300.0; w.max_rps = 1000.0;  // rps_norm = 0.3

    // Context-free Propose treats it as an isolated first window (zero hidden).
    Check(std::abs(pg.Propose(RlPolicy::BuildFeatures(w))[0] - 0.3) < 1e-3,
          "rl policy: v4 context-free forward = rps_norm (zero hidden)");

    pg.ResetContext();
    auto a1 = pg.ProposeFor(w);
    Check(a1.size() == 1 && std::abs(a1[0] - 0.3) < 1e-3,
          "rl policy: v4 window1 (zero context) = rps_norm");
    auto a2 = pg.ProposeFor(w);  // same inputs, but the wheel has turned
    Check(std::abs(a2[0] - 0.797527) < 2e-3,
          "rl policy: v4 window2 adapts via carried GRU context (0.3 -> 0.7975)");
    pg.ResetContext();
    auto a3 = pg.ProposeFor(w);
    Check(std::abs(a3[0] - 0.3) < 1e-3,
          "rl policy: v4 ResetContext restores the zero-context action");
    std::remove(gpath.c_str());
  }

  // --- RL exploration: deterministic, in-range, decorrelated lever schedule ---
  {
    using namespace samurai::control;
    const std::size_t nfields = sizeof(kActionFields) / sizeof(kActionFields[0]);

    // A disabled config perturbs nothing.
    RlExploreConfig off;
    const auto ex_off = ExploreLevers(3, off);
    bool all_sentinel = ex_off.size() == nfields;
    for (double v : ex_off) all_sentinel = all_sentinel && v < 0.0;
    Check(all_sentinel, "rl explore: disabled config leaves every lever untouched");

    RlExploreConfig cfg = DefaultExploreConfig(42);
    Check(cfg.enabled && cfg.levers.size() == nfields,
          "rl explore: default config sized to kActionFields");

    // dim 0 (rps) is never perturbed; the extra levers are.
    const auto a = ExploreLevers(0, cfg);
    Check(a.size() == nfields && a[0] < 0.0, "rl explore: rps (dim 0) never perturbed");
    Check(a[1] >= 1.0 && a[1] <= 16.0, "rl explore: concurrency drawn in [1,16]");
    Check(a[2] >= 0.0 && a[2] <= 11.0, "rl explore: request_mix drawn in [0,11]");
    Check(a[3] >= 1.0 && a[3] <= 8.0, "rl explore: source_rotation drawn in [1,8]");
    Check(a[4] >= 1.0 && a[4] <= 3.0, "rl explore: pacing_mode drawn in [1,3]");
    Check(a[5] >= 0.0 && a[5] <= 2.0, "rl explore: auth_mode drawn in [0,2]");
    Check(a[6] >= 0.0 && a[6] <= 3.0, "rl explore: evasion_tactic drawn in [0,3]");

    // Deterministic: same seed + window => identical draw.
    const auto a2 = ExploreLevers(0, cfg);
    Check(a == a2, "rl explore: same (seed,win) is reproducible");

    // Decorrelated across windows: the schedule actually moves. Sweep many
    // windows and require the request_mix column to hit at least 3 distinct
    // values (a constant column would be unlearnable).
    std::set<long> mix_values;
    for (int w = 0; w < 64; ++w) {
      mix_values.insert(static_cast<long>(ExploreLevers(w, cfg)[2]));
    }
    Check(mix_values.size() >= 3, "rl explore: request_mix varies across windows");

    // A different seed yields a different schedule (not a fixed sequence).
    RlExploreConfig cfg2 = DefaultExploreConfig(7);
    bool differs = false;
    for (int w = 0; w < 16 && !differs; ++w) {
      if (ExploreLevers(w, cfg) != ExploreLevers(w, cfg2)) differs = true;
    }
    Check(differs, "rl explore: seed changes the schedule");

    // Range override + guardrails: rps is rejected, unknown field rejected,
    // inverted range rejected; a valid override takes effect.
    Check(!cfg.SetLever("rps", 1, 9), "rl explore: refuses to explore rps");
    Check(!cfg.SetLever("nonsense", 1, 9), "rl explore: unknown lever rejected");
    Check(!cfg.SetLever("concurrency", 9, 1), "rl explore: inverted range rejected");
    Check(cfg.SetLever("concurrency", 5, 5), "rl explore: valid override accepted");
    Check(ExploreLevers(0, cfg)[1] == 5.0, "rl explore: degenerate range pins the value");
  }

  // --- Lever shield: online veto of a path-blocked categorical variant ---
  {
    using namespace samurai::control;
    LeverShield sh(LeverShield::Config{0.10, 5});

    // Unobserved proposals pass through (first-touch discovery is allowed).
    Check(sh.Govern(3) == 3, "lever shield: unobserved proposal passes through");

    // Observe variant 3 fully blocked (served ~0 => WAF 403) and variant 0 honored.
    sh.Observe(3, 0.0);
    sh.Observe(0, 1.0);
    Check(sh.Blocked(3), "lever shield: variant with ~0 served is flagged blocked");
    Check(!sh.Blocked(0), "lever shield: honored variant not flagged");
    Check(sh.Govern(3) == 0, "lever shield: blocked proposal -> best-known honored variant");
    Check(sh.Govern(0) == 0, "lever shield: honored proposal kept");

    // A rate-limited (not path-blocked) variant keeps its best-case honored window,
    // so it is never vetoed even if later windows dip under load.
    sh.Observe(1, 0.8);
    sh.Observe(1, 0.05);  // high-rps dip does not lower the best-seen success
    Check(!sh.Blocked(1), "lever shield: rate-limited variant (honored once) not blocked");

    // With no honored variant known yet, a blocked proposal probes an unobserved one.
    LeverShield sh2(LeverShield::Config{0.10, 5});
    sh2.Observe(2, 0.0);
    const int probe = sh2.Govern(2);
    Check(probe != 2 && probe >= 0 && probe < 5,
          "lever shield: blocked with no honored known -> probes an unobserved variant");

    sh.Reset();
    Check(!sh.Blocked(3) && sh.Govern(3) == 3, "lever shield: reset clears episode memory");

    // Warm-start + snapshot: seed from a persisted vector, expose the full memory.
    LeverShield sh3(LeverShield::Config{0.10, 5});
    sh3.Warm({-1.0, 0.9, 0.0, -1.0, 0.5});  // variant2 blocked (0.0), 1 & 4 honored
    Check(sh3.Blocked(2), "lever shield: warm-started blocked variant is flagged");
    Check(!sh3.Blocked(1), "lever shield: warm-started honored variant not flagged");
    const auto snap = sh3.snapshot();
    Check(snap.size() == 5 && snap[1] == 0.9 && snap[2] == 0.0,
          "lever shield: snapshot exposes the warm-started memory");
    sh3.Observe(2, 0.7);  // a later honored window raises best-success past the floor
    Check(!sh3.Blocked(2), "lever shield: observing an honored window clears the block");
  }

  // --- Variant memory: per-target block store round-trips through JSON on disk ---
  {
    using namespace samurai::control;
    const std::string mpath = "/tmp/samurai_selftest_variant_mem.json";
    std::remove(mpath.c_str());

    // Missing file loads as an empty store (a first run must not fail).
    Check(VariantMemory::Load(mpath).size() == 0, "variant memory: missing file -> empty store");

    VariantMemory mem;
    mem.Put("10.0.0.1:8080", {-1.0, 0.95, 0.0, 0.9, -1.0});
    mem.Put("10.0.0.2:443", {0.2, 0.2, 0.2});
    Check(mem.Save(mpath), "variant memory: save to disk");

    VariantMemory back = VariantMemory::Load(mpath);
    Check(back.size() == 2, "variant memory: both targets reloaded");
    const auto a = back.Get("10.0.0.1:8080");
    Check(a.size() == 5 && a[1] == 0.95 && a[2] == 0.0 && a[0] == -1.0,
          "variant memory: per-variant values round-trip");
    Check(back.Get("nope:1").empty(), "variant memory: unknown target -> empty");

    // Put replaces an existing key rather than duplicating it.
    back.Put("10.0.0.2:443", {0.5});
    Check(back.size() == 2 && back.Get("10.0.0.2:443").size() == 1,
          "variant memory: Put replaces in place");
    std::remove(mpath.c_str());
  }

  // --- Ban memory: per-target scalar ban_pressure round-trips through JSON on disk ---
  {
    using namespace samurai::control;
    const std::string bpath = "/tmp/samurai_selftest_ban_mem.json";
    std::remove(bpath.c_str());

    Check(BanMemory::Load(bpath).size() == 0, "ban memory: missing file -> empty store");
    Check(BanMemory::Load(bpath).Get("x:1") < 0.0, "ban memory: unknown target -> -1");

    BanMemory bmem;
    bmem.Put("10.0.0.1:8080", 0.73);
    bmem.Put("10.0.0.2:443", 0.0);
    Check(bmem.Save(bpath), "ban memory: save to disk");

    BanMemory bback = BanMemory::Load(bpath);
    Check(bback.size() == 2, "ban memory: both targets reloaded");
    Check(std::abs(bback.Get("10.0.0.1:8080") - 0.73) < 1e-9, "ban memory: pressure round-trips");
    Check(bback.Get("10.0.0.2:443") == 0.0, "ban memory: zero pressure round-trips");
    bback.Put("10.0.0.2:443", 0.5);
    Check(bback.size() == 2 && std::abs(bback.Get("10.0.0.2:443") - 0.5) < 1e-9,
          "ban memory: Put replaces in place");
    std::remove(bpath.c_str());
  }

  // --- Online adapter: warmup is inert, a helpful reward pushes the correction up,
  //     a harmful reward triggers the rollback guard, and state persists ---
  {
    using namespace samurai::control;
    OnlineAdapter::Config cfg;
    cfg.enabled = true;
    cfg.warmup_windows = 3;
    cfg.sigma = 0.05;
    cfg.lr = 0.1;
    const std::vector<double> phi = {1.0};  // single bias feature

    // Warmup: the correction is inert (delta 0) and the frozen baseline is recorded.
    OnlineAdapter ad(cfg, 1, /*seed=*/1);
    for (int w = 0; w < 3; ++w) {
      Check(std::abs(ad.Apply(1000.0, phi) - 1000.0) < 1e-9,
            "online adapter: inert during warmup (no correction)");
      ad.Observe(0.5);  // frozen-policy baseline = 0.5 (headroom above/below)
    }

    // Adapting in a "positive correction helps" environment: reward = 0.5 + 0.5*delta,
    // so a positive correction earns above the 0.5 baseline. The ES gradient must
    // drive the weight positive, and the adapted reward stays above baseline so the
    // rollback guard never fires.
    for (int w = 0; w < 200; ++w) {
      const double applied = ad.Apply(1000.0, phi);
      const double delta = applied / 1000.0 - 1.0;
      ad.Observe(0.5 + 0.5 * delta);
    }
    Check(ad.weights()[0] > 0.05, "online adapter: helpful reward grows the correction");
    Check(ad.rollbacks() == 0, "online adapter: no rollback on a helpful reward");
    Check(ad.Apply(1000.0, phi) > 1000.0, "online adapter: applies a positive correction");

    // A uniformly harmful reward (any correction is below baseline) must roll back to
    // the frozen policy and cool down.
    OnlineAdapter bad(cfg, 1, /*seed=*/2);
    for (int w = 0; w < 3; ++w) { bad.Apply(1000.0, phi); bad.Observe(0.0); }  // baseline 0
    for (int w = 0; w < 40; ++w) { bad.Apply(1000.0, phi); bad.Observe(-0.5); }
    Check(bad.rollbacks() >= 1, "online adapter: harmful reward triggers rollback");

    // Persistence round-trips the learned weights + baseline.
    const std::string apath = "/tmp/samurai_selftest_adapter_mem.json";
    std::remove(apath.c_str());
    Check(AdapterMemory::Load(apath).size() == 0, "adapter memory: missing file -> empty");
    AdapterMemory amem;
    amem.Put("10.0.0.1:8080", {0.11, -0.22, 0.33}, 0.75);
    Check(amem.Save(apath), "adapter memory: save to disk");
    AdapterMemory aback = AdapterMemory::Load(apath);
    const auto e = aback.Get("10.0.0.1:8080");
    Check(e.w.size() == 3 && std::abs(e.w[1] + 0.22) < 1e-9 && e.has_baseline &&
              std::abs(e.baseline - 0.75) < 1e-9,
          "adapter memory: weights + baseline round-trip");
    Check(aback.Get("nope:1").w.empty(), "adapter memory: unknown target -> empty");
    std::remove(apath.c_str());
  }

  // --- Novelty detector: an unexplained success collapse is flagged as out-of-
  //     dictionary; a known-signal failure is NOT; the vocabulary persists ---
  {
    using namespace samurai::control;
    NoveltyDetector::Config cfg;
    cfg.enabled = true;
    cfg.warmup_windows = 2;
    cfg.residual_threshold = 0.35;
    cfg.backoff = 0.5;

    // A KNOWN-signal failure: success ~0 but rate_limited ~1 explains it fully. Never
    // novel — the dictionary covers it.
    NoveltyDetector known(cfg);
    NoveltySignals rl;
    rl.success_ratio = 0.02; rl.rate_limited = 0.98;
    for (int w = 0; w < 6; ++w) known.Observe(rl);
    Check(!known.novel(), "novelty: rate-limited failure is explained, not novel");
    Check(known.vocabulary().empty(), "novelty: no signature minted for a known defense");
    Check(std::abs(known.DampSetpoint(1000.0) - 1000.0) < 1e-9,
          "novelty: no setpoint damping when not novel");

    // A SILENT failure: success collapses with NO known signal moving. Out of the
    // dictionary -> novel, named "silent-success-loss", and the setpoint is damped.
    NoveltyDetector silent(cfg);
    NoveltySignals sl;
    sl.success_ratio = 0.1;  // 90% failing; rate_limited/overload/... all unknown (<0)
    double sc = 0.0;
    for (int w = 0; w < 6; ++w) sc = silent.Observe(sl);
    Check(silent.novel() && sc >= 0.35, "novelty: unexplained success loss is flagged novel");
    Check(silent.last_signature() == "silent-success-loss",
          "novelty: silent failure gets the silent-success-loss signature");
    Check(std::abs(silent.DampSetpoint(1000.0) - 500.0) < 1e-9,
          "novelty: novel regime damps the setpoint (x lever, floored at backoff here)");

    // A graduated signature grows its OWN outcome-tuned lever. With headroom below the
    // default backoff (min_damping < backoff), a persistently-unexplained regime
    // tightens the lever; once the regime recovers, the lever relaxes back toward 1.
    NoveltyDetector::Config lc;
    lc.enabled = true; lc.warmup_windows = 1; lc.residual_threshold = 0.35;
    lc.backoff = 0.90; lc.min_damping = 0.30; lc.promotion_count = 2;
    lc.damp_lr = 0.30; lc.relax_lr = 0.50;
    NoveltyDetector lever(lc);
    NoveltySignals silent2; silent2.success_ratio = 0.1;
    for (int w = 0; w < 8; ++w) lever.Observe(silent2);
    const double tightened = lever.DampSetpoint(1000.0) / 1000.0;
    Check(lever.novel() && tightened < 0.90 - 1e-6 && tightened >= 0.30 - 1e-9,
          "novelty lever: graduated axis tightened below the default backoff");
    NoveltySignals recovered; recovered.success_ratio = 1.0;  // regime gone: fully served
    for (int w = 0; w < 20; ++w) lever.Observe(recovered);
    double relaxed = 0.0;
    for (const auto& ax : lever.axes())
      if (ax.signature == "silent-success-loss") relaxed = ax.damping;
    Check(!lever.novel() && relaxed > tightened + 1e-6,
          "novelty lever: recovery relaxed the learned lever back up");

    // An UNDER-explained failure: a known signal is present but nowhere near enough
    // (success 0.1, only 0.2 conn_drop) -> novel, tagged by the dominant known axis.
    NoveltyDetector partial(cfg);
    NoveltySignals pl;
    pl.success_ratio = 0.1; pl.conn_drop = 0.2;
    for (int w = 0; w < 6; ++w) partial.Observe(pl);
    Check(partial.novel() && partial.last_signature() == "under-explained:conn_drop",
          "novelty: under-explained failure tagged by dominant known axis");

    // Warm-start + persistence round-trip the open vocabulary.
    const std::string npath = "/tmp/samurai_selftest_novelty_mem.json";
    std::remove(npath.c_str());
    Check(NoveltyMemory::Load(npath).size() == 0, "novelty memory: missing file -> empty");
    NoveltyMemory nmem;
    NoveltyDetector::Axis a1; a1.signature = "silent-success-loss"; a1.count = 4;
    a1.damping = 0.62; a1.graduated = true;
    NoveltyDetector::Axis a2; a2.signature = "under-explained:reset"; a2.count = 2;
    a2.damping = 0.80; a2.graduated = false;
    nmem.Put("10.0.0.1:8080", {a1, a2});
    Check(nmem.Save(npath), "novelty memory: save to disk");
    NoveltyMemory nback = NoveltyMemory::Load(npath);
    const auto vocab = nback.Get("10.0.0.1:8080");
    long silent_count = 0;
    double silent_damp = 0.0;
    for (const auto& ax : vocab)
      if (ax.signature == "silent-success-loss") { silent_count = ax.count; silent_damp = ax.damping; }
    Check(vocab.size() == 2 && silent_count == 4 && std::abs(silent_damp - 0.62) < 1e-9,
          "novelty memory: learned levers round-trip (count + damping)");

    NoveltyDetector warmed(cfg);
    warmed.Warm(vocab);
    double warmed_damp = 0.0;
    for (const auto& ax : warmed.axes())
      if (ax.signature == "silent-success-loss") warmed_damp = ax.damping;
    Check(warmed.vocabulary().size() == 2 && std::abs(warmed_damp - 0.62) < 1e-9,
          "novelty: warm-start restores the learned levers");
    std::remove(npath.c_str());
  }

  // --- sut probe: Prometheus /api/v1/query response parsing ---
  {
    using namespace samurai::control;
    double v = 0.0;
    std::string err;

    // vector result (the usual histogram_quantile output)
    const std::string vec =
        R"({"status":"success","data":{"resultType":"vector","result":[)"
        R"({"metric":{"job":"api"},"value":[1700000000.5,"183.4"]}]}})";
    Check(ParsePromInstantScalar(vec, v, err) && v == 183.4, "sut: vector result parsed");

    // scalar result
    const std::string scal =
        R"({"status":"success","data":{"resultType":"scalar","result":[1700000000,"42"]}})";
    v = 0;
    Check(ParsePromInstantScalar(scal, v, err) && v == 42.0, "sut: scalar result parsed");

    // empty vector => no series matched
    const std::string empty =
        R"({"status":"success","data":{"resultType":"vector","result":[]}})";
    Check(!ParsePromInstantScalar(empty, v, err), "sut: empty result rejected");

    // error status from Prometheus
    const std::string bad =
        R"({"status":"error","errorType":"bad_data","error":"parse error"})";
    Check(!ParsePromInstantScalar(bad, v, err), "sut: error status rejected");

    // URL building percent-encodes the PromQL and normalizes the base slash
    const std::string url = BuildPromQueryUrl("http://p:9090/",
                                              "histogram_quantile(0.99, x)*1000");
    Check(url == "http://p:9090/api/v1/query?query="
                 "histogram_quantile%280.99%2C%20x%29%2A1000",
          "sut: query url encoded");

    // A disabled probe scrapes nothing.
    SutProbeConfig off;  // enabled=false
    SutProbe p(off);
    Check(!p.enabled() && !p.Scrape().ok, "sut: disabled probe is inert");
  }

  // --- http client: URL join + response-complete framing ---
  {
    namespace http = samurai::core::http;
    Check(http::JoinUrl("https://h:443/base/path", "/apis/x") == "https://h:443/apis/x",
          "http: JoinUrl keeps authority, replaces path");
    Check(http::ResponseCompleteForTest(
              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
          "http: content-length framing complete");
    Check(!http::ResponseCompleteForTest("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi"),
          "http: short body not complete");
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

  // --- multimaster federation: enqueue -> dequeue -> local dispatch e2e ---
  // Mirrors what samurai_master does: the eu region delegates a job to us, and
  // the us master pulls it off the shared queue and runs it on its own workers
  // via the MasterCoordinator (fake view/commander).
  {
    namespace json = samurai::core::json;
    InMemoryKvStore store;
    std::int64_t clk = 1000;
    auto now = [&clk]() { return clk; };

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

    // eu delegates a 1000-packet cpu job destined for us.
    json::Value spec = json::Value::Object();
    spec.set("count", json::Value::Int(1000));
    spec.set("worker", json::Value::Str("cpu"));
    spec.set("target", json::Value::Str("10.0.0.9"));
    Check(eu.EnqueueJob("us", spec), "federation: eu delegates job to us");

    // us pulls the delegated job and reconstructs a JobConfig (as master_main's
    // BuildJobConfig does).
    auto jobs = us.DequeueJobs(3);
    Check(jobs.size() == 1, "federation: us dequeues the delegated job");
    const json::Value dj = jobs.empty() ? json::Value::Object() : jobs[0];
    JobConfig jc;
    jc.count = dj.find("count") ? dj.find("count")->as_int(0) : 0;
    jc.shard_unit_count = 250;  // 4 shards
    jc.master_poll_interval_ms = 1;
    jc.base_args = json::Value::Object();
    jc.base_args.set(
        "worker", json::Value::Str(dj.find("worker") ? dj.find("worker")->as_string("cpu") : "cpu"));

    // us runs it on its local worker.
    struct FedView : MasterView {
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
    struct FedCmd : WorkerCommander {
      FedView* view = nullptr;
      int dispatched = 0;
      DispatchOutcome Dispatch(const std::string&, const std::string& sid, const std::string&,
                               const std::string&, std::int64_t count, std::int64_t) override {
        ++dispatched;
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {"done", "", "{}"}; }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
    };
    FedView view;
    WorkerInfo w;
    w.worker_id = "us_cpu";
    w.capabilities["control_endpoint"] = "tcp://us_cpu:5099";
    w.capabilities["worker_kinds"] = "cpu";
    w.last_heartbeat_ms = clk;
    view.workers["us_cpu"] = w;
    FedCmd cmd;
    cmd.view = &view;
    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    auto res = coord.RunSingleJob(jc, "deleg-1");
    Check(res.rc == 0, "federation: us runs the delegated job rc=0");
    Check(cmd.dispatched == 4, "federation: delegated job split into 4 shards on us");
    Check(us.DequeueJobs(3).empty(), "federation: us queue drained after pickup");
  }

  // --- redis_kvstore: redis:// url parsing + hiredis-absent factory ---
  {
    RedisUrl a = ParseRedisUrl("redis://10.0.0.5:6380/2");
    Check(a.ok && a.host == "10.0.0.5" && a.port == 6380 && a.db == 2,
          "redis-url: host/port/db parsed");
    RedisUrl d = ParseRedisUrl("redis://127.0.0.1:6379/0");
    Check(d.ok && d.host == "127.0.0.1" && d.port == 6379 && d.db == 0, "redis-url: full default");
    RedisUrl bare = ParseRedisUrl("redis://myhost");
    Check(bare.ok && bare.host == "myhost" && bare.port == 6379 && bare.db == 0,
          "redis-url: bare host -> default port/db");
    RedisUrl cred = ParseRedisUrl("redis://user:pass@cache.local:6390/1");
    Check(cred.ok && cred.host == "cache.local" && cred.port == 6390 && cred.db == 1,
          "redis-url: credentials skipped, host/port/db parsed");

    std::string err;
    std::unique_ptr<KvStore> kv = MakeKvStore("redis://127.0.0.1:6379/0", err);
#ifndef SAMURAI_CONTROL_HAVE_HIREDIS
    Check(kv == nullptr && !err.empty(), "redis-store: MakeKvStore null without hiredis");
#else
    // With hiredis compiled in, run a live round trip only if a test Redis is
    // provided; otherwise just assert MakeKvStore didn't crash.
    const char* test_url = std::getenv("SAMURAI_TEST_REDIS_URL");
    if (test_url && kv) {
      kv->SetEx("samurai:selftest:k", "v1", 30);
      std::string out;
      Check(kv->Get("samurai:selftest:k", out) && out == "v1", "redis-store: live SETEX/GET");
      kv->RPush("samurai:selftest:l", "a");
      kv->RPush("samurai:selftest:l", "b");
      std::string popped;
      Check(kv->LPop("samurai:selftest:l", popped) && popped == "a", "redis-store: live RPUSH/LPOP");
      Check(kv->SetNx("samurai:selftest:nx", "own", 30000), "redis-store: live SET NX");
      Check(!kv->SetNx("samurai:selftest:nx", "other", 30000), "redis-store: NX rejects held key");
      Check(kv->CompareAndDel("samurai:selftest:nx", "own"), "redis-store: CAS del owner");
    } else {
      (void)kv;
    }
#endif
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

  // --- agent bootstrap: HMAC-signed manifest + SHA-256 pins + token gating ---
  {
    const std::string dir = "/tmp/samurai_agent_test";
    (void)std::system(("rm -rf " + dir + " && mkdir -p " + dir).c_str());
    const std::string slave_content = std::string("SLAVE-BINARY-\x01\x02\x03", 16);
    const std::string worker_content = std::string("CPU-WORKER-\x04\x05", 13);
    { std::ofstream f(dir + "/samurai_slave", std::ios::binary); f << slave_content; }
    { std::ofstream f(dir + "/samurai_cpu_worker", std::ios::binary); f << worker_content; }

    auto hexof = [](const unsigned char* p, std::size_t n) {
      static const char* k = "0123456789abcdef";
      std::string o;
      for (std::size_t i = 0; i < n; ++i) { o.push_back(k[p[i] >> 4]); o.push_back(k[p[i] & 15]); }
      return o;
    };
    auto sha = [&](const std::string& d) {
      unsigned char m[SHA256_DIGEST_LENGTH];
      SHA256(reinterpret_cast<const unsigned char*>(d.data()), d.size(), m);
      return hexof(m, SHA256_DIGEST_LENGTH);
    };
    auto hmac = [&](const std::string& d, const std::string& key) {
      unsigned char m[EVP_MAX_MD_SIZE];
      unsigned int l = 0;
      HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(d.data()), d.size(), m, &l);
      return hexof(m, l);
    };

    ManagementConfig cfg;
    cfg.agent_join_token = "JOINSECRET";
    cfg.agent_artifact_dir = dir;
    cfg.agent_advertise_endpoint = "tcp://master.example:5099";
    cfg.agent_worker = "cpu";
    cfg.agent_cluster_secret = "CLUSTERSECRET";
    ManagementApi api(cfg, ManagementProviders{});

    auto areq = [](const std::string& path, std::map<std::string, std::string> q) {
      HttpRequest r;
      r.method = "GET";
      r.path = path;
      r.query = std::move(q);
      r.headers["host"] = "master.example:8089";
      return r;
    };

    Check(api.Handle(areq("/v1/agent/manifest", {})).status == 401,
          "agent: manifest requires token");
    Check(api.Handle(areq("/v1/agent/manifest", {{"token", "WRONG"}})).status == 401,
          "agent: wrong token rejected");

    auto man = api.Handle(areq("/v1/agent/manifest", {{"token", "JOINSECRET"}}));
    Check(man.status == 200 && man.body.rfind("#hmac ", 0) == 0,
          "agent: manifest served with hmac line");
    const std::size_t nl = man.body.find('\n');
    const std::string body = man.body.substr(nl + 1);
    const std::string sig = man.body.substr(6, nl - 6);
    Check(sig == hmac(body, "JOINSECRET"), "agent: manifest HMAC valid (key=join token)");
    Check(body.find("blob samurai_slave " + sha(slave_content)) != std::string::npos,
          "agent: slave sha256 pinned");
    Check(body.find("blob samurai_cpu_worker " + sha(worker_content)) != std::string::npos,
          "agent: worker sha256 pinned");
    Check(body.find("control_endpoint tcp://master.example:5099") != std::string::npos,
          "agent: control endpoint advertised");
    Check(body.find("dispatch_mode reverse") != std::string::npos, "agent: reverse mode advertised");
    Check(body.find("cluster_secret CLUSTERSECRET") != std::string::npos,
          "agent: cluster secret advertised for registration auth");

    auto blob = api.Handle(areq("/v1/agent/blob", {{"token", "JOINSECRET"}, {"name", "samurai_slave"}}));
    Check(blob.status == 200 && blob.body == slave_content &&
              blob.content_type == "application/octet-stream",
          "agent: blob bytes served verbatim");
    Check(api.Handle(areq("/v1/agent/blob", {{"token", "JOINSECRET"}, {"name", "../etc/passwd"}})).status == 400,
          "agent: path traversal rejected");
    Check(api.Handle(areq("/v1/agent/blob", {{"token", "JOINSECRET"}, {"name", "samurai_evil"}})).status == 400,
          "agent: unlisted blob rejected");

    auto inst = api.Handle(areq("/v1/agent/install", {{"token", "JOINSECRET"}}));
    Check(inst.status == 200 && inst.content_type == "text/x-shellscript" &&
              inst.body.find("JOINSECRET") != std::string::npos &&
              inst.body.find("samurai_slave") != std::string::npos &&
              inst.body.find("--cluster-secret") != std::string::npos,
          "agent: install script served");

    ManagementApi api_off(ManagementConfig{}, ManagementProviders{});
    Check(api_off.Handle(areq("/v1/agent/manifest", {{"token", ""}})).status == 404,
          "agent: disabled without join token");

    // TLS: the install-script BASE follows the advertised scheme (https).
    ManagementConfig tcfg = cfg;
    tcfg.agent_public_scheme = "https";
    ManagementApi tapi(tcfg, ManagementProviders{});
    auto tinst = tapi.Handle(areq("/v1/agent/install", {{"token", "JOINSECRET"}}));
    Check(tinst.status == 200 && tinst.body.find("BASE=\"https://") != std::string::npos,
          "agent: install BASE uses https when TLS advertised");

    (void)std::system(("rm -rf " + dir).c_str());
  }

  // --- agent bootstrap: bundle mode ships every present worker binary ---
  {
    const std::string dir = "/tmp/samurai_agent_bundle_test";
    (void)std::system(("rm -rf " + dir + " && mkdir -p " + dir).c_str());
    // Slave + a subset of the catalog present; dpdk/doca deliberately absent to
    // prove the manifest only advertises binaries that actually exist.
    const std::string slave_c = std::string("SLAVE\x01", 6);
    const std::string cpu_c = std::string("CPU\x02", 4);
    const std::string scen_c = std::string("SCEN\x03", 5);
    const std::string l7_c = std::string("L7\x04", 3);
    { std::ofstream f(dir + "/samurai_slave", std::ios::binary); f << slave_c; }
    { std::ofstream f(dir + "/samurai_cpu_worker", std::ios::binary); f << cpu_c; }
    { std::ofstream f(dir + "/samurai_scenario_worker", std::ios::binary); f << scen_c; }
    { std::ofstream f(dir + "/samurai_l7_worker", std::ios::binary); f << l7_c; }

    auto hexof = [](const unsigned char* p, std::size_t n) {
      static const char* k = "0123456789abcdef";
      std::string o;
      for (std::size_t i = 0; i < n; ++i) { o.push_back(k[p[i] >> 4]); o.push_back(k[p[i] & 15]); }
      return o;
    };
    auto sha = [&](const std::string& d) {
      unsigned char m[SHA256_DIGEST_LENGTH];
      SHA256(reinterpret_cast<const unsigned char*>(d.data()), d.size(), m);
      return hexof(m, SHA256_DIGEST_LENGTH);
    };

    ManagementConfig cfg;
    cfg.agent_join_token = "JOINSECRET";
    cfg.agent_artifact_dir = dir;
    cfg.agent_advertise_endpoint = "tcp://master.example:5099";
    cfg.agent_worker = "bundle";
    ManagementApi api(cfg, ManagementProviders{});
    auto areq = [](const std::string& path, std::map<std::string, std::string> q) {
      HttpRequest r;
      r.method = "GET"; r.path = path; r.query = std::move(q);
      r.headers["host"] = "master.example:8089";
      return r;
    };

    auto man = api.Handle(areq("/v1/agent/manifest", {{"token", "JOINSECRET"}}));
    Check(man.status == 200, "agent-bundle: manifest served");
    const std::string body = man.body.substr(man.body.find('\n') + 1);
    Check(body.find("worker bundle") != std::string::npos, "agent-bundle: worker=bundle advertised");
    Check(body.find("blob samurai_cpu_worker " + sha(cpu_c)) != std::string::npos &&
              body.find("blob samurai_scenario_worker " + sha(scen_c)) != std::string::npos &&
              body.find("blob samurai_l7_worker " + sha(l7_c)) != std::string::npos,
          "agent-bundle: every present worker binary pinned");
    Check(body.find("samurai_dpdk_worker") == std::string::npos,
          "agent-bundle: absent worker binary not advertised");
    // Any present catalog binary is fetchable; absent/unknown ones are rejected.
    Check(api.Handle(areq("/v1/agent/blob",
                          {{"token", "JOINSECRET"}, {"name", "samurai_scenario_worker"}})).status == 200,
          "agent-bundle: scenario blob served");
    Check(api.Handle(areq("/v1/agent/blob",
                          {{"token", "JOINSECRET"}, {"name", "samurai_dpdk_worker"}})).status == 400,
          "agent-bundle: absent worker blob rejected");

    // In-memory blob cache verification: remove the file from disk, blob must still serve from memory
    (void)std::system(("rm -f " + dir + "/samurai_scenario_worker").c_str());
    auto cached_blob = api.Handle(areq("/v1/agent/blob",
                                       {{"token", "JOINSECRET"}, {"name", "samurai_scenario_worker"}}));
    Check(cached_blob.status == 200 && cached_blob.body == scen_c,
          "agent-bundle: blob served from in-memory cache after disk removal");

    // Installer script verification: ensure trap is present and exec is avoided
    auto inst = api.Handle(areq("/v1/agent/install", {{"token", "JOINSECRET"}}));
    Check(inst.status == 200, "agent-installer: install script served");
    Check(inst.body.find("trap 'rm -rf \"$TMP\"' EXIT INT TERM HUP") != std::string::npos,
          "agent-installer: cleanup trap configured");
    Check(inst.body.find("exec \"$TMP/samurai_slave\"") == std::string::npos,
          "agent-installer: exec avoided to preserve exit trap");

    (void)std::system(("rm -rf " + dir).c_str());

    // RateLimiter integration verification: bursts beyond rate limit receive HTTP 429
    ManagementConfig rl_cfg;
    rl_cfg.rate_limit_per_sec = 3;
    ManagementApi rl_api(rl_cfg, ManagementProviders{});
    HttpRequest r1; r1.method = "GET"; r1.path = "/healthz"; r1.client_ip = "10.0.0.1";
    HttpRequest r2 = r1;
    HttpRequest r3 = r1;
    HttpRequest r4 = r1;
    HttpRequest r_other = r1; r_other.client_ip = "10.0.0.2";

    Check(rl_api.Handle(r1).status == 200, "ratelimit: req 1 allowed");
    Check(rl_api.Handle(r2).status == 200, "ratelimit: req 2 allowed");
    Check(rl_api.Handle(r3).status == 200, "ratelimit: req 3 allowed");
    HttpResponse blocked = rl_api.Handle(r4);
    Check(blocked.status == 429, "ratelimit: req 4 throttled with 429");
    Check(blocked.body.find("rate_limited") != std::string::npos, "ratelimit: error reason indicates rate_limited");
    Check(rl_api.Handle(r_other).status == 200, "ratelimit: different client allowed independently");
  }

  // --- provisioner: endpoint parsing, command generation, and agent push ---
  {
    using namespace samurai::control;
    namespace json = samurai::core::json;

    // 1. Endpoint parsing
    HostEndpoint ep1 = HostEndpoint::Parse("198.51.100.20:2222");
    Check(ep1.host == "198.51.100.20" && ep1.port == 2222, "provisioner: host endpoint with port");
    HostEndpoint ep2 = HostEndpoint::Parse("node1.internal");
    Check(ep2.host == "node1.internal" && ep2.port == 22, "provisioner: host endpoint default port 22");
    HostEndpoint ep3 = HostEndpoint::Parse("  10.0.0.5:8022  ");
    Check(ep3.host == "10.0.0.5" && ep3.port == 8022, "provisioner: trimmed endpoint");

    // 2. Install command builder
    std::string cmd1 = BuildRemoteInstallCmd("http://127.0.0.1:8089/v1/agent/install?token=SECRET", false);
    Check(cmd1.find("curl -fsSL ") != std::string::npos && cmd1.find("nohup") != std::string::npos,
          "provisioner: install command http");
    std::string cmd2 = BuildRemoteInstallCmd("https://127.0.0.1:8443/v1/agent/install?token=SECRET", true);
    Check(cmd2.find("curl -fsSLk ") != std::string::npos,
          "provisioner: install command https with skip verify");

    // 3. Mock SSH executor & worker checker
    std::vector<std::string> executed_hosts;
    std::set<std::string> joined_hosts;
    auto mock_exec = [&](const std::string& host, int port, const std::string& user,
                         const std::string& key_path, const std::string& remote_cmd,
                         std::string& err) -> int {
      (void)port; (void)user; (void)key_path; (void)remote_cmd; (void)err;
      executed_hosts.push_back(host);
      joined_hosts.insert(host);  // simulate immediate join
      return 0;
    };
    auto mock_check = [&](const std::string& host) -> bool {
      return joined_hosts.count(host) > 0;
    };

    NodeProvisioner prov(mock_exec, mock_check);
    json::Value req_body = json::Value::Object();
    json::Value hosts_arr = json::Value::Array();
    hosts_arr.push_back(json::Value::Str("198.51.100.20:22"));
    hosts_arr.push_back(json::Value::Str("198.51.100.21"));
    req_body.set("hosts", hosts_arr);
    req_body.set("ssh_user", json::Value::Str("ubuntu"));
    req_body.set("ssh_key_path", json::Value::Str("/etc/samurai/key"));
    req_body.set("worker_kind", json::Value::Str("cpu"));
    req_body.set("timeout_s", json::Value::Int(1));

    json::Value res = prov.ProvisionJson(req_body, "http://127.0.0.1:8089/v1/agent/install?token=SEC");
    Check(res.find("status") && res.find("status")->as_string() == "ok", "provisioner: provision status ok");
    Check(res.find("total") && res.find("total")->as_int() == 2, "provisioner: total targets count");
    Check(res.find("triggered") && res.find("triggered")->as_int() == 2, "provisioner: triggered count");
    Check(res.find("joined") && res.find("joined")->as_int() == 2, "provisioner: joined count");
    Check(executed_hosts.size() == 2, "provisioner: executed on both hosts");

    // 4. REST API endpoint /v1/cluster/provision
    ManagementConfig mcfg;
    mcfg.role_tokens["admin"] = "ADMINTKN";
    mcfg.role_tokens["viewer"] = "VIEWTKN";
    mcfg.agent_join_token = "JOINTOKEN";

    ManagementProviders providers;
    bool callback_called = false;
    providers.provision_callback = [&](const json::Value& body) {
      callback_called = true;
      return prov.ProvisionJson(body, "http://127.0.0.1:8089/v1/agent/install?token=JOINTOKEN");
    };

    ManagementApi api(mcfg, providers);

    // POST /v1/cluster/provision with admin token
    HttpRequest prov_req;
    prov_req.method = "POST";
    prov_req.path = "/v1/cluster/provision";
    prov_req.headers["authorization"] = "Bearer ADMINTKN";
    prov_req.body = req_body.dump();

    HttpResponse prov_resp = api.Handle(prov_req);
    Check(prov_resp.status == 200, "mgmt: /v1/cluster/provision returns 200 for admin");
    Check(callback_called, "mgmt: /v1/cluster/provision triggered callback");
    Check(prov_resp.body.find("\"joined\":2") != std::string::npos, "mgmt: /v1/cluster/provision returned joined count");

    // POST with viewer token should be forbidden (403)
    HttpRequest view_req = prov_req;
    view_req.headers["authorization"] = "Bearer VIEWTKN";
    HttpResponse view_resp = api.Handle(view_req);
    Check(view_resp.status == 403, "mgmt: /v1/cluster/provision forbidden for viewer");

    // POST without agent join token configured
    ManagementConfig no_join_cfg = mcfg;
    no_join_cfg.agent_join_token = "";
    ManagementApi no_join_api(no_join_cfg, providers);
    HttpResponse no_join_resp = no_join_api.Handle(prov_req);
    Check(no_join_resp.status == 400, "mgmt: /v1/cluster/provision requires agent_join_token");
  }

  // --- master: coordinator only dispatches shards to matching worker kinds ---
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
      std::set<std::string> dispatched_eps;
      DispatchOutcome Dispatch(const std::string& ep, const std::string& sid, const std::string&,
                               const std::string&, std::int64_t count, std::int64_t) override {
        dispatched_eps.insert(ep);
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {"done", "", "{}"}; }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
    };

    FakeView view;
    std::int64_t clk = 1000000;
    // w_cpu runs only cpu; w_bundle runs the whole catalog. A scenario job must
    // land exclusively on w_bundle.
    WorkerInfo wc;
    wc.worker_id = "w_cpu";
    wc.capabilities["control_endpoint"] = "tcp://w_cpu:5099";
    wc.capabilities["worker_kinds"] = "cpu";
    wc.last_heartbeat_ms = clk;
    view.workers["w_cpu"] = wc;
    WorkerInfo wb;
    wb.worker_id = "w_bundle";
    wb.capabilities["control_endpoint"] = "tcp://w_bundle:5099";
    wb.capabilities["worker_kinds"] = "cpu,gpu,dpdk,afxdp,doca,l7,defense,scenario,afpacket";
    wb.last_heartbeat_ms = clk;
    view.workers["w_bundle"] = wb;

    FakeCmd cmd;
    cmd.view = &view;
    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 1000;
    job.shard_unit_count = 250;  // 4 shards
    job.master_poll_interval_ms = 1;
    job.base_args = json::Value::Object();
    job.base_args.set("worker", json::Value::Str("scenario"));
    auto res = coord.RunSingleJob(job, "kindjob");
    Check(res.rc == 0, "master-kind: scenario job completes rc=0");
    Check(cmd.dispatched_eps.count("tcp://w_bundle:5099") == 1 &&
              cmd.dispatched_eps.count("tcp://w_cpu:5099") == 0,
          "master-kind: scenario shards only went to the bundle worker");
  }

  // --- mgmt API: TLS server starts with an ephemeral self-signed cert ---
  {
    ManagementTlsConfig tls;
    tls.enabled = true;  // no cert/key -> self-signed generated at Start()
    ManagementApiServer srv("127.0.0.1:0", ManagementConfig{}, ManagementProviders{}, tls);
    Check(srv.Start(), "mgmt-tls: self-signed server starts");
    Check(srv.tls_enabled(), "mgmt-tls: reports tls enabled");
    Check(!srv.endpoint().empty(), "mgmt-tls: endpoint resolved");
    srv.Stop();
    Check(!srv.running(), "mgmt-tls: server stops");
  }

  // --- public-exposure safety: loopback endpoint classification ---
  {
    using samurai::control::daemon::IsLoopbackEndpoint;
    // Loopback (safe to run plaintext behind a local tunnel/proxy).
    Check(IsLoopbackEndpoint("tcp://127.0.0.1:5099"), "loopback: tcp 127.0.0.1");
    Check(IsLoopbackEndpoint("127.0.0.1:8089"), "loopback: bare 127.0.0.1");
    Check(IsLoopbackEndpoint("localhost:8089"), "loopback: localhost");
    Check(IsLoopbackEndpoint("tcp://127.5.6.7:1"), "loopback: 127/8 range");
    Check(IsLoopbackEndpoint("[::1]:8089"), "loopback: ipv6 ::1");
    // Exposed (wildcard or routable — must be encrypted or explicitly forced).
    Check(!IsLoopbackEndpoint("tcp://0.0.0.0:5099"), "loopback: 0.0.0.0 is exposed");
    Check(!IsLoopbackEndpoint("0.0.0.0:8089"), "loopback: bare 0.0.0.0 exposed");
    Check(!IsLoopbackEndpoint("tcp://10.0.0.5:5099"), "loopback: private lan exposed");
    Check(!IsLoopbackEndpoint("tcp://203.0.113.9:5099"), "loopback: public ip exposed");
    Check(!IsLoopbackEndpoint(""), "loopback: empty is exposed");
  }

  // --- daemon_args: OptOrEnv flag/env/default precedence ---
  {
    using samurai::control::daemon::OptOrEnv;
    const char* av[] = {"prog", "--cluster-secret", "from-flag"};
    int ac = 3;
    ::setenv("SAMURAI_TEST_SECRET", "from-env", 1);
    Check(OptOrEnv(ac, const_cast<char**>(av), "--cluster-secret", "SAMURAI_TEST_SECRET", "d") ==
              "from-flag",
          "OptOrEnv: flag wins over env");
    const char* av2[] = {"prog"};
    Check(OptOrEnv(1, const_cast<char**>(av2), "--cluster-secret", "SAMURAI_TEST_SECRET", "d") ==
              "from-env",
          "OptOrEnv: env used when flag absent");
    ::unsetenv("SAMURAI_TEST_SECRET");
    Check(OptOrEnv(1, const_cast<char**>(av2), "--cluster-secret", "SAMURAI_TEST_SECRET", "d") ==
              "d",
          "OptOrEnv: default when neither set");
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

    // StopShard is fenced too: a zombie master (epoch below the watermark of 5)
    // must not be able to tear down a shard the current leader owns. The fence
    // trips before the shard lookup, so it holds even for a running shard.
    json::Value stop_stale = json::Value::Object();
    stop_stale.set("shard_id", json::Value::Str("shard-1"));
    stop_stale.set("_leader_epoch", json::Value::Int(3));
    auto stp = svc.StopShard(stop_stale, ctx);
    Check(!stp.find("stopped")->as_bool() && stp.find("error") &&
              stp.find("error")->as_string().find("stale leader epoch") != std::string::npos,
          "wss: stale leader epoch stop rejected");

    // A current-epoch stop clears the fence (no stale-epoch error).
    json::Value stop_ok = json::Value::Object();
    stop_ok.set("shard_id", json::Value::Str("shard-absent"));
    stop_ok.set("_leader_epoch", json::Value::Int(5));
    auto stp2 = svc.StopShard(stop_ok, ctx);
    Check(!(stp2.find("error") &&
            stp2.find("error")->as_string().find("stale leader epoch") != std::string::npos),
          "wss: current-epoch stop passes fence");

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
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
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

  // --- master: TASK-TEST-L5-01 dynamic rebalancing under worker chaos (kill -9) ---
  {
    namespace json = samurai::core::json;

    struct ChaosView : MasterView {
      std::map<std::string, WorkerInfo> workers;
      std::map<std::string, std::string> stats;
      std::int64_t* clk = nullptr;
      std::string dead_worker;

      std::vector<WorkerInfo> Workers() override {
        std::vector<WorkerInfo> out;
        for (auto& kv : workers) {
          WorkerInfo w = kv.second;
          if (w.worker_id != dead_worker) {
            w.last_heartbeat_ms = *clk;  // surviving workers stay alive
          }
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

    struct ChaosCmd : WorkerCommander {
      ChaosView* view = nullptr;
      std::string killed_worker;
      std::string killed_shard;
      std::map<std::string, int> dispatch_counts;

      DispatchOutcome Dispatch(const std::string& endpoint, const std::string& sid,
                               const std::string& job_id, const std::string& args,
                               std::int64_t count, std::int64_t timeout_ms) override {
        (void)job_id; (void)args; (void)timeout_ms;
        std::string wid;
        for (const auto& kv : view->workers) {
          auto it = kv.second.capabilities.find("control_endpoint");
          if (it != kv.second.capabilities.end() && it->second == endpoint) {
            wid = kv.first;
            break;
          }
        }
        dispatch_counts[wid]++;
        if (wid == killed_worker) {
          killed_shard = sid;
          return {true, "accepted-then-killed"};
        }
        json::Value s = json::Value::Object();
        s.set("shard_id", json::Value::Str(sid));
        s.set("worker_id", json::Value::Str(wid));
        s.set("sent", json::Value::Int(count));
        s.set("errors", json::Value::Int(0));
        view->SetShardStats(sid, s.dump());
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {}; }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
    };

    ChaosView view;
    std::int64_t clk = 1000000;
    view.clk = &clk;
    view.dead_worker = "w2";

    for (const char* wid : {"w1", "w2", "w3", "w4"}) {
      WorkerInfo w;
      w.worker_id = wid;
      w.capabilities["control_endpoint"] = std::string("tcp://") + wid + ":5099";
      w.last_heartbeat_ms = clk;
      view.workers[wid] = w;
    }

    ChaosCmd cmd;
    cmd.view = &view;
    cmd.killed_worker = "w2";

    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [&clk](int ms) { clk += ms; });
    JobConfig job;
    job.count = 10000000;
    job.shard_unit_count = 1000000;  // 10 shards
    job.heartbeat_timeout_ms = 2000;
    job.master_poll_interval_ms = 100;

    auto res = coord.RunSingleJob(job, "chaos-l5-01");
    Check(res.rc == 0, "TASK-TEST-L5-01: master completes with rc=0 under worker chaos");
    Check(res.snapshot.find("sent") && res.snapshot.find("sent")->as_int() == 10000000,
          "TASK-TEST-L5-01: exact 10,000,000 packets delivered");
    Check(res.snapshot.find("shards_reported") &&
              res.snapshot.find("shards_reported")->as_int() == 10,
          "TASK-TEST-L5-01: all 10 shards successfully completed");
    Check(res.snapshot.find("lost_workers") &&
              res.snapshot.find("lost_workers")->elements().size() == 1 &&
              res.snapshot.find("lost_workers")->elements()[0].as_string() == "w2",
          "TASK-TEST-L5-01: master detected w2 loss via heartbeat timeout");
    Check(res.snapshot.find("pending_shards_left")->as_int() == 0 &&
              res.snapshot.find("inflight_shards_left")->as_int() == 0,
          "TASK-TEST-L5-01: zero pending or in-flight shards left (zero deadlock)");
  }

  // --- master: leadership lost mid-job recalls inflight shards (chaos) ---
  {
    namespace json = samurai::core::json;

    struct FakeView : MasterView {
      std::map<std::string, WorkerInfo> workers;
      std::vector<WorkerInfo> Workers() override {
        std::vector<WorkerInfo> out;
        for (auto& kv : workers) out.push_back(kv.second);
        return out;
      }
      // Never report completion: shards stay inflight so the abort path has work
      // to recall (simulates a long-running burst outliving the master's lease).
      bool ShardReported(const std::string&) override { return false; }
      std::string GetShardStats(const std::string&) override { return "{}"; }
      void SetShardStats(const std::string&, const std::string&) override {}
    };
    struct FakeCmd : WorkerCommander {
      std::set<std::string> dispatched;
      std::set<std::string> recalled;
      std::int64_t stop_epoch = -1;
      DispatchOutcome Dispatch(const std::string&, const std::string& sid, const std::string&,
                               const std::string&, std::int64_t, std::int64_t) override {
        dispatched.insert(sid);  // accepted but never completes (view reports nothing)
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {"running", "", "{}"}; }
      bool StopShard(const std::string&, const std::string& sid, std::int64_t epoch) override {
        recalled.insert(sid);
        stop_epoch = epoch;
        return true;
      }
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
    MasterCoordinator coord(&view, &cmd, [&clk]() { return clk; }, [](int) {});
    JobConfig job;
    job.count = 1000;
    job.shard_unit_count = 250;  // -> 4 shards
    job.master_poll_interval_ms = 1;
    job.leader_epoch = 7;
    // Leader for the first poll (shards get dispatched), then lease is lost.
    int polls = 0;
    auto guard = [&polls]() { return polls++ < 1; };
    auto res = coord.RunSingleJob(job, "chaos-1", guard);
    Check(res.rc == 1 && res.snapshot.find("error") &&
              res.snapshot.find("error")->as_string() == "leadership_lost_abort",
          "chaos: leadership loss aborts the job");
    Check(!cmd.dispatched.empty() && cmd.recalled == cmd.dispatched,
          "chaos: every inflight shard is recalled on leadership loss");
    Check(cmd.stop_epoch == 7, "chaos: recall stops carry the job leader epoch");
    Check(res.snapshot.find("recalled_shards") &&
              res.snapshot.find("recalled_shards")->as_int() ==
                  static_cast<std::int64_t>(cmd.dispatched.size()),
          "chaos: snapshot recalled_shards matches");
    Check(res.snapshot.find("active_shards_at_loss") &&
              res.snapshot.find("active_shards_at_loss")->as_int() > 0 &&
              res.snapshot.find("abort_latency_ms"),
          "chaos: snapshot carries residual metrics");
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
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
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
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
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
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
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
    slave.set_on_stop([&worker_svc](const std::string& sid, std::int64_t leader_epoch) {
      json::Value stop = json::Value::Object();
      stop.set("shard_id", json::Value::Str(sid));
      stop.set("_leader_epoch", json::Value::Int(leader_epoch));
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

  // --- ReconfigureShard RPC (direct + epoch fence + reverse heartbeat) & Management API ---
  {
    namespace json = samurai::core::json;
    using namespace samurai::control;
    struct ReconfRun : ShardRun {
      std::atomic<bool> alive{true};
      std::atomic<bool> term{false};
      std::mutex rmu;
      std::vector<double> seen_rps;
      bool IsAlive() override { return alive.load(); }
      std::int64_t Progress() const override { return 42; }
      std::int64_t Sent() const override { return 42; }
      std::int64_t Errors() const override { return 0; }
      int ExitCode() const override { return 0; }
      void Terminate() override { term.store(true); alive.store(false); }
      void Join() override {
        while (!term.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        alive.store(false);
      }
      bool Reconfigure(const json::Value& params) override {
        std::lock_guard<std::mutex> lk(rmu);
        if (const json::Value* v = params.find("target_rps")) {
          seen_rps.push_back(v->as_double(0.0));
          return true;
        }
        return false;
      }
    };
    struct ReconfRunner : ShardRunner {
      std::shared_ptr<ReconfRun> last;
      std::shared_ptr<ShardRun> Start(const std::string&, const json::Value&) override {
        last = std::make_shared<ReconfRun>();
        return last;
      }
    };

    AuthConfig no_auth;
    ReconfRunner runner;
    WorkerShardService svc("w-reconf", &runner);
    ControlServer worker_srv("tcp://127.0.0.1:*", &svc, no_auth);
    Check(worker_srv.Start(), "reconf-direct: worker server starts");
    const std::string wep = worker_srv.endpoint();

    json::Value sreq = json::Value::Object();
    sreq.set("shard_id", json::Value::Str("sh-rc-1"));
    sreq.set("job_id", json::Value::Str("job-rc-1"));
    json::Value sargs = json::Value::Object();
    sargs.set("count", json::Value::Int(100));
    sargs.set("_leader_epoch", json::Value::Int(5));
    sreq.set("args_json", json::Value::Str(sargs.dump()));
    sreq.set("packet_count", json::Value::Int(100));
    const json::Value start_res = svc.StartShard(sreq, RpcContext{});
    Check(start_res.find("started") && start_res.find("started")->as_bool(false),
          "reconf-direct: shard started");

    WorkerControlClient wcli(wep);
    const auto r_ok = wcli.ReconfigureShard("sh-rc-1", "{\"target_rps\":1234.5}", 5);
    Check(r_ok.ok && r_ok.body.find("reconfigured") &&
              r_ok.body.find("reconfigured")->as_bool(false),
          "reconf-direct: live ReconfigureShard RPC succeeds at epoch 5");
    const auto r_stale = wcli.ReconfigureShard("sh-rc-1", "{\"target_rps\":9999}", 4);
    const json::Value* r_stale_ok = r_stale.body.find("reconfigured");
    const json::Value* r_stale_err = r_stale.body.find("error");
    Check(r_stale.ok && r_stale_ok && !r_stale_ok->as_bool(true) && r_stale_err &&
              r_stale_err->as_string("").find("stale leader epoch") != std::string::npos,
          "reconf-direct: stale leader_epoch 4 rejected by fence");
    {
      std::lock_guard<std::mutex> lk(runner.last->rmu);
      Check(runner.last->seen_rps.size() == 1 &&
                std::abs(runner.last->seen_rps[0] - 1234.5) < 1e-6,
            "reconf-direct: ShardRun::Reconfigure received updated target_rps");
    }

    // Reverse heartbeat reconfigure path
    ServicerConfig mcfg;
    mcfg.cluster_id = "cluster-reconf";
    Servicer master_svc(mcfg);
    ControlServer master_srv("tcp://127.0.0.1:*", &master_svc, no_auth);
    Check(master_srv.Start(), "reconf-rev: master server starts");
    SlaveControlClient sl_cli(master_srv.endpoint());
    SlaveConfig slcfg;
    slcfg.worker_id = "w-reconf";
    slcfg.capabilities["dispatch_mode"] = "reverse";
    SlaveNode slave(&sl_cli, slcfg);
    slave.set_on_reconfigure([&svc](const json::Value& r) { svc.ReconfigureShard(r, RpcContext{}); });
    slave.set_active_shard_provider([&svc]() { return svc.ActiveShardId(); });
    Check(slave.Register(), "reconf-rev: registers");

    PendingCommand rcmd;
    rcmd.type = "reconfigure";
    rcmd.shard_id = "sh-rc-1";
    rcmd.leader_epoch = 5;
    rcmd.args_json = "{\"target_rps\":5678.0}";
    master_svc.EnqueueCommand("w-reconf", rcmd);
    Check(slave.HeartbeatOnce().ok, "reconf-rev: heartbeat delivers reconfigure");
    {
      std::lock_guard<std::mutex> lk(runner.last->rmu);
      Check(runner.last->seen_rps.size() == 2 &&
                std::abs(runner.last->seen_rps[1] - 5678.0) < 1e-6,
            "reconf-rev: ShardRun::Reconfigure updated via reverse heartbeat");
    }

    json::Value stop = json::Value::Object();
    stop.set("shard_id", json::Value::Str("sh-rc-1"));
    stop.set("_leader_epoch", json::Value::Int(5));
    svc.StopShard(stop, RpcContext{});
    svc.WaitForShardIdle("sh-rc-1");
    master_srv.Stop();
    worker_srv.Stop();
  }

  // --- Management API POST /v1/shards/reconfigure + MasterCoordinator live tick ---
  {
    namespace json = samurai::core::json;
    using namespace samurai::control;
    ManagementConfig mcfg;
    mcfg.role_tokens["viewer"] = "view-tok";
    mcfg.role_tokens["operator"] = "op-tok";
    ManagementProviders providers;
    std::string seen_reconf_shard;
    providers.reconfigure_callback = [&](const json::Value& b) {
      if (const auto* s = b.find("shard_id")) seen_reconf_shard = s->as_string("");
      json::Value o = json::Value::Object();
      o.set("reconfigured", json::Value::Bool(true));
      o.set("applied", json::Value::Int(1));
      return o;
    };
    ManagementApi api(mcfg, providers);

    HttpRequest r_view;
    r_view.method = "POST";
    r_view.path = "/v1/shards/reconfigure";
    r_view.headers["authorization"] = "Bearer view-tok";
    r_view.body = "{\"shard_id\":\"s1\",\"target_rps\":500}";
    Check(api.Handle(r_view).status == 403, "mgmt-reconf: viewer forbidden");

    HttpRequest r_op = r_view;
    r_op.headers["authorization"] = "Bearer op-tok";
    auto resp = api.Handle(r_op);
    Check(resp.status == 200 && seen_reconf_shard == "s1",
          "mgmt-reconf: operator succeeds and invokes callback");

    struct LiveTickView : MasterView {
      std::vector<WorkerInfo> ws;
      std::map<std::string, std::string> stats;
      std::vector<WorkerInfo> Workers() override { return ws; }
      bool ShardReported(const std::string& sid) override { return stats.count(sid) > 0; }
      std::string GetShardStats(const std::string& sid) override {
        return stats.count(sid) ? stats[sid] : "{}";
      }
      void SetShardStats(const std::string& sid, const std::string& s) override { stats[sid] = s; }
    };
    struct LiveTickCmd : WorkerCommander {
      int reconf_calls = 0;
      std::string last_reconf_args;
      bool stopped = false;
      DispatchOutcome Dispatch(const std::string&, const std::string&, const std::string&,
                               const std::string&, std::int64_t, std::int64_t) override {
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override {
        ProbeOutcome p;
        p.state = stopped ? "done" : "running";
        p.active_shard_id = "live-j-shard-1";
        p.stats_json = "{\"sent\":100,\"errors\":0}";
        return p;
      }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override {
        stopped = true;
        return true;
      }
      bool ReconfigureShard(const std::string&, const std::string&,
                            const std::string& args_json, std::int64_t) override {
        ++reconf_calls;
        last_reconf_args = args_json;
        return true;
      }
    };

    LiveTickView ltv;
    WorkerInfo wi;
    wi.worker_id = "w1";
    wi.capabilities["control_endpoint"] = "tcp://127.0.0.1:9";
    ltv.ws.push_back(wi);
    LiveTickCmd ltc;
    std::int64_t fake_now = 1000;
    MasterCoordinator coord(&ltv, &ltc, [&]() { return fake_now; }, [&](int ms) { fake_now += ms; });
    JobConfig jc;
    jc.count = 10000;
    jc.shard_unit_count = 10000;
    jc.job_timeout_s = 30;
    jc.master_poll_interval_ms = 500;
    jc.window_tick_interval_ms = 500;
    jc.window_tick_cb = [](int tick, const std::vector<ProbeOutcome>& probes, bool& should_stop) {
      if (probes.empty()) return std::string();
      if (tick == 0) return std::string("{\"target_rps\":2500}");
      should_stop = true;
      return std::string();
    };
    const JobResult jr = coord.RunSingleJob(jc, "live-j");
    Check(jr.rc == 0 && ltc.reconf_calls == 1 &&
              ltc.last_reconf_args.find("2500") != std::string::npos &&
              ltc.stopped,
          "coord-live-tick: pushes live ReconfigureShard then converges clean stop");
  }
#endif  // SAMURAI_CONTROL_HAVE_ZMQ

  // --- Hierarchical Region Affinity, ASN Map & Multi-Pool Telco Sizing ---
  {
    namespace json = samurai::core::json;
    const auto topo_parsed = json::Parse(
        "{\"asn_to_region\":{\"AS9121\":\"tr-ist\",\"15897\":\"tr-ank\",\"3320\":\"eu-fra\"},"
        "\"region_aliases\":{\"istanbul\":\"tr-ist\"}}");
    RegionTopology topo;
    std::string terr;
    Check(topo_parsed.ok && RegionTopology::FromJson(topo_parsed.value, topo, terr),
          "region-topo: parses ASN and alias JSON");
    Check(topo.ResolveRegion(9121, "") == "tr-ist" &&
              topo.ResolveRegion(0, "ISTANBUL") == "tr-ist",
          "region-topo: resolves ASN and canonical alias");

    std::map<std::string, WorkerCapabilities> caps;
    caps["w-ist"].region = "tr-ist";
    caps["w-ank"].region = "tr-ank";
    caps["w-eu"].region = "eu-fra";
    auto rshards = SplitJobToShards(
        1000, {"w-ist", "w-ank", "w-eu"}, "region", caps, "tr-ist", &topo);
    Check(Sum(rshards) == 1000 &&
              rshards[0].packet_count > rshards[1].packet_count &&
              rshards[1].packet_count >= rshards[2].packet_count,
          "region-topo: exact PoP tr-ist > country-sibling tr-ank >= eu-fra");

    // Lab sizing safety: reject public base_ip, accept isolated RFC 6598/1918 histogram.
    const auto bad_pub = json::Parse("{\"lab_base_ip\":\"8.8.8.0\",\"prefix_counts\":{\"24\":2}}");
    TelcoLabSizingProfile bad_prof;
    std::string berr;
    Check(bad_pub.ok && !TelcoLabSizingProfile::FromJson(bad_pub.value, bad_prof, berr),
          "telco-pool: rejects public IPv4 pool base");

    const auto hist_ok = json::Parse(
        "{\"name\":\"tr-bng-hist\",\"lab_base_ip\":\"100.64.0.0\","
        "\"prefix_counts\":{\"20\":2,\"22\":4,\"24\":8}}");
    TelcoLabSizingProfile hist_prof;
    std::string herr;
    Check(hist_ok.ok && TelcoLabSizingProfile::FromJson(hist_ok.value, hist_prof, herr) &&
              hist_prof.RouteCount() == 14 && hist_prof.buckets.size() == 3,
          "telco-pool: builds 14 disjoint lab routes from manual histogram");

    auto tspecs = SplitTelcoSubscribers(
        3000, {"w-ist", "w-ank", "w-eu"}, caps, "tr-ist", "region",
        "pppoe", 6000, 100, 10, nullptr, 0x0A000001, 0x0A0000FE, &hist_prof, &topo);
    Check(tspecs.size() == 3 &&
              tspecs[0].range.count + tspecs[1].range.count + tspecs[2].range.count == 3000 &&
              tspecs[0].range.count > tspecs[1].range.count &&
              tspecs[0].range.PoolRouteCount() == 14 &&
              tspecs[0].range.EstimatedNatTableEntries(64) ==
                  static_cast<std::uint64_t>(tspecs[0].range.count) * 64ull,
          "telco-pool: region-weighted subscriber partitioning attaches 14 FIB routes");
    bool all_safe = true;
    for (std::uint32_t s = 0; s < 500; ++s) {
      if (!IsSafeTelcoLabIpv4(tspecs[0].range.GetIpFor(s))) all_safe = false;
    }
    Check(all_safe && tspecs[0].range.GetIpFor(0) == 0x64400001u,
          "telco-pool: multi-pool subscriber IPs stay strictly inside RFC6598/lab space");

    // End-to-end MasterCoordinator telco dispatch using target_asn + regional-bng preset.
    struct TelcoStubView : MasterView {
      std::vector<WorkerInfo> ws;
      std::mutex smu;
      std::map<std::string, std::string> stats;
      std::vector<WorkerInfo> Workers() override { return ws; }
      void SetShardStats(const std::string& sid, const std::string& json) override {
        std::lock_guard<std::mutex> lk(smu);
        stats[sid] = json;
      }
      bool ShardReported(const std::string& sid) override {
        std::lock_guard<std::mutex> lk(smu);
        return stats.count(sid) > 0;
      }
      std::string GetShardStats(const std::string& sid) override {
        std::lock_guard<std::mutex> lk(smu);
        auto it = stats.find(sid);
        return it == stats.end() ? "{}" : it->second;
      }
    };
    struct TelcoStubCmd : WorkerCommander {
      TelcoStubView* view = nullptr;
      std::map<std::string, std::int64_t> by_worker_count;
      DispatchOutcome Dispatch(const std::string&, const std::string& shard_id, const std::string&,
                               const std::string& args_json, std::int64_t pkt_cnt,
                               std::int64_t) override {
        const auto ap = samurai::core::json::Parse(args_json);
        if (ap.ok && ap.value.find("_worker_id")) {
          by_worker_count[ap.value.find("_worker_id")->as_string("")] += pkt_cnt;
        }
        view->SetShardStats(shard_id, "{\"sent\":" + std::to_string(pkt_cnt) + ",\"errors\":0}");
        return {true, "ok"};
      }
      ProbeOutcome Probe(const std::string&, const std::string&) override { return {"done", "", "{}"}; }
      bool StopShard(const std::string&, const std::string&, std::int64_t) override { return true; }
    };
    TelcoStubView tv;
    WorkerInfo w1{"w-ist", {{"worker_kinds", "telco"}, {"control_endpoint", "tcp://127.0.0.1:9"}, {"region", "tr-ist"}}, 1000, ""};
    WorkerInfo w2{"w-eu", {{"worker_kinds", "telco"}, {"control_endpoint", "tcp://127.0.0.1:10"}, {"region", "eu-fra"}}, 1000, ""};
    tv.ws = {w1, w2};
    TelcoStubCmd tc;
    tc.view = &tv;
    std::int64_t tnow = 1000;
    MasterCoordinator coord(&tv, &tc, [&]() { return tnow; }, [&](int ms) { tnow += ms; });
    JobConfig cfg;
    cfg.is_telco_job = true;
    cfg.telco_subscribers = 1000;
    cfg.target_asn = 9121;
    cfg.region_topology = topo;
    cfg.telco_pool_profile = TelcoLabSizingProfile::Preset("regional-bng");
    cfg.job_timeout_s = 10;
    cfg.master_poll_interval_ms = 5;
    const JobResult tr = coord.RunSingleJob(cfg, "t-asn-job");
    Check(tr.rc == 0 && tc.by_worker_count["w-ist"] > tc.by_worker_count["w-eu"] &&
              tr.snapshot.find("telco_routing_prefixes") &&
              tr.snapshot.find("telco_routing_prefixes")->as_int(0) == 52 &&
              tr.snapshot.find("resolved_target_region") &&
              tr.snapshot.find("resolved_target_region")->as_string("") == "tr-ist",
          "coord-asn-telco: target_asn + regional-bng weights tr-ist & reports 52 FIB prefixes");
  }

  if (g_failures == 0) {
    std::printf("control selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "control selftest: %d failure(s)\n", g_failures);
  return 1;
}
