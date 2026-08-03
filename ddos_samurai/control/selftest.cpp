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
#include "json.hpp"
#include "jwt.hpp"
#include "shard.hpp"

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

    // tampered signature -> mismatch
    std::string tampered = token;
    tampered[tampered.size() - 1] = (tampered.back() == 'A') ? 'B' : 'A';
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

  if (g_failures == 0) {
    std::printf("control selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "control selftest: %d failure(s)\n", g_failures);
  return 1;
}
