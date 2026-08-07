// Self-test for the native licensing offline core. Exits 0 on success, 1 on the
// first failed check.

#include <cstdio>
#include <cstdlib>
#include <string>

#include "cache.hpp"
#include "constants.hpp"
#include "gates.hpp"
#include "hwid.hpp"
#include "license_types.hpp"

namespace {
int g_failures = 0;
void Check(bool cond, const char* what) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using namespace samurai::licensing;

LicenseResult Lic(Tier tier, bool offline = false) {
  LicenseResult r;
  r.valid = true;
  r.tier = tier;
  r.features = TierFeatures(tier);
  r.limits = TierLimitsFor(tier);
  r.offline = offline;
  return r;
}

struct StubGrant : ExecGrantClient {
  bool succeed;
  explicit StubGrant(bool s) : succeed(s) {}
  ExecGrantResult RequestGrant(const std::string&, const std::string&, const std::string&,
                               const std::string&, const std::string&, const std::string&,
                               const std::vector<std::string>&) override {
    ExecGrantResult r;
    if (succeed) {
      r.ok = true;
      r.grant_token = "tok-123";
      r.expires_at = "2030-01-01";
    } else {
      r.reason = "denied";
    }
    return r;
  }
};
}  // namespace

int main() {
  // --- features / limits ---
  Check(TierFeatures(Tier::kCommunity).empty(), "features: community empty");
  {
    auto pro = Lic(Tier::kPro);
    Check(HasFeature(pro, kFeatureGpuEngine) && HasFeature(pro, kFeatureAfXdp),
          "features: pro has gpu+xdp");
    Check(!HasFeature(pro, kFeatureL7Quic), "features: pro lacks quic");
    auto ent = Lic(Tier::kEnterprise);
    Check(HasFeature(ent, kFeatureL7Quic) && HasFeature(ent, kFeatureNinjaMode),
          "features: enterprise has quic+ninja");
  }
  Check(TierLimitsFor(Tier::kCommunity).max_workers == 2 &&
            TierLimitsFor(Tier::kCommunity).max_pps == 100,
        "limits: community 2 workers / 100 pps");
  Check(TierName(Tier::kEnterprise) == "enterprise" && TierFromName("pro") == Tier::kPro,
        "tier name round trip");

  // --- hwid ---
  {
    const std::string h1 = GetHardwareId();
    const std::string h2 = GetHardwareId();
    Check(h1.size() == 64 && h1 == h2, "hwid: 64-hex and stable");
  }

  // --- gates ---
  {
    // Community: http vector needs l7_http11 -> reject.
    auto community = Lic(Tier::kCommunity);
    GateInput http;
    http.attack_vector = "http";
    auto r = EnforceFeatureGates(http, community);
    Check(!r.ok && r.error.find("http") != std::string::npos, "gate: community http rejected");

    // Pro: http vector allowed.
    auto pro = Lic(Tier::kPro);
    auto r2 = EnforceFeatureGates(http, pro);
    Check(r2.ok, "gate: pro http allowed");

    // Community: cuda backend rejected.
    GateInput cuda;
    cuda.attack_vector = "basic";
    cuda.compute_backend = "cuda";
    auto community2 = Lic(Tier::kCommunity);
    Check(!EnforceFeatureGates(cuda, community2).ok, "gate: community cuda rejected");

    // Community: duration + pps clamped with warnings.
    GateInput big;
    big.attack_vector = "basic";
    big.duration = 300;
    big.rps = 1000.0;
    auto community3 = Lic(Tier::kCommunity);
    auto rc = EnforceFeatureGates(big, community3);
    Check(rc.ok && rc.duration == 60 && rc.rps == 100.0 && rc.warnings.size() >= 2,
          "gate: community clamps duration/pps");

    // Critical + offline -> reject.
    GateInput crit;
    crit.attack_vector = "basic";
    crit.compute_backend = "cuda";  // -> gpu_engine critical
    crit.has_role = true;
    auto ent_offline = Lic(Tier::kEnterprise, /*offline=*/true);
    auto ro = EnforceFeatureGates(crit, ent_offline);
    Check(!ro.ok && ro.error.find("offline") != std::string::npos, "gate: critical offline rejected");

    // Critical + online + no grant client -> reject.
    crit.license_key = "SAM-AAAA-BBBB-CCCC-DDDD";
    auto ent_online = Lic(Tier::kEnterprise);
    Check(!EnforceFeatureGates(crit, ent_online, nullptr).ok,
          "gate: critical without grant client rejected");

    // Critical + online + grant success -> ok, token set.
    auto ent_online2 = Lic(Tier::kEnterprise);
    StubGrant ok_grant(true);
    auto rg = EnforceFeatureGates(crit, ent_online2, &ok_grant);
    Check(rg.ok && ent_online2.exec_grant_token == "tok-123", "gate: critical grant success");

    // Critical + online + grant denied -> reject.
    auto ent_online3 = Lic(Tier::kEnterprise);
    StubGrant deny(false);
    Check(!EnforceFeatureGates(crit, ent_online3, &deny).ok, "gate: critical grant denied");
  }

  // --- cache (redirect HOME to a scratch dir) ---
  {
    ::setenv("HOME",
             "/tmp/claude-0/-home-user-Samurai/e22cf02a-7f79-5de1-b1eb-8cd527ed8d7d/scratchpad",
             1);
    ClearCache();
    const std::string hwid = "test-hwid-abc";
    auto src = Lic(Tier::kPro);
    src.customer_email = "user@example.com";
    src.session_id = "sess-1";
    Check(SaveCache(src, hwid), "cache: save");

    LicenseResult loaded;
    Check(LoadCache(hwid, loaded), "cache: load");
    Check(loaded.offline && loaded.reason == "offline_cache", "cache: marked offline");
    Check(loaded.tier == Tier::kPro && HasFeature(loaded, kFeatureAfXdp), "cache: tier+features");
    Check(loaded.customer_email == "user@example.com" && loaded.session_id == "sess-1",
          "cache: metadata preserved");
    Check(loaded.limits.has_value && loaded.limits.max_workers == 16, "cache: limits preserved");

    // Wrong HWID cannot decrypt.
    LicenseResult bad;
    Check(!LoadCache("other-hwid", bad), "cache: wrong hwid fails auth");

    ClearCache();
    LicenseResult gone;
    Check(!LoadCache(hwid, gone), "cache: cleared");
  }

  if (g_failures == 0) {
    std::printf("license selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "license selftest: %d failure(s)\n", g_failures);
  return 1;
}
