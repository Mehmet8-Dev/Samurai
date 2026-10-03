// Self-test for the native licensing offline core. Exits 0 on success, 1 on the
// first failed check.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "anti_tamper.hpp"
#include "cache.hpp"
#include "client.hpp"
#include "constants.hpp"
#include "gates.hpp"
#include "http_client.hpp"
#include "hwid.hpp"
#include "license_types.hpp"
#include "obfuscate.hpp"

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

// One-thread mock HTTP server: replies by path (validate vs exec-grant).
struct MockLicenseServer {
  int fd = -1;
  int port = 0;
  std::atomic<bool> running{false};
  std::thread th;

  bool Start() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    timeval tv{0, 200 * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(fd, 8) != 0) {
      ::close(fd);
      fd = -1;
      return false;
    }
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bl);
    port = ntohs(bound.sin_port);
    running.store(true);
    th = std::thread([this] { Loop(); });
    return true;
  }
  void Loop() {
    while (running.load()) {
      int c = ::accept(fd, nullptr, nullptr);
      if (c < 0) continue;
      std::string req;
      char buf[2048];
      timeval tv{1, 0};
      ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ssize_t n = ::recv(c, buf, sizeof(buf), 0);
      if (n > 0) req.assign(buf, static_cast<std::size_t>(n));
      const bool grant = req.find("exec-grant") != std::string::npos;
      const std::string body =
          grant ? std::string("{\"granted\":true,\"grant_token\":\"grant-xyz\",\"expires_at\":\"2030\"}")
                : std::string("{\"valid\":true,\"tier\":\"pro\",\"features\":[\"af_xdp\",\"gpu_engine\"],"
                              "\"limits\":{\"max_workers\":16,\"max_pps\":0,\"max_duration_s\":0,\"max_devices\":3},"
                              "\"expires\":\"2030-01-01\",\"customer_email\":\"a@b.co\",\"session_id\":\"sess-9\"}");
      std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                         std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
      ::send(c, resp.data(), resp.size(), 0);
      ::close(c);
    }
  }
  void Stop() {
    running.store(false);
    if (th.joinable()) th.join();
    if (fd >= 0) ::close(fd);
  }
};

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
    ::setenv("HOME", "/tmp/samurai_license_test_home", 1);
    ::system("mkdir -p /tmp/samurai_license_test_home");
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

  // --- http license client against a mock server ---
  {
    MockLicenseServer server;
    if (!server.Start()) {
      std::fprintf(stderr, "FAIL: mock server start\n");
      ++g_failures;
    } else {
      const std::string url = "http://127.0.0.1:" + std::to_string(server.port);
      HttpLicenseClient client(url, 3);

      LicenseResult lr = client.Validate("SAM-AAAA-BBBB-CCCC-DDDD", "hwid-1");
      Check(lr.valid && lr.tier == Tier::kPro, "client: validate -> valid pro");
      Check(HasFeature(lr, kFeatureAfXdp) && lr.limits.has_value && lr.limits.max_workers == 16,
            "client: features + limits parsed");
      Check(lr.session_id == "sess-9" && lr.customer_email == "a@b.co",
            "client: metadata parsed");

      ExecGrantResult g = client.RequestGrant("SAM-AAAA-BBBB-CCCC-DDDD", "hwid-1", "sess-9",
                                              "http2", "cpu", "standalone", {"l7_http2"});
      Check(g.ok && g.grant_token == "grant-xyz", "client: exec-grant granted");

      // The client satisfies the gates' ExecGrantClient interface end to end.
      auto ent = Lic(Tier::kEnterprise);
      GateInput crit;
      crit.attack_vector = "http2";
      crit.has_role = true;
      crit.license_key = "SAM-AAAA-BBBB-CCCC-DDDD";
      auto rg = EnforceFeatureGates(crit, ent, &client);
      Check(rg.ok && ent.exec_grant_token == "grant-xyz", "client: drives gate exec-grant");

      server.Stop();
    }
    // Unreachable server -> invalid with a reason (no hang).
    HttpLicenseClient dead("http://127.0.0.1:9", 1);
    LicenseResult bad = dead.Validate("SAM-X", "h");
    Check(!bad.valid && bad.reason.find("unreachable") != std::string::npos,
          "client: unreachable server reason");
  }

  // --- obfuscation & dev mode & anti-tamper ---
  {
    const std::string s1 = SAMURAI_OBFUSCATE("hello_secret_world");
    Check(s1 == "hello_secret_world", "obfuscate: roundtrip string match");
    Check(ValidateEndpoint() == SAMURAI_OBFUSCATE("/api/v1/license/validate"), "obfuscate: endpoint matches");
    Check(ExecGrantEndpoint() == SAMURAI_OBFUSCATE("/api/v1/license/exec-grant"), "obfuscate: grant endpoint matches");

    // Dev mode check: in Release mode (NDEBUG defined), IsDevMode must always be false
#if defined(NDEBUG)
    ::setenv("SAMURAI_LICENSE_DEV_MODE", "1", 1);
    Check(!IsDevMode(), "devmode: locked down in release mode");
#endif

    // Anti-tamper & ELF text section integrity check
    IntegrityResult ir = VerifySelfIntegrity();
    Check(ir.ok, "anti-tamper: self integrity check passed");
    Check(!ir.text_sha256.empty(), "anti-tamper: text sha256 computed");

    // Invalid license rejection check
    LicenseResult invalid_lr;
    invalid_lr.valid = false;
    invalid_lr.reason = "mock test invalid key";
    GateInput gi;
    gi.attack_vector = "basic";
    Check(!EnforceFeatureGates(gi, invalid_lr).ok, "gate: invalid license strictly rejected");

    // Wire-speed clamping check under Community tier
    GateInput wirespeed_gi;
    wirespeed_gi.attack_vector = "basic";
    wirespeed_gi.rps = 0.0;
    auto comm_lr = Lic(Tier::kCommunity);
    auto wirespeed_res = EnforceFeatureGates(wirespeed_gi, comm_lr);
    Check(wirespeed_res.ok && wirespeed_res.rps == 100.0, "gate: wire-speed rps=0 clamped to community max_pps");
  }

  if (g_failures == 0) {
    std::printf("license selftest: all checks passed\n");
    return 0;
  }
  std::fprintf(stderr, "license selftest: %d failure(s)\n", g_failures);
  return 1;
}
