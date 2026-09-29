#pragma once

// License tiers, feature constants, limits, and the validation result. Pure
// data + lookups.

#include <string>
#include <vector>

namespace samurai::licensing {

enum class Tier { kCommunity, kPro, kEnterprise };

inline std::string TierName(Tier t) {
  switch (t) {
    case Tier::kPro: return "pro";
    case Tier::kEnterprise: return "enterprise";
    default: return "community";
  }
}
inline Tier TierFromName(const std::string& s) {
  if (s == "pro") return Tier::kPro;
  if (s == "enterprise") return Tier::kEnterprise;
  return Tier::kCommunity;
}

struct TierLimits {
  int max_workers = 0;      // 0 = unlimited
  int max_pps = 0;          // 0 = unlimited
  int max_duration_s = 0;   // 0 = unlimited
  int max_devices = 1;
  bool has_value = false;   // false => "no limits object"
};

struct LicenseResult {
  bool valid = false;
  Tier tier = Tier::kCommunity;
  std::vector<std::string> features;
  TierLimits limits;
  std::string expires;
  std::string customer_email;
  std::string reason;
  std::string session_id;
  bool offline = false;
  std::string exec_grant_token;
  std::string exec_grant_expires;
};

// Feature identifiers.
inline constexpr const char* kFeatureGpuEngine = "gpu_engine";
inline constexpr const char* kFeatureAfXdp = "af_xdp";
inline constexpr const char* kFeatureL7Http11 = "l7_http11";
inline constexpr const char* kFeatureL7Http2 = "l7_http2";
inline constexpr const char* kFeatureL7Quic = "l7_quic";
inline constexpr const char* kFeatureL7Websocket = "l7_websocket";
inline constexpr const char* kFeatureCustomTcp = "custom_tcp";
inline constexpr const char* kFeaturePcapGen = "pcap_gen";
inline constexpr const char* kFeatureKpiGate = "kpi_gate";
inline constexpr const char* kFeatureKpiGateAdvanced = "kpi_gate_advanced";
inline constexpr const char* kFeatureReportingJson = "reporting_json";
inline constexpr const char* kFeatureReportingMd = "reporting_md";
inline constexpr const char* kFeatureReportingProm = "reporting_prom";
inline constexpr const char* kFeatureSoakTesting = "soak_testing";
inline constexpr const char* kFeatureNinjaMode = "ninja_mode";
inline constexpr const char* kFeatureAmplification = "amplification";
inline constexpr const char* kFeatureSpoofing = "spoofing";
inline constexpr const char* kFeatureSlowloris = "slowloris";
inline constexpr const char* kFeatureApiKey = "api_key";

// Feature set for a tier (Pro ⊂ Enterprise).
std::vector<std::string> TierFeatures(Tier tier);
TierLimits TierLimitsFor(Tier tier);

inline bool HasFeature(const LicenseResult& r, const std::string& feature) {
  for (const auto& f : r.features) {
    if (f == feature) return true;
  }
  return false;
}

}  // namespace samurai::licensing
