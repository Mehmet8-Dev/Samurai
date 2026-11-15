#include "license_types.hpp"

namespace samurai::licensing {

std::vector<std::string> TierFeatures(Tier tier) {
  const std::vector<std::string> pro = {
      kFeatureGpuEngine, kFeatureAfXdp,        kFeatureL7Http11, kFeatureCustomTcp,
      kFeaturePcapGen,   kFeatureKpiGate,      kFeatureReportingJson, kFeatureReportingMd,
      kFeatureSoakTesting, kFeatureAmplification, kFeatureSpoofing, kFeatureSlowloris,
  };
  switch (tier) {
    case Tier::kCommunity:
      return {};
    case Tier::kPro:
      return pro;
    case Tier::kEnterprise: {
      std::vector<std::string> ent = pro;
      ent.insert(ent.end(), {kFeatureL7Http2, kFeatureL7Quic, kFeatureL7Websocket,
                             kFeatureKpiGateAdvanced, kFeatureReportingProm, kFeatureNinjaMode,
                             kFeatureApiKey});
      return ent;
    }
  }
  return {};
}

TierLimits TierLimitsFor(Tier tier) {
  TierLimits l;
  l.has_value = true;
  switch (tier) {
    case Tier::kPro:
      l.max_workers = 16;
      l.max_pps = 0;
      l.max_duration_s = 0;
      l.max_devices = 3;
      return l;
    case Tier::kEnterprise:
      l.max_workers = 0;
      l.max_pps = 0;
      l.max_duration_s = 0;
      l.max_devices = 10;
      return l;
    default:  // community
      l.max_workers = 2;
      l.max_pps = 100;
      l.max_duration_s = 60;
      l.max_devices = 1;
      return l;
  }
}

}  // namespace samurai::licensing
