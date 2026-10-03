#include "gates.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include "constants.hpp"
#include "hwid.hpp"

namespace samurai::licensing {

namespace {

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}
std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

const std::map<std::string, std::string>& VectorFeatureMap() {
  static const std::map<std::string, std::string> m = {
      {"http", kFeatureL7Http11},   {"http2", kFeatureL7Http2},
      {"quic", kFeatureL7Quic},     {"websocket", kFeatureL7Websocket},
      {"slowloris", kFeatureSlowloris}, {"ntp-amp", kFeatureAmplification},
      {"ssdp-amp", kFeatureAmplification}, {"dns-amp", kFeatureAmplification},
      {"memcached-amp", kFeatureAmplification}, {"ldap-amp", kFeatureAmplification},
  };
  return m;
}

const std::set<std::string>& CriticalFeatures() {
  static const std::set<std::string> s = {
      kFeatureGpuEngine, kFeatureAfXdp,     kFeatureL7Http2,  kFeatureL7Quic,     kFeatureL7Websocket,
      kFeatureNinjaMode, kFeatureAmplification, kFeatureSpoofing, kFeatureCustomTcp};
  return s;
}

std::string UpgradeHint(const std::string& feature) {
  static const std::set<std::string> enterprise_only = {
      kFeatureL7Http2, kFeatureL7Quic,          kFeatureL7Websocket, kFeatureNinjaMode,
      kFeatureKpiGateAdvanced, kFeatureReportingProm, kFeatureApiKey};
  if (enterprise_only.count(feature)) {
    return "Bu özellik Enterprise plana özeldir. https://ddosamurai.com/fiyatlandirma";
  }
  return "Bu özellik Pro veya Enterprise plana yükseltme gerektirir. https://ddosamurai.com/fiyatlandirma";
}

std::string ResolveLicenseKey(const std::string& key, const std::string& key_file) {
  const std::string k = Strip(key);
  if (!k.empty()) return k;
  const std::string kf = Strip(key_file);
  if (!kf.empty()) {
    std::ifstream f(kf);
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      const std::string content = Strip(ss.str());
      if (!content.empty()) return content;
    }
  }
  return EnvOr("SAMURAI_LICENSE_KEY", "");
}

GateResult Fail(const std::string& msg, const std::string& hint) {
  GateResult r;
  r.ok = false;
  r.error = msg;
  r.upgrade_hint = hint;
  return r;
}

}  // namespace

GateResult EnforceFeatureGates(const GateInput& in, LicenseResult& lr, ExecGrantClient* grant) {
  if (!lr.valid) {
    return Fail("Lisans geçersiz veya doğrulanamadı: " + (lr.reason.empty() ? std::string("Geçersiz lisans") : lr.reason),
                "Geçerli bir lisans anahtarı sağlayın veya Community modunda çalıştırın.");
  }

  GateResult result;
  result.duration = in.duration;
  result.rps = in.rps;

  const std::string attack_vector = Lower(Strip(in.attack_vector.empty() ? "basic" : in.attack_vector));
  const std::string compute_backend = Lower(Strip(in.compute_backend.empty() ? "cpu" : in.compute_backend));
  const std::string custom_tcp_mode = Lower(Strip(in.custom_tcp_mode.empty() ? "off" : in.custom_tcp_mode));

  static const std::set<std::string> community_vectors = {"basic", "dns"};

  // 1. Vector.
  const auto& vfm = VectorFeatureMap();
  auto vit = vfm.find(attack_vector);
  if (vit != vfm.end()) {
    if (!HasFeature(lr, vit->second)) {
      return Fail("'" + attack_vector + "' saldırı vektörü '" + vit->second +
                      "' özelliğini gerektirir. Mevcut tier: " + TierName(lr.tier) + ".",
                  UpgradeHint(vit->second));
    }
  } else if (!community_vectors.count(attack_vector)) {
    if (lr.features.empty()) {
      return Fail("'" + attack_vector + "' vektörü Community planında desteklenmiyor.",
                  "Pro veya Enterprise plana yükseltin.");
    }
  }

  // 2. Compute backend.
  if (compute_backend == "cuda" && !HasFeature(lr, kFeatureGpuEngine)) {
    return Fail("CUDA/GPU engine Pro veya Enterprise plan gerektirir.",
                "GPU hızlandırma için Pro plana yükseltin.");
  }

  // 3. AF_XDP / Custom TCP.
  const bool xdp_req = in.xdp_enable || !Strip(in.xdp_interface).empty();
  if (xdp_req && !HasFeature(lr, kFeatureAfXdp)) {
    return Fail("AF_XDP sender backend Pro veya Enterprise plan gerektirir.",
                "Yüksek performanslı ağ yolu için Pro plana yükseltin.");
  }
  if ((custom_tcp_mode == "auto" || custom_tcp_mode == "required") &&
      !HasFeature(lr, kFeatureCustomTcp)) {
    return Fail("Custom TCP stack Pro veya Enterprise plan gerektirir.",
                "Stateful L7 engine için Pro plana yükseltin.");
  }

  // 4. Ninja mode.
  if (in.ninja_mode && !HasFeature(lr, kFeatureNinjaMode)) {
    return Fail("Ninja Mode (WAF Bypass) Enterprise plan gerektirir.",
                "Gelişmiş WAF bypass için Enterprise plana yükseltin.");
  }

  // 5. Spoofing.
  const bool spoof_enabled = in.spoof || in.realistic_spoof || !Strip(in.spoof_subnet).empty() ||
                             !Strip(in.spoof_list_file).empty() || !Strip(in.spoof_ip).empty();
  if (spoof_enabled && !HasFeature(lr, kFeatureSpoofing)) {
    return Fail("IP spoofing Pro veya Enterprise plan gerektirir.",
                "Source IP spoofing için Pro plana yükseltin.");
  }

  // 6. PCAP.
  if (attack_vector == "pcap-replay" && !HasFeature(lr, kFeaturePcapGen)) {
    return Fail("PCAP replay/generation Pro veya Enterprise plan gerektirir.",
                "PCAP özelliği için Pro plana yükseltin.");
  }

  // 7. KPI gate.
  const std::string kpi_profile = Lower(Strip(in.kpi_gate_profile.empty() ? "off" : in.kpi_gate_profile));
  if (kpi_profile != "off" && !HasFeature(lr, kFeatureKpiGate)) {
    return Fail("KPI Gate Pro veya Enterprise plan gerektirir.",
                "Performans gating için Pro plana yükseltin.");
  }
  if (kpi_profile == "dedicated_lab" && !HasFeature(lr, kFeatureKpiGateAdvanced)) {
    return Fail("Dedicated Lab KPI profili Enterprise plan gerektirir.",
                "Dedicated lab profili için Enterprise plana yükseltin.");
  }

  // 8. Soak/fault injection.
  if (in.fault_inject && !HasFeature(lr, kFeatureSoakTesting)) {
    return Fail("Soak/fault injection testing Pro veya Enterprise plan gerektirir.",
                "Dayanıklılık testi için Pro plana yükseltin.");
  }

  // 9. Prometheus metrics.
  if (!Strip(in.prom_textfile).empty() && !HasFeature(lr, kFeatureReportingProm)) {
    result.warnings.push_back(
        "Prometheus metrics çıktısı Enterprise plan gerektirir. --prom-textfile yoksayılıyor.");
    result.prom_textfile_cleared = true;
  }

  // 10. Duration limit.
  if (lr.limits.has_value && lr.limits.max_duration_s > 0) {
    const long max_dur = lr.limits.max_duration_s;
    if (result.duration > max_dur) {
      result.warnings.push_back("Süre lisans limitine (" + std::to_string(max_dur) +
                                "s) düşürüldü. (İstenen: " + std::to_string(result.duration) + "s)");
      result.duration = max_dur;
    } else if (result.duration <= 0) {
      result.duration = max_dur;
    }
  }

  // 11. PPS limit.
  if (lr.limits.has_value && lr.limits.max_pps > 0) {
    const double max_pps = static_cast<double>(lr.limits.max_pps);
    if (result.rps <= 0.0 || result.rps > max_pps) {
      if (result.rps <= 0.0) {
        result.warnings.push_back(
            "Sınırsız (wire-speed) PPS Community planında desteklenmiyor. PPS lisans limitine (" +
            std::to_string(lr.limits.max_pps) + ") düşürüldü.");
      } else {
        result.warnings.push_back("PPS lisans limitine (" + std::to_string(lr.limits.max_pps) +
                                  ") düşürüldü. (İstenen: " + std::to_string(static_cast<long>(result.rps)) +
                                  ")");
      }
      result.rps = max_pps;
    }
  }

  // 12. Critical capabilities -> server-side execution grant.
  std::set<std::string> required_critical;
  if (compute_backend == "cuda") required_critical.insert(kFeatureGpuEngine);
  if (xdp_req) required_critical.insert(kFeatureAfXdp);
  if (custom_tcp_mode == "auto" || custom_tcp_mode == "required")
    required_critical.insert(kFeatureCustomTcp);
  if (in.ninja_mode) required_critical.insert(kFeatureNinjaMode);
  if (spoof_enabled) required_critical.insert(kFeatureSpoofing);
  if (attack_vector == "http2") {
    required_critical.insert(kFeatureL7Http2);
  } else if (attack_vector == "quic") {
    required_critical.insert(kFeatureL7Quic);
  } else if (attack_vector == "websocket") {
    required_critical.insert(kFeatureL7Websocket);
  } else if (attack_vector == "ntp-amp" || attack_vector == "ssdp-amp" || attack_vector == "dns-amp" ||
             attack_vector == "memcached-amp" || attack_vector == "ldap-amp") {
    required_critical.insert(kFeatureAmplification);
  }
  {
    std::set<std::string> filtered;
    for (const auto& f : required_critical) {
      if (CriticalFeatures().count(f)) filtered.insert(f);
    }
    required_critical.swap(filtered);
  }

  if (!required_critical.empty()) {
    if (!in.has_role) return result;  // no distributed role -> no grant required
    if (lr.offline) {
      return Fail(
          "Kritik yetenekler offline cache ile calistirilamaz. SaaS control-plane online dogrulama zorunludur.",
          "Internete cikis + lisans sunucusu erisimi saglayip tekrar deneyin.");
    }
    const std::string resolved_key = ResolveLicenseKey(in.license_key, in.license_file);
    if (resolved_key.empty()) {
      return Fail("Server-side execution grant icin lisans anahtari cozumlenemedi.",
                  "--license-key / --license-file / SAMURAI_LICENSE_KEY tanimlayin.");
    }
    if (grant == nullptr) {
      return Fail("Kritik yetenekler icin server-side execution grant alinamadi: client unavailable",
                  "SaaS control-plane ve abonelik durumunu kontrol edin.");
    }
    std::vector<std::string> req_features(required_critical.begin(), required_critical.end());
    const ExecGrantResult g = grant->RequestGrant(resolved_key, GetHardwareId(), lr.session_id,
                                                  attack_vector, compute_backend, in.role, req_features);
    if (!g.ok) {
      return Fail("Kritik yetenekler icin server-side execution grant alinamadi: " +
                      (g.reason.empty() ? "denied" : g.reason),
                  "SaaS control-plane ve abonelik durumunu kontrol edin.");
    }
    lr.exec_grant_token = g.grant_token;
    lr.exec_grant_expires = g.expires_at;
    if (lr.exec_grant_token.empty()) {
      return Fail("Server-side execution grant token bos dondu.",
                  "Lisans sunucusu execution grant endpointini kontrol edin.");
    }
    result.warnings.push_back("Kritik yetenekler server-side grant ile etkinlesti (expires=" +
                              (lr.exec_grant_expires.empty() ? "n/a" : lr.exec_grant_expires) + ").");
  }

  return result;
}

}  // namespace samurai::licensing
