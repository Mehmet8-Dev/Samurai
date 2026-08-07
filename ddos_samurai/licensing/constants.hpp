#pragma once

// License system configuration — native C++ port of
// ddos_samurai/licensing/constants.py. Values resolve from the environment at
// call time (not load time), matching the Python getenv semantics.

#include <cstdlib>
#include <string>

namespace samurai::licensing {

inline std::string EnvOr(const char* key, const std::string& def) {
  const char* v = std::getenv(key);
  return (v && *v) ? std::string(v) : def;
}
inline long EnvInt(const char* key, long def) {
  const char* v = std::getenv(key);
  if (!v || !*v) return def;
  try {
    return std::stol(v);
  } catch (...) {
    return def;
  }
}

inline std::string LicenseServerUrl() {
  return EnvOr("SAMURAI_LICENSE_SERVER_URL", "https://license.ddosamurai.com");
}
inline constexpr const char* kApiVersion = "v1";
inline constexpr const char* kValidateEndpoint = "/api/v1/license/validate";
inline constexpr const char* kHeartbeatEndpoint = "/api/v1/license/heartbeat";
inline constexpr const char* kDeactivateEndpoint = "/api/v1/license/deactivate";
inline constexpr const char* kExecGrantEndpoint = "/api/v1/license/exec-grant";

inline int RequestTimeoutS() { return static_cast<int>(EnvInt("SAMURAI_LICENSE_TIMEOUT_S", 10)); }
inline int HeartbeatIntervalS() { return static_cast<int>(EnvInt("SAMURAI_LICENSE_HEARTBEAT_S", 3600)); }
inline long OfflineGracePeriodS() { return EnvInt("SAMURAI_LICENSE_GRACE_HOURS", 72) * 3600; }

inline std::string CacheDir() { return EnvOr("HOME", "/root") + "/.samurai"; }
inline std::string CacheFile() { return CacheDir() + "/license.cache"; }
inline std::string LicenseKeyFile() { return CacheDir() + "/license.key"; }

inline constexpr const char* kLicenseKeyPrefix = "SAM";
// ^SAM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$
inline constexpr const char* kLicenseKeyPattern =
    "^SAM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$";

inline bool IsDevMode() {
  std::string v = EnvOr("SAMURAI_LICENSE_DEV_MODE", "0");
  for (char& c : v) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return v == "1" || v == "true" || v == "yes" || v == "on";
}

}  // namespace samurai::licensing
