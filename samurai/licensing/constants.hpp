#pragma once

// License system configuration. Values resolve from the environment at call
// time (not load time).

#include <cstdlib>
#include <string>

#include "obfuscate.hpp"

namespace samurai::licensing {

inline std::string EnvOr(const std::string& key, const std::string& def) {
  const char* v = std::getenv(key.c_str());
  return (v && *v) ? std::string(v) : def;
}
inline long EnvInt(const std::string& key, long def) {
  const char* v = std::getenv(key.c_str());
  if (!v || !*v) return def;
  try {
    return std::stol(v);
  } catch (...) {
    return def;
  }
}

inline std::string LicenseServerUrl() {
  return EnvOr(SAMURAI_OBFUSCATE("SAMURAI_LICENSE_SERVER_URL"),
               SAMURAI_OBFUSCATE("https://license.samurai.local"));
}

inline std::string ApiVersion() { return SAMURAI_OBFUSCATE("v1"); }
inline std::string ValidateEndpoint() { return SAMURAI_OBFUSCATE("/api/v1/license/validate"); }
inline std::string HeartbeatEndpoint() { return SAMURAI_OBFUSCATE("/api/v1/license/heartbeat"); }
inline std::string DeactivateEndpoint() { return SAMURAI_OBFUSCATE("/api/v1/license/deactivate"); }
inline std::string ExecGrantEndpoint() { return SAMURAI_OBFUSCATE("/api/v1/license/exec-grant"); }

inline int RequestTimeoutS() {
  return static_cast<int>(EnvInt(SAMURAI_OBFUSCATE("SAMURAI_LICENSE_TIMEOUT_S"), 10));
}
inline int HeartbeatIntervalS() {
  return static_cast<int>(EnvInt(SAMURAI_OBFUSCATE("SAMURAI_LICENSE_HEARTBEAT_S"), 3600));
}
inline long OfflineGracePeriodS() {
  return EnvInt(SAMURAI_OBFUSCATE("SAMURAI_LICENSE_GRACE_HOURS"), 72) * 3600;
}

inline std::string CacheDir() {
  return EnvOr(SAMURAI_OBFUSCATE("HOME"), SAMURAI_OBFUSCATE("/root")) + "/.samurai";
}
inline std::string CacheFile() { return CacheDir() + "/license.cache"; }
inline std::string LicenseKeyFile() { return CacheDir() + "/license.key"; }

inline constexpr const char* kLicenseKeyPrefix = "SAM";
// ^SAM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$
inline constexpr const char* kLicenseKeyPattern =
    "^SAM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$";

inline bool IsDevMode() {
#if defined(NDEBUG)
  // In release builds, the dev-mode bypass is strictly disabled.
  return false;
#else
  std::string v = EnvOr(SAMURAI_OBFUSCATE("SAMURAI_LICENSE_DEV_MODE"), "0");
  for (char& c : v) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return v == "1" || v == "true" || v == "yes" || v == "on";
#endif
}

}  // namespace samurai::licensing
