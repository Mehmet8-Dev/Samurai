#pragma once

// Tiny argv helpers for the control daemons: "--flag value" options and
// "--flag" booleans. Not a full parser — just enough for the daemon entrypoints.

#include <string>

namespace samurai::control::daemon {

inline std::string Opt(int argc, char** argv, const char* flag, const std::string& def) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (flag == std::string(argv[i])) return argv[i + 1];
  }
  return def;
}

inline long OptInt(int argc, char** argv, const char* flag, long def) {
  const std::string v = Opt(argc, argv, flag, "");
  if (v.empty()) return def;
  try {
    return std::stol(v);
  } catch (...) {
    return def;
  }
}

inline bool Flag(int argc, char** argv, const char* flag) {
  for (int i = 1; i < argc; ++i) {
    if (flag == std::string(argv[i])) return true;
  }
  return false;
}

// True only when `ep` binds a loopback interface, i.e. traffic never leaves the
// host (safe to run plaintext behind a local TLS proxy / tunnel). A wildcard
// bind ("0.0.0.0", "*", "::", empty) or any routable address returns false —
// the caller treats those as "exposed" and requires encryption or an explicit
// override. Accepts "tcp://host:port", "host:port", "[v6]:port", or bare host.
inline bool IsLoopbackEndpoint(const std::string& ep) {
  std::string s = ep;
  const std::string scheme = "://";
  const auto sp = s.find(scheme);
  if (sp != std::string::npos) s = s.substr(sp + scheme.size());
  std::string host;
  if (!s.empty() && s.front() == '[') {          // [ipv6]:port
    const auto rb = s.find(']');
    host = (rb == std::string::npos) ? s.substr(1) : s.substr(1, rb - 1);
  } else {
    const auto colon = s.rfind(':');             // host:port (ipv4 / name)
    host = (colon == std::string::npos) ? s : s.substr(0, colon);
  }
  if (host == "localhost" || host == "::1") return true;
  return host.rfind("127.", 0) == 0;             // 127.0.0.0/8
}

}  // namespace samurai::control::daemon
