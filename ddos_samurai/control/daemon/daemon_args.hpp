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

}  // namespace samurai::control::daemon
