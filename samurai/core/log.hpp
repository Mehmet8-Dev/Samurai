#pragma once

// Native logging helpers. Timestamped, ANSI-coloured (when stderr is a TTY)
// console lines written strictly to stderr so stdout remains clean for JSON/NDJSON
// reports and MCP stdio traffic.
//
// Respects `SAMURAI_LOG_LEVEL` (`quiet` | `error` | `warn` | `info`, default `info`).

#include <string>

namespace samurai::core {

enum class LogLevel {
  kQuiet = 0,
  kError = 1,
  kWarn = 2,
  kInfo = 3,
};

LogLevel CurrentLogLevel();

// "YYYY-MM-DD HH:MM:SS" in local time.
std::string Timestamp();

// Structured component logger: `[YYYY-MM-DD HH:MM:SS] [<component>] [<LEVEL>] <msg>`.
void LogTagged(const std::string& component, LogLevel level, const std::string& msg);

// Info line. `protocol`, when non-empty, is upper-cased and appended as " [PROTO]".
void LogInfo(const std::string& msg, const std::string& protocol = "");
void LogWarning(const std::string& msg);
void LogError(const std::string& msg);
void LogCritical(const std::string& msg);

}  // namespace samurai::core
