#pragma once

// Native logging helpers — the log_* family. Timestamped, ANSI-coloured console
// lines (dim timestamp, accent glyph, message). Shared by the CLI, the
// orchestrator, and the control/licensing layers.

#include <string>

namespace samurai::core {

// "YYYY-MM-DD HH:MM:SS" in local time — mirrors utils.get_timestamp().
std::string Timestamp();

// Info line. `protocol`, when non-empty, is upper-cased and appended as
// " [PROTO]" — mirrors utils.log_info(msg, protocol=...).
void LogInfo(const std::string& msg, const std::string& protocol = "");
void LogWarning(const std::string& msg);
void LogError(const std::string& msg);
void LogCritical(const std::string& msg);

}  // namespace samurai::core
