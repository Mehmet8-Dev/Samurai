#include "log.hpp"

#include <cstdio>
#include <ctime>
#include <string>

namespace samurai::core {

namespace {

// ANSI palette (RESET/DIM/WHITE/ACCENT).
constexpr const char* kReset = "\033[0m";
constexpr const char* kDim = "\033[90m";
constexpr const char* kWhite = "\033[37m";
constexpr const char* kAccent = "\033[97m";

std::string Upper(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return out;
}

// Common console form: "[<ts>] <glyph>  <msg>", timestamp dimmed, glyph+msg in
// `body_color`. Written to stdout to match the Python log_* behaviour.
void Emit(const char* glyph, const std::string& msg, const char* body_color) {
  const std::string ts = Timestamp();
  std::printf("%s[%s]%s %s%s%s  %s%s%s\n", kDim, ts.c_str(), kReset, kAccent,
              glyph, kReset, body_color, msg.c_str(), kReset);
}

}  // namespace

std::string Timestamp() {
  std::time_t now = std::time(nullptr);
  std::tm tm_buf{};
  localtime_r(&now, &tm_buf);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
  return std::string(buf);
}

void LogInfo(const std::string& msg, const std::string& protocol) {
  std::string line = msg;
  if (!protocol.empty()) {
    line += " [" + Upper(protocol) + "]";
  }
  Emit("●", line, kWhite);  // ● info
}

void LogWarning(const std::string& msg) {
  Emit("⚠", msg, kWhite);  // ⚠ warning
}

void LogError(const std::string& msg) {
  Emit("✗", msg, kAccent);  // ✗ error
}

void LogCritical(const std::string& msg) {
  Emit("▲", msg, kAccent);  // ▲ critical
}

}  // namespace samurai::core
