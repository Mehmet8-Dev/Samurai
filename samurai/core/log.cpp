#include "log.hpp"

#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

namespace samurai::core {

namespace {

constexpr const char* kReset = "\033[0m";
constexpr const char* kDim = "\033[90m";
constexpr const char* kWhite = "\033[37m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kRed = "\033[91m";
constexpr const char* kAccent = "\033[97m";

std::string Upper(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string Lower(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

bool StderrIsTty() {
  static const bool kIsTty = (::isatty(STDERR_FILENO) == 1);
  return kIsTty;
}

const char* LevelLabel(LogLevel level) {
  switch (level) {
    case LogLevel::kError:
      return "ERROR";
    case LogLevel::kWarn:
      return "WARN";
    case LogLevel::kInfo:
      return "INFO";
    case LogLevel::kQuiet:
    default:
      return "QUIET";
  }
}

const char* LevelColor(LogLevel level) {
  switch (level) {
    case LogLevel::kError:
      return kRed;
    case LogLevel::kWarn:
      return kYellow;
    case LogLevel::kInfo:
    default:
      return kAccent;
  }
}

void Emit(const char* glyph, LogLevel level, const std::string& msg, const char* body_color) {
  if (static_cast<int>(level) > static_cast<int>(CurrentLogLevel())) return;
  const std::string ts = Timestamp();
  if (StderrIsTty()) {
    std::fprintf(stderr, "%s[%s]%s %s%s%s  %s%s%s\n", kDim, ts.c_str(), kReset, kAccent,
                 glyph, kReset, body_color, msg.c_str(), kReset);
  } else {
    std::fprintf(stderr, "[%s] [%s] %s\n", ts.c_str(), LevelLabel(level), msg.c_str());
  }
}

}  // namespace

LogLevel CurrentLogLevel() {
  const char* raw = std::getenv("SAMURAI_LOG_LEVEL");
  if (!raw || raw[0] == '\0') return LogLevel::kInfo;
  const std::string v = Lower(raw);
  if (v == "quiet" || v == "silent" || v == "0") return LogLevel::kQuiet;
  if (v == "error" || v == "err" || v == "1") return LogLevel::kError;
  if (v == "warn" || v == "warning" || v == "2") return LogLevel::kWarn;
  return LogLevel::kInfo;
}

std::string Timestamp() {
  std::time_t now = std::time(nullptr);
  std::tm tm_buf{};
  localtime_r(&now, &tm_buf);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
  return std::string(buf);
}

void LogTagged(const std::string& component, LogLevel level, const std::string& msg) {
  if (static_cast<int>(level) > static_cast<int>(CurrentLogLevel())) return;
  const std::string ts = Timestamp();
  const char* lbl = LevelLabel(level);
  if (StderrIsTty()) {
    std::fprintf(stderr, "%s[%s]%s [%s] %s%-5s%s %s\n",
                 kDim, ts.c_str(), kReset,
                 component.c_str(),
                 LevelColor(level), lbl, kReset,
                 msg.c_str());
  } else {
    std::fprintf(stderr, "[%s] [%s] [%s] %s\n",
                 ts.c_str(), component.c_str(), lbl, msg.c_str());
  }
}

void LogInfo(const std::string& msg, const std::string& protocol) {
  std::string line = msg;
  if (!protocol.empty()) {
    line += " [" + Upper(protocol) + "]";
  }
  Emit("●", LogLevel::kInfo, line, kWhite);
}

void LogWarning(const std::string& msg) {
  Emit("⚠", LogLevel::kWarn, msg, kYellow);
}

void LogError(const std::string& msg) {
  Emit("✗", LogLevel::kError, msg, kRed);
}

void LogCritical(const std::string& msg) {
  Emit("▲", LogLevel::kError, msg, kRed);
}

}  // namespace samurai::core
