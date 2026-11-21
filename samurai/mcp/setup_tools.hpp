#pragma once

// Native C++17 MCP client diagnostics (`doctor`) and automated registration
// (`setup`) for Samurai (`samurai_mcp doctor|setup` and `samurai mcp doctor|setup`).
//
// Zero external dependencies; relies solely on samurai_core (JSON) + POSIX/std::filesystem.

#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::mcp {

struct DoctorOptions {
  std::string client;  // optional filter (e.g. "claude_code", "cursor", "codex", ...)
  bool json = false;
  std::string home_override;     // optional HOME override (for testing)
  std::string project_override;  // optional project root override (for testing)
};

struct SetupOptions {
  std::string client;            // required: client ID
  std::string scope = "user";    // "user" or "project"
  std::string image = "ghcr.io/mehmet8-dev/samurai:latest";
  bool docker = false;
  bool npx = false;
  bool dry_run = false;
  bool yes = false;
  bool json = false;
  std::string binary_override;   // optional samurai_mcp path override
  std::string home_override;     // optional HOME override (for testing)
  std::string project_override;  // optional project root override (for testing)
};

const std::vector<std::string>& SupportedClients();

// Normalize user-supplied client aliases (e.g. "claude-code" -> "claude_code").
std::string NormalizeClientId(const std::string& raw);

// Run non-mutating diagnostics on native binaries, skills, Docker, and client configs.
samurai::core::json::Value BuildDoctorReport(const DoctorOptions& opts);
int RunDoctorCli(int argc, char** argv);

// Plan or apply MCP server registration for a target AI client.
// Never mutates files unless `opts.yes && !opts.dry_run`.
struct SetupResult {
  bool ok = false;
  int exit_code = 0;
  samurai::core::json::Value report;
};
SetupResult ExecuteSetup(const SetupOptions& opts);
int RunSetupCli(int argc, char** argv);

}  // namespace samurai::mcp
