// samurai_mcp — Pure native C++17 Model Context Protocol (MCP) stdio server.
//
// Zero Python runtime, zero third-party MCP SDKs. Speaks JSON-RPC 2.0 over
// stdin/stdout (protocolVersion: "2024-11-05") and exposes Samurai's native
// dataplane engines, RFC compliance suites, reproducible benchmarks, and
// Closed-Loop Autopilot / Mahoraga RL Agent controllers.

#include <cstdio>
#include <iostream>
#include <string>

#include "autopilot_tools.hpp"
#include "protocol.hpp"
#include "safety.hpp"
#include "tool_registry.hpp"

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      std::printf(
          "samurai_mcp %s — Pure C++17 MCP Server (protocolVersion: %s)\n"
          "\n"
          "Speaks newline-delimited JSON-RPC 2.0 over stdin/stdout for Claude Code,\n"
          "Cursor, Codex, Antigravity, and autonomous Autopilot / RL agents.\n"
          "\n"
          "Environment variables:\n"
          "  SAMURAI_BIN_DIR                    Directory containing samurai binaries\n"
          "  SAMURAI_MCP_ALLOW_TARGETS          Optional CSV allowlist of lab IPv4/CIDRs\n"
          "  SAMURAI_MCP_DENY_TARGETS           Optional CSV denylist (always wins)\n"
          "  SAMURAI_MCP_MAX_COUNT              Max packet/request count per tool call (default: 500000)\n"
          "  SAMURAI_MANAGEMENT_API_VIEWER_TOKEN Optional Bearer token for samurai_master :8089\n",
          samurai::mcp::kServerVersion,
          samurai::mcp::kProtocolVersion);
      return 0;
    }
    if (arg == "--version" || arg == "-v") {
      std::printf("%s %s (protocolVersion=%s)\n",
                  samurai::mcp::kServerName,
                  samurai::mcp::kServerVersion,
                  samurai::mcp::kProtocolVersion);
      return 0;
    }
  }

  std::ios::sync_with_stdio(false);
  std::cin.tie(nullptr);

  const samurai::mcp::SafetyConfig safety = samurai::mcp::LoadSafetyConfigFromEnv();
  samurai::mcp::AutopilotManager autopilot;
  samurai::mcp::McpServer server;
  samurai::mcp::RegisterAllTools(server, autopilot, safety);

  return server.RunStream(std::cin, std::cout);
}
