#pragma once

// Modular C++17 Model Context Protocol (MCP) JSON-RPC 2.0 engine.
// Implements MCP protocolVersion "2024-11-05" over stdio (newline-delimited JSON)
// using samurai_core's dependency-free JSON parser/serializer.

#include <functional>
#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::mcp {

inline constexpr const char* kServerName = "samurai-mcp";
inline constexpr const char* kServerVersion = "3.0.0";
inline constexpr const char* kProtocolVersion = "2024-11-05";

struct ToolResult {
  samurai::core::json::Value payload;
  bool is_error = false;
};

using ToolHandler = std::function<ToolResult(const samurai::core::json::Value& args)>;

struct ToolSpec {
  std::string name;
  std::string description;
  samurai::core::json::Value input_schema;
  ToolHandler handler;
};

// Convenience builders for tool handlers.
ToolResult MakeToolSuccess(samurai::core::json::Value payload);
ToolResult MakeToolError(const std::string& message);

class McpServer {
 public:
  McpServer(std::string name = kServerName, std::string version = kServerVersion);

  void RegisterTool(ToolSpec spec);

  // Dispatches a single JSON-RPC 2.0 request object. Returns std::nullopt for
  // notifications that require no response.
  std::optional<samurai::core::json::Value> HandleRequest(const samurai::core::json::Value& req) const;

  // Parses and dispatches a single raw JSON line.
  std::optional<std::string> HandleLine(const std::string& line) const;

  // Runs the newline-delimited JSON-RPC 2.0 loop over `in`/`out` until EOF.
  int RunStream(std::istream& in, std::ostream& out) const;

  std::size_t ToolCount() const { return tools_.size(); }

 private:
  std::string name_;
  std::string version_;
  std::vector<ToolSpec> tools_;
};

}  // namespace samurai::mcp
