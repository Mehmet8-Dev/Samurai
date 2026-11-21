#pragma once

// Modular C++17 Model Context Protocol (MCP) JSON-RPC 2.0 engine.
// Implements MCP protocolVersion "2024-11-05" over stdio (newline-delimited JSON)
// with Tools, Resources (portable Skills & Worker playbooks), and Prompts using
// samurai_core's dependency-free JSON parser/serializer.

#include <functional>
#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::mcp {

inline constexpr const char* kServerName = "samurai-mcp";
inline constexpr const char* kServerVersion = "3.3.0";
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

struct ResourceSpec {
  std::string uri;
  std::string name;
  std::string description;
  std::string mime_type = "text/markdown";
  std::function<std::string()> reader;
};

struct PromptSpec {
  std::string name;
  std::string description;
  std::function<std::string(const samurai::core::json::Value& args)> renderer;
};

// Convenience builders for tool handlers.
ToolResult MakeToolSuccess(samurai::core::json::Value payload);
ToolResult MakeToolError(const std::string& message);

class McpServer {
 public:
  McpServer(std::string name = kServerName, std::string version = kServerVersion);

  void RegisterTool(ToolSpec spec);
  void RegisterResource(ResourceSpec spec);
  void RegisterPrompt(PromptSpec spec);

  // Dispatches a single JSON-RPC 2.0 request object. Returns std::nullopt for
  // notifications that require no response.
  std::optional<samurai::core::json::Value> HandleRequest(const samurai::core::json::Value& req) const;

  // Parses and dispatches a single raw JSON line.
  std::optional<std::string> HandleLine(const std::string& line) const;

  // Runs the newline-delimited JSON-RPC 2.0 loop over `in`/`out` until EOF.
  int RunStream(std::istream& in, std::ostream& out) const;

  std::size_t ToolCount() const { return tools_.size(); }
  std::size_t ResourceCount() const { return resources_.size(); }
  std::size_t PromptCount() const { return prompts_.size(); }

 private:
  std::string name_;
  std::string version_;
  std::vector<ToolSpec> tools_;
  std::vector<ResourceSpec> resources_;
  std::vector<PromptSpec> prompts_;
};

}  // namespace samurai::mcp
