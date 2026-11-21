#include "protocol.hpp"

#include <cctype>
#include <utility>

namespace samurai::mcp {

namespace {

using samurai::core::json::Value;

std::string TrimWhitespace(const std::string& s) {
  std::size_t start = 0;
  while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
  std::size_t end = s.size();
  while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
  return s.substr(start, end - start);
}

Value MakeRpcResult(const Value* id, Value result) {
  Value resp = Value::Object();
  resp.set("jsonrpc", Value::Str("2.0"));
  resp.set("id", id ? *id : Value::Null());
  resp.set("result", std::move(result));
  return resp;
}

Value MakeRpcError(const Value* id, int code, const std::string& message) {
  Value err = Value::Object();
  err.set("code", Value::Int(code));
  err.set("message", Value::Str(message));

  Value resp = Value::Object();
  resp.set("jsonrpc", Value::Str("2.0"));
  resp.set("id", id ? *id : Value::Null());
  resp.set("error", std::move(err));
  return resp;
}

}  // namespace

ToolResult MakeToolSuccess(Value payload) {
  return ToolResult{std::move(payload), false};
}

ToolResult MakeToolError(const std::string& message) {
  Value obj = Value::Object();
  obj.set("error", Value::Str(message));
  return ToolResult{std::move(obj), true};
}

McpServer::McpServer(std::string name, std::string version)
    : name_(std::move(name)), version_(std::move(version)) {}

void McpServer::RegisterTool(ToolSpec spec) {
  tools_.push_back(std::move(spec));
}

std::optional<Value> McpServer::HandleRequest(const Value& req) const {
  if (!req.is_object()) {
    return MakeRpcError(nullptr, -32600, "Invalid Request: expected JSON object");
  }

  const Value* id = req.find("id");
  const Value* method_val = req.find("method");
  if (!method_val || !method_val->is_string()) {
    return MakeRpcError(id, -32600, "Invalid Request: missing string 'method'");
  }
  const std::string method = method_val->as_string();

  // Notifications carry no response per JSON-RPC 2.0 / MCP spec.
  if (method.rfind("notifications/", 0) == 0) {
    return std::nullopt;
  }

  if (method == "initialize") {
    Value caps = Value::Object();
    caps.set("tools", Value::Object());

    Value server_info = Value::Object();
    server_info.set("name", Value::Str(name_));
    server_info.set("version", Value::Str(version_));

    Value result = Value::Object();
    result.set("protocolVersion", Value::Str(kProtocolVersion));
    result.set("capabilities", std::move(caps));
    result.set("serverInfo", std::move(server_info));
    return MakeRpcResult(id, std::move(result));
  }

  if (method == "ping") {
    return MakeRpcResult(id, Value::Object());
  }

  if (method == "tools/list") {
    Value arr = Value::Array();
    for (const auto& t : tools_) {
      Value entry = Value::Object();
      entry.set("name", Value::Str(t.name));
      entry.set("description", Value::Str(t.description));
      entry.set("inputSchema", t.input_schema);
      arr.push_back(std::move(entry));
    }
    Value result = Value::Object();
    result.set("tools", std::move(arr));
    return MakeRpcResult(id, std::move(result));
  }

  if (method == "tools/call") {
    const Value* params = req.find("params");
    if (!params || !params->is_object()) {
      return MakeRpcError(id, -32602, "Invalid params: expected object");
    }
    const Value* name_val = params->find("name");
    if (!name_val || !name_val->is_string()) {
      return MakeRpcError(id, -32602, "Invalid params: missing tool 'name'");
    }
    const std::string tool_name = name_val->as_string();

    const Value empty_args = Value::Object();
    const Value* args_val = params->find("arguments");
    const Value& args = (args_val && args_val->is_object()) ? *args_val : empty_args;

    for (const auto& t : tools_) {
      if (t.name == tool_name) {
        const ToolResult tr = t.handler(args);
        Value content_item = Value::Object();
        content_item.set("type", Value::Str("text"));
        content_item.set("text", Value::Str(tr.payload.dump()));

        Value content = Value::Array();
        content.push_back(std::move(content_item));

        Value result = Value::Object();
        result.set("content", std::move(content));
        result.set("isError", Value::Bool(tr.is_error));
        return MakeRpcResult(id, std::move(result));
      }
    }
    return MakeRpcError(id, -32601, "Unknown tool: " + tool_name);
  }

  return MakeRpcError(id, -32601, "Method not found: " + method);
}

std::optional<std::string> McpServer::HandleLine(const std::string& line) const {
  const std::string trimmed = TrimWhitespace(line);
  if (trimmed.empty()) return std::nullopt;

  const auto parsed = samurai::core::json::Parse(trimmed);
  if (!parsed.ok) {
    return MakeRpcError(nullptr, -32700, "Parse error: " + parsed.error).dump();
  }
  const auto resp = HandleRequest(parsed.value);
  if (!resp.has_value()) return std::nullopt;
  return resp->dump();
}

int McpServer::RunStream(std::istream& in, std::ostream& out) const {
  std::string line;
  while (std::getline(in, line)) {
    const auto resp = HandleLine(line);
    if (resp.has_value()) {
      out << *resp << '\n';
      out.flush();
    }
  }
  return 0;
}

}  // namespace samurai::mcp
