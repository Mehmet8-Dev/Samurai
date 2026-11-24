#include "setup_tools.hpp"

#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace samurai::mcp {

namespace {

namespace fs = std::filesystem;
using samurai::core::json::Parse;
using samurai::core::json::Value;

enum class ConfigFormat { kJsonMcpServers, kJsonServersStdio, kJsonOpencode, kTomlCodex };

struct ClientSpec {
  const char* id;
  const char* display_name;
  ConfigFormat format;
  bool supports_project_scope;
};

constexpr ClientSpec kClients[] = {
    {"claude_code", "Claude Code", ConfigFormat::kJsonMcpServers, true},
    {"claude_desktop", "Claude Desktop", ConfigFormat::kJsonMcpServers, false},
    {"cursor", "Cursor", ConfigFormat::kJsonMcpServers, true},
    {"codex", "Codex CLI", ConfigFormat::kTomlCodex, false},
    {"gemini_cli", "Gemini CLI", ConfigFormat::kJsonMcpServers, true},
    {"antigravity", "Antigravity", ConfigFormat::kJsonMcpServers, false},
    {"windsurf", "Windsurf", ConfigFormat::kJsonMcpServers, false},
    {"vscode", "VS Code", ConfigFormat::kJsonServersStdio, true},
    {"opencode", "OpenCode", ConfigFormat::kJsonOpencode, true},
    {"copilot_cli", "GitHub Copilot CLI", ConfigFormat::kJsonMcpServers, false},
};

const ClientSpec* FindClient(const std::string& normalized_id) {
  for (const auto& c : kClients) {
    if (normalized_id == c.id) return &c;
  }
  return nullptr;
}

std::string HomeDir(const std::string& override_home) {
  if (!override_home.empty()) return override_home;
  const char* h = std::getenv("HOME");
  return (h && h[0] != '\0') ? std::string(h) : ".";
}

std::string ProjectDir(const std::string& override_proj) {
  if (!override_proj.empty()) return override_proj;
  std::error_code ec;
  const fs::path cwd = fs::current_path(ec);
  return ec ? "." : cwd.string();
}

std::string SelfExeDir() {
  char buf[4096] = {0};
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return "";
  std::string p(buf, static_cast<std::size_t>(n));
  const auto slash = p.find_last_of('/');
  return slash == std::string::npos ? "" : p.substr(0, slash);
}

bool IsExecutable(const std::string& path) {
  return !path.empty() && ::access(path.c_str(), X_OK) == 0;
}

std::string FindInPath(const std::string& name) {
  const char* env_path = std::getenv("PATH");
  if (!env_path) return "";
  std::stringstream ss(env_path);
  std::string dir;
  while (std::getline(ss, dir, ':')) {
    if (dir.empty()) continue;
    const std::string cand = dir + "/" + name;
    if (IsExecutable(cand)) return cand;
  }
  return "";
}

std::string LocateBinary(const std::vector<std::string>& names) {
  const std::string self = SelfExeDir();
  const char* bin_env = std::getenv("SAMURAI_BIN_DIR");
  const std::string proj = ProjectDir("");

  std::vector<std::string> search_dirs;
  if (bin_env && bin_env[0] != '\0') search_dirs.emplace_back(bin_env);
  if (!self.empty()) {
    search_dirs.push_back(self);
    search_dirs.push_back(self + "/../mcp");
    search_dirs.push_back(self + "/../cli");
    search_dirs.push_back(self + "/../zmq");
    search_dirs.push_back(self + "/../control/daemon");
    search_dirs.push_back(self + "/../l4");
  }
  search_dirs.push_back(proj + "/build/mcp");
  search_dirs.push_back(proj + "/build/cli");
  search_dirs.push_back(proj + "/build/zmq");
  search_dirs.push_back(proj + "/build/control/daemon");
  search_dirs.push_back(proj + "/build/l4");
  search_dirs.emplace_back("/usr/local/bin");

  for (const auto& name : names) {
    for (const auto& dir : search_dirs) {
      const std::string cand = dir + "/" + name;
      if (IsExecutable(cand)) {
        std::error_code ec;
        const fs::path canonical = fs::weakly_canonical(cand, ec);
        return ec ? cand : canonical.string();
      }
    }
    const std::string in_path = FindInPath(name);
    if (!in_path.empty()) return in_path;
  }
  return "";
}

std::string LocateSkillsDir() {
  const std::string self = SelfExeDir();
  const std::string proj = ProjectDir("");
  std::vector<std::string> cands = {
      proj + "/skills",
      "/usr/local/share/samurai/skills",
  };
  if (!self.empty()) {
    cands.push_back(self + "/../skills");
    cands.push_back(self + "/../../skills");
    cands.push_back(self + "/../share/samurai/skills");
  }
  for (const auto& c : cands) {
    std::error_code ec;
    if (fs::is_directory(c, ec) && fs::exists(c + "/samurai-netbench/SKILL.md", ec)) {
      const fs::path canonical = fs::weakly_canonical(c, ec);
      return ec ? c : canonical.string();
    }
  }
  return "";
}

std::string NormalizeHostOs(const std::string& raw) {
  std::string s;
  s.reserve(raw.size());
  for (char c : raw) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  if (s == "win" || s == "win32" || s == "windows") return "windows";
  if (s == "mac" || s == "macos" || s == "darwin") return "macos";
  if (s == "linux") return "linux";
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#else
  return "linux";
#endif
}

std::string AppDataDir(const std::string& override_appdata, const std::string& home) {
  if (!override_appdata.empty()) return override_appdata;
  if (const char* a = std::getenv("APPDATA"); a && a[0] != '\0') return std::string(a);
  return home + "/AppData/Roaming";
}

std::string ResolveClientConfigPath(const ClientSpec& spec,
                                    const std::string& scope,
                                    const std::string& home,
                                    const std::string& project,
                                    const std::string& host_os = "",
                                    const std::string& appdata_override = "") {
  const std::string os_kind = NormalizeHostOs(host_os);
  const std::string id = spec.id;
  if (scope == "project" && spec.supports_project_scope) {
    if (id == "claude_code") return project + "/.mcp.json";
    if (id == "cursor") return project + "/.cursor/mcp.json";
    if (id == "gemini_cli") return project + "/.gemini/settings.json";
    if (id == "vscode") return project + "/.vscode/mcp.json";
    if (id == "opencode") return project + "/opencode.json";
  }

  if (id == "claude_code") return home + "/.claude.json";
  if (id == "claude_desktop") {
    if (os_kind == "windows") {
      return AppDataDir(appdata_override, home) + "/Claude/claude_desktop_config.json";
    }
    if (os_kind == "macos") {
      return home + "/Library/Application Support/Claude/claude_desktop_config.json";
    }
    return home + "/.config/Claude/claude_desktop_config.json";
  }
  if (id == "cursor") return home + "/.cursor/mcp.json";
  if (id == "codex") return home + "/.codex/config.toml";
  if (id == "gemini_cli") return home + "/.gemini/settings.json";
  if (id == "antigravity") return home + "/.gemini/antigravity/mcp_config.json";
  if (id == "windsurf") return home + "/.codeium/windsurf/mcp_config.json";
  if (id == "vscode") {
    if (os_kind == "windows") {
      return AppDataDir(appdata_override, home) + "/Code/User/mcp.json";
    }
    if (os_kind == "macos") {
      return home + "/Library/Application Support/Code/User/mcp.json";
    }
    return home + "/.config/Code/User/mcp.json";
  }
  if (id == "opencode") return home + "/.config/opencode/opencode.json";
  if (id == "copilot_cli") return home + "/.copilot/mcp-config.json";
  return "";
}

bool ReadFileText(const std::string& path, std::string& out) {
  std::ifstream in(path);
  if (!in.is_open()) return false;
  std::ostringstream oss;
  oss << in.rdbuf();
  out = oss.str();
  return true;
}

bool WriteFileText(const std::string& path, const std::string& content, std::string& err) {
  std::error_code ec;
  const fs::path p(path);
  if (p.has_parent_path()) {
    fs::create_directories(p.parent_path(), ec);
    if (ec) {
      err = "Failed to create parent directory: " + ec.message();
      return false;
    }
  }
  std::ofstream out(path, std::ios::trunc);
  if (!out.is_open()) {
    err = "Failed to open config file for writing: " + path;
    return false;
  }
  out << content;
  if (!out.good()) {
    err = "Failed while writing config file: " + path;
    return false;
  }
  return true;
}

// Pretty-print a samurai::core::json::Value with 2-space indentation for clean config diffs.
void DumpPrettyImpl(const Value& v, int indent, std::string& out) {
  const std::string pad(static_cast<std::size_t>(indent), ' ');
  const std::string pad_inner(static_cast<std::size_t>(indent + 2), ' ');
  switch (v.type()) {
    case Value::Type::Array: {
      const auto& elems = v.elements();
      if (elems.empty()) {
        out += "[]";
        return;
      }
      out += "[\n";
      for (std::size_t i = 0; i < elems.size(); ++i) {
        out += pad_inner;
        DumpPrettyImpl(elems[i], indent + 2, out);
        if (i + 1 < elems.size()) out += ",";
        out += "\n";
      }
      out += pad + "]";
      return;
    }
    case Value::Type::Object: {
      const auto& members = v.members();
      if (members.empty()) {
        out += "{}";
        return;
      }
      out += "{\n";
      for (std::size_t i = 0; i < members.size(); ++i) {
        out += pad_inner + Value::Str(members[i].first).dump() + ": ";
        DumpPrettyImpl(members[i].second, indent + 2, out);
        if (i + 1 < members.size()) out += ",";
        out += "\n";
      }
      out += pad + "}";
      return;
    }
    default:
      out += v.dump();
      return;
  }
}

std::string DumpPretty(const Value& v) {
  std::string out;
  DumpPrettyImpl(v, 0, out);
  out.push_back('\n');
  return out;
}

const char* JsonContainerKey(ConfigFormat fmt) {
  switch (fmt) {
    case ConfigFormat::kJsonServersStdio:
      return "servers";
    case ConfigFormat::kJsonOpencode:
      return "mcp";
    case ConfigFormat::kJsonMcpServers:
    default:
      return "mcpServers";
  }
}

Value BuildServerEntry(ConfigFormat fmt,
                       const std::string& command,
                       const std::vector<std::string>& args) {
  Value entry = Value::Object();
  if (fmt == ConfigFormat::kJsonOpencode) {
    entry.set("type", Value::Str("local"));
    Value cmd_arr = Value::Array();
    cmd_arr.push_back(Value::Str(command));
    for (const auto& a : args) cmd_arr.push_back(Value::Str(a));
    entry.set("command", std::move(cmd_arr));
    entry.set("enabled", Value::Bool(true));
    return entry;
  }
  if (fmt == ConfigFormat::kJsonServersStdio) {
    entry.set("type", Value::Str("stdio"));
  }
  entry.set("command", Value::Str(command));
  Value args_arr = Value::Array();
  for (const auto& a : args) args_arr.push_back(Value::Str(a));
  entry.set("args", std::move(args_arr));
  return entry;
}

std::string TomlQuote(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else out.push_back(c);
  }
  out.push_back('"');
  return out;
}

std::string BuildCodexTomlBlock(const std::string& command,
                                const std::vector<std::string>& args) {
  std::ostringstream oss;
  oss << "[mcp_servers.samurai]\n";
  oss << "command = " << TomlQuote(command) << "\n";
  oss << "args = [";
  for (std::size_t i = 0; i < args.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << TomlQuote(args[i]);
  }
  oss << "]\n";
  return oss.str();
}

std::string UpsertCodexToml(const std::string& existing, const std::string& new_block) {
  const std::string header = "[mcp_servers.samurai]";
  std::istringstream iss(existing);
  std::ostringstream out;
  std::string line;
  bool skipping = false;
  bool replaced = false;

  while (std::getline(iss, line)) {
    std::string trimmed = line;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r"));
    if (!trimmed.empty() && trimmed.front() == '[') {
      if (skipping) skipping = false;
      if (trimmed.rfind(header, 0) == 0 &&
          (trimmed.size() == header.size() || trimmed[header.size()] == ' ' ||
           trimmed[header.size()] == '\t' || trimmed[header.size()] == '\r')) {
        skipping = true;
        replaced = true;
        out << new_block;
        continue;
      }
    }
    if (!skipping) {
      out << line << "\n";
    }
  }

  if (!replaced) {
    std::string result = out.str();
    if (!result.empty() && result.back() != '\n') result.push_back('\n');
    if (!result.empty()) result.push_back('\n');
    result += new_block;
    return result;
  }
  return out.str();
}

bool HasCodexSamuraiSection(const std::string& content) {
  std::istringstream iss(content);
  std::string line;
  while (std::getline(iss, line)) {
    const auto pos = line.find_first_not_of(" \t\r");
    if (pos == std::string::npos) continue;
    const std::string trimmed = line.substr(pos);
    if (trimmed.rfind("[mcp_servers.samurai]", 0) == 0) return true;
  }
  return false;
}

Value InspectClientRegistration(const ClientSpec& spec,
                                const std::string& home,
                                const std::string& project,
                                const std::string& host_os = "",
                                const std::string& appdata_override = "") {
  Value obj = Value::Object();
  obj.set("client", Value::Str(spec.id));
  obj.set("display_name", Value::Str(spec.display_name));

  const std::string path =
      ResolveClientConfigPath(spec, "user", home, project, host_os, appdata_override);
  obj.set("config_path", Value::Str(path));

  std::error_code ec;
  const bool exists = fs::exists(path, ec);
  obj.set("config_exists", Value::Bool(exists));

  bool registered = false;
  std::string configured_cmd;
  bool parse_ok = true;

  if (exists) {
    std::string text;
    if (ReadFileText(path, text)) {
      if (spec.format == ConfigFormat::kTomlCodex) {
        registered = HasCodexSamuraiSection(text);
      } else if (!text.empty()) {
        const auto parsed = Parse(text);
        if (!parsed.ok || !parsed.value.is_object()) {
          parse_ok = false;
        } else {
          const Value* container = parsed.value.find(JsonContainerKey(spec.format));
          if (container && container->is_object()) {
            const Value* entry = container->find("samurai");
            if (entry && entry->is_object()) {
              registered = true;
              const Value* cmd = entry->find("command");
              if (cmd && cmd->is_string()) {
                configured_cmd = cmd->as_string();
              } else if (cmd && cmd->is_array() && !cmd->elements().empty()) {
                configured_cmd = cmd->elements()[0].as_string();
              }
            }
          }
        }
      }
    }
  }

  obj.set("config_valid", Value::Bool(parse_ok));
  obj.set("registered", Value::Bool(registered));
  if (!configured_cmd.empty()) {
    obj.set("configured_command", Value::Str(configured_cmd));
    const bool cmd_ok = (configured_cmd == "docker" && !FindInPath("docker").empty()) ||
                        IsExecutable(configured_cmd) ||
                        !FindInPath(configured_cmd).empty();
    obj.set("command_executable", Value::Bool(cmd_ok));
  }
  return obj;
}

void PrintSetupUsage() {
  std::printf(
      "Usage:\n"
      "  samurai_mcp doctor [--client <id>] [--host-os <linux|macos|windows>] [--json]\n"
      "  samurai_mcp setup --client <id> [--yes] [--docker | --npx] [--ghcr] [--image <ref>] [--host-os <linux|macos|windows>] [--scope user|project] [--json]\n"
      "\n"
      "Supported --client IDs:\n"
      "  claude_code, claude_desktop, cursor, codex, gemini_cli,\n"
      "  antigravity, windsurf, vscode, opencode, copilot_cli\n");
}

}  // namespace

const std::vector<std::string>& SupportedClients() {
  static const std::vector<std::string> kIds = {
      "claude_code", "claude_desktop", "cursor",   "codex",    "gemini_cli",
      "antigravity", "windsurf",       "vscode",   "opencode", "copilot_cli",
  };
  return kIds;
}

std::string NormalizeClientId(const std::string& raw) {
  std::string s;
  s.reserve(raw.size());
  for (char c : raw) {
    if (c == '-') {
      s.push_back('_');
    } else {
      s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
  }
  if (s == "claude") return "claude_code";
  if (s == "gemini") return "gemini_cli";
  if (s == "copilot") return "copilot_cli";
  if (s == "vs_code") return "vscode";
  return s;
}

Value BuildDoctorReport(const DoctorOptions& opts) {
  const std::string home = HomeDir(opts.home_override);
  const std::string project = ProjectDir(opts.project_override);

  Value root = Value::Object();
  root.set("host_os", Value::Str(NormalizeHostOs(opts.host_os)));
  root.set("platform", Value::Str(
#if defined(__APPLE__)
                           "darwin"
#elif defined(__linux__)
                           "linux"
#else
                           "other"
#endif
                           ));

  Value binaries = Value::Object();
  const char* core_bins[] = {"samurai_mcp", "samurai", "samurai_master", "samurai_slave"};
  for (const char* b : core_bins) {
    const std::string path = LocateBinary({b});
    Value info = Value::Object();
    info.set("available", Value::Bool(!path.empty()));
    if (!path.empty()) info.set("path", Value::Str(path));
    binaries.set(b, std::move(info));
  }
  root.set("core_binaries", std::move(binaries));

  Value workers = Value::Object();
  const char* worker_names[] = {"cpu",  "afpacket", "afxdp",   "dpdk",  "gpu",
                                "doca", "l7",       "scenario", "telco", "defense"};
  int workers_available = 0;
  for (const char* w : worker_names) {
    const std::string bin_name = std::string("samurai_") + w + "_worker";
    const std::string path = LocateBinary({bin_name});
    if (!path.empty()) ++workers_available;
    Value info = Value::Object();
    info.set("available", Value::Bool(!path.empty()));
    if (!path.empty()) info.set("path", Value::Str(path));
    workers.set(w, std::move(info));
  }
  root.set("workers_available_count", Value::Int(workers_available));
  root.set("workers", std::move(workers));

  const std::string docker_path = FindInPath("docker");
  Value prereqs = Value::Object();
  prereqs.set("docker_available", Value::Bool(!docker_path.empty()));
  if (!docker_path.empty()) prereqs.set("docker_path", Value::Str(docker_path));
  const std::string skills_dir = LocateSkillsDir();
  prereqs.set("skills_available", Value::Bool(!skills_dir.empty()));
  if (!skills_dir.empty()) prereqs.set("skills_dir", Value::Str(skills_dir));
  const std::string cmake_path = FindInPath("cmake");
  const std::string cxx_path = !FindInPath("g++").empty() ? FindInPath("g++") : FindInPath("clang++");
  prereqs.set("cmake_available", Value::Bool(!cmake_path.empty()));
  prereqs.set("cxx_available", Value::Bool(!cxx_path.empty()));
  root.set("prerequisites", std::move(prereqs));

  Value hw = Value::Object();
  utsname uts{};
  if (::uname(&uts) == 0) {
    hw.set("arch", Value::Str(uts.machine));
  }
  hw.set("logical_cores", Value::Int(static_cast<std::int64_t>(std::thread::hardware_concurrency())));

  std::string cpu_model;
  bool has_avx2 = false;
  bool has_avx512 = false;
  bool has_aes = false;
  {
    std::string cpuinfo;
    if (ReadFileText("/proc/cpuinfo", cpuinfo)) {
      std::istringstream cis(cpuinfo);
      std::string line;
      while (std::getline(cis, line)) {
        if (cpu_model.empty() && line.rfind("model name", 0) == 0) {
          const auto colon = line.find(':');
          if (colon != std::string::npos) {
            cpu_model = line.substr(colon + 1);
            cpu_model.erase(0, cpu_model.find_first_not_of(" \t"));
          }
        }
        if (line.rfind("flags", 0) == 0 || line.rfind("Features", 0) == 0) {
          if (line.find("avx2") != std::string::npos) has_avx2 = true;
          if (line.find("avx512f") != std::string::npos) has_avx512 = true;
          if (line.find(" aes") != std::string::npos || line.find(": aes") != std::string::npos) has_aes = true;
          break;
        }
      }
    }
  }
  if (!cpu_model.empty()) hw.set("cpu_model", Value::Str(cpu_model));
  hw.set("avx2", Value::Bool(has_avx2));
  hw.set("avx512", Value::Bool(has_avx512));
  hw.set("aes_ni", Value::Bool(has_aes));

  std::error_code hw_ec;
  const bool has_cuda_gpu = fs::exists("/dev/nvidia0", hw_ec);
  const std::string nvcc_path = !FindInPath("nvcc").empty()
                                    ? FindInPath("nvcc")
                                    : (IsExecutable("/usr/local/cuda/bin/nvcc") ? "/usr/local/cuda/bin/nvcc" : "");
  const bool has_io_uring = fs::exists("/usr/include/linux/io_uring.h", hw_ec) ||
                            fs::exists("/usr/include/x86_64-linux-gnu/linux/io_uring.h", hw_ec);
  const bool has_af_xdp = fs::exists("/usr/include/bpf/bpf.h", hw_ec) ||
                          fs::exists("/usr/include/xdp/xsk.h", hw_ec);
  const bool has_dpdk = fs::exists("/usr/include/rte_eal.h", hw_ec) ||
                        fs::exists("/usr/include/dpdk/rte_config.h", hw_ec);
  const bool has_doca = fs::exists("/opt/mellanox/doca", hw_ec);
  const std::string self_dir = SelfExeDir();
  const bool running_host_native =
      self_dir.find("-native/") != std::string::npos ||
      self_dir.find("/build/") != std::string::npos;

  hw.set("cuda_gpu_present", Value::Bool(has_cuda_gpu));
  hw.set("cuda_nvcc_available", Value::Bool(!nvcc_path.empty()));
  hw.set("io_uring_headers", Value::Bool(has_io_uring));
  hw.set("af_xdp_headers", Value::Bool(has_af_xdp));
  hw.set("dpdk_headers", Value::Bool(has_dpdk));
  hw.set("doca_sdk_present", Value::Bool(has_doca));
  hw.set("running_host_native_build", Value::Bool(running_host_native));
  const bool native_rec = !running_host_native && (has_cuda_gpu || !nvcc_path.empty() || has_dpdk || has_doca || has_avx512);
  hw.set("native_build_recommended", Value::Bool(native_rec));
  if (native_rec) {
    hw.set("native_build_command", Value::Str("npx -y samurai-net build"));
  }
  root.set("host_hardware", std::move(hw));

  Value clients = Value::Array();
  const std::string norm_filter = opts.client.empty() ? "" : NormalizeClientId(opts.client);
  bool filter_matched = norm_filter.empty();
  for (const auto& c : kClients) {
    if (!norm_filter.empty() && norm_filter != c.id) continue;
    filter_matched = true;
    clients.push_back(InspectClientRegistration(c, home, project, opts.host_os, opts.appdata_override));
  }
  if (!filter_matched) {
    root.set("client_filter_error", Value::Str("Unknown client ID: " + opts.client));
  }
  root.set("clients", std::move(clients));
  root.set("supported_clients", [&]() {
    Value arr = Value::Array();
    for (const auto& id : SupportedClients()) arr.push_back(Value::Str(id));
    return arr;
  }());

  const bool ready = !LocateBinary({"samurai_mcp"}).empty() || !docker_path.empty();
  root.set("ready", Value::Bool(ready && filter_matched));
  return root;
}

SetupResult ExecuteSetup(const SetupOptions& opts) {
  SetupResult res;
  const std::string norm_id = NormalizeClientId(opts.client);
  const ClientSpec* spec = FindClient(norm_id);
  if (!spec) {
    Value err = Value::Object();
    err.set("ok", Value::Bool(false));
    err.set("error", Value::Str("Unsupported --client: '" + opts.client + "'"));
    Value supported = Value::Array();
    for (const auto& id : SupportedClients()) supported.push_back(Value::Str(id));
    err.set("supported_clients", std::move(supported));
    res.exit_code = 2;
    res.report = std::move(err);
    return res;
  }

  if (opts.scope != "user" && opts.scope != "project") {
    Value err = Value::Object();
    err.set("ok", Value::Bool(false));
    err.set("error", Value::Str("Invalid --scope (expected 'user' or 'project'): " + opts.scope));
    res.exit_code = 2;
    res.report = std::move(err);
    return res;
  }

  if (opts.scope == "project" && !spec->supports_project_scope) {
    Value err = Value::Object();
    err.set("ok", Value::Bool(false));
    err.set("error", Value::Str("Client '" + std::string(spec->id) + "' does not support --scope project."));
    res.exit_code = 2;
    res.report = std::move(err);
    return res;
  }

  if (opts.docker && opts.npx) {
    Value err = Value::Object();
    err.set("ok", Value::Bool(false));
    err.set("error", Value::Str("Cannot combine --docker and --npx; choose one transport mode."));
    res.exit_code = 2;
    res.report = std::move(err);
    return res;
  }

  const std::string host_os = NormalizeHostOs(opts.host_os);
  const std::string home = HomeDir(opts.home_override);
  const std::string project = ProjectDir(opts.project_override);
  const std::string config_path =
      ResolveClientConfigPath(*spec, opts.scope, home, project, host_os, opts.appdata_override);
  const std::string backup_path = config_path + ".bak";

  std::string mcp_bin = opts.binary_override.empty() ? LocateBinary({"samurai_mcp"}) : opts.binary_override;
  const bool use_npx = opts.npx;
  const bool use_docker = !use_npx && (opts.docker || host_os != "linux" || mcp_bin.empty());

  std::string command;
  std::vector<std::string> args;
  if (use_npx) {
    command = (host_os == "windows") ? "npx.cmd" : "npx";
    args = {"-y", "-p", "samurai-net", "samurai-mcp"};
  } else if (use_docker) {
    command = "docker";
    args = {"run", "-i", "--rm", "-v", "samurai-build-cache:/var/cache/samurai"};
    if (host_os == "linux") {
      args.emplace_back("--network");
      args.emplace_back("host");
    } else {
      args.emplace_back("--add-host");
      args.emplace_back("host.docker.internal:host-gateway");
    }
    args.push_back(opts.image);
    args.emplace_back("samurai_mcp");
  } else {
    command = mcp_bin;
  }

  std::error_code ec;
  const bool exists = fs::exists(config_path, ec);
  std::string existing_text;
  if (exists && !ReadFileText(config_path, existing_text)) {
    Value err = Value::Object();
    err.set("ok", Value::Bool(false));
    err.set("error", Value::Str("Failed to read existing config: " + config_path));
    res.exit_code = 1;
    res.report = std::move(err);
    return res;
  }

  std::string new_content;
  Value proposed_entry = Value::Null();
  if (spec->format == ConfigFormat::kTomlCodex) {
    const std::string block = BuildCodexTomlBlock(command, args);
    new_content = UpsertCodexToml(existing_text, block);
    proposed_entry = Value::Str(block);
  } else {
    Value doc = Value::Object();
    if (exists && !existing_text.empty()) {
      const auto parsed = Parse(existing_text);
      if (!parsed.ok || !parsed.value.is_object()) {
        Value err = Value::Object();
        err.set("ok", Value::Bool(false));
        err.set("error", Value::Str("Existing config is not valid JSON (refusing to overwrite): " + config_path));
        res.exit_code = 2;
        res.report = std::move(err);
        return res;
      }
      doc = parsed.value;
    }
    const char* container_key = JsonContainerKey(spec->format);
    const Value* existing_container = doc.find(container_key);
    Value container = (existing_container && existing_container->is_object())
                          ? *existing_container
                          : Value::Object();
    proposed_entry = BuildServerEntry(spec->format, command, args);
    container.set("samurai", proposed_entry);
    doc.set(container_key, std::move(container));
    new_content = DumpPretty(doc);
  }

  const bool apply = opts.yes;
  bool backed_up = false;
  if (apply) {
    if (exists) {
      std::string backup_err;
      if (!WriteFileText(backup_path, existing_text, backup_err)) {
        Value err = Value::Object();
        err.set("ok", Value::Bool(false));
        err.set("error", Value::Str("Backup failed: " + backup_err));
        res.exit_code = 1;
        res.report = std::move(err);
        return res;
      }
      backed_up = true;
    }
    std::string write_err;
    if (!WriteFileText(config_path, new_content, write_err)) {
      Value err = Value::Object();
      err.set("ok", Value::Bool(false));
      err.set("error", Value::Str(write_err));
      res.exit_code = 1;
      res.report = std::move(err);
      return res;
    }
  }

  Value out = Value::Object();
  out.set("ok", Value::Bool(true));
  out.set("applied", Value::Bool(apply));
  out.set("host_os", Value::Str(host_os));
  out.set("client", Value::Str(spec->id));
  out.set("display_name", Value::Str(spec->display_name));
  out.set("scope", Value::Str(opts.scope));
  out.set("transport_mode", Value::Str(use_npx ? "npx" : (use_docker ? "docker" : "native")));
  out.set("config_path", Value::Str(config_path));
  out.set("config_existed", Value::Bool(exists));
  out.set("backup_path", Value::Str(exists ? backup_path : ""));
  out.set("backup_created", Value::Bool(backed_up));
  out.set("proposed_entry", std::move(proposed_entry));
  const std::string skills_dir = LocateSkillsDir();
  if (!skills_dir.empty()) out.set("skills_dir", Value::Str(skills_dir));
  out.set("next_step", Value::Str(apply
                                      ? "Restart or reconnect " + std::string(spec->display_name) +
                                            " so the samurai MCP tools become active."
                                      : "Re-run with --yes to write the proposed configuration."));
  res.ok = true;
  res.exit_code = 0;
  res.report = std::move(out);
  return res;
}

int RunDoctorCli(int argc, char** argv) {
  DoctorOptions opts;
  for (int i = 0; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      PrintSetupUsage();
      return 0;
    } else if (a == "--json") {
      opts.json = true;
    } else if (a == "--client") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai: missing value for --client\n");
        return 2;
      }
      opts.client = argv[++i];
    } else if (a == "--host-os") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai: missing value for --host-os\n");
        return 2;
      }
      opts.host_os = argv[++i];
    } else {
      std::fprintf(stderr, "samurai doctor: unknown option '%s'\n", a.c_str());
      return 2;
    }
  }

  const Value report = BuildDoctorReport(opts);
  if (opts.json) {
    std::printf("%s\n", report.dump().c_str());
  } else {
    std::printf("Samurai MCP Doctor (%s)\n", report.find("platform")->as_string().c_str());
    if (const Value* err = report.find("client_filter_error")) {
      std::fprintf(stderr, "error: %s\n", err->as_string().c_str());
      return 2;
    }
    const Value* bins = report.find("core_binaries");
    if (bins) {
      std::printf("\nCore Binaries:\n");
      for (const auto& kv : bins->members()) {
        const bool avail = kv.second.find("available")->as_bool(false);
        const std::string path = kv.second.find("path") ? kv.second.find("path")->as_string() : "not found";
        std::printf("  %-16s [%s] %s\n", kv.first.c_str(), avail ? "OK" : "MISSING", path.c_str());
      }
    }
    std::printf("\nDataplane Workers: %lld/10 discovered\n",
                static_cast<long long>(report.find("workers_available_count")->as_int(0)));
    const Value* prereqs = report.find("prerequisites");
    if (prereqs) {
      std::printf("Docker:            %s\n",
                  prereqs->find("docker_available")->as_bool(false) ? "available" : "not found");
      std::printf("Agent Skills:      %s\n",
                  prereqs->find("skills_available")->as_bool(false)
                      ? prereqs->find("skills_dir")->as_string().c_str()
                      : "bundled via MCP resources://skills/*");
    }
    const Value* hw = report.find("host_hardware");
    if (hw) {
      std::printf("\nHost Hardware:\n");
      if (const Value* cpu = hw->find("cpu_model")) {
        std::printf("  CPU:             %s (%lld threads, avx2=%s, avx512=%s)\n",
                    cpu->as_string().c_str(),
                    static_cast<long long>(hw->find("logical_cores")->as_int(0)),
                    hw->find("avx2")->as_bool(false) ? "yes" : "no",
                    hw->find("avx512")->as_bool(false) ? "yes" : "no");
      }
      std::printf("  Acceleration:    cuda_gpu=%s nvcc=%s dpdk=%s af_xdp=%s io_uring=%s doca=%s\n",
                  hw->find("cuda_gpu_present")->as_bool(false) ? "yes" : "no",
                  hw->find("cuda_nvcc_available")->as_bool(false) ? "yes" : "no",
                  hw->find("dpdk_headers")->as_bool(false) ? "yes" : "no",
                  hw->find("af_xdp_headers")->as_bool(false) ? "yes" : "no",
                  hw->find("io_uring_headers")->as_bool(false) ? "yes" : "no",
                  hw->find("doca_sdk_present")->as_bool(false) ? "yes" : "no");
      if (hw->find("native_build_recommended") && hw->find("native_build_recommended")->as_bool(false)) {
        std::printf("  Optimization:    portable binary active; run 'npx -y samurai-net build' for host-native hardware tuning\n");
      }
    }
    const Value* clients = report.find("clients");
    if (clients) {
      std::printf("\nMCP Clients:\n");
      for (const auto& c : clients->elements()) {
        const std::string id = c.find("client")->as_string();
        const bool reg = c.find("registered")->as_bool(false);
        const std::string cfg_path = c.find("config_path")->as_string();
        std::printf("  %-16s [%-14s] %s\n",
                    id.c_str(),
                    reg ? "REGISTERED" : "NOT REGISTERED",
                    cfg_path.c_str());
      }
    }
  }
  return report.find("ready")->as_bool(false) ? 0 : 1;
}

int RunSetupCli(int argc, char** argv) {
  SetupOptions opts;
  for (int i = 0; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      PrintSetupUsage();
      return 0;
    } else if (a == "--client") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai setup: missing value for --client\n");
        return 2;
      }
      opts.client = argv[++i];
    } else if (a == "--scope") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai setup: missing value for --scope\n");
        return 2;
      }
      opts.scope = argv[++i];
    } else if (a == "--image") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai setup: missing value for --image\n");
        return 2;
      }
      opts.image = argv[++i];
    } else if (a == "--host-os") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "samurai setup: missing value for --host-os\n");
        return 2;
      }
      opts.host_os = argv[++i];
    } else if (a == "--docker") {
      opts.docker = true;
    } else if (a == "--ghcr") {
      opts.docker = true;
      opts.image = "ghcr.io/mehmet8-dev/samurai:latest";
    } else if (a == "--npx") {
      opts.npx = true;
    } else if (a == "--yes" || a == "-y") {
      opts.yes = true;
    } else if (a == "--json") {
      opts.json = true;
    } else {
      std::fprintf(stderr, "samurai setup: unknown option '%s'\n", a.c_str());
      return 2;
    }
  }

  if (opts.client.empty()) {
    if (opts.json) {
      Value err = Value::Object();
      err.set("ok", Value::Bool(false));
      err.set("error", Value::Str("--client is required"));
      std::printf("%s\n", err.dump().c_str());
    } else {
      PrintSetupUsage();
    }
    return 2;
  }

  const SetupResult res = ExecuteSetup(opts);
  if (opts.json) {
    std::printf("%s\n", res.report.dump().c_str());
  } else if (!res.ok) {
    std::fprintf(stderr, "samurai setup: %s\n", res.report.find("error")->as_string().c_str());
  } else {
    const bool applied = res.report.find("applied")->as_bool(false);
    std::printf("Samurai MCP Setup (%s)\n", res.report.find("display_name")->as_string().c_str());
    std::printf("  Status:     %s\n", applied ? "APPLIED" : "NOT WRITTEN (pass --yes to apply)");
    std::printf("  Mode:       %s\n", res.report.find("transport_mode")->as_string().c_str());
    std::printf("  Config:     %s\n", res.report.find("config_path")->as_string().c_str());
    if (res.report.find("config_existed")->as_bool(false)) {
      std::printf("  Backup:     %s\n", res.report.find("backup_path")->as_string().c_str());
    }
    std::printf("  Next step:  %s\n", res.report.find("next_step")->as_string().c_str());
  }
  return res.exit_code;
}

}  // namespace samurai::mcp
