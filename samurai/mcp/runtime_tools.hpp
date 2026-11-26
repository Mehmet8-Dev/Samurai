#pragma once

// Native C++17 runtime & dataplane tool handlers for Samurai MCP:
//   - Binary discovery (SAMURAI_BIN_DIR, exe siblings, ./build, /usr/local/bin, PATH)
//   - Shell-free POSIX fork/exec/pipe subprocess runner with poll() timeout
//   - Pure POSIX TCP HTTP GET client for samurai_master Management API (:8089)
//   - Tool handlers: list_workers, list_profiles, run_benchmark, run_rfc_suite,
//                    bench_tcp_flows, bench_l7_userspace, cluster_status

#include <atomic>
#include <functional>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

#include "json.hpp"
#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

using EnvVarList = std::vector<std::pair<std::string, std::string>>;

struct CustomTcpEnvResolution {
  bool active = false;
  std::string wire;      // "af_xdp" | "af_packet" | "dpdk" | "in_memory"
  std::string xdp_mode;  // "0" (skb/copy), "1" (native/zerocopy), "2" (offload)
  std::string iface;
  std::string src_ip;
  std::string src_mac;
  std::string dst_mac;
  std::string queue_id;
  bool auto_detected = false;
  std::string error;
  EnvVarList env_overrides;
  samurai::core::json::Value summary_json;
};

struct SubprocessResult {
  int exit_code = -1;
  bool timed_out = false;
  std::string stdout_text;
  std::string stderr_text;
  std::string error;
};

// Locate an executable across SAMURAI_BIN_DIR, exe dir siblings, build tree,
// /usr/local/bin, and $PATH. Returns empty string if not found.
std::string FindNativeBinary(const std::vector<std::string>& candidates);

// Resolve custom_tcp / AF_XDP SKB-copy-mode environment overrides from explicit
// tool arguments, process environment, and Linux route/interface/ARP discovery.
CustomTcpEnvResolution ResolveCustomTcpEnv(const samurai::core::json::Value& args,
                                           const std::string& target_ip,
                                           int target_port,
                                           bool requested_custom_tcp);

// Execute `argv` directly via fork/execv (never invokes /bin/sh) with a bounded
// wall-clock timeout, optional child env overrides, and non-blocking stdout/stderr capture.
SubprocessResult RunSubprocess(const std::vector<std::string>& argv,
                               int timeout_s,
                               const EnvVarList& env_overrides = {});

// Cancellable variant used by synchronous calls and background soak jobs.
SubprocessResult RunSubprocessCancellable(const std::vector<std::string>& argv,
                                          int timeout_s,
                                          const EnvVarList& env_overrides,
                                          const std::atomic<bool>* cancel_flag,
                                          std::atomic<pid_t>* active_pid_out);

// Launch a background job asynchronously (for long-running enterprise soak runs)
// and track it for `samurai_job_status` / `samurai_job_stop`.
ToolResult StartAsyncMcpJob(
    const std::string& tool_name,
    const std::string& target,
    int port,
    int timeout_s,
    std::function<samurai::core::json::Value(
        const std::atomic<bool>& cancel_flag,
        std::atomic<pid_t>& active_pid,
        std::string& final_status_out)> runner);

// Build a JSON object summarizing OS, kernel, architecture, and CPU count.
samurai::core::json::Value HostMetadataJson();

// Native MCP tool handlers.
ToolResult HandleListWorkers(const samurai::core::json::Value& args);
ToolResult HandleListProfiles(const samurai::core::json::Value& args);
ToolResult HandleRunBenchmark(const samurai::core::json::Value& args, const SafetyConfig& safety);
ToolResult HandleRunRfcSuite(const samurai::core::json::Value& args, const SafetyConfig& safety);
ToolResult HandleBenchTcpFlows(const samurai::core::json::Value& args);
ToolResult HandleBenchL7Userspace(const samurai::core::json::Value& args);
ToolResult HandleClusterStatus(const samurai::core::json::Value& args, const SafetyConfig& safety);
ToolResult HandleJobStatus(const samurai::core::json::Value& args);
ToolResult HandleJobStop(const samurai::core::json::Value& args);

}  // namespace samurai::mcp
