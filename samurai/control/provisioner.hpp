#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

// Parsed host and port endpoint (e.g. "198.51.100.20:22" or "198.51.100.20")
struct HostEndpoint {
  std::string host;
  int port = 22;

  static HostEndpoint Parse(const std::string& raw);
};

// Target remote node configuration for SSH provisioning
struct ProvisionTarget {
  std::string host;
  int port = 22;
  std::string user = "root";
  std::string key_path;
  std::string worker_kind = "cpu";
};

// Result of a provisioning attempt for a single node
struct ProvisionResult {
  std::string host;
  int port = 22;
  bool triggered = false;
  bool worker_joined = false;
  std::string message;
  int exit_code = 0;

  samurai::core::json::Value ToJson() const;
};

// SshExecutor function signature:
// (host, port, user, key_path, remote_cmd, error_out) -> exit_code
using SshExecutor = std::function<int(const std::string& host, int port,
                                      const std::string& user, const std::string& key_path,
                                      const std::string& remote_cmd, std::string& error_out)>;

// WorkerChecker function signature:
// Returns whether the given host has registered / sent heartbeat
using WorkerChecker = std::function<bool(const std::string& host)>;

// Default POSIX fork()/execvp() SSH executor implementation
int PosixSshExecutor(const std::string& host, int port,
                     const std::string& user, const std::string& key_path,
                     const std::string& remote_cmd, std::string& error_out);

// Build the remote bootstrap install shell command
std::string BuildRemoteInstallCmd(const std::string& install_url, bool tls_skip_verify = false);

// NodeProvisioner: Triggers remote nodes over SSH to download and start the agent
// in reverse mode, and verifies cluster join via heartbeat polling.
class NodeProvisioner {
 public:
  explicit NodeProvisioner(SshExecutor executor = PosixSshExecutor,
                           WorkerChecker checker = nullptr);

  void SetWorkerChecker(WorkerChecker checker) { checker_ = std::move(checker); }
  void SetSshExecutor(SshExecutor executor) { executor_ = std::move(executor); }

  std::vector<ProvisionResult> Provision(const std::vector<ProvisionTarget>& targets,
                                         const std::string& install_url,
                                         bool tls_skip_verify = false,
                                         int timeout_s = 10) const;

  samurai::core::json::Value ProvisionJson(const samurai::core::json::Value& body,
                                           const std::string& default_install_url,
                                           bool tls_skip_verify = false) const;

 private:
  SshExecutor executor_;
  WorkerChecker checker_;
};

}  // namespace samurai::control
