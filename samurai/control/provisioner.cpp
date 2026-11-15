#include "provisioner.hpp"

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace samurai::control {

using samurai::core::json::Value;

HostEndpoint HostEndpoint::Parse(const std::string& raw) {
  HostEndpoint ep;
  ep.port = 22;
  std::string s = raw;
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();

  const auto colon = s.rfind(':');
  if (colon != std::string::npos && colon + 1 < s.size()) {
    std::string port_str = s.substr(colon + 1);
    bool all_digits = true;
    for (char c : port_str) {
      if (!std::isdigit(static_cast<unsigned char>(c))) {
        all_digits = false;
        break;
      }
    }
    if (all_digits) {
      ep.host = s.substr(0, colon);
      ep.port = std::atoi(port_str.c_str());
      if (ep.port <= 0 || ep.port > 65535) ep.port = 22;
      return ep;
    }
  }
  ep.host = s;
  return ep;
}

Value ProvisionResult::ToJson() const {
  Value obj = Value::Object();
  obj.set("host", Value::Str(host));
  obj.set("port", Value::Int(port));
  obj.set("triggered", Value::Bool(triggered));
  obj.set("worker_joined", Value::Bool(worker_joined));
  obj.set("exit_code", Value::Int(exit_code));
  obj.set("message", Value::Str(message));
  return obj;
}

std::string BuildRemoteInstallCmd(const std::string& install_url, bool tls_skip_verify) {
  const char* curl_flags = tls_skip_verify ? "-fsSLk" : "-fsSL";
  return "nohup sh -c 'curl " + std::string(curl_flags) + " \"" + install_url + "\" | sh' >/dev/null 2>&1 &";
}

int PosixSshExecutor(const std::string& host, int port,
                     const std::string& user, const std::string& key_path,
                     const std::string& remote_cmd, std::string& error_out) {
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    error_out = "pipe() failed: " + std::string(std::strerror(errno));
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    error_out = "fork() failed: " + std::string(std::strerror(errno));
    return -1;
  }

  if (pid == 0) {
    // Child process
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      close(devnull);
    }

    std::vector<std::string> args = {
      "ssh",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-o", "ConnectTimeout=5",
      "-p", std::to_string(port)
    };
    if (!key_path.empty()) {
      args.push_back("-i");
      args.push_back(key_path);
    }
    args.push_back(user + "@" + host);
    args.push_back(remote_cmd);

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    execvp("ssh", argv.data());
    const char* err = "execvp(ssh) failed\n";
    ssize_t w = write(STDERR_FILENO, err, std::strlen(err));
    (void)w;
    _exit(127);
  }

  // Parent process
  close(pipefd[1]);
  std::string captured;
  char buf[512];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
    buf[n] = '\0';
    captured.append(buf, static_cast<std::size_t>(n));
  }
  close(pipefd[0]);

  int status = 0;
  waitpid(pid, &status, 0);

  if (WIFEXITED(status)) {
    int exit_code = WEXITSTATUS(status);
    if (exit_code != 0) {
      error_out = captured.empty() ? ("ssh exited with " + std::to_string(exit_code)) : captured;
      while (!error_out.empty() && (error_out.back() == '\n' || error_out.back() == '\r')) {
        error_out.pop_back();
      }
    }
    return exit_code;
  } else if (WIFSIGNALED(status)) {
    error_out = "ssh terminated by signal " + std::to_string(WTERMSIG(status));
    return -1;
  }
  return -1;
}

NodeProvisioner::NodeProvisioner(SshExecutor executor, WorkerChecker checker)
    : executor_(std::move(executor)), checker_(std::move(checker)) {}

std::vector<ProvisionResult> NodeProvisioner::Provision(
    const std::vector<ProvisionTarget>& targets,
    const std::string& install_url,
    bool tls_skip_verify,
    int timeout_s) const {
  std::vector<ProvisionResult> results;
  results.resize(targets.size());

  std::vector<std::thread> workers;
  for (std::size_t i = 0; i < targets.size(); ++i) {
    workers.emplace_back([this, i, &targets, &results, &install_url, tls_skip_verify]() {
      const auto& t = targets[i];
      auto& r = results[i];
      r.host = t.host;
      r.port = t.port;

      std::string target_url = install_url;
      if (!t.worker_kind.empty()) {
        const char sep = (target_url.find('?') == std::string::npos) ? '?' : '&';
        target_url += sep;
        target_url += "worker=";
        target_url += t.worker_kind;
      }

      std::string cmd = BuildRemoteInstallCmd(target_url, tls_skip_verify);
      std::string err;
      int code = executor_(t.host, t.port, t.user, t.key_path, cmd, err);
      r.exit_code = code;
      if (code == 0) {
        r.triggered = true;
        r.message = "triggered successfully";
      } else {
        r.triggered = false;
        r.message = err.empty() ? ("ssh failed with code " + std::to_string(code)) : err;
      }
    });
  }
  for (auto& w : workers) {
    if (w.joinable()) w.join();
  }

  // Poll for worker join confirmation if checker is provided
  if (checker_ && timeout_s > 0) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    while (std::chrono::steady_clock::now() < deadline) {
      bool all_joined = true;
      for (auto& r : results) {
        if (r.triggered && !r.worker_joined) {
          if (checker_(r.host)) {
            r.worker_joined = true;
            r.message = "worker joined cluster successfully";
          } else {
            all_joined = false;
          }
        }
      }
      if (all_joined) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
  }

  return results;
}

Value NodeProvisioner::ProvisionJson(const Value& body,
                                    const std::string& default_install_url,
                                    bool tls_skip_verify) const {
  std::vector<ProvisionTarget> targets;
  std::string default_user = "root";
  std::string default_key_path;
  std::string default_worker_kind = "cpu";
  int timeout_s = 10;

  if (const Value* u = body.find("ssh_user")) default_user = u->as_string(default_user);
  if (const Value* k = body.find("ssh_key_path")) default_key_path = k->as_string("");
  if (const Value* wk = body.find("worker_kind")) default_worker_kind = wk->as_string(default_worker_kind);
  if (const Value* to = body.find("timeout_s")) timeout_s = static_cast<int>(to->as_int(timeout_s));

  std::string install_url = default_install_url;
  if (const Value* iu = body.find("install_url")) {
    std::string custom_url = iu->as_string("");
    if (!custom_url.empty()) install_url = custom_url;
  }

  const Value* hosts_val = body.find("hosts");
  if (hosts_val && hosts_val->is_array()) {
    for (const auto& h : hosts_val->elements()) {
      std::string h_str = h.as_string("");
      if (!h_str.empty()) {
        HostEndpoint ep = HostEndpoint::Parse(h_str);
        ProvisionTarget t;
        t.host = ep.host;
        t.port = ep.port;
        t.user = default_user;
        t.key_path = default_key_path;
        t.worker_kind = default_worker_kind;
        targets.push_back(t);
      }
    }
  } else if (hosts_val && hosts_val->is_string()) {
    std::string h_str = hosts_val->as_string("");
    std::stringstream ss(h_str);
    std::string item;
    while (std::getline(ss, item, ',')) {
      if (!item.empty()) {
        HostEndpoint ep = HostEndpoint::Parse(item);
        ProvisionTarget t;
        t.host = ep.host;
        t.port = ep.port;
        t.user = default_user;
        t.key_path = default_key_path;
        t.worker_kind = default_worker_kind;
        targets.push_back(t);
      }
    }
  }

  if (targets.empty()) {
    Value err = Value::Object();
    err.set("status", Value::Str("error"));
    err.set("error", Value::Str("no_valid_hosts_provided"));
    err.set("total", Value::Int(0));
    err.set("triggered", Value::Int(0));
    err.set("joined", Value::Int(0));
    err.set("provisioned", Value::Array());
    return err;
  }

  auto results = Provision(targets, install_url, tls_skip_verify, timeout_s);

  int triggered_count = 0;
  int joined_count = 0;
  Value prov_arr = Value::Array();
  for (const auto& r : results) {
    if (r.triggered) ++triggered_count;
    if (r.worker_joined) ++joined_count;
    prov_arr.push_back(r.ToJson());
  }

  Value out = Value::Object();
  out.set("status", Value::Str("ok"));
  out.set("total", Value::Int(static_cast<std::int64_t>(results.size())));
  out.set("triggered", Value::Int(triggered_count));
  out.set("joined", Value::Int(joined_count));
  out.set("provisioned", std::move(prov_arr));
  return out;
}

}  // namespace samurai::control
