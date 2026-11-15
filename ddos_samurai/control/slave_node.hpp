#pragma once

// Distributed slave orchestration loop — the register + heartbeat control flow
// (the shard execution side is WorkerShardService). Drives a SlaveControlClient:
// register with retry
// until accepted or a deadline, then heartbeat periodically and re-register when
// the master answers "register". Built only with libzmq (uses the ZMQ client).

#include <cstdint>
#include <functional>
#include <map>
#include <string>

#include "control_client.hpp"

namespace samurai::control {

struct SlaveConfig {
  std::string worker_id;   // defaults to hostname when blank
  std::string hostname;    // defaults to worker_id
  std::map<std::string, std::string> capabilities;
  int register_timeout_s = 10;
  int heartbeat_interval_ms = 2000;
  int master_timeout_s = 30;  // exit the loop if the master is unreachable this long (0 = never)
};

struct HeartbeatOutcome {
  bool ok = false;         // RPC round-trip succeeded
  bool acknowledged = false;
  std::string command;     // "continue" | "register" | ...
};

class SlaveNode {
 public:
  // `client` is non-owning. now_s / sleep_ms are injectable for tests.
  SlaveNode(SlaveControlClient* client, const SlaveConfig& cfg,
            std::function<double()> now_s = {}, std::function<void(int)> sleep_ms = {});

  const std::string& worker_id() const { return worker_id_; }

  // Reverse-mode callbacks. When the master piggybacks a command on a heartbeat
  // response, HeartbeatOnce invokes these: on_start with the shard payload
  // (shard_id/job_id/args_json/...), on_stop with the shard_id. Unset in direct
  // mode (the master drives shards over the inbound control server instead).
  void set_on_start(std::function<void(const samurai::core::json::Value&)> cb) {
    on_start_ = std::move(cb);
  }
  void set_on_stop(std::function<void(const std::string&, std::int64_t)> cb) {
    on_stop_ = std::move(cb);
  }
  void set_on_reconfigure(std::function<void(const samurai::core::json::Value&)> cb) {
    on_reconfigure_ = std::move(cb);
  }

  // Reverse-mode pickup echo: when set, each heartbeat reports the shard the
  // worker is currently running ("" = idle) so the master can confirm the
  // dispatched shard was picked up. Unset (direct mode) omits the field.
  void set_active_shard_provider(std::function<std::string()> cb) {
    active_shard_provider_ = std::move(cb);
  }

  // Register with retry until accepted or the register timeout elapses.
  bool Register();

  // One heartbeat; re-registers if the master replies "register".
  HeartbeatOutcome HeartbeatOnce();

  // Heartbeat loop: HeartbeatOnce + sleep while should_continue() is true and the
  // master has been reachable within master_timeout_s. Returns 0 normally.
  int RunHeartbeatLoop(std::function<bool()> should_continue);

 private:
  SlaveControlClient* client_;
  SlaveConfig cfg_;
  std::string worker_id_;
  std::string hostname_;
  std::int64_t boot_ms_;
  std::function<double()> now_s_;
  std::function<void(int)> sleep_ms_;
  std::function<void(const samurai::core::json::Value&)> on_start_;
  std::function<void(const std::string&, std::int64_t)> on_stop_;
  std::function<void(const samurai::core::json::Value&)> on_reconfigure_;
  std::function<std::string()> active_shard_provider_;
};

}  // namespace samurai::control
