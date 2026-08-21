#include "slave_node.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <unistd.h>

#include "control_wire.hpp"

namespace samurai::control {

namespace {
using samurai::core::json::Value;

std::string Hostname() {
  char buf[256] = {0};
  if (::gethostname(buf, sizeof(buf) - 1) == 0 && buf[0]) return std::string(buf);
  return "localhost";
}

double WallSec() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}
}  // namespace

SlaveNode::SlaveNode(SlaveControlClient* client, const SlaveConfig& cfg,
                     std::function<double()> now_s, std::function<void(int)> sleep_ms)
    : client_(client), cfg_(cfg) {
  worker_id_ = cfg_.worker_id.empty() ? Hostname() : cfg_.worker_id;
  hostname_ = cfg_.hostname.empty() ? worker_id_ : cfg_.hostname;
  now_s_ = now_s ? std::move(now_s) : std::function<double()>(WallSec);
  sleep_ms_ = sleep_ms ? std::move(sleep_ms) : std::function<void(int)>([](int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  });
  boot_ms_ = static_cast<std::int64_t>(now_s_() * 1000.0);
}

bool SlaveNode::Register() {
  const double deadline = now_s_() + static_cast<double>(std::max(5, cfg_.register_timeout_s));
  while (now_s_() < deadline) {
    const wire::Response r = client_->RegisterWorker(worker_id_, hostname_, cfg_.capabilities);
    if (r.ok) {
      const Value* accepted = r.body.find("accepted");
      if (accepted && accepted->as_bool()) return true;
      // A definitive rejection is terminal.
      if (accepted && !accepted->as_bool()) return false;
    }
    sleep_ms_(250);
  }
  return false;
}

HeartbeatOutcome SlaveNode::HeartbeatOnce() {
  HeartbeatOutcome out;
  const std::int64_t now_ms = static_cast<std::int64_t>(now_s_() * 1000.0);
  std::string active;
  const std::string* active_ptr = nullptr;
  if (active_shard_provider_) {
    active = active_shard_provider_();
    active_ptr = &active;  // reverse mode: always echo (even when idle)
  }
  const wire::Response r =
      client_->Heartbeat(worker_id_, std::max<std::int64_t>(0, now_ms - boot_ms_), 0.0, 0.0, 0.0,
                         active_ptr);
  if (!r.ok) return out;  // ok=false
  out.ok = true;
  const Value* ack = r.body.find("acknowledged");
  out.acknowledged = ack && ack->as_bool();
  const Value* cmd = r.body.find("command");
  out.command = cmd ? cmd->as_string("") : "";
  if (out.command == "register") {
    client_->RegisterWorker(worker_id_, hostname_, cfg_.capabilities);  // best effort
  }
  // Reverse-mode: the master piggybacks shard start/stop on the heartbeat body.
  const Value* shard = r.body.find("shard");
  if (shard && shard->is_object() && on_start_) on_start_(*shard);
  const Value* stop = r.body.find("stop_shard");
  if (stop && on_stop_) on_stop_(stop->as_string(""));
  return out;
}

int SlaveNode::RunHeartbeatLoop(std::function<bool()> should_continue) {
  double last_ok = now_s_();
  while (!should_continue || should_continue()) {
    const HeartbeatOutcome hb = HeartbeatOnce();
    if (hb.ok) {
      last_ok = now_s_();
    } else if (cfg_.master_timeout_s > 0 &&
               (now_s_() - last_ok) >= static_cast<double>(cfg_.master_timeout_s)) {
      break;  // master unreachable too long
    }
    sleep_ms_(std::max(500, cfg_.heartbeat_interval_ms));
  }
  return 0;
}

}  // namespace samurai::control
