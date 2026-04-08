#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace ddos_samurai::l7_emu_native {

struct Expectation {
  std::string kind;
  std::string name;
  std::string value;
  int status_min{0};
  int status_max{0};
};

struct FlowOp {
  std::string opcode;
  std::string method;
  std::string path;
  std::map<std::string, std::string> headers;
  std::vector<unsigned char> body;
  Expectation expect{};
  bool has_expect{false};
  std::string capture_name;
  std::string capture_source;
  int think_time_ms{0};
  int loop_count{0};
};

struct Profile {
  std::string protocol;
  std::string sender_path;
  std::string target_ip;
  int target_port{0};
  std::string scheme;
  std::string host_header;
  int verify{1};
  int keepalive{1};
  int timeout_ms{5000};
  int max_connections{1};
  int max_streams_per_connection{1};
  int session_repeats{1};
  int flow_attempted{0};
  std::vector<FlowOp> ops;
};

struct RuntimeConfig {
  int concurrency{1};
};

struct RuntimeCapabilities {
  bool openssl{false};
  bool nghttp2{false};
};

struct TimerWheel {
  std::size_t slot_count{1024};
  std::size_t active_timers{0};
};

struct ConnectionPool {
  int max_connections{1};
  int active_connections{0};
  int reused_connections{0};
};

struct ShardState {
  int shard_id{0};
  int epoll_fd{-1};
  TimerWheel timer_wheel{};
  ConnectionPool connection_pool{};
};

RuntimeCapabilities detect_capabilities();
std::map<std::string, double> run_profile(const Profile& profile, const RuntimeConfig& cfg);

}  // namespace ddos_samurai::l7_emu_native
