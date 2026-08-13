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

  // TLS action fields
  std::string tls_sni{};
  std::string tls_alpn{};
  std::string tls_cipher_list{};
  int tls_verify{0};

  // DNS action fields
  std::string dns_hostname{};
  std::string dns_protocol{"udp"};
  std::string dns_qtype{"A"};
  int dns_edns0{0};
  std::string dns_ecs_subnet{};

  // DHCP action fields
  std::string dhcp_client_mac{};
  int dhcp_version{4};

  // IGMP action fields
  std::string igmp_group_ip{};
  int igmp_version{2};

  // IPv6 ND action fields
  std::string nd_target_ip{};
};

struct Profile {
  std::string protocol;
  std::string sender_path;
  std::string transport_backend{"custom_tcp"};
  std::string stateful_runtime_backend{"kernel"};
  int stateful_runtime_strict{0};
  int legacy_mode{0};
  std::string source_ip;
  std::string target_ip;
  std::string interface_name;
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
  int profile_l7{0};
  int profile_sample_limit{0};
};

struct RuntimeCapabilities {
  bool openssl{false};
  bool nghttp2{false};
  bool ngtcp2{false};
  bool nghttp3{false};
};

struct ScenarioStepResult {
  std::string flow;
  std::string vu_id;
  std::string on_failure;
  bool success{false};
  bool timeout{false};
  int status_code{0};
  double latency_ms{0.0};
  std::string protocol;
};

enum class ReactorBackend {
  SocketEpoll = 0,
};

enum class TransportBackend {
  CustomTcp = 0,
  CustomQuic = 1,
  KernelSocket = 2,
  DpdkDirect = 3,
};

enum class TlsBackend {
  Unavailable = 0,
  OpenSSL = 1,
};

enum class Http2Backend {
  Unavailable = 0,
  Nghttp2Native = 1,
};

enum class NativeHotPathLevel {
  Basic = 0,
  UserspaceReactor = 1,
  UserspaceReactorTemplates = 2,
};

inline const char* reactor_backend_name(ReactorBackend backend) {
  switch (backend) {
    case ReactorBackend::SocketEpoll:
      return "socket_epoll";
  }
  return "unknown";
}

inline const char* transport_backend_name(TransportBackend backend) {
  switch (backend) {
    case TransportBackend::CustomTcp:
      return "custom_tcp";
    case TransportBackend::CustomQuic:
      return "custom_quic";
    case TransportBackend::KernelSocket:
      return "kernel_socket";
    case TransportBackend::DpdkDirect:
      return "dpdk_direct";
  }
  return "unknown";
}

inline const char* tls_backend_name(TlsBackend backend) {
  switch (backend) {
    case TlsBackend::OpenSSL:
      return "openssl";
    case TlsBackend::Unavailable:
      return "unavailable";
  }
  return "unknown";
}

inline const char* http2_backend_name(Http2Backend backend) {
  switch (backend) {
    case Http2Backend::Nghttp2Native:
      return "nghttp2_native";
    case Http2Backend::Unavailable:
      return "unavailable";
  }
  return "unknown";
}

inline const char* native_hot_path_level_name(NativeHotPathLevel level) {
  switch (level) {
    case NativeHotPathLevel::UserspaceReactorTemplates:
      return "userspace_reactor_templates";
    case NativeHotPathLevel::UserspaceReactor:
      return "userspace_reactor";
    case NativeHotPathLevel::Basic:
      return "basic";
  }
  return "unknown";
}

struct TimerWheel {
  std::size_t slot_count{1024};
  std::size_t active_timers{0};
};

struct ConnectionPool {
  int max_connections{1};
  int active_connections{0};
  int reused_connections{0};
  int active_connections_peak{0};
};

struct ShardState {
  int shard_id{0};
  int epoll_fd{-1};
  TimerWheel timer_wheel{};
  ConnectionPool connection_pool{};
};

RuntimeCapabilities detect_capabilities();
std::map<std::string, double> run_profile(const Profile& profile, const RuntimeConfig& cfg);
std::vector<ScenarioStepResult> consume_last_scenario_step_results();

namespace custom_quic_stack {
std::map<std::string, double> run_quic_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps,
    TransportBackend transport_backend);
}  // namespace custom_quic_stack

}  // namespace ddos_samurai::l7_emu_native
