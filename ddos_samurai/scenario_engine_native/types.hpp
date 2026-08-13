#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddos_samurai::scenario_native {

enum class StepType : std::uint8_t {
  Request = 0,
  Pause = 1,
  Branch = 2,
  Loop = 3,
  Assert = 4,
  EndSession = 5,
  TcpConnect = 6,
  TcpSend = 7,
  TcpExpect = 8,
  TcpClose = 9,
  // L7 protocol emulation actions (Faz 5).
  TlsConnect = 10,
  TlsDisconnect = 11,
  DnsResolve = 12,
  DhcpAcquire = 13,
  DhcpRelease = 14,
  ArpResolve = 15,
  IgmpJoin = 16,
  IgmpLeave = 17,
  Ipv6NdSolicit = 18,
};

struct ThinkTime {
  int min_ms{0};
  int max_ms{0};
  std::string distribution{"uniform"};
  int mean_ms{0};
  int stddev_ms{0};
};

struct Step {
  StepType type{StepType::Request};
  std::string method{"GET"};
  std::string path{"/"};
  std::string body_template{};
  std::string flow{};
  int repeat{1};
  double probability{1.0};
  std::string on_failure{"retry"};
  std::uint16_t dst_port{0};
  std::string payload_template{};
  std::string condition{};
  int timeout_ms{0};
  ThinkTime think_time{};

  // TLS action fields (TlsConnect / TlsDisconnect).
  std::string tls_sni{};
  std::string tls_alpn{};          // e.g. "h2", "http/1.1"
  std::string tls_cipher_list{};   // OpenSSL cipher string
  int tls_verify{0};

  // DNS action fields (DnsResolve).
  std::string dns_hostname{};
  std::string dns_protocol{"udp"};  // udp, tcp, doh, dot
  std::string dns_qtype{"A"};       // A, AAAA, CNAME, MX, etc.
  int dns_edns0{0};
  std::string dns_ecs_subnet{};     // EDNS0 Client Subnet

  // DHCP action fields (DhcpAcquire / DhcpRelease).
  std::string dhcp_client_mac{};
  int dhcp_version{4};              // 4 or 6

  // IGMP action fields (IgmpJoin / IgmpLeave).
  std::string igmp_group_ip{};
  int igmp_version{2};              // 2 or 3

  // IPv6 ND action fields (Ipv6NdSolicit).
  std::string nd_target_ip{};
};

struct Persona {
  std::string name{};
  std::string device_profile{"web"};
  std::unordered_map<std::string, std::string> headers{};
  std::unordered_map<std::string, std::string> cookies{};
  int request_timeout_ms{5000};
  int session_timeout_ms{0};
  int max_retries{0};
  double weight{1.0};
};

struct Flow {
  std::string name{};
  std::string persona{};
  std::vector<Step> steps{};
};

struct LoadModel {
  std::string backend{"http"};
  int concurrent_vus{0};
  int ramp_seconds{0};
};

struct ScenarioSpecNative {
  std::vector<Flow> flows{};
  std::unordered_map<std::string, std::size_t> flow_index{};
  std::unordered_map<std::string, Persona> personas{};
  LoadModel load_model{};
};

}  // namespace ddos_samurai::scenario_native

