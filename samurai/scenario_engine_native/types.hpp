#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace samurai::scenario_native {

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
  double shape_alpha{1.5};

  int sample(std::mt19937_64& rng) const {
    if (min_ms >= max_ms && max_ms > 0) return min_ms;
    if (distribution == "normal" || distribution == "gaussian") {
      int m = mean_ms > 0 ? mean_ms : (min_ms + max_ms) / 2;
      int s = stddev_ms > 0 ? stddev_ms : std::max(1, (max_ms - min_ms) / 6);
      std::normal_distribution<double> dist(m, s);
      int val = static_cast<int>(dist(rng));
      return std::clamp(val, std::max(0, min_ms), std::max(min_ms, max_ms));
    } else if (distribution == "exponential") {
      double m = mean_ms > 0 ? static_cast<double>(mean_ms) : static_cast<double>(std::max(1, (min_ms + max_ms) / 2));
      std::exponential_distribution<double> dist(1.0 / m);
      int val = static_cast<int>(dist(rng));
      return std::clamp(val, std::max(0, min_ms), std::max(min_ms, max_ms));
    } else if (distribution == "pareto") {
      double scale = min_ms > 0 ? static_cast<double>(min_ms) : 100.0;
      std::uniform_real_distribution<double> dist(0.0001, 0.9999);
      double u = dist(rng);
      double val = scale / std::pow(1.0 - u, 1.0 / shape_alpha);
      return std::clamp(static_cast<int>(val), std::max(0, min_ms), max_ms > 0 ? max_ms : static_cast<int>(scale * 10.0));
    }
    std::uniform_int_distribution<int> dist(std::max(0, min_ms), std::max(min_ms, max_ms));
    return dist(rng);
  }
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

  // Dynamic persona, session token & cookie binding fields
  std::string extract_token_regex{};
  std::string token_variable_name{};
  // Where the session token lives in the login response:
  //   "cookie"    (default) -> Set-Cookie
  //   "header"    -> response header named token_path
  //   "body_json" -> JSON dotted path token_path (e.g. "accessToken", "data.token")
  std::string token_source{"cookie"};
  std::string token_path{};
  std::unordered_map<std::string, std::string> headers{};
  std::unordered_map<std::string, std::string> cookies{};

  // Per-step response expectations (optional).
  int expect_status_min{0};
  int expect_status_max{0};
  std::string expect_body_contains{};
  std::string expect_header_name{};
  std::string expect_header_value{};

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
  double duration_s{0.0};
};

struct ScenarioSpecNative {
  std::vector<Flow> flows{};
  std::unordered_map<std::string, std::size_t> flow_index{};
  std::unordered_map<std::string, Persona> personas{};
  LoadModel load_model{};
};

}  // namespace samurai::scenario_native

