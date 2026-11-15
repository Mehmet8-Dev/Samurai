#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace samurai::l7_emu_native::dns {

struct DnsResponse {
  std::string hostname;
  std::vector<std::string> ips;
  std::vector<std::string> txt_records;
  std::string cname;
  int ttl{0};
  uint16_t txid{0};
  uint16_t rcode{0};
  bool nxdomain{false};
  bool success{false};
};

class DnsClientEngine {
 public:
  DnsClientEngine() = default;
  ~DnsClientEngine() = default;

  // Disallow copy and assignment
  DnsClientEngine(const DnsClientEngine&) = delete;
  DnsClientEngine& operator=(const DnsClientEngine&) = delete;

  // Execute a DNS resolution loop (offline/simulated response or real network socket I/O)
  DnsResponse resolve(
      const std::string& hostname,
      const std::string& protocol,
      const std::string& qtype,
      int edns0,
      const std::string& ecs_subnet);

  // Perform a real network UDP/TCP socket query to a target DNS server IP/port
  DnsResponse resolve_network(
      const std::string& server_ip,
      uint16_t server_port,
      const std::string& hostname,
      const std::string& protocol,
      const std::string& qtype,
      int edns0,
      const std::string& ecs_subnet,
      int timeout_ms = 2000);


  // Wire-format packet builders & response parsers
  static std::vector<uint8_t> build_dns_query_payload(
      const std::string& hostname,
      const std::string& qtype,
      bool recursive,
      int edns0,
      const std::string& ecs_subnet,
      uint16_t txid);

  static bool parse_dns_response_payload(
      const uint8_t* data, size_t len, DnsResponse& out_resp);

  const std::vector<uint8_t>& last_query_packet() const { return last_query_packet_; }

 private:
  std::unordered_map<std::string, DnsResponse> cache_;
  std::vector<uint8_t> last_query_packet_;
};

}  // namespace samurai::l7_emu_native::dns
