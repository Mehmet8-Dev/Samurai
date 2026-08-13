#include "dns_client_engine.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <random>
#include <sstream>


namespace ddos_samurai::l7_emu_native::dns {

namespace {

inline void append_be16(std::vector<uint8_t>& buf, uint16_t val) {
  buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

inline void append_be32(std::vector<uint8_t>& buf, uint32_t val) {
  buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

inline uint16_t read_be16(const uint8_t* ptr) {
  return static_cast<uint16_t>((ptr[0] << 8) | ptr[1]);
}

inline uint32_t read_be32(const uint8_t* ptr) {
  return (static_cast<uint32_t>(ptr[0]) << 24) |
         (static_cast<uint32_t>(ptr[1]) << 16) |
         (static_cast<uint32_t>(ptr[2]) << 8) |
         static_cast<uint32_t>(ptr[3]);
}

std::string to_upper(std::string s) {
  for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

uint16_t qtype_to_code(const std::string& qtype) {
  const std::string u = to_upper(qtype);
  if (u == "A") return 1;
  if (u == "NS") return 2;
  if (u == "CNAME") return 5;
  if (u == "SOA") return 6;
  if (u == "PTR") return 12;
  if (u == "MX") return 15;
  if (u == "TXT") return 16;
  if (u == "AAAA") return 28;
  if (u == "SRV") return 33;
  if (u == "ANY") return 255;
  return 1; // Default A
}

// Parse domain name from DNS response packet handling pointer compression
std::string parse_dns_name(const uint8_t* buf, size_t len, size_t& offset, int depth = 0) {
  if (depth > 10 || offset >= len) return "";
  std::string name;
  bool jumped = false;
  size_t original_offset = offset;

  while (offset < len) {
    uint8_t len_byte = buf[offset];
    if (len_byte == 0) {
      if (!jumped) offset++;
      break;
    }
    // Compression pointer (top 2 bits set)
    if ((len_byte & 0xC0) == 0xC0) {
      if (offset + 1 >= len) break;
      uint16_t pointer = read_be16(&buf[offset]) & 0x3FFF;
      if (!jumped) {
        original_offset = offset + 2;
        jumped = true;
      }
      offset = pointer;
      depth++;
      continue;
    }

    offset++;
    if (offset + len_byte > len) break;
    if (!name.empty()) name.push_back('.');
    name.append(reinterpret_cast<const char*>(&buf[offset]), len_byte);
    offset += len_byte;
  }

  if (jumped) offset = original_offset;
  return name;
}

}  // namespace

std::vector<uint8_t> DnsClientEngine::build_dns_query_payload(
    const std::string& hostname,
    const std::string& qtype,
    bool recursive,
    int edns0,
    const std::string& ecs_subnet,
    uint16_t txid) {
  std::vector<uint8_t> out;

  // Header: 12 bytes
  append_be16(out, txid);
  // Flags: Standard query, Recursion Desired (0x0100)
  uint16_t flags = 0x0100;
  if (!recursive) flags &= ~0x0100;
  append_be16(out, flags);
  append_be16(out, 1); // QDCOUNT (Questions: 1)
  append_be16(out, 0); // ANCOUNT
  append_be16(out, 0); // NSCOUNT
  append_be16(out, edns0 > 0 ? 1 : 0); // ARCOUNT (Additional records for EDNS0)

  // QNAME
  std::string trimmed = hostname;
  if (trimmed.empty() || trimmed == ".") {
    out.push_back(0);
  } else {
    if (!trimmed.empty() && trimmed.back() == '.') trimmed.pop_back();
    std::stringstream ss(trimmed);
    std::string label;
    while (std::getline(ss, label, '.')) {
      if (label.empty() || label.size() > 63) continue;
      out.push_back(static_cast<uint8_t>(label.size()));
      out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
  }

  // QTYPE & QCLASS (IN = 1)
  append_be16(out, qtype_to_code(qtype));
  append_be16(out, 1);

  // OPT RR for EDNS0 / ECS
  if (edns0 > 0) {
    out.push_back(0);        // NAME: root
    append_be16(out, 41);   // TYPE: OPT (41)
    append_be16(out, 4096); // CLASS: UDP Payload Size (4096)
    append_be32(out, 0);    // TTL: Extended RCODE & flags

    if (!ecs_subnet.empty()) {
      // Build EDNS Client Subnet (ECS) option (Option code 8)
      uint32_t ecs_ip = 0;
      inet_pton(AF_INET, ecs_subnet.c_str(), &ecs_ip);
      const uint8_t opt_data[] = {
          0, 8,              // Option Code 8 (ECS)
          0, 7,              // Option Length (7 bytes)
          0, 1,              // Family (1 = IPv4)
          24, 0,             // Source prefix len 24, Scope 0
          static_cast<uint8_t>(ecs_ip & 0xFF),
          static_cast<uint8_t>((ecs_ip >> 8) & 0xFF),
          static_cast<uint8_t>((ecs_ip >> 16) & 0xFF)
      };
      append_be16(out, sizeof(opt_data));
      out.insert(out.end(), opt_data, opt_data + sizeof(opt_data));
    } else {
      append_be16(out, 0);   // RDLEN: 0 options
    }
  }

  return out;
}

bool DnsClientEngine::parse_dns_response_payload(
    const uint8_t* data, size_t len, DnsResponse& out_resp) {
  if (data == nullptr || len < 12) {
    return false;
  }

  out_resp.txid = read_be16(&data[0]);
  const uint16_t flags = read_be16(&data[2]);
  out_resp.rcode = flags & 0x000F;
  out_resp.nxdomain = (out_resp.rcode == 3);

  const uint16_t qdcount = read_be16(&data[4]);
  const uint16_t ancount = read_be16(&data[6]);

  size_t offset = 12;

  // Skip questions
  for (uint16_t q = 0; q < qdcount; ++q) {
    std::string qname = parse_dns_name(data, len, offset);
    if (out_resp.hostname.empty()) out_resp.hostname = qname;
    offset += 4; // Skip QTYPE & QCLASS
    if (offset > len) return false;
  }

  // Parse Answer Section
  for (uint16_t a = 0; a < ancount; ++a) {
    if (offset >= len) break;
    std::string name = parse_dns_name(data, len, offset);
    if (offset + 10 > len) break;

    const uint16_t type = read_be16(&data[offset]);
    const uint16_t rclass = read_be16(&data[offset + 2]);
    const uint32_t ttl = read_be32(&data[offset + 4]);
    const uint16_t rdlen = read_be16(&data[offset + 8]);
    (void)rclass;

    offset += 10;
    if (offset + rdlen > len) break;

    out_resp.ttl = static_cast<int>(ttl);

    if (type == 1 && rdlen == 4) { // TYPE A (IPv4)
      char ip_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &data[offset], ip_str, sizeof(ip_str));
      out_resp.ips.push_back(ip_str);
    } else if (type == 28 && rdlen == 16) { // TYPE AAAA (IPv6)
      char ip_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &data[offset], ip_str, sizeof(ip_str));
      out_resp.ips.push_back(ip_str);
    } else if (type == 5) { // CNAME
      size_t cname_off = offset;
      out_resp.cname = parse_dns_name(data, len, cname_off);
    } else if (type == 16) { // TXT
      if (rdlen > 1) {
        uint8_t txt_len = data[offset];
        if (txt_len < rdlen) {
          out_resp.txt_records.push_back(
              std::string(reinterpret_cast<const char*>(&data[offset + 1]), txt_len));
        }
      }
    }

    offset += rdlen;
  }

  out_resp.success = (out_resp.rcode == 0 && !out_resp.ips.empty());
  return true;
}

DnsResponse DnsClientEngine::resolve(
    const std::string& hostname,
    const std::string& protocol,
    const std::string& qtype,
    int edns0,
    const std::string& ecs_subnet) {
  (void)protocol;

  const std::string cache_key = hostname + ":" + qtype + ":" + ecs_subnet;
  auto it = cache_.find(cache_key);
  if (it != cache_.end()) {
    return it->second;
  }

  std::mt19937 rng(std::random_device{}());
  const uint16_t txid = static_cast<uint16_t>(rng() & 0xFFFF);

  // Generate real wire-format DNS query payload
  last_query_packet_ = build_dns_query_payload(hostname, qtype, true, edns0, ecs_subnet, txid);

  DnsResponse resp{};
  resp.hostname = hostname;
  resp.txid = txid;
  resp.ttl = 300;
  resp.rcode = 0;
  resp.success = true;

  const std::string upper_qt = to_upper(qtype);
  if (upper_qt == "AAAA") {
    resp.ips.push_back("2001:db8::1");
  } else if (upper_qt == "TXT") {
    resp.txt_records.push_back("v=spf1 include:_spf.example.com ~all");
  } else {
    resp.ips.push_back("192.168.1.1");
  }

  cache_[cache_key] = resp;
  return resp;
}

DnsResponse DnsClientEngine::resolve_network(
    const std::string& server_ip,
    uint16_t server_port,
    const std::string& hostname,
    const std::string& protocol,
    const std::string& qtype,
    int edns0,
    const std::string& ecs_subnet,
    int timeout_ms) {
  std::mt19937 rng(std::random_device{}());
  const uint16_t txid = static_cast<uint16_t>(rng() & 0xFFFF);

  last_query_packet_ = build_dns_query_payload(hostname, qtype, true, edns0, ecs_subnet, txid);

  DnsResponse resp{};
  resp.hostname = hostname;
  resp.txid = txid;

  const std::string proto_lc = to_upper(protocol) == "TCP" ? "TCP" : "UDP";
  const int sock_type = proto_lc == "TCP" ? SOCK_STREAM : SOCK_DGRAM;

  int fd = socket(AF_INET, sock_type, 0);
  if (fd < 0) {
    resp.success = false;
    return resp;
  }

  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  sockaddr_in dest_addr{};
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(server_port == 0 ? 53 : server_port);
  inet_pton(AF_INET, server_ip.c_str(), &dest_addr.sin_addr);

  if (connect(fd, reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr)) != 0) {
    close(fd);
    resp.success = false;
    return resp;
  }

  if (proto_lc == "UDP") {
    ssize_t sent = send(fd, last_query_packet_.data(), last_query_packet_.size(), 0);
    if (sent < 0) {
      close(fd);
      resp.success = false;
      return resp;
    }

    uint8_t rx_buf[4096];
    ssize_t n = recv(fd, rx_buf, sizeof(rx_buf), 0);
    close(fd);

    if (n > 0) {
      bool ok = parse_dns_response_payload(rx_buf, static_cast<size_t>(n), resp);
      resp.success = ok && (resp.rcode == 0);
      return resp;
    }
  } else {
    // TCP DNS requires 2-byte length prefix
    std::vector<uint8_t> tcp_req;
    append_be16(tcp_req, static_cast<uint16_t>(last_query_packet_.size()));
    tcp_req.insert(tcp_req.end(), last_query_packet_.begin(), last_query_packet_.end());

    ssize_t sent = send(fd, tcp_req.data(), tcp_req.size(), 0);
    if (sent < 0) {
      close(fd);
      resp.success = false;
      return resp;
    }

    uint8_t len_buf[2];
    ssize_t n_len = recv(fd, len_buf, 2, 0);
    if (n_len < 2) {
      close(fd);
      resp.success = false;
      return resp;
    }
    uint16_t resp_len = read_be16(len_buf);

    std::vector<uint8_t> rx_buf(resp_len);
    ssize_t n_resp = recv(fd, rx_buf.data(), resp_len, 0);
    close(fd);

    if (n_resp == resp_len) {
      bool ok = parse_dns_response_payload(rx_buf.data(), static_cast<size_t>(n_resp), resp);
      resp.success = ok && (resp.rcode == 0);
      return resp;
    }
  }

  close(fd);
  resp.success = false;
  return resp;
}

}  // namespace ddos_samurai::l7_emu_native::dns

