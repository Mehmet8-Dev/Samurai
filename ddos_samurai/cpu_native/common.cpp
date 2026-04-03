#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;
PacketPoolBuffer::PacketPoolBuffer() : storage(std::make_shared<std::vector<uint8_t>>()), packet_size(0) {}

PacketPoolBuffer::PacketPoolBuffer(std::shared_ptr<std::vector<uint8_t>> data, size_t stride)
    : storage(std::move(data)), packet_size(stride) {}

uint8_t* PacketPoolBuffer::data() { return storage ? storage->data() : nullptr; }

const uint8_t* PacketPoolBuffer::data() const { return storage ? storage->data() : nullptr; }

size_t PacketPoolBuffer::size() const { return storage ? storage->size() : 0; }

uint16_t checksum(const uint8_t* data, size_t len) {
  uint32_t s = 0;
  size_t i = 0;
  while (i + 1 < len) {
    s += (static_cast<uint32_t>(data[i]) << 8) | static_cast<uint32_t>(data[i + 1]);
    i += 2;
  }
  if (i < len) s += static_cast<uint32_t>(data[i]) << 8;
  return finalize_sum(s);
}

int ip_to_int(const std::string& ip_str) {
  in_addr addr {};
  if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
    throw std::invalid_argument("Invalid IPv4 address: " + ip_str);
  }
  return static_cast<int>(ntohl(addr.s_addr));
}

std::string int_to_ip(uint32_t value) {
  in_addr addr {};
  addr.s_addr = htonl(value);
  char buf[INET_ADDRSTRLEN] = {0};
  if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
    throw std::runtime_error("inet_ntop failed");
  }
  return std::string(buf);
}

std::vector<uint8_t> ip_to_bytes(const std::string& ip_str) {
  const uint32_t ip = static_cast<uint32_t>(ip_to_int(ip_str));
  return {
      static_cast<uint8_t>((ip >> 24) & 0xFF),
      static_cast<uint8_t>((ip >> 16) & 0xFF),
      static_cast<uint8_t>((ip >> 8) & 0xFF),
      static_cast<uint8_t>(ip & 0xFF),
  };
}

int parse_tcp_flags(const std::string& flags_str) {
  static const std::map<std::string, int> names = {
      {"FIN", TCP_FIN}, {"SYN", TCP_SYN}, {"RST", TCP_RST}, {"PSH", TCP_PSH},
      {"ACK", TCP_ACK}, {"URG", TCP_URG}, {"ECE", TCP_ECE}, {"CWR", TCP_CWR},
  };
  static const std::map<char, int> compact = {
      {'F', TCP_FIN}, {'S', TCP_SYN}, {'R', TCP_RST}, {'P', TCP_PSH},
      {'A', TCP_ACK}, {'U', TCP_URG}, {'E', TCP_ECE}, {'C', TCP_CWR},
  };

  if (flags_str.empty()) return 0;
  std::string normalized = flags_str;
  for (char& c : normalized) {
    if (c == '+' || c == ',' || c == '/' || c == '|') {
      c = ' ';
    } else {
      c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
  }

  std::istringstream iss(normalized);
  std::string token;
  int result = 0;
  while (iss >> token) {
    const auto name_it = names.find(token);
    if (name_it != names.end()) {
      result |= name_it->second;
      continue;
    }
    size_t idx = 0;
    while (idx < token.size()) {
      bool matched = false;
      for (const auto& [name, value] : names) {
        if (token.compare(idx, name.size(), name) == 0) {
          result |= value;
          idx += name.size();
          matched = true;
          break;
        }
      }
      if (matched) continue;
      const auto compact_it = compact.find(token[idx]);
      if (compact_it != compact.end()) result |= compact_it->second;
      idx += 1;
    }
  }
  return result;
}

std::vector<uint8_t> build_tcp_options(
    const std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>>& options) {
  std::vector<uint8_t> out;
  for (const auto& [kind, value] : options) {
    switch (kind) {
      case TCP_OPT_EOL:
        append_u8(out, 0);
        break;
      case TCP_OPT_NOP:
        append_u8(out, 1);
        break;
      case TCP_OPT_MSS:
        append_u8(out, 2);
        append_u8(out, 4);
        append_be16(out, static_cast<uint16_t>(value ? value->first : 1460));
        break;
      case TCP_OPT_WSCALE:
        append_u8(out, 3);
        append_u8(out, 3);
        append_u8(out, static_cast<uint8_t>(value ? value->first : 7));
        break;
      case TCP_OPT_SACK_OK:
        append_u8(out, 4);
        append_u8(out, 2);
        break;
      case TCP_OPT_TIMESTAMP:
        append_u8(out, 8);
        append_u8(out, 10);
        append_be32(out, value ? value->first : rand_u32(1, 0xFFFFFFFFu));
        append_be32(out, value ? value->second : 0u);
        break;
      default:
        break;
    }
  }
  while (out.size() % 4 != 0) out.push_back(0);
  return out;
}

std::vector<uint8_t> build_ipv4_header(const std::string& src_ip,
                                       const std::string& dst_ip,
                                       int protocol,
                                       int payload_len,
                                       int ttl,
                                       int tos,
                                       int identification,
                                       uint16_t flags_frag,
                                       const std::vector<uint8_t>& options) {
  if (options.size() % 4 != 0) throw std::invalid_argument("IPv4 options must be 4-byte aligned");

  const uint32_t src = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst = static_cast<uint32_t>(ip_to_int(dst_ip));
  const int ihl = static_cast<int>((20 + options.size()) / 4);
  if (ihl < 5 || ihl > 15) throw std::invalid_argument("Invalid IPv4 IHL");

  std::vector<uint8_t> hdr;
  hdr.reserve(static_cast<size_t>(ihl * 4));
  append_u8(hdr, static_cast<uint8_t>((4 << 4) | ihl));
  append_u8(hdr, static_cast<uint8_t>(tos & 0xFF));
  append_be16(hdr, static_cast<uint16_t>(ihl * 4 + payload_len));
  append_be16(hdr, static_cast<uint16_t>(identification == 0 ? rand_int(0, 0xFFFF) : identification));
  append_be16(hdr, flags_frag);
  append_u8(hdr, static_cast<uint8_t>(ttl & 0xFF));
  append_u8(hdr, static_cast<uint8_t>(protocol & 0xFF));
  append_be16(hdr, 0);
  append_be32(hdr, src);
  append_be32(hdr, dst);
  hdr.insert(hdr.end(), options.begin(), options.end());
  write_be16(hdr, 10, checksum(hdr.data(), hdr.size()));
  return hdr;
}

std::vector<uint8_t> build_tcp_header(int src_port,
                                      int dst_port,
                                      uint32_t seq,
                                      uint32_t ack,
                                      int flags,
                                      int window,
                                      int urgent,
                                      const std::vector<uint8_t>& options_bytes,
                                      uint32_t src_ip_int,
                                      uint32_t dst_ip_int,
                                      const std::vector<uint8_t>& payload) {
  const size_t total_len = 20 + options_bytes.size();
  const uint8_t data_offset = static_cast<uint8_t>((total_len + 3) / 4);

  std::vector<uint8_t> hdr;
  hdr.reserve(static_cast<size_t>(data_offset) * 4);
  append_be16(hdr, static_cast<uint16_t>(src_port));
  append_be16(hdr, static_cast<uint16_t>(dst_port));
  append_be32(hdr, seq);
  append_be32(hdr, ack);
  append_be16(hdr, static_cast<uint16_t>((static_cast<uint16_t>(data_offset) << 12) | (flags & 0x1FF)));
  append_be16(hdr, static_cast<uint16_t>(window));
  append_be16(hdr, 0);
  append_be16(hdr, static_cast<uint16_t>(urgent));
  hdr.insert(hdr.end(), options_bytes.begin(), options_bytes.end());
  while (hdr.size() < static_cast<size_t>(data_offset) * 4) hdr.push_back(0);

  uint32_t s = pseudo_header_sum(src_ip_int, dst_ip_int, PROTO_TCP, static_cast<uint16_t>(hdr.size() + payload.size()));
  std::vector<uint8_t> l4 = hdr;
  l4.insert(l4.end(), payload.begin(), payload.end());
  if (l4.size() % 2 != 0) l4.push_back(0);
  for (size_t i = 0; i < l4.size(); i += 2) {
    s += (static_cast<uint32_t>(l4[i]) << 8) | static_cast<uint32_t>(l4[i + 1]);
  }
  write_be16(hdr, 16, finalize_sum(s));
  return hdr;
}

std::vector<uint8_t> build_udp_header(int src_port,
                                      int dst_port,
                                      const std::vector<uint8_t>& payload,
                                      uint32_t src_ip_int,
                                      uint32_t dst_ip_int,
                                      bool compute_checksum) {
  std::vector<uint8_t> hdr;
  hdr.reserve(8);
  append_be16(hdr, static_cast<uint16_t>(src_port));
  append_be16(hdr, static_cast<uint16_t>(dst_port));
  append_be16(hdr, static_cast<uint16_t>(8 + payload.size()));
  append_be16(hdr, 0);

  if (compute_checksum && (src_ip_int || dst_ip_int)) {
    uint32_t s = pseudo_header_sum(src_ip_int, dst_ip_int, PROTO_UDP, static_cast<uint16_t>(hdr.size() + payload.size()));
    std::vector<uint8_t> l4 = hdr;
    l4.insert(l4.end(), payload.begin(), payload.end());
    if (l4.size() % 2 != 0) l4.push_back(0);
    for (size_t i = 0; i < l4.size(); i += 2) {
      s += (static_cast<uint32_t>(l4[i]) << 8) | static_cast<uint32_t>(l4[i + 1]);
    }
    uint16_t cksum = finalize_sum(s);
    if (cksum == 0) cksum = 0xFFFFu;
    write_be16(hdr, 6, cksum);
  }
  return hdr;
}

std::vector<uint8_t> build_icmp_echo(int identifier, int sequence, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> hdr;
  hdr.reserve(8 + payload.size());
  append_u8(hdr, ICMP_ECHO_REQUEST_LOCAL);
  append_u8(hdr, 0);
  append_be16(hdr, 0);
  append_be16(hdr, static_cast<uint16_t>(identifier == 0 ? rand_int(0, 0xFFFF) : identifier));
  append_be16(hdr, static_cast<uint16_t>(sequence));
  hdr.insert(hdr.end(), payload.begin(), payload.end());
  write_be16(hdr, 2, checksum(hdr.data(), hdr.size()));
  return hdr;
}

std::vector<uint8_t> build_ethernet_header(const std::vector<uint8_t>& dst_mac,
                                           const std::vector<uint8_t>& src_mac,
                                           int ethertype) {
  if (dst_mac.size() != 6 || src_mac.size() != 6) {
    throw std::invalid_argument("MAC addresses must be 6 bytes");
  }
  std::vector<uint8_t> out;
  out.reserve(14);
  out.insert(out.end(), dst_mac.begin(), dst_mac.end());
  out.insert(out.end(), src_mac.begin(), src_mac.end());
  append_be16(out, static_cast<uint16_t>(ethertype));
  return out;
}

std::vector<uint8_t> build_dns_query(const std::string& qname,
                                     const std::string& qtype,
                                     bool recursive,
                                     bool edns,
                                     int transaction_id) {
  static const std::map<std::string, uint16_t> qtypes = {
      {"A", 1}, {"NS", 2},   {"CNAME", 5}, {"SOA", 6}, {"PTR", 12},
      {"MX", 15}, {"TXT", 16}, {"AAAA", 28}, {"SRV", 33}, {"ANY", 255},
  };

  std::vector<uint8_t> out;
  const uint16_t txid = static_cast<uint16_t>(transaction_id == 0 ? rand_int(0, 0xFFFF) : transaction_id);
  append_be16(out, txid);
  append_be16(out, static_cast<uint16_t>(DNS_QR_QUERY_LOCAL | (recursive ? DNS_QUERY_FLAG_LOCAL : 0)));
  append_be16(out, 1);
  append_be16(out, 0);
  append_be16(out, 0);
  append_be16(out, edns ? 1 : 0);

  std::string trimmed = qname;
  if (trimmed.empty() || trimmed == ".") {
    out.push_back(0);
  } else {
    if (!trimmed.empty() && trimmed.back() == '.') trimmed.pop_back();
    std::stringstream ss(trimmed);
    std::string label;
    while (std::getline(ss, label, '.')) {
      if (label.empty()) throw std::invalid_argument("Invalid DNS name with empty label");
      if (label.size() > 63) throw std::invalid_argument("DNS label too long");
      out.push_back(static_cast<uint8_t>(label.size()));
      out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
  }

  const auto it = qtypes.find(to_upper(qtype));
  append_be16(out, it == qtypes.end() ? 1 : it->second);
  append_be16(out, DNS_CLASS_IN_LOCAL);

  if (edns) {
    append_u8(out, 0);
    append_be16(out, 41);
    append_be16(out, 4096);
    append_be32(out, 0);
    append_be16(out, 0);
  }
  return out;
}
std::vector<OSProfile> os_profiles() { return profiles_ref(); }
}  // namespace ddos_samurai::cpu_native
