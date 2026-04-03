#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;
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

  if (auto ip = try_probe(target_ip)) return *ip;
  if (auto ip = try_probe("8.8.8.8")) return *ip;

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
        if (out != "0.0.0.0") return out;
      }
      freeaddrinfo(res);
    }
  }
  return "127.0.0.1";
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
}  // namespace ddos_samurai::cpu_native
