#include "net_utils.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.hpp"

namespace samurai::core {

namespace {

constexpr const char* kBroadcastMac = "ff:ff:ff:ff:ff:ff";

std::string ToLower(const std::string& s) {
  std::string out = s;
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

// Read the default-route gateway IPv4 (dotted) from /proc/net/route. Columns:
// Iface Destination Gateway Flags ... — destination 00000000 marks the default
// route; Gateway is a little-endian hex u32. Returns "" if none found.
std::string DefaultGatewayIp() {
  std::ifstream route("/proc/net/route");
  if (!route) return "";

  std::string line;
  std::getline(route, line);  // header
  while (std::getline(route, line)) {
    std::istringstream iss(line);
    std::string iface, dest_hex, gw_hex;
    if (!(iss >> iface >> dest_hex >> gw_hex)) continue;
    if (dest_hex != "00000000") continue;  // only the default route

    std::uint32_t gw_le = 0;
    if (std::sscanf(gw_hex.c_str(), "%x", &gw_le) != 1 || gw_le == 0) continue;
    // /proc stores the address in network-host little-endian; the four octets
    // are already in network order for inet_ntop when read as-is.
    in_addr addr{};
    addr.s_addr = gw_le;
    char buf[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return std::string(buf);
  }
  return "";
}

// Look up `ip`'s MAC in the ARP cache (/proc/net/arp). Columns:
// IP address, HW type, Flags, HW address, Mask, Device. Returns "" if absent
// or all-zero.
std::string ArpLookup(const std::string& ip) {
  std::ifstream arp("/proc/net/arp");
  if (!arp) return "";

  std::string line;
  std::getline(arp, line);  // header
  while (std::getline(arp, line)) {
    std::istringstream iss(line);
    std::string ip_col, hw_type, flags, mac_col;
    if (!(iss >> ip_col >> hw_type >> flags >> mac_col)) continue;
    if (ip_col != ip) continue;
    const std::string mac = ToLower(mac_col);
    if (!mac.empty() && mac != "00:00:00:00:00:00") return mac;
  }
  return "";
}

}  // namespace

std::string GetLocalIp() {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0) {
    sockaddr_in probe{};
    probe.sin_family = AF_INET;
    probe.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &probe.sin_addr);  // route selection only
    // UDP connect emits no packets; it only picks a source route.
    if (::connect(fd, reinterpret_cast<sockaddr*>(&probe), sizeof(probe)) == 0) {
      sockaddr_in local{};
      socklen_t len = sizeof(local);
      if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
        char buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf)) && buf[0]) {
          ::close(fd);
          return std::string(buf);
        }
      }
    }
    ::close(fd);
  }

  // Fallback: resolve the host name.
  char host[256] = {0};
  if (::gethostname(host, sizeof(host) - 1) == 0) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host, nullptr, &hints, &res) == 0 && res) {
      char buf[INET_ADDRSTRLEN] = {0};
      auto* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
      const bool ok = inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) && buf[0];
      std::string out = ok ? std::string(buf) : std::string("127.0.0.1");
      ::freeaddrinfo(res);
      return out;
    }
  }
  return "127.0.0.1";
}

std::string GetGatewayMac(const std::string& target_ip) {
  // If the target is directly reachable and present in the ARP cache, prefer
  // its own MAC; otherwise fall back to the default gateway.
  if (!target_ip.empty()) {
    const std::string direct = ArpLookup(target_ip);
    if (!direct.empty()) {
      LogInfo("Gateway MAC found: " + direct);
      return direct;
    }
  }

  const std::string gw = DefaultGatewayIp();
  if (gw.empty()) {
    LogWarning("Gateway IP not found; falling back to broadcast MAC.");
    return kBroadcastMac;
  }

  const std::string mac = ArpLookup(gw);
  if (!mac.empty()) {
    LogInfo("Gateway MAC found: " + mac);
    return mac;
  }

  LogWarning("ARP reply not received; falling back to broadcast MAC.");
  return kBroadcastMac;
}

std::uint64_t MacToInt(const std::string& mac) {
  std::uint64_t value = 0;
  int nibbles = 0;
  for (char c : mac) {
    if (c == ':' || c == '-') continue;
    int digit;
    if (c >= '0' && c <= '9') {
      digit = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      digit = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      digit = c - 'A' + 10;
    } else {
      return 0;  // malformed
    }
    value = (value << 4) | static_cast<std::uint64_t>(digit);
    ++nibbles;
  }
  return nibbles == 12 ? value : 0;
}

}  // namespace samurai::core
