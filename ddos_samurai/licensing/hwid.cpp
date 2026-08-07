#include "hwid.hpp"

#include <dirent.h>
#include <fstream>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/sha.h>

namespace samurai::licensing {

namespace {

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

// CPU model name from /proc/cpuinfo (best-effort).
std::string CpuId() {
  std::ifstream f("/proc/cpuinfo");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("model name", 0) == 0) {
      const auto colon = line.find(':');
      if (colon != std::string::npos) return Strip(line.substr(colon + 1));
    }
  }
  struct utsname u{};
  if (uname(&u) == 0 && u.machine[0]) return std::string(u.machine);
  return "unknown-cpu";
}

// First non-loopback interface MAC from /sys/class/net/*/address.
std::string PrimaryMac() {
  DIR* d = ::opendir("/sys/class/net");
  if (!d) return "fallback-mac";
  std::string best;
  struct dirent* e;
  while ((e = ::readdir(d)) != nullptr) {
    const std::string name = e->d_name;
    if (name == "." || name == ".." || name == "lo") continue;
    std::ifstream f(std::string("/sys/class/net/") + name + "/address");
    std::string mac;
    if (f && std::getline(f, mac)) {
      mac = Strip(mac);
      if (!mac.empty() && mac != "00:00:00:00:00:00") {
        best = mac;
        break;
      }
    }
  }
  ::closedir(d);
  return best.empty() ? "fallback-mac" : best;
}

std::string Sha256Hex(const std::string& data) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char b : digest) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

}  // namespace

std::string GetHardwareId() {
  std::string hostname = "unknown-host";
  char hbuf[256] = {0};
  if (::gethostname(hbuf, sizeof(hbuf) - 1) == 0 && hbuf[0]) hostname = hbuf;

  std::string system = "unknown-os";
  struct utsname u{};
  if (uname(&u) == 0 && u.sysname[0]) system = u.sysname;

  const std::string fingerprint = CpuId() + "|" + PrimaryMac() + "|" + hostname + "|" + system;
  return Sha256Hex(fingerprint);
}

}  // namespace samurai::licensing
