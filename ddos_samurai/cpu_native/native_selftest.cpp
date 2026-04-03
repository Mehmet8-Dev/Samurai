#include "engine.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace ddos_samurai::cpu_native;

static uint16_t read_be16(const std::vector<uint8_t>& buf, size_t off) {
  return static_cast<uint16_t>((static_cast<uint16_t>(buf[off]) << 8) | static_cast<uint16_t>(buf[off + 1]));
}

int main() {
  auto iphdr = build_ipv4_header("192.0.2.1", "198.51.100.2", PROTO_TCP, 20, 64, 0, 0x1234, 0x4000, {});
  if (iphdr.size() != 20) {
    std::cerr << "ipv4 header size mismatch\n";
    return 1;
  }

  bool threw = false;
  try {
    (void)build_ipv4_header("192.0.2.1", "198.51.100.2", PROTO_TCP, 20, 64, 0, 0x1234, 0x4000, {1, 2, 3});
  } catch (const std::invalid_argument&) {
    threw = true;
  }
  if (!threw) {
    std::cerr << "misaligned options should throw\n";
    return 2;
  }

  const auto subnet_ip = generate_ip_from_subnet("203.0.113.10/31");
  if (subnet_ip != "203.0.113.10" && subnet_ip != "203.0.113.11") {
    std::cerr << "subnet /31 generation escaped subnet\n";
    return 3;
  }

  PacketConfig cfg;
  cfg.target_ip = "8.8.8.8";
  cfg.target_port = 53;
  cfg.protocol = "udp";
  cfg.payload = std::vector<uint8_t>(600, 'Q');
  cfg.has_payload = true;
  auto pkt = create_packet(cfg);
  pkt[6] = 0x20;
  pkt[7] = 0x20;
  auto frags = fragment_packet(pkt, 200);
  if (frags.empty()) {
    std::cerr << "fragmentation returned no fragments\n";
    return 4;
  }
  if ((read_be16(frags.front(), 6) & 0x1FFFu) != 32u) {
    std::cerr << "fragment base offset not preserved\n";
    return 5;
  }

  auto owner = generate_packet_pool_view(cfg, 32, true, true);
  if (owner.packet_size == 0 || owner.size() != owner.packet_size * 32) {
    std::cerr << "pool owner invalid\n";
    return 6;
  }

  std::cout << "cpu_native selftest ok\n";
  return 0;
}
