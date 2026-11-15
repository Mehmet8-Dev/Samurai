#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace samurai::l7_emu_native::l2l3 {

class ArpEngine {
 public:
  ArpEngine() = default;
  ~ArpEngine() = default;

  void send_arp_request(const std::string& target_ip);
  void send_arp_request(const std::string& src_mac, const std::string& src_ip, const std::string& target_ip);
  void process_arp_reply(const std::string& sender_ip, const std::string& sender_mac);
  std::string get_mac(const std::string& target_ip) const;
  bool is_resolved(const std::string& target_ip) const;

  // Byte-level binary serialization routines
  static std::vector<uint8_t> build_arp_request(
      const std::string& src_mac, const std::string& src_ip, const std::string& target_ip);
  static std::vector<uint8_t> build_arp_reply(
      const std::string& src_mac, const std::string& src_ip,
      const std::string& dst_mac, const std::string& dst_ip);
  static bool parse_arp_packet(
      const uint8_t* data, size_t len,
      std::string& out_sender_ip, std::string& out_sender_mac, uint16_t& out_op);

  const std::vector<uint8_t>& last_tx_packet() const { return last_tx_packet_; }

 private:
  std::unordered_map<std::string, std::string> arp_cache_;
  std::vector<uint8_t> last_tx_packet_;
};

}  // namespace samurai::l7_emu_native::l2l3
