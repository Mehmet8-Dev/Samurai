#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace ddos_samurai::l7_emu_native::l2l3 {

class IgmpEngine {
 public:
  IgmpEngine() = default;
  ~IgmpEngine() = default;

  void join_group(const std::string& group_ip, int version = 2);
  void leave_group(const std::string& group_ip, int version = 2);
  bool is_member(const std::string& group_ip) const;

  // Byte-level binary packet builder routines
  static std::vector<uint8_t> build_igmp_report(
      const std::string& group_ip, int version, const std::string& src_ip = "10.0.0.1");
  static std::vector<uint8_t> build_igmp_leave(
      const std::string& group_ip, int version, const std::string& src_ip = "10.0.0.1");

  const std::vector<uint8_t>& last_tx_packet() const { return last_tx_packet_; }

 private:
  std::unordered_set<std::string> active_groups_;
  std::vector<uint8_t> last_tx_packet_;
};

}  // namespace ddos_samurai::l7_emu_native::l2l3

