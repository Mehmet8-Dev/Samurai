#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ddos_samurai::l7_emu_native::l2l3 {

enum class DhcpState {
  Init,
  Selecting,
  Requesting,
  Bound,
  Renewing,
  Rebinding
};

struct DhcpConfig {
  std::string client_mac;
  int version{4}; // 4 or 6
  uint32_t xid{0x12345678};
};

class DhcpStateMachine {
 public:
  DhcpStateMachine() = default;
  ~DhcpStateMachine() = default;

  void start(const DhcpConfig& config);
  void process_offer(const std::string& offered_ip = "", const std::string& server_ip = "");
  void process_ack(const std::string& acked_ip = "");
  DhcpState current_state() const { return state_; }
  std::string acquired_ip() const { return ip_; }
  std::string server_ip() const { return server_ip_; }
  uint32_t xid() const { return config_.xid; }

  // Byte-level binary packet builders & parsers
  static std::vector<uint8_t> build_dhcp_discover(
      const std::string& client_mac, uint32_t xid);
  static std::vector<uint8_t> build_dhcp_request(
      const std::string& client_mac, uint32_t xid,
      const std::string& requested_ip, const std::string& server_ip);
  static bool parse_dhcp_packet(
      const uint8_t* data, size_t len,
      uint32_t& out_xid, std::string& out_yiaddr,
      std::string& out_server_ip, int& out_msg_type);

  const std::vector<uint8_t>& last_tx_packet() const { return last_tx_packet_; }

 private:
  DhcpState state_{DhcpState::Init};
  DhcpConfig config_;
  std::string ip_{""};
  std::string server_ip_{""};
  std::vector<uint8_t> last_tx_packet_;
};

}  // namespace ddos_samurai::l7_emu_native::l2l3

