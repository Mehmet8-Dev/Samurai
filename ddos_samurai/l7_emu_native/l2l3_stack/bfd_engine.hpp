#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace ddos_samurai::l7_emu_native::l2l3 {

enum class BfdState : uint8_t {
  AdminDown = 0,
  Down = 1,
  Init = 2,
  Up = 3
};

enum class BfdDiag : uint8_t {
  None = 0,
  ControlDetectionTimeExpired = 1,
  EchoFailed = 2,
  NeighborSignaledDown = 3,
  ForwardingPlaneReset = 4,
  PathDown = 5,
  ConcatenatedPathDown = 6,
  AdministrativelyDown = 7,
  ReverseConcatenatedPathDown = 8
};

#pragma pack(push, 1)
struct BfdControlHeader {
  // vers_diag: 3 bits Version (1), 5 bits Diagnostic
  uint8_t vers_diag;
  // sta_flags: 2 bits State, 1 bit P (Poll), 1 bit F (Final), 1 bit C (CPI),
  //            1 bit A (Auth), 1 bit D (Demand), 1 bit M (Multipoint)
  uint8_t sta_flags;
  uint8_t detect_mult;           // Detect time multiplier (e.g. 3)
  uint8_t length;                // Total header size (24 bytes)
  uint32_t my_discriminator;     // Local session discriminator (network order)
  uint32_t your_discriminator;   // Remote discriminator (network order)
  uint32_t min_tx_interval_us;   // Desired min TX interval in microseconds
  uint32_t min_rx_interval_us;   // Required min RX interval in microseconds
  uint32_t min_echo_rx_interval; // Required min Echo RX interval
};
#pragma pack(pop)
static_assert(sizeof(BfdControlHeader) == 24, "BfdControlHeader must be exactly 24 bytes");

struct BfdSessionConfig {
  std::string local_ip{"192.168.1.100"};
  std::string remote_ip{"192.168.1.1"};
  std::string local_mac{"00:11:22:33:44:55"};
  std::string remote_mac{"00:aa:bb:cc:dd:ee"};
  uint16_t udp_src_port{49152};           // Dynamic source port (RFC 5881: 49152..65535)
  uint16_t udp_dst_port{3784};            // Single-hop BFD destination port (RFC 5881)
  uint32_t desired_tx_interval_us{10000}; // Default 10ms transmit interval
  uint32_t required_rx_interval_us{10000};// Default 10ms receive interval
  uint8_t detect_multiplier{3};           // 3 x 10ms = 30ms detection time
  uint32_t local_disc{0x10000001};        // Local session discriminator
};

class BfdEngine {
 public:
  BfdEngine() = default;
  ~BfdEngine() = default;

  void start_session(const BfdSessionConfig& cfg);
  void stop_session();

  // Process incoming BFD UDP control packet and advance state machine
  bool process_rx_packet(const uint8_t* data, size_t len, uint64_t now_tsc);

  // Periodic tick: evaluates TX timer (sends keepalive if due) and RX detection timeout
  bool step_timer(uint64_t now_tsc, uint64_t tsc_hz);

  // State inspection
  BfdState current_state() const noexcept { return state_; }
  bool is_up() const noexcept { return state_ == BfdState::Up; }
  bool has_failed() const noexcept { return failover_triggered_; }
  void reset_failover_flag() noexcept { failover_triggered_ = false; }
  uint32_t remote_discriminator() const noexcept { return remote_disc_; }

  // Binary serialization & parsing helpers
  static std::vector<uint8_t> build_bfd_control_packet(
      const BfdSessionConfig& cfg, BfdState state, BfdDiag diag,
      uint32_t remote_disc, bool poll = false, bool final_flag = false);

  static bool parse_bfd_control_packet(
      const uint8_t* data, size_t len,
      BfdControlHeader& out_hdr, uint32_t& out_remote_disc);

  const std::vector<uint8_t>& last_tx_packet() const noexcept { return last_tx_packet_; }

 private:
  BfdSessionConfig cfg_{};
  BfdState state_{BfdState::Down};
  BfdDiag local_diag_{BfdDiag::None};
  uint32_t remote_disc_{0};
  uint32_t negotiated_rx_us_{10000};
  uint32_t negotiated_tx_us_{10000};

  uint64_t last_tx_tsc_{0};
  uint64_t last_rx_tsc_{0};
  uint64_t detection_time_tsc_{0};
  bool failover_triggered_{false};
  bool is_active_{false};

  std::vector<uint8_t> last_tx_packet_;
};

}  // namespace ddos_samurai::l7_emu_native::l2l3
