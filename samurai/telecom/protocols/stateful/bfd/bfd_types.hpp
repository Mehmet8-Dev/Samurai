#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace samurai::telecom::bfd {

// RFC 5881 UDP Ports
inline constexpr uint16_t BFD_CONTROL_PORT = 3784;
inline constexpr uint16_t BFD_ECHO_PORT    = 3785;

enum class BfdState : uint8_t {
    AdminDown = 0,
    Down      = 1,
    Init      = 2,
    Up        = 3
};

inline std::string_view BfdStateToString(BfdState s) noexcept {
    switch (s) {
        case BfdState::AdminDown: return "AdminDown";
        case BfdState::Down: return "Down";
        case BfdState::Init: return "Init";
        case BfdState::Up: return "Up";
        default: return "Unknown";
    }
}

enum class BfdDiag : uint8_t {
    None                        = 0,
    ControlDetectionTimeExpired = 1,
    EchoFailed                  = 2,
    NeighborSignaledDown        = 3,
    ForwardingPlaneReset        = 4,
    PathDown                    = 5,
    ConcatenatedPathDown        = 6,
    AdministrativelyDown        = 7,
    ReverseConcatenatedPathDown = 8
};

#pragma pack(push, 1)
struct BfdControlHeader {
    // vers_diag: 3 bits Version (1), 5 bits Diagnostic
    uint8_t  vers_diag;
    // sta_flags: 2 bits State (7-6), 1 bit P (5), 1 bit F (4), 1 bit C (3),
    //            1 bit A (2), 1 bit D (1), 1 bit M (0)
    uint8_t  sta_flags;
    uint8_t  detect_mult;           // Detect time multiplier (e.g. 3)
    uint8_t  length;                // Total header size (24 bytes)
    uint32_t my_discriminator;     // Local session discriminator (network order)
    uint32_t your_discriminator;   // Remote discriminator (network order)
    uint32_t min_tx_interval_us;   // Desired min TX interval in microseconds
    uint32_t min_rx_interval_us;   // Required min RX interval in microseconds
    uint32_t min_echo_rx_interval; // Required min Echo RX interval
};
#pragma pack(pop)
static_assert(sizeof(BfdControlHeader) == 24, "BfdControlHeader must be exactly 24 bytes");

struct BfdConfig {
    uint32_t desired_tx_interval_us{10000}; // Default 10ms fast heartbeat
    uint32_t required_rx_interval_us{10000};// Default 10ms
    uint8_t  detect_multiplier{3};          // 3 x 10ms = 30ms detection time
    uint32_t local_disc{0x10000001};
    uint8_t  dscp{0xC0};                    // CS6 (RFC 5881)
    bool     demand_mode{false};
};

struct BfdSessionConfig {
    std::string local_ip{"192.168.1.100"};
    std::string remote_ip{"192.168.1.1"};
    std::string local_mac{"00:11:22:33:44:55"};
    std::string remote_mac{"00:aa:bb:cc:dd:ee"};
    uint16_t udp_src_port{49152};           // Dynamic source port (RFC 5881: 49152..65535)
    uint16_t udp_dst_port{3784};            // Single-hop BFD destination port (RFC 5881)
    uint32_t desired_tx_interval_us{10000}; // Default 10ms transmit interval
    uint32_t required_rx_interval_us{10000};// Default 10ms receive interval
    uint8_t  detect_multiplier{3};          // 3 x 10ms = 30ms detection time
    uint32_t local_disc{0x10000001};        // Local session discriminator
};

} // namespace samurai::telecom::bfd
