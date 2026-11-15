#pragma once

#include "samurai/telecom/core/telco_protocol_if.hpp"

#include <cstdint>
#include <cstddef>

namespace samurai::telecom {

enum class TelcoFrameType : uint8_t {
    Unknown = 0,
    None = 0,
    Arp = 1,
    Dhcp = 2,
    Icmpv6Nd = 3,
    Igmp = 4,
    Bfd = 5,
    PppoeDiscovery = 6,
    Pppoe = 6,
    PppoeSession = 7,
    Eapol = 8,
    Gtpu = 9,
    Pfcp = 10,
    Sctp = 11,
    Diameter = 12,
    Sip = 13,
    Rtp = 14,
    Ipv4Data = 20,
    Ipv6Data = 21
};

class FastpathClassifier {
public:
    static inline bool IsControlFrame(TelcoFrameType type) noexcept {
        return type == TelcoFrameType::Arp ||
               type == TelcoFrameType::Dhcp ||
               type == TelcoFrameType::Icmpv6Nd ||
               type == TelcoFrameType::Igmp ||
               type == TelcoFrameType::Bfd ||
               type == TelcoFrameType::PppoeDiscovery ||
               type == TelcoFrameType::PppoeSession ||
               type == TelcoFrameType::Eapol ||
               type == TelcoFrameType::Pfcp ||
               type == TelcoFrameType::Sctp ||
               type == TelcoFrameType::Diameter ||
               type == TelcoFrameType::Sip ||
               type == TelcoFrameType::Rtp;
    }

    // Nanometrik hizda calisan donanim/mbuf ayrıştırıcı
    static bool Classify(const uint8_t* frame, size_t len, 
                         PacketMetadata& meta, 
                         TelcoFrameType& out_type) noexcept;
};

} // namespace samurai::telecom
