#pragma once

#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"

#include <cstdint>
#include <cstddef>

namespace ddos_samurai::telecom {

enum class TelcoFrameType : uint8_t {
    Unknown = 0,
    Arp = 1,
    Dhcp = 2,
    Icmpv6Nd = 3,
    Igmp = 4,
    Bfd = 5,
    PppoeDiscovery = 6,
    PppoeSession = 7,
    Eapol = 8,
    Gtpu = 9,
    Pfcp = 10,
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
               type == TelcoFrameType::Pfcp;
    }

    // Nanometrik hizda calisan donanim/mbuf ayrıştırıcı
    static bool Classify(const uint8_t* frame, size_t len, 
                         PacketMetadata& meta, 
                         TelcoFrameType& out_type) noexcept;
};

} // namespace ddos_samurai::telecom
