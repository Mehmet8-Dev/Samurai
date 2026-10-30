#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace ddos_samurai::telecom::sip_rtp {

constexpr uint16_t SIP_STANDARD_PORT = 5060;
constexpr uint16_t RTP_BASE_PORT     = 10000;

// SIP Metotları
enum class SipMethod : uint8_t {
    UNKNOWN = 0,
    INVITE,
    ACK,
    BYE,
    CANCEL,
    REGISTER,
    OPTIONS
};

// SIP FSM Durumları (RFC 3261 & RFC 2617)
enum class SipCallState : uint8_t {
    IDLE = 0,
    CALLING,        // INVITE gönderildi
    AUTHENTICATING, // 401/407 Unauthorized alındı, Authorization ile yeni INVITE gönderildi
    PROCEEDING,     // 100 Trying veya 180 Ringing alındı
    ESTABLISHED,    // 200 OK alındı, ACK gönderildi (Medya/RTP aktif)
    TERMINATING,    // BYE gönderildi
    TERMINATED,     // 200 OK (BYE) alındı veya arama sonlandı
    FAILED
};

#pragma pack(push, 1)

// RTP Fixed Header (12 Bayt - RFC 3550 Section 5.1)
struct RtpHeader {
    uint8_t  v_p_x_cc;       // 2 bit Version (2), 1 bit Padding, 1 bit Extension, 4 bit CC (0)
    uint8_t  m_pt;           // 1 bit Marker, 7 bit Payload Type (0=PCMU G.711u)
    uint16_t seq_number;     // Sequence Number (network byte order)
    uint32_t timestamp;      // Timestamp (network byte order, 8000 Hz = 160 per 20ms)
    uint32_t ssrc;           // Synchronization Source Identifier (network byte order)
};
static_assert(sizeof(RtpHeader) == 12, "RtpHeader must be 12 bytes");

#pragma pack(pop)

struct SipCallConfig {
    std::string from_uri{"sip:alice@samurai.local"};
    std::string to_uri{"sip:bob@ims.operator.net"};
    std::string call_id{"samurai-call-1001@client.local"};
    std::string local_ip_str{"10.0.0.1"};
    std::string peer_ip_str{"10.0.0.2"};

    uint32_t local_ip{0};
    uint32_t peer_ip{0};
    uint16_t local_sip_port{SIP_STANDARD_PORT};
    uint16_t peer_sip_port{SIP_STANDARD_PORT};
    uint16_t local_rtp_port{RTP_BASE_PORT};
    uint16_t peer_rtp_port{RTP_BASE_PORT};

    uint8_t  local_mac[6]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t  peer_mac[6]{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint16_t vlan_s{0};
    uint16_t vlan_c{0};

    uint32_t ssrc{0x12345678};
    uint8_t  payload_type{0}; // 0 = PCMU (G.711 u-law 64 kbps)
    uint32_t ptime_ms{20};    // 20ms packetization interval
    uint32_t sample_rate{8000};

    // SIP Digest Kimlik Doğrulama Parametreleri (RFC 2617 & RFC 3261)
    std::string auth_username{"alice"};
    std::string auth_password{"secret123"};
    std::string auth_cnonce{"0a4f113b"};
    uint32_t    auth_nc{1};

    // SRTP Medya Şifreleme Parametreleri (RFC 3711)
    bool    enable_srtp{false};
    uint8_t master_key[16]{0};
    uint8_t master_salt[14]{0};
};

// RFC 3550 Jitter İstatistikleri
struct RtpJitterStats {
    uint32_t packets_received{0};
    uint32_t packets_lost{0};
    uint32_t last_rtp_timestamp{0};
    uint64_t last_arrival_tsc{0};
    double   jitter_us{0.0};
};

} // namespace ddos_samurai::telecom::sip_rtp
