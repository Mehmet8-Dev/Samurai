#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace ddos_samurai::telecom::diameter {

constexpr uint16_t DIAMETER_STANDARD_PORT = 3868;

// Diameter Command Codes (RFC 6733 & RFC 4006)
constexpr uint32_t CMD_CAPABILITIES_EXCHANGE = 257; // CER / CEA
constexpr uint32_t CMD_DEVICE_WATCHDOG       = 280; // DWR / DWA
constexpr uint32_t CMD_DISCONNECT_PEER       = 282; // DPR / DPA
constexpr uint32_t CMD_CREDIT_CONTROL        = 272; // CCR / CCA (3GPP Ro / Gy / Gx)
constexpr uint32_t CMD_RE_AUTH               = 258; // RAR / RAA
constexpr uint32_t CMD_ABORT_SESSION         = 274; // ASR / ASA
constexpr uint32_t CMD_SESSION_TERMINATION   = 275; // STR / STA

// Diameter Application Identifiers
constexpr uint32_t APP_DIAMETER_BASE_COMMON   = 0;
constexpr uint32_t APP_DIAMETER_CREDIT_CONTROL = 4;        // RFC 4006
constexpr uint32_t APP_3GPP_GX                 = 16777238; // 3GPP TS 29.212
constexpr uint32_t APP_3GPP_GY_RO              = 4;        // 3GPP TS 32.299

// 3GPP Vendor ID
constexpr uint32_t VENDOR_ID_3GPP = 10415;

// Standard Diameter AVP Codes
constexpr uint32_t AVP_USER_NAME              = 1;
constexpr uint32_t AVP_HOST_IP_ADDRESS        = 257;
constexpr uint32_t AVP_AUTH_APPLICATION_ID    = 258;
constexpr uint32_t AVP_SESSION_ID             = 263;
constexpr uint32_t AVP_ORIGIN_HOST            = 264;
constexpr uint32_t AVP_SUPPORTED_VENDOR_ID    = 265;
constexpr uint32_t AVP_VENDOR_ID              = 266;
constexpr uint32_t AVP_RESULT_CODE            = 268;
constexpr uint32_t AVP_PRODUCT_NAME           = 269;
constexpr uint32_t AVP_DISCONNECT_CAUSE       = 273;
constexpr uint32_t AVP_DESTINATION_REALM      = 283;
constexpr uint32_t AVP_DESTINATION_HOST       = 293;
constexpr uint32_t AVP_ORIGIN_REALM           = 296;
constexpr uint32_t AVP_CC_REQUEST_NUMBER      = 415;
constexpr uint32_t AVP_CC_REQUEST_TYPE        = 416;

// CC-Request-Type Değerleri (RFC 4006)
enum class CcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Result-Code Değerleri (RFC 6733)
constexpr uint32_t RESULT_DIAMETER_SUCCESS             = 2001;
constexpr uint32_t RESULT_DIAMETER_COMMAND_UNSUPPORTED = 3001;
constexpr uint32_t RESULT_DIAMETER_UNABLE_TO_DELIVER   = 3002;
constexpr uint32_t RESULT_DIAMETER_REALM_NOT_SERVED    = 3003;
constexpr uint32_t RESULT_DIAMETER_TOO_BUSY            = 3004;

// Diameter Peer FSM Durumları (RFC 6733)
enum class DiameterPeerState : uint8_t {
    CLOSED = 0,
    WAIT_CONN_ACK,
    WAIT_I_CEA,     // CER gönderildi, CEA bekleniyor
    OPEN,           // CER/CEA başarılı; veri akışı ve CCR/CCA serbest
    SUSPECT,        // DWR zaman aşımı
    CLOSING,        // DPR gönderildi
    FAILED
};

#pragma pack(push, 1)

// Diameter Header (20 Bayt - RFC 6733 Section 3)
struct DiameterHeader {
    uint8_t  version;             // Version 1
    uint8_t  length[3];           // 24-bit Message Length (dahil 20 bayt header)
    uint8_t  command_flags;       // R, P, E, T flags
    uint8_t  command_code[3];     // 24-bit Command Code
    uint32_t application_id;      // Application-ID (network byte order)
    uint32_t hop_by_hop_id;       // Hop-by-Hop Identifier (network byte order)
    uint32_t end_to_end_id;       // End-to-End Identifier (network byte order)
};
static_assert(sizeof(DiameterHeader) == 20, "DiameterHeader must be 20 bytes");

// AVP Header (8 Bayt - RFC 6733 Section 4.1)
struct AvpHeader {
    uint32_t avp_code;            // AVP Code (network byte order)
    uint8_t  avp_flags;           // V, M, P flags
    uint8_t  avp_length[3];       // 24-bit AVP Length
};
static_assert(sizeof(AvpHeader) == 8, "AvpHeader must be 8 bytes");

#pragma pack(pop)

struct DiameterPeerConfig {
    std::string origin_host{"samurai.client.local"};
    std::string origin_realm{"client.local"};
    std::string destination_host{"hss.epc.mnc001.mcc001.3gppnetwork.org"};
    std::string destination_realm{"epc.mnc001.mcc001.3gppnetwork.org"};
    std::string product_name{"DDoSamurai-Diameter"};
    uint32_t vendor_id{VENDOR_ID_3GPP};

    uint32_t local_ip{0};
    uint32_t peer_ip{0};
    uint16_t local_port{13868};
    uint16_t peer_port{DIAMETER_STANDARD_PORT};
    uint8_t  local_mac[6]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t  peer_mac[6]{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint16_t vlan_s{0};
    uint16_t vlan_c{0};

    uint32_t watchdog_interval_ms{5000};
    uint32_t retransmit_timeout_ms{1000};
    uint16_t max_retries{3};
};

} // namespace ddos_samurai::telecom::diameter
