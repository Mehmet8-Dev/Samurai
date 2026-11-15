#pragma once

#include <cstdint>

namespace samurai::telecom::pppoe {

inline constexpr uint16_t ETHERTYPE_PPPOE_DISCOVERY = 0x8863;
inline constexpr uint16_t ETHERTYPE_PPPOE_SESSION   = 0x8864;

inline constexpr uint16_t PPP_PROTOCOL_LCP   = 0xC021;
inline constexpr uint16_t PPP_PROTOCOL_PAP   = 0xC023;
inline constexpr uint16_t PPP_PROTOCOL_CHAP  = 0xC223;
inline constexpr uint16_t PPP_PROTOCOL_IPCP  = 0x8021;
inline constexpr uint16_t PPP_PROTOCOL_IPV6CP= 0x8057;
inline constexpr uint16_t PPP_PROTOCOL_IPV4  = 0x0021;

enum class PppoeCode : uint8_t {
    DATA = 0x00,
    PADO = 0x07,
    PADI = 0x09,
    PADR = 0x19,
    PADS = 0x65,
    PADT = 0xA7
};

enum class LcpCode : uint8_t {
    CONF_REQ  = 1,
    CONF_ACK  = 2,
    CONF_NAK  = 3,
    CONF_REJ  = 4,
    TERM_REQ  = 5,
    TERM_ACK  = 6,
    CODE_REJ  = 7,
    PROT_REJ  = 8,
    ECHO_REQ  = 9,
    ECHO_REP  = 10,
    DISC_REQ  = 11
};

enum class PapCode : uint8_t {
    AUTH_REQ = 1,
    AUTH_ACK = 2,
    AUTH_NAK = 3
};

enum class ChapCode : uint8_t {
    CHALLENGE = 1,
    RESPONSE  = 2,
    SUCCESS   = 3,
    FAILURE   = 4
};

enum class PppoeTagType : uint16_t {
    END_OF_LIST        = 0x0000,
    SERVICE_NAME       = 0x0101,
    AC_NAME            = 0x0102,
    HOST_UNIQ          = 0x0103,
    AC_COOKIE          = 0x0104,
    VENDOR_SPECIFIC    = 0x0105,
    RELAY_SESSION_ID   = 0x0110,
    SERVICE_NAME_ERROR = 0x0201,
    AC_SYSTEM_ERROR    = 0x0202,
    GENERIC_ERROR      = 0x0203
};

inline constexpr uint8_t LCP_OPT_MRU   = 1;
inline constexpr uint8_t LCP_OPT_AUTH  = 3;
inline constexpr uint8_t LCP_OPT_MAGIC = 5;

inline constexpr uint8_t IPCP_OPT_IP            = 3;
inline constexpr uint8_t IPCP_OPT_PRIMARY_DNS   = 129;
inline constexpr uint8_t IPCP_OPT_SECONDARY_DNS = 131;

#pragma pack(push, 1)

struct PppoeHeader {
    uint8_t  ver_type;    // Upper 4 bits = version (1), lower 4 bits = type (1) -> 0x11
    uint8_t  code;        // PppoeCode
    uint16_t session_id;  // Network byte order
    uint16_t length;      // Payload length (excluding this 6-byte header)
};

struct PppoeTag {
    uint16_t type;        // Network byte order
    uint16_t length;      // Network byte order
};

struct PppHeader {
    uint16_t protocol;    // Network byte order (e.g. 0xC021, 0x8021)
};

struct PppControlHeader {
    uint8_t  code;        // Conf-Req, Conf-Ack, etc.
    uint8_t  identifier;  // Transaction ID
    uint16_t length;      // Length of control frame including this header
};

struct PppOptionHeader {
    uint8_t type;
    uint8_t length;       // Total length including type & length bytes
};

#pragma pack(pop)

static_assert(sizeof(PppoeHeader) == 6, "PppoeHeader tam 6 bayt olmalidir");
static_assert(sizeof(PppoeTag) == 4, "PppoeTag tam 4 bayt olmalidir");
static_assert(sizeof(PppHeader) == 2, "PppHeader tam 2 bayt olmalidir");
static_assert(sizeof(PppControlHeader) == 4, "PppControlHeader tam 4 bayt olmalidir");

} // namespace samurai::telecom::pppoe
