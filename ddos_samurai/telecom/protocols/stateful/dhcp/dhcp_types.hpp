#pragma once

#include <cstdint>
#include <cstddef>

namespace ddos_samurai::telecom::dhcp {

// UDP Ports
inline constexpr uint16_t DHCPV4_SERVER_PORT = 67;
inline constexpr uint16_t DHCPV4_CLIENT_PORT = 68;
inline constexpr uint16_t DHCPV6_SERVER_PORT = 547;
inline constexpr uint16_t DHCPV6_CLIENT_PORT = 546;

// DHCPv4 Constants
inline constexpr uint32_t DHCPV4_MAGIC_COOKIE = 0x63825363; // Network byte order or check ntohl
inline constexpr uint8_t  DHCPV4_HTYPE_ETHERNET = 1;
inline constexpr uint8_t  DHCPV4_HLEN_ETHERNET  = 6;

enum class Dhcpv4Op : uint8_t {
    BOOTREQUEST = 1,
    BOOTREPLY   = 2
};

enum class Dhcpv4MsgType : uint8_t {
    DISCOVER = 1,
    OFFER    = 2,
    REQUEST  = 3,
    DECLINE  = 4,
    ACK      = 5,
    NAK      = 6,
    RELEASE  = 7,
    INFORM   = 8
};

enum class Dhcpv4Option : uint8_t {
    PAD                 = 0,
    SUBNET_MASK         = 1,
    ROUTER              = 3,
    DNS_SERVERS         = 6,
    HOST_NAME           = 12,
    DOMAIN_NAME         = 15,
    REQUESTED_IP        = 50,
    LEASE_TIME          = 51,
    OPTION_OVERLOAD     = 52,
    MSG_TYPE            = 53,
    SERVER_IDENTIFIER   = 54,
    PARAM_REQ_LIST      = 55,
    RENEWAL_TIME_T1     = 58,
    REBINDING_TIME_T2   = 59,
    RELAY_AGENT_INFO    = 82,
    END                 = 255
};

enum class Dhcpv4RelaySubOption : uint8_t {
    CIRCUIT_ID = 1,
    REMOTE_ID  = 2
};

#pragma pack(push, 1)
struct Dhcpv4Header {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic_cookie;
};
#pragma pack(pop)
static_assert(sizeof(Dhcpv4Header) == 240, "Dhcpv4Header must be 240 bytes");

// DHCPv6 Constants & Types
enum class Dhcpv6MsgType : uint8_t {
    SOLICIT             = 1,
    ADVERTISE           = 2,
    REQUEST             = 3,
    CONFIRM             = 4,
    RENEW               = 5,
    REBIND              = 6,
    REPLY               = 7,
    RELEASE             = 8,
    DECLINE             = 9,
    RECONFIGURE         = 10,
    INFORMATION_REQUEST = 11
};

enum class Dhcpv6Option : uint16_t {
    CLIENTID            = 1,
    SERVERID            = 2,
    IA_NA               = 3,
    IA_TA               = 4,
    IA_ADDR             = 5,
    ORO                 = 6,
    PREFERENCE          = 7,
    ELAPSED_TIME        = 8,
    RELAY_MSG           = 9,
    AUTH                = 11,
    UNICAST             = 12,
    STATUS_CODE         = 13,
    RAPID_COMMIT        = 14,
    USER_CLASS          = 15,
    VENDOR_CLASS        = 16,
    VENDOR_OPTS         = 17,
    INTERFACE_ID        = 18,
    RECONF_MSG          = 19,
    RECONF_ACCEPT       = 20,
    DNS_SERVERS         = 23,
    DOMAIN_LIST         = 24,
    IA_PD               = 25,
    IAPREFIX            = 26
};

#pragma pack(push, 1)
struct Dhcpv6Header {
    uint8_t  msg_type;
    uint8_t  transaction_id[3];
};

struct Dhcpv6OptionHeader {
    uint16_t code;
    uint16_t length;
};

struct Dhcpv6IaNaHeader {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
};

struct Dhcpv6IaAddrHeader {
    uint8_t  ipv6_addr[16];
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;
};
#pragma pack(pop)
static_assert(sizeof(Dhcpv6Header) == 4, "Dhcpv6Header must be 4 bytes");
static_assert(sizeof(Dhcpv6OptionHeader) == 4, "Dhcpv6OptionHeader must be 4 bytes");
static_assert(sizeof(Dhcpv6IaNaHeader) == 12, "Dhcpv6IaNaHeader must be 12 bytes");
static_assert(sizeof(Dhcpv6IaAddrHeader) == 24, "Dhcpv6IaAddrHeader must be 24 bytes");

} // namespace ddos_samurai::telecom::dhcp
