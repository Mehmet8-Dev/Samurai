#pragma once

#include <cstdint>
#include <cstddef>

namespace ddos_samurai::telemetry {

// NetFlow v9 Header (RFC 3954 Section 5.1 - 20 bytes)
#pragma pack(push, 1)
struct NetFlowV9Header {
  uint16_t version;         // 0x0009
  uint16_t count;           // Number of records (template + data)
  uint32_t sys_uptime_ms;   // Current time in millis since router booted
  uint32_t unix_secs;       // Seconds since 0000 UTC 1970
  uint32_t sequence_number; // Incremental sequence of all export packets
  uint32_t source_id;       // Engine ID / Observation domain
};
static_assert(sizeof(NetFlowV9Header) == 20, "NetFlowV9Header must be exactly 20 bytes");

// IPFIX Header (RFC 7011 Section 3.1 - 16 bytes)
struct IpfixHeader {
  uint16_t version;         // 0x000A (10)
  uint16_t length;          // Total length of IPFIX message in bytes (incl. header)
  uint32_t export_time;     // Unix epoch seconds
  uint32_t sequence_number; // Incremental sequence counter
  uint32_t observation_domain_id; // Observation domain identifier
};
static_assert(sizeof(IpfixHeader) == 16, "IpfixHeader must be exactly 16 bytes");

// Set Header for NetFlow v9 and IPFIX (4 bytes)
struct IpfixSetHeader {
  uint16_t set_id; // v9: 0=Template, 1=Options; IPFIX: 2=Template, 3=Options, >=256 Data
  uint16_t length; // Total length of this Set in bytes (incl. set header)
};
static_assert(sizeof(IpfixSetHeader) == 4, "IpfixSetHeader must be exactly 4 bytes");

// Standard IANA Field Specifier (4 bytes)
struct IpfixFieldSpecifier {
  uint16_t element_id; // Top bit (0x8000) indicates enterprise-specific
  uint16_t field_length;
};
static_assert(sizeof(IpfixFieldSpecifier) == 4, "IpfixFieldSpecifier must be 4 bytes");

// Enterprise-Specific Field Specifier (8 bytes with PEN)
struct IpfixEnterpriseFieldSpecifier {
  uint16_t element_id;   // Top bit set (0x8000 | id)
  uint16_t field_length;
  uint32_t enterprise_number; // Private Enterprise Number (PEN)
};
static_assert(sizeof(IpfixEnterpriseFieldSpecifier) == 8, "IpfixEnterpriseFieldSpecifier must be 8 bytes");

// Standard IANA Information Element (IE) IDs
enum class IanaElementId : uint16_t {
  octetDeltaCount = 1,
  packetDeltaCount = 2,
  protocolIdentifier = 4,
  ipClassOfService = 5,
  tcpControlBits = 6,
  sourceTransportPort = 7,
  sourceIPv4Address = 8,
  destinationTransportPort = 11,
  destinationIPv4Address = 12,
  flowEndSysUpTime = 21,
  flowStartSysUpTime = 22,
  sourceIPv6Address = 27,
  destinationIPv6Address = 28,
  dot1qVlanId = 58,
  flowStartNanoseconds = 152,
  flowEndNanoseconds = 153,
  tcpWindowSize = 186
};

// Custom Samurai / Infinity Enterprise Information Elements
// Private Enterprise Number (PEN) for Samurai / Infinity
inline constexpr uint32_t SAMURAI_ENTERPRISE_PEN = 59888;

enum class SamuraiEnterpriseId : uint16_t {
  rttMicroseconds = 1,
  retransmitPacketCount = 2,
  outOfOrderPacketCount = 3,
  flowSecurityFlags = 4,
  attackVectorId = 5,
  mitigationAction = 6
};

// 16-bayt temel 5-tuple akış anahtarı
struct SamuraiFlowKey {
  std::uint32_t src_ip;    // 4 bayt: Ağ sırasındaki Kaynak IPv4
  std::uint32_t dst_ip;    // 4 bayt: Ağ sırasındaki Hedef IPv4
  std::uint16_t src_port;  // 2 bayt: Ağ sırasındaki Kaynak Port
  std::uint16_t dst_port;  // 2 bayt: Ağ sırasındaki Hedef Port
  std::uint8_t  protocol;  // 1 bayt: IP Protokolü (6=TCP, 17=UDP, 1=ICMP)
  std::uint8_t  pad0;      // 1 bayt: Doldurma
  std::uint16_t vlan_id;   // 2 bayt: 802.1Q VLAN kimliği
};
static_assert(sizeof(SamuraiFlowKey) == 16, "SamuraiFlowKey must be exactly 16 bytes");

// 64-bayt önbellek satırına (Cache-Line) tam hizalı akış kaydı
struct alignas(64) SamuraiFlowRecord {
  SamuraiFlowKey key;           // 16 bayt (0..15)
  std::uint64_t start_tsc;      // 8 bayt  (16..23): Akış başlangıç zamanı (TSC)
  std::uint64_t last_tsc;       // 8 bayt  (24..31): Son görülen paket zamanı (TSC)
  std::uint64_t packet_count;   // 8 bayt  (32..39): Toplam paket sayısı
  std::uint64_t byte_count;     // 8 bayt  (40..47): Toplam bayt sayısı
  std::uint32_t flow_id;        // 4 bayt  (48..51): Benzersiz akış sıra no
  std::uint16_t rtt_us;         // 2 bayt  (52..53): Ölçülen RTT (mikrosaniye)
  std::uint16_t retransmit_cnt; // 2 bayt  (54..55): TCP yeniden iletim sayısı
  std::uint16_t out_of_order_cnt;// 2 bayt (56..57): Sırasız paket sayısı
  std::uint8_t  tcp_flags_or;   // 1 bayt  (58): Birikimli TCP bayrakları OR katlaması
  std::uint8_t  state;          // 1 bayt  (59): 0=Free, 1=Active, 2=FinClosing, 3=Evicted
  std::uint32_t security_flags; // 4 bayt  (60..63): Güvenlik / WAF / Anomali bayrakları
};
#pragma pack(pop)
static_assert(sizeof(SamuraiFlowRecord) == 64, "SamuraiFlowRecord must be exactly 64 bytes");

}  // namespace ddos_samurai::telemetry
