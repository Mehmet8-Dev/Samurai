#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace samurai::telecom::sctp {

// SCTP IP Protokol Numarası
constexpr uint8_t IP_PROTO_SCTP = 132;

// Bilinen Telekom SCTP Portları
constexpr uint16_t SCTP_PORT_S1AP = 36412; // 4G S1-AP (MME - eNB)
constexpr uint16_t SCTP_PORT_NGAP = 38412; // 5G NG-AP (AMF - gNB)
constexpr uint16_t SCTP_PORT_DIAMETER = 3868; // Diameter over SCTP

// 3GPP Standart Payload Protocol Identifiers (PPID)
constexpr uint32_t SCTP_PPID_S1AP = 18; // 3GPP TS 36.413
constexpr uint32_t SCTP_PPID_NGAP = 60; // 3GPP TS 38.413
constexpr uint32_t SCTP_PPID_X2AP = 27; // 3GPP TS 36.423
constexpr uint32_t SCTP_PPID_F1AP = 62; // 3GPP TS 38.472
constexpr uint32_t SCTP_PPID_DIAMETER = 46; // RFC 6733

// SCTP Chunk Türleri (RFC 4960)
enum class SctpChunkType : uint8_t {
    DATA = 0x00,
    INIT = 0x01,
    INIT_ACK = 0x02,
    SACK = 0x03,
    HEARTBEAT = 0x04,
    HEARTBEAT_ACK = 0x05,
    ABORT = 0x06,
    SHUTDOWN = 0x07,
    SHUTDOWN_ACK = 0x08,
    ERROR = 0x09,
    COOKIE_ECHO = 0x0A,
    COOKIE_ACK = 0x0B,
    ECNE = 0x0C,
    CWR = 0x0D,
    SHUTDOWN_COMPLETE = 0x0E,
    // ASCONF (RFC 5061 - Type 0x80)
    ASCONF_ACK = 0x80,
    // PR-SCTP (RFC 3758 - Type 0xC0)
    FORWARD_TSN = 0xC0,
    // ASCONF (RFC 5061 - Type 0xC1)
    ASCONF = 0xC1
};

// ASCONF (RFC 5061) TLV Parametre Tipleri
constexpr uint16_t SCTP_ASCONF_PARAM_SUCCESS = 0x0000;      // Success Indication
constexpr uint16_t SCTP_ASCONF_PARAM_IPV4 = 0x0005;         // IPv4 Address Parameter
constexpr uint16_t SCTP_ASCONF_PARAM_ADD_IP = 0xC001;       // Add IP Address
constexpr uint16_t SCTP_ASCONF_PARAM_DEL_IP = 0xC002;       // Delete IP Address
constexpr uint16_t SCTP_ASCONF_PARAM_ERROR = 0xC003;        // Error Indication
constexpr uint16_t SCTP_ASCONF_PARAM_SET_PRIMARY = 0xC004;  // Set Primary IP Address

// RFC 4960 Durum Makinesi
enum class SctpState : uint8_t {
    CLOSED = 0,
    COOKIE_WAIT,
    COOKIE_ECHOED,
    ESTABLISHED,
    SHUTDOWN_PENDING,
    SHUTDOWN_SENT,
    SHUTDOWN_RECEIVED,
    SHUTDOWN_ACK_SENT,
    FAILED
};

// RFC 4960 §8 Yol Durumları (Multihoming Path Status)
enum class SctpPathStatus : uint8_t {
    INACTIVE = 0,
    UNCONFIRMED = 1,
    ACTIVE = 2
};

// Bir SCTP ilişkilendirmesi için en fazla 4 yol (1 birincil + 3 yedek/ikincil yol)
constexpr size_t SCTP_MAX_PATHS = 4;

struct SctpPath {
    uint32_t ip{0};
    uint16_t port{0};
    uint8_t  mac[6]{0};
    SctpPathStatus status{SctpPathStatus::UNCONFIRMED};
    uint16_t error_counter{0};
    uint32_t rto_ms{1000};
    bool is_primary{false};
    uint64_t last_hb_tsc{0};
};

#pragma pack(push, 1)

// SCTP Common Header (12 Bayt - RFC 4960 Section 3.1)
struct SctpCommonHeader {
    uint16_t src_port;          // Kaynak port (network byte order)
    uint16_t dst_port;          // Hedef port (network byte order)
    uint32_t verification_tag;  // Doğrulama etiketi (network byte order)
    uint32_t checksum;          // CRC32c checksum (little-endian byte order on wire as per RFC 4960)
};
static_assert(sizeof(SctpCommonHeader) == 12, "SctpCommonHeader must be 12 bytes");

// SCTP Chunk Header (4 Bayt - RFC 4960 Section 3.2)
struct SctpChunkHeader {
    uint8_t  type;              // Chunk Type
    uint8_t  flags;             // Chunk Flags
    uint16_t length;            // Chunk Length dahil header (network byte order)
};
static_assert(sizeof(SctpChunkHeader) == 4, "SctpChunkHeader must be 4 bytes");

// INIT ve INIT_ACK Sabit Gövdesi (16 Bayt - RFC 4960 Section 3.3.2)
struct SctpInitChunkBody {
    uint32_t initiate_tag;      // Başlatma Etiketi (peer'in VTag'i olur)
    uint32_t a_rwnd;            // Alıcı Penceresi
    uint16_t num_outbound_streams;
    uint16_t num_inbound_streams;
    uint32_t initial_tsn;       // Başlangıç İletim Sıra Numarası (TSN)
};
static_assert(sizeof(SctpInitChunkBody) == 16, "SctpInitChunkBody must be 16 bytes");

// DATA Chunk Sabit Gövdesi (12 Bayt - RFC 4960 Section 3.3.1)
struct SctpDataChunkBody {
    uint32_t tsn;               // İletim Sıra Numarası
    uint16_t stream_id;         // Akış Tanımlayıcısı
    uint16_t stream_seq;        // Akış Sıra Numarası
    uint32_t ppid;              // Payload Protocol Identifier (S1AP=18, NGAP=60)
};
static_assert(sizeof(SctpDataChunkBody) == 12, "SctpDataChunkBody must be 12 bytes");

// SACK Chunk Sabit Gövdesi (12 Bayt - RFC 4960 Section 3.3.4)
struct SctpSackChunkBody {
    uint32_t cumulative_tsn_ack;
    uint32_t a_rwnd;
    uint16_t num_gap_ack_blocks;
    uint16_t num_duplicate_tsn;
};
static_assert(sizeof(SctpSackChunkBody) == 12, "SctpSackChunkBody must be 12 bytes");

// PR-SCTP FORWARD_TSN Chunk Gövdesi (4 Bayt - RFC 3758 Section 3.2)
struct SctpForwardTsnChunkBody {
    uint32_t new_cumulative_tsn; // İlerletilecek yeni kümülatif TSN
};
static_assert(sizeof(SctpForwardTsnChunkBody) == 4, "SctpForwardTsnChunkBody must be 4 bytes");

// PR-SCTP Terk Edilen Akış Sıra Numarası Çifti (4 Bayt - RFC 3758 Section 3.2)
struct SctpForwardTsnStreamEntry {
    uint16_t stream_id;
    uint16_t stream_seq;
};
static_assert(sizeof(SctpForwardTsnStreamEntry) == 4, "SctpForwardTsnStreamEntry must be 4 bytes");

// ASCONF Chunk Gövdesi (4 Bayt Sabit Başlık - RFC 5061 §3.1.1)
struct SctpAsconfChunkBody {
    uint32_t serial_number; // ASCONF İstek Sıra Numarası
};
static_assert(sizeof(SctpAsconfChunkBody) == 4, "SctpAsconfChunkBody must be 4 bytes");

// ASCONF_ACK Chunk Gövdesi (4 Bayt Sabit Başlık - RFC 5061 §3.1.2)
struct SctpAsconfAckChunkBody {
    uint32_t serial_number; // Yanıtlanan ASCONF Sıra Numarası
};
static_assert(sizeof(SctpAsconfAckChunkBody) == 4, "SctpAsconfAckChunkBody must be 4 bytes");

// Genel ASCONF TLV Parametre Başlığı (4 Bayt)
struct SctpAsconfParamHeader {
    uint16_t type;
    uint16_t length;
};
static_assert(sizeof(SctpAsconfParamHeader) == 4, "SctpAsconfParamHeader must be 4 bytes");

// IPv4 Adres Parametresi (RFC 5061 / RFC 4960 §3.3.2.1 - Type 0x0005, Len 8)
struct SctpIpv4AddressParam {
    uint16_t type{0x0005}; // network order
    uint16_t length{8};     // network order
    uint32_t ipv4_address;  // network order
};
static_assert(sizeof(SctpIpv4AddressParam) == 8, "SctpIpv4AddressParam must be 8 bytes");

// Add / Delete / Set Primary IP Adres Parametresi (RFC 5061 §4.2 - Len 16)
struct SctpAsconfAddressParam {
    uint16_t type;          // 0xC001, 0xC002 veya 0xC004
    uint16_t length;        // 16 bayt
    uint32_t correlation_id;
    SctpIpv4AddressParam addr;
};
static_assert(sizeof(SctpAsconfAddressParam) == 16, "SctpAsconfAddressParam must be 16 bytes");

// Success Indication Yanıt Parametresi (RFC 5061 §4.2.4 - Type 0x0000, Len 8)
struct SctpAsconfSuccessParam {
    uint16_t type{0x0000};
    uint16_t length{8};
    uint32_t correlation_id;
};
static_assert(sizeof(SctpAsconfSuccessParam) == 8, "SctpAsconfSuccessParam must be 8 bytes");

#pragma pack(pop)

struct SctpAssociationConfig {
    uint32_t local_ip{0};
    uint32_t peer_ip{0};
    uint16_t local_port{SCTP_PORT_NGAP};
    uint16_t peer_port{SCTP_PORT_NGAP};
    uint8_t  local_mac[6]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t  peer_mac[6]{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint16_t vlan_s{0};
    uint16_t vlan_c{0};

    uint32_t my_vtag{0x12345678};
    uint32_t peer_vtag{0};
    uint32_t my_initial_tsn{1000};
    uint32_t peer_initial_tsn{0};
    uint32_t a_rwnd{65536};
    uint16_t outbound_streams{10};
    uint16_t inbound_streams{10};
    uint32_t heartbeat_interval_ms{5000};
    uint32_t retransmit_timeout_ms{1000};
    uint16_t max_retries{3};

    // Multihoming Desteği (RFC 4960 §5.1.2 & §8)
    std::vector<uint32_t> peer_secondary_ips{};
    uint16_t path_max_retrans{3};
    bool enable_pr_sctp{true};
};

} // namespace samurai::telecom::sctp
