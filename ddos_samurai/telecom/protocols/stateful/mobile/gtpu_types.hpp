#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace ddos_samurai::telecom::mobile {

// 3GPP TS 29.281 GTPv1-U Sabitleri
inline constexpr uint16_t GTPU_PORT = 2152;

// GTP-U Mesaj Tipleri
enum class GtpuMessageType : uint8_t {
    EchoRequest                = 1,
    EchoResponse               = 2,
    ErrorIndication            = 26,
    SupportedExtHeadersNotify  = 31,
    EndMarker                  = 254,
    GPdu                       = 255
};

inline std::string_view GtpuMessageTypeToString(GtpuMessageType t) noexcept {
    switch (t) {
        case GtpuMessageType::EchoRequest: return "EchoRequest";
        case GtpuMessageType::EchoResponse: return "EchoResponse";
        case GtpuMessageType::ErrorIndication: return "ErrorIndication";
        case GtpuMessageType::SupportedExtHeadersNotify: return "SupportedExtHeadersNotify";
        case GtpuMessageType::EndMarker: return "EndMarker";
        case GtpuMessageType::GPdu: return "G-PDU";
        default: return "Unknown";
    }
}

// GTP-U Bayrak Maskeleri (3GPP TS 29.281 Section 5.1)
inline constexpr uint8_t GTPU_VERSION_1   = 0x20; // 0010 0000b (Version 1)
inline constexpr uint8_t GTPU_PROTO_GTP   = 0x10; // 0001 0000b (Protocol Type: GTP=1, GTP'=0)
inline constexpr uint8_t GTPU_FLAG_E      = 0x04; // 0000 0100b (Extension Header Flag)
inline constexpr uint8_t GTPU_FLAG_S      = 0x02; // 0000 0010b (Sequence Number Flag)
inline constexpr uint8_t GTPU_FLAG_PN     = 0x01; // 0000 0001b (N-PDU Number Flag)

inline constexpr uint8_t GTPU_HDR_BASE_FLAGS = GTPU_VERSION_1 | GTPU_PROTO_GTP; // 0x30

#pragma pack(push, 1)
// 3GPP TS 29.281 Zorunlu 8-Bayt GTPv1-U Başlığı
struct GtpuHeader {
    uint8_t  flags;       // Version (3 bit), PT (1 bit), Res (1 bit), E, S, PN
    uint8_t  msg_type;    // GtpuMessageType (1, 2, 26, 255)
    uint16_t length;      // Takip eden yükün uzunluğu (Ağ sırası - big endian)
    uint32_t teid;        // Tunnel Endpoint Identifier (Ağ sırası - big endian)
};

// E, S veya PN bayraklarından biri aktifse eklenen 4 baytlık opsiyonel alan
struct GtpuOptFields {
    uint16_t seq_num;     // Sıra numarası (Ağ sırası)
    uint8_t  n_pdu;       // N-PDU numarası
    uint8_t  next_ext;    // Sonraki uzantı başlık tipi (Yoksa 0x00)
};
#pragma pack(pop)

static_assert(sizeof(GtpuHeader) == 8, "GtpuHeader tam 8 bayt olmalidir");
static_assert(sizeof(GtpuOptFields) == 4, "GtpuOptFields tam 4 bayt olmalidir");

// GTP-U Oturum Alt Durumları
enum class GtpuSubState : uint8_t {
    IDLE = 0,
    ACTIVE,          // Tünel kuruldu, veri akışı aktif
    ECHO_PENDING,    // Echo Request gönderildi, yanıt bekleniyor
    DEGRADED,        // Echo kaybı yaşandı (yeniden deneniyor)
    TEARDOWN,        // Tünel sonlandırıldı / Error Indication alındı
    FAILED           // Canlılık tamamen koptu
};

// GTP-U Tünel Yapılandırması
struct GtpuTunnelConfig {
    uint32_t uplink_teid{0};       // UE -> UPF yönü TEID
    uint32_t downlink_teid{0};     // UPF -> gNodeB yönü TEID
    uint32_t peer_upf_ip{0};       // UPF IPv4 (Ağ sırası değil, host integer)
    uint32_t local_gnb_ip{0};      // gNodeB IPv4
    uint16_t peer_port{GTPU_PORT}; // Varsayılan 2152
    uint16_t local_port{GTPU_PORT};
    uint8_t  peer_mac[6]{0};
    uint8_t  local_mac[6]{0};
    uint32_t echo_interval_ms{5000}; // 5 saniye canlılık sorgusu
    uint8_t  echo_max_retries{3};
};

struct GtpuDecapInfo {
    uint32_t teid{0};
    uint8_t  msg_type{0};
    uint16_t seq_num{0};
    bool     has_seq{false};
    const uint8_t* payload{nullptr};
    size_t   payload_len{0};
};

} // namespace ddos_samurai::telecom::mobile
