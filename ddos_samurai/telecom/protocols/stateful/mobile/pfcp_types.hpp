#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ddos_samurai::telecom::mobile {

// 3GPP TS 29.244 PFCP N4 Portu
inline constexpr uint16_t PFCP_PORT = 8805;

// PFCP Mesaj Tipleri (3GPP TS 29.244 Table 6.1-1)
enum class PfcpMessageType : uint8_t {
    HeartbeatRequest                = 1,
    HeartbeatResponse               = 2,
    PfdManagementRequest            = 3,
    PfdManagementResponse           = 4,
    AssociationSetupRequest         = 5,
    AssociationSetupResponse        = 6,
    AssociationUpdateRequest        = 7,
    AssociationUpdateResponse       = 8,
    AssociationReleaseRequest       = 9,
    AssociationReleaseResponse      = 10,
    VersionNotSupportedResponse     = 11,
    NodeReportRequest               = 12,
    NodeReportResponse              = 13,
    SessionSetDeletionRequest       = 14,
    SessionSetDeletionResponse      = 15,

    // Oturum Mesajları (S = 1, 64-bit SEID içerir)
    SessionEstablishmentRequest     = 50,
    SessionEstablishmentResponse    = 51,
    SessionModificationRequest      = 52,
    SessionModificationResponse     = 53,
    SessionDeletionRequest          = 54,
    SessionDeletionResponse         = 55,
    SessionReportRequest            = 56,
    SessionReportResponse           = 57
};

inline std::string_view PfcpMessageTypeToString(PfcpMessageType t) noexcept {
    switch (t) {
        case PfcpMessageType::HeartbeatRequest: return "HeartbeatRequest";
        case PfcpMessageType::HeartbeatResponse: return "HeartbeatResponse";
        case PfcpMessageType::AssociationSetupRequest: return "AssociationSetupRequest";
        case PfcpMessageType::AssociationSetupResponse: return "AssociationSetupResponse";
        case PfcpMessageType::SessionEstablishmentRequest: return "SessionEstablishmentRequest";
        case PfcpMessageType::SessionEstablishmentResponse: return "SessionEstablishmentResponse";
        case PfcpMessageType::SessionModificationRequest: return "SessionModificationRequest";
        case PfcpMessageType::SessionModificationResponse: return "SessionModificationResponse";
        case PfcpMessageType::SessionDeletionRequest: return "SessionDeletionRequest";
        case PfcpMessageType::SessionDeletionResponse: return "SessionDeletionResponse";
        default: return "Unknown";
    }
}

// PFCP Information Element (IE) Tipleri (3GPP TS 29.244 Table 8.1.1-1)
enum class PfcpIeType : uint16_t {
    CreatePdr                = 1,
    Pdi                      = 2,
    CreateFar                = 3,
    ForwardingParameters     = 4,
    Cause                    = 19,
    SourceInterface          = 20,
    FTeid                    = 21,
    NetworkInstance          = 22,
    DestinationInterface     = 42,
    ApplyAction              = 44,
    PdrId                    = 56,
    FSeid                    = 57,
    NodeId                   = 60,
    OuterHeaderCreation      = 84,
    UeIpAddress              = 93,
    RecoveryTimeStamp        = 96,
    FarId                    = 108,
    UpdateFar                = 124
};

// PFCP Neden Kodları (Cause IE)
enum class PfcpCause : uint8_t {
    RequestAccepted                  = 1,
    RequestRejected                  = 64,
    SessionContextNotFound           = 65,
    MandatoryIeMissing               = 66,
    ConditionalIeMissing             = 67,
    InvalidLength                    = 68,
    MandatoryIeIncorrect             = 69,
    RuleCreationOrModificationFailure= 72,
    SystemFailure                    = 75,
    NoResourcesAvailable             = 76
};

// PFCP Arayüz Tipleri (Source / Destination Interface IE)
enum class PfcpInterface : uint8_t {
    Access = 0,
    Core   = 1,
    SgiLan = 2,
    CpFunction = 3
};

// Apply Action Bayrakları (Apply Action IE)
inline constexpr uint8_t PFCP_APPLY_ACTION_DROP = 0x01;
inline constexpr uint8_t PFCP_APPLY_ACTION_FORW = 0x02;
inline constexpr uint8_t PFCP_APPLY_ACTION_BUFF = 0x04;
inline constexpr uint8_t PFCP_APPLY_ACTION_NOCP = 0x08;
inline constexpr uint8_t PFCP_APPLY_ACTION_DUPL = 0x10;

#pragma pack(push, 1)
// PFCP Node Başlığı (S = 0, Düğüm Yönetim Mesajları, 8 Bayt)
struct PfcpNodeHeader {
    uint8_t  flags;       // Version (3 bit = 1), FO(0), MP(0), S(0) -> 0x20
    uint8_t  msg_type;    // PfcpMessageType
    uint16_t length;      // 4. bayttan sonraki toplam uzunluk (Ağ sırası)
    uint8_t  seq_num[3];  // 24-bit sequence number (Ağ sırası)
    uint8_t  spare;       // 0x00
};

// PFCP Session Başlığı (S = 1, Oturum Mesajları, 16 Bayt)
struct PfcpSessionHeader {
    uint8_t  flags;       // Version (3 bit = 1), FO(0), MP(0), S(1) -> 0x21
    uint8_t  msg_type;    // PfcpMessageType
    uint16_t length;      // 4. bayttan sonraki toplam uzunluk (Ağ sırası)
    uint64_t seid;        // 64-bit Session Endpoint Identifier (Ağ sırası)
    uint8_t  seq_num[3];  // 24-bit sequence number (Ağ sırası)
    uint8_t  spare;       // 0x00
};

// PFCP TLV Information Element (IE) Başlığı (4 Bayt)
struct PfcpIeHeader {
    uint16_t type;        // PfcpIeType (Ağ sırası)
    uint16_t length;      // IE yükünün bayt cinsinden uzunluğu (Ağ sırası)
};
#pragma pack(pop)

static_assert(sizeof(PfcpNodeHeader) == 8, "PfcpNodeHeader tam 8 bayt olmalidir");
static_assert(sizeof(PfcpSessionHeader) == 16, "PfcpSessionHeader tam 16 bayt olmalidir");
static_assert(sizeof(PfcpIeHeader) == 4, "PfcpIeHeader tam 4 bayt olmalidir");

// PFCP Oturum Alt Durumları
enum class PfcpSubState : uint8_t {
    IDLE = 0,
    ASSOC_PENDING,         // Association Setup Request gönderildi
    ASSOCIATED,            // Düğüm seviyesi ilişki kuruldu (Node Ready)
    SESSION_ESTAB_PENDING, // Session Establishment Request gönderildi
    ESTABLISHED,           // PDR ve FAR kuralları UPF'te aktif
    SESSION_MOD_PENDING,   // Modification gönderildi
    SESSION_DEL_PENDING,   // Deletion gönderildi
    RELEASED,              // Oturum tamamen silindi
    FAILED                 // Timeout veya Cause Error
};

// PDR (Packet Detection Rule) Veri Yapısı
struct PfcpPdr {
    uint16_t pdr_id{1};
    uint32_t precedence{100};
    PfcpInterface source_interface{PfcpInterface::Access};
    uint32_t teid{0};             // Uplink F-TEID
    uint32_t ue_ip{0};            // İstemci UE IP adresi
    uint32_t far_id{1};           // Bağlı olduğu FAR kuralı
};

// FAR (Forwarding Action Rule) Veri Yapısı
struct PfcpFar {
    uint32_t far_id{1};
    uint8_t  apply_action{PFCP_APPLY_ACTION_FORW};
    PfcpInterface destination_interface{PfcpInterface::Core};
    uint32_t outer_teid{0};       // Downlink iletim için TEID
    uint32_t peer_upf_ip{0};      // Hedef IP
};

// PFCP Düğüm ve Oturum Yapılandırması
struct PfcpConfig {
    std::string local_node_id{"smf-samurai-01"};
    uint32_t local_ip{0x0A000001};       // 10.0.0.1
    uint32_t remote_upf_ip{0x0A000002};   // 10.0.0.2
    uint16_t local_port{PFCP_PORT};
    uint16_t remote_port{PFCP_PORT};
    uint8_t  local_mac[6]{0};
    uint8_t  remote_mac[6]{0};
    uint32_t heartbeat_interval_ms{5000};
    uint8_t  max_retries{3};
};

struct PfcpDecapInfo {
    bool     is_session{false};
    uint8_t  msg_type{0};
    uint64_t seid{0};
    uint32_t seq_num{0};
    uint8_t  cause{0};
    bool     has_cause{false};
    uint64_t f_seid{0};
    bool     has_f_seid{false};
    uint32_t f_teid{0};
    bool     has_f_teid{false};
    uint32_t ue_ip{0};
    bool     has_ue_ip{false};
    uint16_t pdr_id{0};
    uint32_t far_id{0};
    const uint8_t* payload{nullptr};
    size_t   payload_len{0};
};

} // namespace ddos_samurai::telecom::mobile
