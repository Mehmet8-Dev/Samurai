#pragma once

#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "pfcp_types.hpp"

#include <vector>
#include <string>
#include <memory>

namespace ddos_samurai::telecom::mobile {

class PfcpEngine final : public ITelcoProtocol {
public:
    explicit PfcpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel = nullptr);
    ~PfcpEngine() override = default;

    bool Init(const ProtocolConfig& cfg) override;
    void Shutdown() override;

    void OnRxPacket(rte_mbuf* mbuf, 
                    const PacketMetadata& meta, 
                    TelcoSessionContext* session) override;

    uint32_t OnTimerTick(uint64_t current_tsc) override;

    rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                            TelcoSessionContext* session, 
                            uint16_t event_type) override;

    bool IsStateful() const noexcept override { return true; }
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::PFCP; }
    std::string_view GetProtocolName() const noexcept override { return "PFCP"; }

    // Ham paket işleme ve doğrulama
    bool ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session = nullptr);

    // Düğüm Düzeyi İlişki (Node Association)
    void StartAssociation(const PfcpConfig& cfg);
    bool IsAssociated() const noexcept { return is_associated_; }

    // Oturum Yönetimi (Session Lifecycle)
    void EstablishSession(TelcoSessionContext* session, 
                          uint64_t cp_seid, 
                          const PfcpPdr& pdr, 
                          const PfcpFar& far);

    void ModifySession(TelcoSessionContext* session, const PfcpFar& updated_far);
    void DeleteSession(TelcoSessionContext* session);

    // Durum ve Alt Durum Sorgulama
    PfcpSubState GetSubState(const TelcoSessionContext* session) const noexcept;
    void SetSubState(TelcoSessionContext* session, PfcpSubState state) noexcept;

    // Ayrıştırıcı (Decoder / Packet Parser)
    static bool ParsePfcpPacket(const uint8_t* frame, size_t len, PfcpDecapInfo& out_info);

    // Node Paket Üreticileri (S = 0) - Zero-Allocation Buffer & Vector API
    size_t BuildAssociationSetupRequestInto(uint32_t seq, uint32_t node_ip, uint8_t* out_buf, size_t max_len) noexcept;
    size_t BuildAssociationSetupResponseInto(uint32_t seq, uint32_t node_ip, PfcpCause cause, uint8_t* out_buf, size_t max_len) noexcept;
    size_t BuildHeartbeatRequestInto(uint32_t seq, uint8_t* out_buf, size_t max_len) noexcept;
    size_t BuildHeartbeatResponseInto(uint32_t seq, uint32_t recovery_timestamp, uint8_t* out_buf, size_t max_len) noexcept;

    std::vector<uint8_t> BuildAssociationSetupRequest(uint32_t seq, const std::string& node_id, uint32_t node_ip);
    std::vector<uint8_t> BuildAssociationSetupResponse(uint32_t seq, const std::string& node_id, uint32_t node_ip, PfcpCause cause = PfcpCause::RequestAccepted);
    std::vector<uint8_t> BuildHeartbeatRequest(uint32_t seq);
    std::vector<uint8_t> BuildHeartbeatResponse(uint32_t seq, uint32_t recovery_timestamp);

    // Oturum Paket Üreticileri (S = 1) - Zero-Allocation Buffer & Vector API
    size_t BuildSessionEstablishmentRequestInto(TelcoSessionContext* session,
                                                uint32_t seq,
                                                uint64_t cp_seid,
                                                const PfcpPdr& pdr,
                                                const PfcpFar& far,
                                                uint8_t* out_buf,
                                                size_t max_len) noexcept;
    size_t BuildSessionEstablishmentResponseInto(TelcoSessionContext* session,
                                                 uint32_t seq,
                                                 uint64_t cp_seid,
                                                 uint64_t up_seid,
                                                 PfcpCause cause,
                                                 uint8_t* out_buf,
                                                 size_t max_len) noexcept;
    size_t BuildSessionModificationRequestInto(TelcoSessionContext* session,
                                               uint32_t seq,
                                               const PfcpFar& updated_far,
                                               uint8_t* out_buf,
                                               size_t max_len) noexcept;
    size_t BuildSessionModificationResponseInto(TelcoSessionContext* session,
                                                uint32_t seq,
                                                PfcpCause cause,
                                                uint8_t* out_buf,
                                                size_t max_len) noexcept;
    size_t BuildSessionDeletionRequestInto(TelcoSessionContext* session,
                                           uint32_t seq,
                                           uint8_t* out_buf,
                                           size_t max_len) noexcept;
    size_t BuildSessionDeletionResponseInto(TelcoSessionContext* session,
                                            uint32_t seq,
                                            PfcpCause cause,
                                            uint8_t* out_buf,
                                            size_t max_len) noexcept;

    std::vector<uint8_t> BuildSessionEstablishmentRequest(TelcoSessionContext* session, 
                                                         uint32_t seq, 
                                                         uint64_t cp_seid, 
                                                         const PfcpPdr& pdr, 
                                                         const PfcpFar& far);

    std::vector<uint8_t> BuildSessionEstablishmentResponse(TelcoSessionContext* session, 
                                                          uint32_t seq, 
                                                          uint64_t cp_seid, 
                                                          uint64_t up_seid, 
                                                          PfcpCause cause = PfcpCause::RequestAccepted);

    std::vector<uint8_t> BuildSessionModificationRequest(TelcoSessionContext* session, 
                                                        uint32_t seq, 
                                                        const PfcpFar& updated_far);

    std::vector<uint8_t> BuildSessionModificationResponse(TelcoSessionContext* session, 
                                                         uint32_t seq, 
                                                         PfcpCause cause = PfcpCause::RequestAccepted);

    std::vector<uint8_t> BuildSessionDeletionRequest(TelcoSessionContext* session, uint32_t seq);
    std::vector<uint8_t> BuildSessionDeletionResponse(TelcoSessionContext* session, 
                                                     uint32_t seq, 
                                                     PfcpCause cause = PfcpCause::RequestAccepted);

    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }
    const std::vector<uint8_t>& GetLastTxFrame() const noexcept { return last_tx_frame_; }

    void HandleTimeout(TelcoSessionContext* session);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_;
    PfcpConfig pfcp_cfg_;

    bool is_associated_{false};
    uint32_t next_seq_{1};
    uint32_t recovery_timestamp_{0x60000000};

    std::vector<uint8_t> last_tx_frame_;

    // PDR ve FAR Deposu
    PfcpPdr last_pdr_{};
    PfcpFar last_far_{};
};

} // namespace ddos_samurai::telecom::mobile
