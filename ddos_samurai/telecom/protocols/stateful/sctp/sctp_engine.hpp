#pragma once

#include "sctp_types.hpp"
#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_context.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <vector>
#include <string_view>

namespace ddos_samurai::telecom::sctp {

class SctpEngine : public ITelcoProtocol {
public:
    SctpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel);
    ~SctpEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::SCTP; }
    std::string_view GetProtocolName() const noexcept override { return "SCTP"; }

    // Oturum Başlatma ve Sonlandırma
    void StartAssociation(TelcoSessionContext* session, const SctpAssociationConfig& cfg);
    void StopAssociation(TelcoSessionContext* session);

    // Gelen çerçeveyi doğrudan işleme ve FSM ilerletme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc);

    // SCTP Durum Makinesi Sorgulama
    SctpState GetState(const TelcoSessionContext* session) const noexcept;
    void SetState(TelcoSessionContext* session, SctpState state) noexcept;

    // Paket İnşa Fonksiyonları
    std::vector<uint8_t> BuildInitPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildInitAckPacket(TelcoSessionContext* session, uint32_t peer_initiate_tag, uint32_t peer_initial_tsn);
    std::vector<uint8_t> BuildCookieEchoPacket(TelcoSessionContext* session, const std::vector<uint8_t>& cookie);
    std::vector<uint8_t> BuildCookieAckPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildHeartbeatPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildHeartbeatAckPacket(TelcoSessionContext* session, const uint8_t* info_param, size_t info_len);
    std::vector<uint8_t> BuildDataPacket(TelcoSessionContext* session, uint32_t ppid, const uint8_t* payload, size_t payload_len);
    std::vector<uint8_t> BuildSackPacket(TelcoSessionContext* session, uint32_t cumulative_tsn);
    std::vector<uint8_t> BuildShutdownPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildShutdownAckPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildShutdownCompletePacket(TelcoSessionContext* session);

    // Donanım Hızlandırmalı CRC32c Hesaplama (RFC 4960 Castagnoli 0x1EDC6F41)
    static uint32_t ComputeCrc32c(const uint8_t* data, size_t len) noexcept;

    const std::vector<uint8_t>& last_tx_packet() const noexcept { return last_tx_frame_; }
    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_{};
    std::vector<uint8_t> last_tx_frame_;
    std::vector<uint8_t> last_cookie_;

    void HandleTimeout(TelcoSessionContext* session);
    bool ParseAndProcessChunks(TelcoSessionContext* session, const uint8_t* sctp_pkt, size_t sctp_len, uint64_t now_tsc);
};

} // namespace ddos_samurai::telecom::sctp
