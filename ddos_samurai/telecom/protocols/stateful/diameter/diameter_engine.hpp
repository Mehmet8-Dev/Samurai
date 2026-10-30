#pragma once

#include "diameter_types.hpp"
#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_context.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <vector>
#include <string>
#include <string_view>

namespace ddos_samurai::telecom::diameter {

class DiameterEngine : public ITelcoProtocol {
public:
    DiameterEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel);
    ~DiameterEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::DIAMETER; }
    std::string_view GetProtocolName() const noexcept override { return "DIAMETER"; }

    // Oturum Başlatma ve Sonlandırma
    void StartPeerSession(TelcoSessionContext* session, const DiameterPeerConfig& cfg);
    void StopPeerSession(TelcoSessionContext* session);

    // Gelen çerçeveyi doğrudan işleme ve FSM ilerletme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc);

    // FSM Durumu
    DiameterPeerState GetState(const TelcoSessionContext* session) const noexcept;
    void SetState(TelcoSessionContext* session, DiameterPeerState state) noexcept;

    // Paket Üretim Fonksiyonları
    std::vector<uint8_t> BuildCerPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildCeaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id);
    std::vector<uint8_t> BuildDwrPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildDwaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id);
    std::vector<uint8_t> BuildDprPacket(TelcoSessionContext* session, uint32_t disconnect_cause);
    std::vector<uint8_t> BuildDpaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id);
    std::vector<uint8_t> BuildCcrPacket(TelcoSessionContext* session, const std::string& session_id, CcRequestType req_type, uint32_t req_number);
    std::vector<uint8_t> BuildCcaPacket(TelcoSessionContext* session, const std::string& session_id, uint32_t result_code, CcRequestType req_type, uint32_t req_number, uint32_t hop_id, uint32_t end_id);

    // AVP Kodlama Yardımcıları
    static void AppendAvpString(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, const std::string& str, uint32_t vendor_id = 0);
    static void AppendAvpU32(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, uint32_t val, uint32_t vendor_id = 0);
    static void AppendAvpIp(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, uint32_t ipv4, uint32_t vendor_id = 0);

    const std::vector<uint8_t>& last_tx_packet() const noexcept { return last_tx_frame_; }
    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_{};
    DiameterPeerConfig peer_cfg_{};
    std::vector<uint8_t> last_tx_frame_;
    uint32_t next_hop_by_hop_id_{0x10000000};
    uint32_t next_end_to_end_id_{0x20000000};

    void HandleTimeout(TelcoSessionContext* session);
    bool ProcessDiameterPayload(TelcoSessionContext* session, const uint8_t* payload, size_t len, uint64_t now_tsc);
};

} // namespace ddos_samurai::telecom::diameter
