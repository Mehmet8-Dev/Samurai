#pragma once

#include "samurai/telecom/core/telco_protocol_if.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "gtpu_types.hpp"

#include <vector>
#include <string>
#include <memory>

namespace samurai::telecom::mobile {

class GtpuEngine final : public ITelcoProtocol {
public:
    explicit GtpuEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel = nullptr);
    ~GtpuEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::GTPU; }
    std::string_view GetProtocolName() const noexcept override { return "GTP-U"; }

    // Ham paket (Raw frame) seviyesi doğrulama ve veri düzlemi işleme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session = nullptr);

    // Oturum Başlatma ve Sonlandırma
    void StartSession(TelcoSessionContext* session, const GtpuTunnelConfig& tunnel_cfg);
    void StopSession(TelcoSessionContext* session);

    // Tünelleme / Paket Kapsülleme (Encapsulation) - Zero-Allocation Buffer & Vector API
    size_t EncapsulateInto(TelcoSessionContext* session,
                           const uint8_t* inner_pkt,
                           size_t inner_len,
                           uint8_t* out_buf,
                           size_t max_len,
                           uint16_t seq_num = 0) noexcept;

    std::vector<uint8_t> Encapsulate(TelcoSessionContext* session, 
                                     const uint8_t* inner_pkt, 
                                     size_t inner_len, 
                                     uint16_t seq_num = 0);

    // Tünel Çözme (Decapsulation & Doğrulama)
    static bool Decapsulate(const uint8_t* frame, size_t len, GtpuDecapInfo& out_info);

    // Canlılık ve Hata Paket Üreticileri (Zero-Allocation Buffer & Vector API)
    size_t BuildEchoRequestInto(TelcoSessionContext* session,
                                uint16_t seq_num,
                                uint8_t* out_buf,
                                size_t max_len) noexcept;
    size_t BuildEchoResponseInto(TelcoSessionContext* session,
                                 uint16_t seq_num,
                                 uint8_t restart_counter,
                                 uint8_t* out_buf,
                                 size_t max_len) noexcept;
    size_t BuildErrorIndicationInto(TelcoSessionContext* session,
                                    uint32_t teid,
                                    uint32_t peer_ip,
                                    uint8_t* out_buf,
                                    size_t max_len) noexcept;

    std::vector<uint8_t> BuildEchoRequest(TelcoSessionContext* session, uint16_t seq_num);
    std::vector<uint8_t> BuildEchoResponse(TelcoSessionContext* session, uint16_t seq_num, uint8_t restart_counter = 0);
    std::vector<uint8_t> BuildErrorIndication(TelcoSessionContext* session, uint32_t teid, uint32_t peer_ip);

    // Durum ve Alt Durum Yönetimi
    GtpuSubState GetSubState(const TelcoSessionContext* session) const noexcept;
    void SetSubState(TelcoSessionContext* session, GtpuSubState state) noexcept;

    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }
    const std::vector<uint8_t>& GetLastTxFrame() const noexcept { return last_tx_frame_; }

    void HandleTimeout(TelcoSessionContext* session);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_;

    std::vector<uint8_t> last_tx_frame_;
    uint16_t next_seq_num_{1};
    uint8_t restart_counter_{1};
};

} // namespace samurai::telecom::mobile
