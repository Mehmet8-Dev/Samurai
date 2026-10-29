#pragma once

#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "bfd_types.hpp"
#include "bfd_fsm.hpp"

#include <vector>
#include <string>
#include <memory>

namespace ddos_samurai::telecom::bfd {

class BfdEngine final : public ITelcoProtocol {
public:
    explicit BfdEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel = nullptr);
    ~BfdEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::BFD; }
    std::string_view GetProtocolName() const noexcept override { return "BFD"; }

    // Ham paket (Raw frame) seviyesi doğrulama ve veri düzlemi işleme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc = 0, TelcoSessionContext* session = nullptr);

    // Oturum Başlatma ve Sonlandırma
    void StartSession(TelcoSessionContext* session, const BfdConfig& bfd_cfg);
    void StopSession(TelcoSessionContext* session);

    // Durum ve Hata Sorgulama
    BfdState GetState(const TelcoSessionContext* session) const noexcept;
    bool IsUp(const TelcoSessionContext* session) const noexcept;
    bool HasFailed(const TelcoSessionContext* session) const noexcept;

    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }
    const std::vector<uint8_t>& GetLastTxFrame() const noexcept { return last_tx_frame_; }

    // Paket Üreticisi
    std::vector<uint8_t> BuildBfdControlPacket(TelcoSessionContext* session, 
                                               BfdState state, 
                                               BfdDiag diag, 
                                               bool poll = false, 
                                               bool final_flag = false);

    // Paket Ayrıştırıcı
    static bool ParseBfdControlPacket(const uint8_t* data, size_t len, 
                                      BfdControlHeader& out_hdr, 
                                      uint32_t& out_remote_disc);

    // Zamanlayıcı Zaman Aşımı / Kalp Atışı (Timing Wheel Callback)
    void HandleTimerStep(TelcoSessionContext* session, uint64_t now_tsc);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_;

    std::vector<uint8_t> last_tx_frame_;

    // Negotiated timing parameters
    uint32_t negotiated_tx_us_{10000};
    uint32_t negotiated_rx_us_{10000};
    uint8_t  detect_mult_{3};
    bool     failover_triggered_{false};
};

} // namespace ddos_samurai::telecom::bfd
