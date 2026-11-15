#pragma once

#include "sip_rtp_types.hpp"
#include "sip_digest_auth.hpp"
#include "srtp_engine.hpp"
#include "samurai/telecom/core/telco_protocol_if.hpp"
#include "samurai/telecom/core/session_context.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <vector>
#include <string>
#include <string_view>

namespace samurai::telecom::sip_rtp {

class SipRtpEngine : public ITelcoProtocol {
public:
    SipRtpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel);
    ~SipRtpEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::SIP_RTP; }
    std::string_view GetProtocolName() const noexcept override { return "SIP_RTP"; }

    // Oturum Başlatma ve Sonlandırma
    void StartCall(TelcoSessionContext* session, const SipCallConfig& cfg);
    void TerminateCall(TelcoSessionContext* session);

    // Gelen çerçeveyi doğrudan işleme (SIP kontrol veya RTP medya)
    bool ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc);

    // Durum Sorgulama
    SipCallState GetState(const TelcoSessionContext* session) const noexcept;
    void SetState(TelcoSessionContext* session, SipCallState state) noexcept;

    // Paket Üretim Fonksiyonları
    std::vector<uint8_t> BuildInvitePacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildAckPacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildByePacket(TelcoSessionContext* session);
    std::vector<uint8_t> BuildResponsePacket(TelcoSessionContext* session, int status_code, const std::string& reason);
    std::vector<uint8_t> BuildRtpPacket(TelcoSessionContext* session, const uint8_t* audio_samples, size_t sample_len);

    // RFC 3550 Jitter Bilgisi
    RtpJitterStats GetJitterStats() const noexcept { return jitter_stats_; }

    uint32_t current_cseq() const noexcept { return current_cseq_; }
    const std::string& auth_header() const noexcept { return auth_header_; }

    SrtpEngine& srtp_tx() noexcept { return srtp_tx_; }
    const SrtpEngine& srtp_tx() const noexcept { return srtp_tx_; }
    SrtpEngine& srtp_rx() noexcept { return srtp_rx_; }
    const SrtpEngine& srtp_rx() const noexcept { return srtp_rx_; }

    const std::vector<uint8_t>& last_tx_packet() const noexcept { return last_tx_frame_; }
    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }
    void HandleTimeout(TelcoSessionContext* session);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_{};
    SipCallConfig call_cfg_{};
    std::vector<uint8_t> last_tx_frame_;

    SrtpEngine srtp_tx_{};
    SrtpEngine srtp_rx_{};

    uint32_t current_cseq_{1};
    std::string auth_header_;
    uint32_t current_rtp_ts_{0};
    uint16_t current_rtp_seq_{0};
    RtpJitterStats jitter_stats_{};
    std::vector<TelcoSessionContext*> active_sip_sessions_;

    bool ProcessSipMessage(TelcoSessionContext* session, const std::string& sip_msg, uint64_t now_tsc);
    bool ProcessRtpPacket(TelcoSessionContext* session, const uint8_t* rtp_data, size_t len, uint64_t now_tsc);
};

} // namespace samurai::telecom::sip_rtp
