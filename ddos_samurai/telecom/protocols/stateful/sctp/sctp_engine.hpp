#pragma once

#include "sctp_types.hpp"
#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_context.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <vector>
#include <string_view>

namespace ddos_samurai::telecom::sctp {

// Önbellek çizgisi hizalı SCTP İlişkilendirme Ek Durumu (Multihoming & PR-SCTP & ASCONF)
struct alignas(64) SctpAssociationState {
    SctpPath paths[SCTP_MAX_PATHS];
    uint8_t  path_count{0};
    uint8_t  primary_path_idx{0};
    uint8_t  active_path_idx{0};
    uint16_t path_max_retrans{3};
    uint32_t asconf_serial{100};
    uint32_t asconf_ack_serial{0};

    // PR-SCTP Zaman Aşımı Kuyruğu (Sıfır yığın ayırma halka tamponu)
    static constexpr size_t MAX_UNACKED_CHUNKS = 32;
    struct TimedChunk {
        uint32_t tsn{0};
        uint16_t stream_id{0};
        uint16_t stream_seq{0};
        uint64_t expire_tsc{0};
        bool active{false};
        bool abandoned{false};
    } unacked_chunks[MAX_UNACKED_CHUNKS];
    size_t unacked_head{0};
    size_t unacked_tail{0};

    // Akış yeniden birleştirme ve sıra takip dizisi
    static constexpr size_t MAX_STREAMS = 16;
    uint16_t next_stream_seq[MAX_STREAMS]{0};

    void Reset() noexcept {
        for (size_t i = 0; i < SCTP_MAX_PATHS; ++i) {
            paths[i] = SctpPath{};
        }
        path_count = 0;
        primary_path_idx = 0;
        active_path_idx = 0;
        path_max_retrans = 3;
        asconf_serial = 100;
        asconf_ack_serial = 0;
        unacked_head = 0;
        unacked_tail = 0;
        for (size_t i = 0; i < MAX_UNACKED_CHUNKS; ++i) {
            unacked_chunks[i] = TimedChunk{};
        }
        for (size_t i = 0; i < MAX_STREAMS; ++i) {
            next_stream_seq[i] = 0;
        }
    }
};

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

    // Multihoming Yol Yönetimi Fonksiyonları (RFC 4960 §5.1.2 & §8)
    bool AddPath(TelcoSessionContext* session, uint32_t peer_ip, bool is_primary = false);
    bool RemovePath(TelcoSessionContext* session, uint32_t peer_ip);
    bool SetPrimaryPath(TelcoSessionContext* session, uint32_t peer_ip);
    size_t GetPathCount(const TelcoSessionContext* session) const;
    const SctpPath* GetPath(const TelcoSessionContext* session, size_t index) const;
    const SctpPath* GetPrimaryPath(const TelcoSessionContext* session) const;
    const SctpPath* GetActivePath(const TelcoSessionContext* session) const;
    size_t GetActivePathIndex(const TelcoSessionContext* session) const;

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
    std::vector<SctpAssociationState> assoc_states_;
    mutable SctpAssociationState fallback_state_;

    SctpAssociationState& GetAssocState(TelcoSessionContext* session);
    const SctpAssociationState& GetAssocState(const TelcoSessionContext* session) const;

    void HandleTimeout(TelcoSessionContext* session);
    bool ParseAndProcessChunks(TelcoSessionContext* session, const uint8_t* sctp_pkt, size_t sctp_len, uint64_t now_tsc);
};

} // namespace ddos_samurai::telecom::sctp
