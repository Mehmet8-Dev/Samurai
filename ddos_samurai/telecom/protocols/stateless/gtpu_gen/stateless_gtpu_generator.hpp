#pragma once

#include "gtpu_gen_types.hpp"
#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace ddos_samurai::telecom::stateless {

class alignas(64) StatelessGtpuGenerator final : public ITelcoProtocol {
public:
    StatelessGtpuGenerator();
    explicit StatelessGtpuGenerator(const GtpuGenConfig& cfg);
    ~StatelessGtpuGenerator() override = default;

    // ITelcoProtocol Arayüzü Uygulaması
    bool Init(const ProtocolConfig& cfg) override;
    bool Init(const GtpuGenConfig& cfg);
    void Shutdown() override;

    void OnRxPacket(rte_mbuf* mbuf, 
                    const PacketMetadata& meta, 
                    TelcoSessionContext* session) override;
    uint32_t OnTimerTick(uint64_t current_tsc) override;
    rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                            TelcoSessionContext* session, 
                            uint16_t event_type) override;

    bool IsStateful() const noexcept override { return false; }
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::STATELESS_GTPU; }
    std::string_view GetProtocolName() const noexcept override { return "Stateless-GTP-U"; }

    // =========================================================================
    // Yüksek Hızlı Sıfır-Heap Veri Düzlemi Paket Üreteç API'si (Wire-Speed API)
    // =========================================================================
    
    // Tek bir GTP-U paketini tahsis edilmemiş hedef arabelleğe yazar. (Zero-Heap)
    uint32_t GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept;

    // Toplu paket üretimi (DPDK burst tx veya batch socket aktarımı için)
    uint32_t GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
                          uint32_t count, size_t single_buf_capacity) noexcept;

    // Durum ve İstatistikler
    const GtpuGenStats& GetStats() const noexcept { return stats_; }
    void ResetStats() noexcept;
    uint32_t GetCurrentTeid() const noexcept {
        return stats_.packets_generated > 0 ? stats_.current_teid : config_.teid_start;
    }
    size_t GetPacketSize() const noexcept { return total_len_; }
    const GtpuGenConfig& GetConfig() const noexcept { return config_; }

    // Paket Doğrulama Yardımcısı (RFC & 3GPP TS 29.281 Byte Doğrulaması)
    static bool VerifyFrame(const uint8_t* frame, size_t len, GtpuGenVerification& out_verif) noexcept;

private:
    void BuildTemplate();
    inline uint32_t NextTeid() noexcept;
    inline uint32_t NextInnerIp() noexcept;
    inline void UpdateInnerIpChecksum(uint8_t* packet) noexcept;

    GtpuGenConfig config_;
    GtpuGenStats  stats_;

    // 64-bayt hizalı şablon tampon (Zero-heap hot path, Jumbo frame desteği: 10240B)
    alignas(64) uint8_t template_buf_[10240];
    size_t total_len_{0};

    // Şablon içi hızlı erişim ofsetleri (Precomputed Offsets)
    size_t eth_offset_{0};
    size_t outer_ip_offset_{0};
    size_t outer_udp_offset_{0};
    size_t gtpu_offset_{0};
    size_t teid_offset_{0};
    size_t seq_offset_{0};
    size_t inner_ip_offset_{0};
    size_t inner_src_ip_offset_{0};
    size_t inner_ip_csum_offset_{0};
    size_t inner_l4_offset_{0};
    size_t inner_payload_offset_{0};

    // Dinamik döngü sayaçları
    uint32_t current_teid_{1};
    uint32_t current_inner_ip_{0};
    uint16_t current_seq_{1};
    uint32_t rng_state_{0x12345678};
    bool     initialized_{false};
};

} // namespace ddos_samurai::telecom::stateless
