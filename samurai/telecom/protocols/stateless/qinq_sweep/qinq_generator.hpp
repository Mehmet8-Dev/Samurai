#pragma once

#include "qinq_types.hpp"
#include "samurai/telecom/core/telco_protocol_if.hpp"

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace samurai::telecom::stateless {

class alignas(64) QinQGenerator final : public ITelcoProtocol {
public:
    QinQGenerator();
    explicit QinQGenerator(const QinQGeneratorConfig& cfg);
    ~QinQGenerator() override = default;

    // ITelcoProtocol Arayüzü Uygulaması
    bool Init(const ProtocolConfig& cfg) override;
    bool Init(const QinQGeneratorConfig& cfg);
    void Shutdown() override;

    void OnRxPacket(rte_mbuf* mbuf, 
                    const PacketMetadata& meta, 
                    TelcoSessionContext* session) override;
    uint32_t OnTimerTick(uint64_t current_tsc) override;
    rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                            TelcoSessionContext* session, 
                            uint16_t event_type) override;

    bool IsStateful() const noexcept override { return false; }
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::QINQ_SWEEP; }
    std::string_view GetProtocolName() const noexcept override { return "QinQ-Sweep"; }

    // =========================================================================
    // Yüksek Hızlı Sıfır-Heap Veri Düzlemi QinQ Paket Üreteç API'si
    // =========================================================================

    // Tek bir QinQ etiketli çerçeveyi hedef arabelleğe yazar. (Zero-Heap)
    uint32_t GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept;

    // Toplu QinQ çerçeve üretimi (Zero-Heap)
    uint32_t GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
                          uint32_t count, size_t single_buf_capacity) noexcept;

    // Durum ve İstatistikler
    const QinQGenStats& GetStats() const noexcept { return stats_; }
    void ResetStats() noexcept;
    uint16_t GetCurrentSVlan() const noexcept {
        return stats_.packets_generated > 0 ? stats_.current_s_vlan : config_.s_vlan_min;
    }
    uint16_t GetCurrentCVlan() const noexcept {
        return stats_.packets_generated > 0 ? stats_.current_c_vlan : config_.c_vlan_min;
    }
    size_t GetPacketSize() const noexcept { return total_len_; }
    const QinQGeneratorConfig& GetConfig() const noexcept { return config_; }

    // Çerçeve Doğrulama Yardımcısı (802.1ad / 802.1Q Byte Doğrulaması)
    static bool VerifyFrame(const uint8_t* frame, size_t len, QinQVerificationInfo& out_verif) noexcept;

private:
    void BuildTemplate();
    inline void AdvanceVlanIndices() noexcept;

    QinQGeneratorConfig config_;
    QinQGenStats        stats_;

    // 64-bayt hizalı şablon tampon (Jumbo frame desteği: 10240B)
    alignas(64) uint8_t template_buf_[10240];
    size_t total_len_{0};

    // Ofsetler
    size_t s_tci_offset_{14}; // template_buf_ + 12 (s_tag.tpid) + 2 = 14
    size_t c_tci_offset_{18}; // template_buf_ + 16 (c_tag.tpid) + 2 = 18

    // Dinamik döngü değişkenleri
    uint16_t current_s_vlan_{1};
    uint16_t current_c_vlan_{1};
    uint32_t rng_state_{0x98765432};
    bool     initialized_{false};
};

} // namespace samurai::telecom::stateless
