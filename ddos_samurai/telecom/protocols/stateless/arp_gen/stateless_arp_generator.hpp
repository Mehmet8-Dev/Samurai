#pragma once

#include "arp_gen_types.hpp"
#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace ddos_samurai::telecom::stateless {

class alignas(64) StatelessArpGenerator final : public ITelcoProtocol {
public:
    StatelessArpGenerator();
    explicit StatelessArpGenerator(const ArpGeneratorConfig& cfg);
    ~StatelessArpGenerator() override = default;

    // ITelcoProtocol Arayüzü Uygulaması
    bool Init(const ProtocolConfig& cfg) override;
    bool Init(const ArpGeneratorConfig& cfg);
    void Shutdown() override;

    void OnRxPacket(rte_mbuf* mbuf, 
                    const PacketMetadata& meta, 
                    TelcoSessionContext* session) override;
    uint32_t OnTimerTick(uint64_t current_tsc) override;
    rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                            TelcoSessionContext* session, 
                            uint16_t event_type) override;

    bool IsStateful() const noexcept override { return false; }
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::STATELESS_ARP; }
    std::string_view GetProtocolName() const noexcept override { return "Stateless-ARP"; }

    // =========================================================================
    // Yüksek Hızlı Sıfır-Heap Veri Düzlemi ARP Paket Üreteç API'si
    // =========================================================================

    // Tek bir RFC 826 ARP veya GARP paketini hedef arabelleğe yazar. (Zero-Heap)
    uint32_t GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept;

    // Toplu ARP çerçeve üretimi (Zero-Heap)
    uint32_t GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
                          uint32_t count, size_t single_buf_capacity) noexcept;

    // CIDR Alt Ağ Ayarı (Örn: 192.168.1.0/24 veya 10.0.0.0/16)
    void SetSubnetCidr(uint32_t network_ip, uint8_t prefix_len);

    // Durum ve İstatistikler
    const ArpGenStats& GetStats() const noexcept { return stats_; }
    void ResetStats() noexcept;
    uint32_t GetCurrentTargetIp() const noexcept {
        return stats_.packets_generated > 0 ? stats_.current_target_ip : config_.target_ip_start;
    }
    size_t GetPacketSize() const noexcept { return total_len_; }
    const ArpGeneratorConfig& GetConfig() const noexcept { return config_; }

    // Çerçeve Doğrulama Yardımcısı (RFC 826 / RFC 5227 Byte Doğrulaması)
    static bool VerifyFrame(const uint8_t* frame, size_t len, ArpVerificationInfo& out_verif) noexcept;

private:
    void BuildTemplate();
    inline uint32_t NextIp() noexcept;

    ArpGeneratorConfig config_;
    ArpGenStats        stats_;

    // 64-bayt hizalı şablon tampon (Padded frames desteği: 2048B)
    alignas(64) uint8_t template_buf_[2048];
    size_t total_len_{0};

    // Ofsetler
    size_t eth_header_len_{14};
    size_t arp_payload_offset_{14};
    size_t sender_mac_offset_{22};
    size_t sender_ip_offset_{28};
    size_t target_mac_offset_{32};
    size_t target_ip_offset_{38};

    // Dinamik döngü değişkenleri
    uint32_t current_ip_{0};
    uint32_t current_mac_seq_{1};
    uint32_t rng_state_{0x55AA55AA};
    bool     initialized_{false};
};

} // namespace ddos_samurai::telecom::stateless
