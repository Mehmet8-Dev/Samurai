#pragma once

#include <cstdint>
#include <string_view>

struct rte_mbuf;
struct rte_mempool;

namespace ddos_samurai::telecom {

struct TelcoSessionContext;

enum class TelcoProtocolId : uint8_t {
    NONE = 0,
    PPPOE = 1,
    DHCPV4 = 2,
    DHCPV6 = 3,
    GTPU = 4,
    PFCP = 5,
    BFD = 6,
    DOT1X = 7,
    STATELESS_GTPU = 10,
    QINQ_SWEEP = 11
};

struct PacketMetadata {
    uint16_t outer_vlan{0};
    uint16_t inner_vlan{0};
    uint16_t ether_type{0};
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  src_mac[6]{0};
    uint8_t  dst_mac[6]{0};
    const uint8_t* raw_frame{nullptr};
    uint16_t raw_len{0};
    const uint8_t* payload_ptr{nullptr};
    uint16_t payload_len{0};
};

struct ProtocolConfig {
    uint32_t max_sessions{100000};
    uint32_t rate_cps{1000};            // Hedef kurulum hızı (Calls Per Second)
    uint32_t retransmit_timeout_ms{500};// Yeniden iletim zaman aşımı (ms)
    uint32_t max_retries{3};            // Maksimum yeniden deneme
    bool     enable_vlan_tagging{false};
    uint16_t base_vlan_s{0};
    uint16_t base_vlan_c{0};
};

class ITelcoProtocol {
public:
    virtual ~ITelcoProtocol() = default;

    virtual bool Init(const ProtocolConfig& cfg) = 0;
    virtual void Shutdown() = 0;

    // Gelen veri veya kontrol paketini işle
    virtual void OnRxPacket(rte_mbuf* mbuf, 
                            const PacketMetadata& meta, 
                            TelcoSessionContext* session) = 0;

    // Zamanlayıcı tikinde retransmission veya periyodik işleri yürüt
    virtual uint32_t OnTimerTick(uint64_t current_tsc) = 0;

    // Belirli bir oturum ve olay için paket üret
    virtual rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                                    TelcoSessionContext* session, 
                                    uint16_t event_type) = 0;

    virtual bool IsStateful() const noexcept = 0;
    virtual TelcoProtocolId GetProtocolId() const noexcept = 0;
    virtual std::string_view GetProtocolName() const noexcept = 0;
};

} // namespace ddos_samurai::telecom
