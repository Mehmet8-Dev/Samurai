#pragma once

#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "dhcp_types.hpp"
#include "dhcp_fsm.hpp"

#include <vector>
#include <string>
#include <memory>

namespace ddos_samurai::telecom::dhcp {

class DhcpEngine final : public ITelcoProtocol {
public:
    explicit DhcpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel = nullptr);
    ~DhcpEngine() override = default;

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
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::DHCPV4; }
    std::string_view GetProtocolName() const noexcept override { return "DHCP"; }

    // Ham paket (Raw frame) seviyesi doğrulama ve veri düzlemi işleme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session = nullptr);

    // Oturum Yönetimi
    void StartDhcpv4(TelcoSessionContext* session, uint32_t xid = 0);
    void StartDhcpv6(TelcoSessionContext* session, uint32_t xid = 0);
    void RenewDhcp(TelcoSessionContext* session);
    void ReleaseDhcp(TelcoSessionContext* session);

    // Alt durum kontrolü
    DhcpSubState GetSubState(const TelcoSessionContext* session) const noexcept;
    void SetSubState(TelcoSessionContext* session, DhcpSubState sub) noexcept;

    // Option 82 Relay Agent Information desteği
    void SetRelayAgentInfo(const std::string& circuit_id, const std::string& remote_id);
    bool HasRelayAgentInfo() const noexcept { return !circuit_id_.empty() || !remote_id_.empty(); }

    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }
    const std::vector<uint8_t>& GetLastTxFrame() const noexcept { return last_tx_frame_; }

    // DHCPv4 Çerçeve Oluşturucuları
    std::vector<uint8_t> BuildDhcpv4Discover(TelcoSessionContext* session);
    std::vector<uint8_t> BuildDhcpv4Request(TelcoSessionContext* session, uint32_t req_ip, uint32_t server_ip);
    std::vector<uint8_t> BuildDhcpv4Release(TelcoSessionContext* session);
    std::vector<uint8_t> BuildDhcpv4Inform(TelcoSessionContext* session);

    // Sunucu Tarafı Simülatörleri (Testler İçin)
    std::vector<uint8_t> BuildDhcpv4Offer(TelcoSessionContext* session, uint32_t offered_ip, uint32_t server_ip,
                                          uint32_t lease_time = 3600, const std::string& circuit_id = "", const std::string& remote_id = "");
    std::vector<uint8_t> BuildDhcpv4Ack(TelcoSessionContext* session, uint32_t acked_ip, uint32_t server_ip,
                                        uint32_t lease_time = 3600);
    std::vector<uint8_t> BuildDhcpv4Nak(TelcoSessionContext* session, uint32_t server_ip);

    // DHCPv6 Çerçeve Oluşturucuları (RFC 8415 SARR)
    std::vector<uint8_t> BuildDhcpv6Solicit(TelcoSessionContext* session);
    std::vector<uint8_t> BuildDhcpv6Request(TelcoSessionContext* session, const uint8_t* server_duid, size_t server_duid_len, const uint8_t ipv6_addr[16]);
    std::vector<uint8_t> BuildDhcpv6Release(TelcoSessionContext* session, const uint8_t* server_duid, size_t server_duid_len);

    std::vector<uint8_t> BuildDhcpv6Advertise(TelcoSessionContext* session, const uint8_t ipv6_addr[16],
                                              const uint8_t* server_duid = nullptr, size_t server_duid_len = 0);
    std::vector<uint8_t> BuildDhcpv6Reply(TelcoSessionContext* session, const uint8_t ipv6_addr[16],
                                          const uint8_t* server_duid = nullptr, size_t server_duid_len = 0);

    // Zamanlayıcı Zaman Aşımı Geri Çağırma (Timing Wheel Callback)
    void HandleTimeout(TelcoSessionContext* session);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_;

    std::string circuit_id_{""};
    std::string remote_id_{""};
    std::vector<uint8_t> last_tx_frame_;

    // Dahili İşleyiciler
    void HandleDhcpv4Message(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session);
    void HandleDhcpv6Message(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session);
};

} // namespace ddos_samurai::telecom::dhcp
